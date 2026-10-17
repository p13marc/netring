//! Session-tier subscription runtime (0.25 S3b).
//!
//! A session subscription delivers a parsed L7 **message** (`P::Message`) as
//! soon as it parses, gated by a filter over the message's L7 fields (SNI /
//! HTTP host / DNS qname) plus the flow's 5-tuple. Like the flow tier, it's
//! sugar over the existing typed dispatch: `session::<P>()…​.to(h)` installs a
//! predicate-gated `on::<P>` handler.
//!
//! The L7 fields come from the message via [`L7Fields`]; the 5-tuple comes from
//! [`Ctx::flow`](crate::ctx::Ctx) at dispatch time (the message itself doesn't
//! carry the key).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use flowscope::L4Proto;

use super::predicate::{FieldSource, Predicate};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::protocol::{FlowKey, MessageProtocol, Protocol};

/// L7 field accessors for a parsed session message. Each protocol's message
/// type implements the subset it carries (the rest default to `None`), so the
/// session filter can test `sni` / `http_host` / `dns_qname` uniformly.
///
/// Sealed: implemented only by netring for flowscope's L7 message types (issue
/// #37 §D).
#[allow(unused_variables)]
pub trait L7Fields: super::sealed::Sealed {
    /// TLS Server Name Indication.
    fn sni(&self) -> Option<&str> {
        None
    }
    /// HTTP `Host` header.
    fn http_host(&self) -> Option<&str> {
        None
    }
    /// DNS query name (first question).
    fn dns_qname(&self) -> Option<&str> {
        None
    }
}

#[cfg(feature = "tls")]
impl super::sealed::Sealed for flowscope::tls::TlsMessage {}
#[cfg(feature = "tls")]
impl L7Fields for flowscope::tls::TlsMessage {
    fn sni(&self) -> Option<&str> {
        match self {
            flowscope::tls::TlsMessage::ClientHello(ch) => ch.sni.as_deref(),
            _ => None,
        }
    }
}

#[cfg(feature = "tls")]
impl super::sealed::Sealed for flowscope::tls::TlsHandshake {}
#[cfg(feature = "tls")]
impl L7Fields for flowscope::tls::TlsHandshake {
    fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }
}

#[cfg(feature = "http")]
impl super::sealed::Sealed for flowscope::http::HttpMessage {}
#[cfg(feature = "http")]
impl L7Fields for flowscope::http::HttpMessage {
    fn http_host(&self) -> Option<&str> {
        match self {
            flowscope::http::HttpMessage::Request(req) => req.host(),
            flowscope::http::HttpMessage::Response(_) => None,
            // flowscope 0.20 #78: HttpMessage is now #[non_exhaustive].
            _ => None,
        }
    }
}

#[cfg(feature = "dns")]
impl super::sealed::Sealed for flowscope::dns::DnsMessage {}
#[cfg(feature = "dns")]
impl L7Fields for flowscope::dns::DnsMessage {
    fn dns_qname(&self) -> Option<&str> {
        let questions = match self {
            flowscope::dns::DnsMessage::Query(q) | flowscope::dns::DnsMessage::Unanswered(q) => {
                &q.questions
            }
            flowscope::dns::DnsMessage::Response(r) => &r.questions,
            // `DnsMessage` is `#[non_exhaustive]`; any future variant carries
            // no question we can name → no qname.
            _ => return None,
        };
        questions.first().map(|q| q.name.as_str())
    }
}

/// A session-tier handler: the parsed `P::Message` plus `&mut Ctx`. Synchronous
/// (runs in the post-batch protocol-slot drain).
pub type SessionHandler<P> =
    Arc<dyn for<'c> Fn(&<P as Protocol>::Message, &mut Ctx<'c>) -> Result<()> + Send + Sync>;

/// A built session subscription: the filter [`Predicate`] + its handler.
/// Produced by `session::<P>()…​.to(handler)` and registered via
/// [`MonitorBuilder::subscribe`](crate::monitor::MonitorBuilder::subscribe).
#[derive(Clone)]
pub struct SessionSubscription<P: MessageProtocol> {
    pub(crate) predicate: Predicate,
    pub(crate) handler: SessionHandler<P>,
}

impl<P: MessageProtocol> std::fmt::Debug for SessionSubscription<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSubscription")
            .field("predicate", &self.predicate)
            .field("handler", &"<fn>")
            .finish()
    }
}

/// [`FieldSource`] over a parsed session message: L7 fields from the message
/// (via [`L7Fields`]), 5-tuple from the flow carried on the [`Ctx`] — read
/// from the flow's **initiator** ([`Ctx::endpoints`]: `src_*` is the endpoint
/// that opened the connection, whichever side sent this message; 0.32, #215).
/// Only when the initiator is unknown does it fall back to the address-sorted
/// key's `a` / `b`.
pub(crate) struct SessionFields<'a, M: L7Fields> {
    pub(crate) key: Option<FlowKey>,
    /// `(initiator, responder)`, when known.
    pub(crate) endpoints: Option<(SocketAddr, SocketAddr)>,
    pub(crate) msg: &'a M,
}

impl<M: L7Fields> SessionFields<'_, M> {
    /// `(src, dst)`: the endpoints, else the key as stored.
    fn src_dst(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.endpoints.or_else(|| self.key.map(|k| (k.a, k.b)))
    }
}

impl<M: L7Fields> FieldSource for SessionFields<'_, M> {
    fn l4proto(&self) -> Option<L4Proto> {
        self.key.map(|k| k.proto)
    }
    fn src_port(&self) -> Option<u16> {
        self.src_dst().map(|(s, _)| s.port())
    }
    fn dst_port(&self) -> Option<u16> {
        self.src_dst().map(|(_, d)| d.port())
    }
    fn src_ip(&self) -> Option<IpAddr> {
        self.src_dst().map(|(s, _)| s.ip())
    }
    fn dst_ip(&self) -> Option<IpAddr> {
        self.src_dst().map(|(_, d)| d.ip())
    }
    fn sni(&self) -> Option<&str> {
        self.msg.sni()
    }
    fn http_host(&self) -> Option<&str> {
        self.msg.http_host()
    }
    fn dns_qname(&self) -> Option<&str> {
        self.msg.dns_qname()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::subscription::predicate::{Atom, Glob, Predicate};

    struct MockMsg {
        sni: Option<String>,
    }
    impl crate::monitor::subscription::sealed::Sealed for MockMsg {}
    impl L7Fields for MockMsg {
        fn sni(&self) -> Option<&str> {
            self.sni.as_deref()
        }
    }

    fn tls_key() -> FlowKey {
        flowscope::extract::FiveTupleKey::new(
            L4Proto::Tcp,
            "10.0.0.1:54321".parse().unwrap(),
            "10.0.0.2:443".parse().unwrap(),
        )
    }

    #[test]
    fn session_fields_combine_5tuple_and_l7() {
        let msg = MockMsg {
            sni: Some("login.bank.example".into()),
        };
        let fields = SessionFields {
            key: Some(tls_key()),
            endpoints: None,
            msg: &msg,
        };
        // 5-tuple comes from the flow key…
        assert_eq!(fields.l4proto(), Some(L4Proto::Tcp));
        assert_eq!(fields.dst_port(), Some(443));
        // …L7 fields from the message.
        assert_eq!(fields.sni(), Some("login.bank.example"));

        // A combined filter (tcp AND dst_port 443 AND sni glob) matches.
        let p = Predicate::Atom(Atom::Proto(L4Proto::Tcp))
            .and(Predicate::Atom(Atom::DstPort(443)))
            .and(Predicate::Atom(Atom::SniGlob(Glob::new("*.bank.example"))));
        assert!(p.eval(&fields));

        // A non-matching SNI glob doesn't.
        assert!(!Predicate::Atom(Atom::SniGlob(Glob::new("*.gov"))).eval(&fields));
    }

    /// #215: with the initiator known, `src_*` is the client even when the
    /// key sorts the server first.
    #[test]
    fn session_fields_read_from_the_initiator() {
        let msg = MockMsg { sni: None };
        let server: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let client: SocketAddr = "10.0.0.9:54321".parse().unwrap();
        let fields = SessionFields {
            key: Some(FlowKey::new(L4Proto::Tcp, server, client)),
            endpoints: Some((client, server)),
            msg: &msg,
        };
        assert_eq!(fields.src_ip(), Some(client.ip()));
        assert_eq!(fields.src_port(), Some(54321));
        assert_eq!(fields.dst_port(), Some(443));
        assert!(Predicate::Atom(Atom::DstPort(443)).eval(&fields));
    }

    #[test]
    fn missing_l7_field_does_not_match() {
        let msg = MockMsg { sni: None };
        let fields = SessionFields {
            key: Some(tls_key()),
            endpoints: None,
            msg: &msg,
        };
        // No SNI on the message → an sni filter evaluates false (not a panic).
        assert!(!Predicate::Atom(Atom::SniGlob(Glob::new("*"))).eval(&fields));
    }
}
