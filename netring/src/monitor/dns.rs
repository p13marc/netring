//! Structured DNS observation + IP→name mapping (issue #120).
//!
//! Two surfaces, both over the parsed [`flowscope::dns::DnsMessage`]:
//!
//! - [`on_dns`](crate::monitor::MonitorBuilder::on_dns) — a handler fired per
//!   parsed DNS message with a [`DnsView`] that resolves the client/server sides
//!   and exposes the common fields (qname, rcode, answers, unanswered) without
//!   re-deriving them.
//! - [`name_map`](crate::monitor::MonitorBuilder::name_map) +
//!   [`on_name`](crate::monitor::MonitorBuilder::on_name) — a passive reverse
//!   map (`IP → observed names`) built from DNS responses, so later flows to that
//!   IP can be annotated with the name that resolved to it
//!   ([`Ctx::names`](crate::ctx::Ctx::names)).

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use flowscope::Timestamp;
use flowscope::dns::{DnsMessage, DnsRcode, NameClaim, NameMap, NameMapConfig};

use crate::protocol::FlowKey;

/// A parsed DNS message with its flow context resolved (issue #120). Borrows the
/// underlying [`DnsMessage`]; handed to an
/// [`on_dns`](crate::monitor::MonitorBuilder::on_dns) handler.
pub struct DnsView<'a> {
    /// The parsed DNS message (query or response).
    pub message: &'a DnsMessage,
    /// The client endpoint (the non-`53` side of the flow).
    pub client: IpAddr,
    /// The resolver endpoint (the `53` side, or the flow's `b` side by default).
    pub server: IpAddr,
    /// The flow's 5-tuple key.
    pub key: FlowKey,
    /// Observation timestamp.
    pub ts: Timestamp,
}

impl DnsView<'_> {
    /// The first question's name (the queried FQDN), if any.
    pub fn qname(&self) -> Option<&str> {
        match self.message {
            DnsMessage::Query(q) => q.questions.first().map(|x| x.name.as_str()),
            DnsMessage::Response(r) => r.questions.first().map(|x| x.name.as_str()),
            _ => None,
        }
    }

    /// The response code, for responses.
    pub fn rcode(&self) -> Option<DnsRcode> {
        match self.message {
            DnsMessage::Response(r) => Some(r.rcode),
            _ => None,
        }
    }

    /// `true` if this is a response with no answer records (NXDOMAIN, empty
    /// NOERROR, or a SERVFAIL/REFUSED with no data).
    pub fn is_answerless(&self) -> bool {
        match self.message {
            DnsMessage::Response(r) => r.answers.is_empty(),
            _ => false,
        }
    }

    /// `true` if the message is a query.
    pub fn is_query(&self) -> bool {
        matches!(self.message, DnsMessage::Query(_))
    }

    /// The [Community ID](https://github.com/corelight/community-id-spec) of the
    /// flow, matching the flow events' accessor (issue #123).
    pub fn community_id(&self) -> Option<String> {
        flowscope::KeyFields::community_id(&self.key)
    }
}

/// Resolve `(client, server)` from a flow key: the `53` side is the server; if
/// neither side is `53` (unusual), default the `b` side to the server.
pub(crate) fn client_server(key: &FlowKey) -> (IpAddr, IpAddr) {
    if key.a.port() == 53 {
        (key.b.ip(), key.a.ip())
    } else {
        (key.a.ip(), key.b.ip())
    }
}

/// A handler invoked with each newly-learned `(IP, name)` claim.
pub type NameHandler = Arc<dyn Fn(IpAddr, &NameClaim, &mut crate::ctx::Ctx<'_>) + Send + Sync>;

/// Shared, append-only registry of [`NameHandler`]s — shared between the builder
/// and the internal DNS feed closure so `on_name`/`name_map` call order is
/// irrelevant.
pub(crate) type NameHandlers = Arc<Mutex<Vec<NameHandler>>>;

/// StateMap cell wrapping flowscope's [`NameMap`] plus a reusable drain buffer.
/// Seeded via `name_map()`; the `Default` impl is a never-hit `state_mut`
/// fallback.
pub(crate) struct NameMapState {
    pub(crate) map: NameMap,
    pub(crate) scratch: Vec<(IpAddr, NameClaim)>,
}

impl NameMapState {
    pub(crate) fn new(config: NameMapConfig) -> Self {
        Self {
            map: NameMap::with_config(config),
            scratch: Vec::new(),
        }
    }
}

impl Default for NameMapState {
    fn default() -> Self {
        Self {
            map: NameMap::new(),
            scratch: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowscope::L4Proto;
    use flowscope::extract::FiveTupleKey;

    #[test]
    fn client_server_picks_the_port_53_side() {
        // server on the `a` side.
        let k = FiveTupleKey::new(
            L4Proto::Udp,
            "9.9.9.9:53".parse().unwrap(),
            "10.0.0.5:40000".parse().unwrap(),
        );
        let (c, s) = client_server(&k);
        assert_eq!(c.to_string(), "10.0.0.5");
        assert_eq!(s.to_string(), "9.9.9.9");

        // server on the `b` side.
        let k = FiveTupleKey::new(
            L4Proto::Udp,
            "10.0.0.5:40000".parse().unwrap(),
            "9.9.9.9:53".parse().unwrap(),
        );
        let (c, s) = client_server(&k);
        assert_eq!(c.to_string(), "10.0.0.5");
        assert_eq!(s.to_string(), "9.9.9.9");
    }
}
