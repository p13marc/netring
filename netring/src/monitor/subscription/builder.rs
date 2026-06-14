//! Typed subscription builders (0.25 Phase A1).
//!
//! Three tier constructors return a [`SubscriptionBuilder`] specialised to a
//! tier marker. The typed filter combinators AND atoms into the builder's
//! [`Predicate`]; `into_predicate()` yields the finished AST (consumed by the
//! Phase A2 kernel split and by userspace evaluation). The handler terminal
//! `.to(..)` + registry wiring land in the follow-up unit (A1c).
//!
//! **Compile-time tier/protocol gating** is the headline: the 5-tuple
//! combinators are shared across every tier, byte/packet-count combinators
//! exist only on the flow tier, and each L7 glob combinator exists only on the
//! session tier of a protocol that *has* that field — `session::<Tls>()` has
//! [`sni_glob`](SubscriptionBuilder::sni_glob); `session::<Dns>()` does not
//! (it has [`qname_glob`](SubscriptionBuilder::qname_glob) instead). Invalid
//! combinations are compile errors, not runtime no-ops.
//!
//! ```
//! use netring::monitor::subscription::{packet, flow};
//! use netring::protocol::builtin::Tcp;
//!
//! let _ = packet().tcp().dst_port(443).into_predicate();
//! let _ = flow::<Tcp>().bytes_over(1 << 20).into_predicate();
//! ```
//!
//! With the `tls` feature, the session tier adds protocol-gated L7 globs —
//! `session::<Tls>().sni_glob("*.bank.example")` — but `session::<Dns>()`
//! exposes `qname_glob` instead, and `session::<Tcp>()` doesn't compile.

use std::marker::PhantomData;
use std::net::IpAddr;

use flowscope::L4Proto;

use super::predicate::{Atom, Glob, Predicate};
use crate::config::ipnet::IpNet;
use crate::protocol::{FlowProtocol, MessageProtocol};

/// Tier marker: every captured frame, as a `PacketView`. Filters are L2–L4
/// only (all kernel-pushable).
#[derive(Debug, Clone, Copy)]
pub struct PacketTier;

/// Tier marker: flow lifecycle/tick events for protocol `P`. Adds byte/packet
/// count filters on top of the 5-tuple.
#[derive(Debug, Clone, Copy)]
pub struct FlowTier<P: FlowProtocol>(PhantomData<fn() -> P>);

/// Tier marker: parsed L7 messages (`P::Message`) for protocol `P`. Adds the
/// L7 glob filters its protocol exposes.
#[derive(Debug, Clone, Copy)]
pub struct SessionTier<P: MessageProtocol>(PhantomData<fn() -> P>);

/// A subscription under construction: a tier marker `T` plus the accumulated
/// filter [`Predicate`]. Combinators AND atoms in; [`Self::into_predicate`]
/// finishes.
#[derive(Debug, Clone)]
#[must_use = "a SubscriptionBuilder does nothing until `.to(handler)` (or `.into_predicate()`)"]
pub struct SubscriptionBuilder<T> {
    predicate: Predicate,
    _tier: PhantomData<fn() -> T>,
}

impl<T> SubscriptionBuilder<T> {
    fn start() -> Self {
        Self {
            predicate: Predicate::Always,
            _tier: PhantomData,
        }
    }

    fn and_atom(mut self, atom: Atom) -> Self {
        self.predicate = self.predicate.and(Predicate::Atom(atom));
        self
    }

    /// Finish building and return the filter AST. `Always` if no combinator
    /// was applied (the unfiltered subscription — the `on::<E>` shim shape).
    pub fn into_predicate(self) -> Predicate {
        self.predicate
    }
}

/// Subscribe to **every captured frame** (`PacketView`). The new packet tier:
/// raw frames before any flow tracking, with kernel-pushable L2–L4 filters.
pub fn packet() -> SubscriptionBuilder<PacketTier> {
    SubscriptionBuilder::start()
}

/// Subscribe to **flow events** for protocol `P` (`FlowStarted/Ended/Tick<P>`).
/// `P` is bound to [`FlowProtocol`], so `flow::<Http>()` is a compile error
/// (HTTP is a message protocol, not a flow protocol).
pub fn flow<P: FlowProtocol>() -> SubscriptionBuilder<FlowTier<P>> {
    SubscriptionBuilder::start()
}

/// Subscribe to **parsed L7 messages** for protocol `P` (`P::Message`). `P` is
/// bound to [`MessageProtocol`], so `session::<Tcp>()` is a compile error:
///
/// ```compile_fail
/// use netring::monitor::subscription::session;
/// use netring::protocol::builtin::Tcp;
/// // Tcp is a FlowProtocol, not a MessageProtocol — no L7 session to parse.
/// let _ = session::<Tcp>();
/// ```
pub fn session<P: MessageProtocol>() -> SubscriptionBuilder<SessionTier<P>> {
    SubscriptionBuilder::start()
}

// ---- shared 5-tuple combinators (every tier) ---------------------------

impl<T> SubscriptionBuilder<T> {
    /// Match TCP.
    pub fn tcp(self) -> Self {
        self.and_atom(Atom::Proto(L4Proto::Tcp))
    }
    /// Match UDP.
    pub fn udp(self) -> Self {
        self.and_atom(Atom::Proto(L4Proto::Udp))
    }
    /// Match ICMP (v4).
    pub fn icmp(self) -> Self {
        self.and_atom(Atom::Proto(L4Proto::Icmp))
    }
    /// Match a specific L4 protocol.
    pub fn proto(self, proto: L4Proto) -> Self {
        self.and_atom(Atom::Proto(proto))
    }
    /// Match L4 source port.
    pub fn src_port(self, port: u16) -> Self {
        self.and_atom(Atom::SrcPort(port))
    }
    /// Match L4 destination port.
    pub fn dst_port(self, port: u16) -> Self {
        self.and_atom(Atom::DstPort(port))
    }
    /// Match L4 source OR destination port.
    pub fn port(self, port: u16) -> Self {
        self.and_atom(Atom::AnyPort(port))
    }
    /// Match source IP host.
    pub fn src_host(self, ip: IpAddr) -> Self {
        self.and_atom(Atom::SrcHost(ip))
    }
    /// Match destination IP host.
    pub fn dst_host(self, ip: IpAddr) -> Self {
        self.and_atom(Atom::DstHost(ip))
    }
    /// Match source OR destination host.
    pub fn host(self, ip: IpAddr) -> Self {
        self.and_atom(Atom::AnyHost(ip))
    }
    /// Match source network.
    pub fn src_net(self, net: IpNet) -> Self {
        self.and_atom(Atom::SrcNet(net))
    }
    /// Match destination network.
    pub fn dst_net(self, net: IpNet) -> Self {
        self.and_atom(Atom::DstNet(net))
    }
    /// Match source OR destination network.
    pub fn net(self, net: IpNet) -> Self {
        self.and_atom(Atom::AnyNet(net))
    }
    /// Match 802.1Q VLAN id.
    pub fn vlan(self, id: u16) -> Self {
        self.and_atom(Atom::VlanId(id))
    }
}

// ---- packet-tier terminal ----------------------------------------------

impl SubscriptionBuilder<PacketTier> {
    /// Finish a packet subscription with its handler. The handler sees every
    /// frame matching the filter as a borrowed `PacketView`, with `&mut Ctx`
    /// for emitting / state — synchronous (it runs in the zero-copy drain).
    /// Register the result with
    /// [`MonitorBuilder::subscribe`](crate::monitor::MonitorBuilder::subscribe).
    pub fn to<H>(self, handler: H) -> super::packet::PacketSubscription
    where
        H: for<'a, 'c> Fn(
                &flowscope::PacketView<'a>,
                &mut crate::ctx::Ctx<'c>,
            ) -> crate::error::Result<()>
            + Send
            + Sync
            + 'static,
    {
        super::packet::PacketSubscription {
            predicate: self.predicate,
            handler: std::sync::Arc::new(handler),
        }
    }
}

// ---- flow-tier combinators (byte / packet counts) ----------------------

impl<P: FlowProtocol> SubscriptionBuilder<FlowTier<P>> {
    /// Match flows whose total bytes strictly exceed `n` (userspace — gated
    /// on a flow-tick / flow-ended evaluation).
    pub fn bytes_over(self, n: u64) -> Self {
        self.and_atom(Atom::BytesOver(n))
    }
    /// Match flows whose total packets strictly exceed `n`.
    pub fn packets_over(self, n: u64) -> Self {
        self.and_atom(Atom::PacketsOver(n))
    }

    /// Finish a flow subscription with its handler (0.25 S3). The handler is
    /// called **once per flow, at its end** ([`FlowEnded<P>`]) — with the
    /// flow's final key + stats — for flows matching the filter. Register the
    /// result with
    /// [`MonitorBuilder::subscribe`](crate::monitor::MonitorBuilder::subscribe).
    ///
    /// [`FlowEnded<P>`]: crate::protocol::event_typed::FlowEnded
    pub fn to<H>(self, handler: H) -> super::flow::FlowSubscription<P>
    where
        H: for<'c> Fn(
                &crate::protocol::event_typed::FlowEnded<P>,
                &mut crate::ctx::Ctx<'c>,
            ) -> crate::error::Result<()>
            + Send
            + Sync
            + 'static,
    {
        super::flow::FlowSubscription {
            predicate: self.predicate,
            handler: std::sync::Arc::new(handler),
        }
    }
}

// ---- session-tier combinators (gated by which L7 field P exposes) -------

/// Protocols whose session messages carry a TLS SNI. Gates
/// [`SubscriptionBuilder::sni_glob`] to only those tiers.
pub trait HasSni: MessageProtocol {}
#[cfg(feature = "tls")]
impl HasSni for crate::protocol::builtin::Tls {}
#[cfg(feature = "tls")]
impl HasSni for crate::protocol::builtin::TlsHandshake {}

/// Protocols whose session messages carry an HTTP `Host` header.
pub trait HasHttpHost: MessageProtocol {}
#[cfg(feature = "http")]
impl HasHttpHost for crate::protocol::builtin::Http {}

/// Protocols whose session messages carry a DNS query name.
pub trait HasQname: MessageProtocol {}
#[cfg(feature = "dns")]
impl HasQname for crate::protocol::builtin::Dns {}

impl<P: HasSni> SubscriptionBuilder<SessionTier<P>> {
    /// Match a TLS SNI glob (e.g. `*.bank.example`). Only available on
    /// `session::<Tls>()` / `session::<TlsHandshake>()`.
    pub fn sni_glob(self, pattern: impl Into<String>) -> Self {
        self.and_atom(Atom::SniGlob(Glob::new(pattern)))
    }
}

impl<P: HasHttpHost> SubscriptionBuilder<SessionTier<P>> {
    /// Match an HTTP `Host` glob. Only available on `session::<Http>()`.
    pub fn host_glob(self, pattern: impl Into<String>) -> Self {
        self.and_atom(Atom::HttpHostGlob(Glob::new(pattern)))
    }
}

impl<P: HasQname> SubscriptionBuilder<SessionTier<P>> {
    /// Match a DNS query-name glob. Only available on `session::<Dns>()`.
    pub fn qname_glob(self, pattern: impl Into<String>) -> Self {
        self.and_atom(Atom::DnsQnameGlob(Glob::new(pattern)))
    }
}

impl<P> SubscriptionBuilder<SessionTier<P>>
where
    P: MessageProtocol,
    P::Message: super::session::L7Fields,
{
    /// Finish a session subscription with its handler (0.25 S3b). The handler
    /// is called with each parsed `P::Message` whose L7 fields + flow 5-tuple
    /// match the filter. Register the result with
    /// [`MonitorBuilder::subscribe`](crate::monitor::MonitorBuilder::subscribe);
    /// the protocol's parser must also be registered via
    /// [`protocol::<P>()`](crate::monitor::MonitorBuilder::protocol).
    pub fn to<H>(self, handler: H) -> super::session::SessionSubscription<P>
    where
        H: for<'c> Fn(
                &<P as crate::protocol::Protocol>::Message,
                &mut crate::ctx::Ctx<'c>,
            ) -> crate::error::Result<()>
            + Send
            + Sync
            + 'static,
    {
        super::session::SessionSubscription {
            predicate: self.predicate,
            handler: std::sync::Arc::new(handler),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::protocol::builtin::{Tcp, Udp};

    #[test]
    fn packet_tier_builds_kernel_pushable_conjunction() {
        let p = packet().tcp().dst_port(443).into_predicate();
        // tcp AND dst_port(443)
        match p {
            Predicate::And(l, r) => {
                assert_eq!(*l, Predicate::Atom(Atom::Proto(L4Proto::Tcp)));
                assert_eq!(*r, Predicate::Atom(Atom::DstPort(443)));
            }
            other => panic!("expected And, got {other:?}"),
        }
    }

    #[test]
    fn empty_builder_is_always() {
        assert_eq!(packet().into_predicate(), Predicate::Always);
        assert_eq!(flow::<Tcp>().into_predicate(), Predicate::Always);
    }

    #[test]
    fn flow_tier_count_filters() {
        let p = flow::<Udp>().udp().bytes_over(1024).into_predicate();
        // The last atom in the AND chain is the byte count.
        match p {
            Predicate::And(_, r) => assert_eq!(*r, Predicate::Atom(Atom::BytesOver(1024))),
            other => panic!("expected And, got {other:?}"),
        }
    }

    #[cfg(all(feature = "tls", feature = "http", feature = "dns"))]
    #[test]
    fn session_tier_l7_globs() {
        use crate::protocol::builtin::{Dns, Http, Tls};
        let tls = session::<Tls>().tcp().sni_glob("*.bank").into_predicate();
        match tls {
            Predicate::And(_, r) => {
                assert_eq!(*r, Predicate::Atom(Atom::SniGlob(Glob::new("*.bank"))))
            }
            other => panic!("expected And, got {other:?}"),
        }
        let dns = session::<Dns>().qname_glob("*.evil.test").into_predicate();
        assert_eq!(
            dns,
            Predicate::Atom(Atom::DnsQnameGlob(Glob::new("*.evil.test")))
        );
        let http = session::<Http>().host_glob("api.*").into_predicate();
        assert_eq!(
            http,
            Predicate::Atom(Atom::HttpHostGlob(Glob::new("api.*")))
        );
    }

    #[test]
    fn net_and_host_combinators() {
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        let p = packet()
            .src_net(net)
            .dst_host(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
            .into_predicate();
        // Both atoms present in the conjunction.
        let mut atoms = Vec::new();
        collect_atoms(&p, &mut atoms);
        assert!(atoms.contains(&Atom::SrcNet(net)));
        assert!(atoms.contains(&Atom::DstHost(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))));
    }

    fn collect_atoms(p: &Predicate, out: &mut Vec<Atom>) {
        match p {
            Predicate::Atom(a) => out.push(a.clone()),
            Predicate::And(l, r) | Predicate::Or(l, r) => {
                collect_atoms(l, out);
                collect_atoms(r, out);
            }
            Predicate::Not(inner) => collect_atoms(inner, out),
            Predicate::Always => {}
        }
    }
}
