//! Protocol plugin layer + typed event surface.
//!
//! The [`Protocol`] trait + role markers ([`FlowProtocol`] /
//! [`MessageProtocol`]) define how the [`Monitor`](crate::monitor::Monitor)
//! observes traffic. Built-in markers ship in [`builtin`]; typed
//! lifecycle/message events live in [`event_typed`].
//!
//! The 0.19 `ProtocolMonitor` / `ProtocolEvent` sum-type API was
//! removed in 0.22 — use `Monitor::builder()` + `on`/`on_ctx` instead.

pub mod builtin;
pub mod event_typed;

pub use event_typed::{
    AnyFlowAnomaly, Event, FlowEnded, FlowEstablished, FlowPacket, FlowStarted, FlowTick,
    ParserClosed, Side, Tick,
};

// Re-export the built-in `Protocol` markers at the protocol
// module level so `use netring::protocol::Http;` works (without
// the intermediate `::builtin::` path). The markers also live at
// `netring::protocol::builtin::*` and `netring::prelude::*` for
// users who prefer those paths.
#[cfg(feature = "dhcp")]
pub use builtin::Dhcp;
#[cfg(feature = "dns")]
pub use builtin::Dns;
#[cfg(feature = "http")]
pub use builtin::Http;
#[cfg(feature = "kerberos")]
pub use builtin::Kerberos;
#[cfg(feature = "ldap")]
pub use builtin::Ldap;
#[cfg(feature = "netbios-ns")]
pub use builtin::Nbns;
#[cfg(feature = "rdp")]
pub use builtin::Rdp;
#[cfg(feature = "smb")]
pub use builtin::Smb;
#[cfg(feature = "ssdp")]
pub use builtin::Ssdp;
pub use builtin::{Icmp, Tcp, Udp};
#[cfg(feature = "tls")]
pub use builtin::{Tls, TlsHandshake};

// ─── Plugin layer (netring 0.20, Phase A) ──────────────────────────────────
//
// The `Protocol` trait + supporting types define a protocol-agnostic plugin
// layer. Downstream crates implement `Protocol` for their own marker types
// and register them via the (forthcoming) `Monitor::builder().protocol::<P>()`
// API.
//
// In Phase A these types are defined but NOT yet consumed by the existing
// `ProtocolMonitorBuilder`. Phase B introduces the `Monitor` builder that
// uses them.

/// A protocol the monitor can observe.
///
/// Implementors are usually zero-sized marker types (`struct Http;`).
/// The marker is used as a type-level identifier; the runtime
/// dispatch key is its `TypeId`.
///
/// `'static` is required because dispatch is keyed by `TypeId`.
/// This forecloses lifetime-parameterized marker types — not a
/// real limitation since markers are typically ZSTs.
///
/// Built-in markers ship in [`builtin`]; downstream crates can
/// add their own without editing netring.
///
/// ## Why [`Self::register`] instead of returning a boxed parser
///
/// flowscope's `DriverBuilder::session_on_ports` (and friends)
/// require `P: SessionParser + Clone + Send + 'static`. A boxed
/// trait object (`Box<dyn SessionParser<Message = M>>`) can't
/// satisfy `Clone` and is `!Sized`, so the "give me your boxed
/// parser, I'll register it" shape doesn't compile. Instead the
/// `Protocol` impl drives the registration itself — it keeps the
/// parser as its concrete type all the way to the call site.
pub trait Protocol: Send + Sync + 'static {
    /// The typed message this protocol's parser emits. Must be
    /// `'static` (owning) — the framework downcasts via `Any`,
    /// which requires `'static`.
    type Message: Send + Sync + 'static;

    /// Stable identifier, used for metrics labels, log targets,
    /// and the `parser_kind` field on the low-level Stream API.
    /// Convention: lowercase, hyphenated. Examples: `"http/1"`,
    /// `"dns-udp"`, `"tls-handshake"`. Matches flowscope's
    /// `parser_kinds::*` constants where applicable.
    const NAME: &'static str;

    /// How packets get routed to this protocol's parser.
    fn dispatch() -> Dispatch;

    /// Register this protocol's parser with the given flowscope
    /// driver builder and return the typed drain handle.
    ///
    /// The builder is parameterised on
    /// [`flowscope::extract::FiveTuple`] — netring's canonical
    /// flow extractor. The handle yields per-parser typed
    /// messages of [`Self::Message`].
    ///
    /// Lifecycle-only markers ([`builtin::Tcp`] / [`builtin::Udp`])
    /// have no parser to register and return
    /// [`ProtocolInitError`]; the [`crate::monitor::Monitor`] builder treats
    /// [`Dispatch::AllTcp`] / [`Dispatch::AllUdp`] as "lifecycle
    /// dispatch only — central tracker handles it" and ignores
    /// the error.
    fn register(
        builder: &mut flowscope::driver::DriverBuilder<flowscope::extract::FiveTuple>,
    ) -> Result<
        flowscope::driver::SlotHandle<Self::Message, flowscope::extract::FiveTupleKey>,
        ProtocolInitError,
    >;

    /// 0.21 F.1: register this protocol's parser as a *broadcast*
    /// slot — every drain handle clone receives a copy of each
    /// emitted message, enabling
    /// [`crate::monitor::Monitor::subscribe`] for this protocol.
    ///
    /// Default returns `Err` — protocols that need broadcast must
    /// override (e.g. via flowscope's
    /// `DriverBuilder::session_on_ports_broadcast_each`). The
    /// override imposes `Message: Send + Sync + Clone + 'static`
    /// (per-subscriber clone semantics).
    ///
    /// Used by [`crate::monitor::MonitorBuilder::with_broadcast`]
    /// — calling `register_broadcast` on the builder also adds the
    /// returned handle to the monitor's slot drain (so registered
    /// handlers still see every message, in addition to user
    /// subscribers).
    fn register_broadcast(
        _builder: &mut flowscope::driver::DriverBuilder<flowscope::extract::FiveTuple>,
    ) -> Result<
        flowscope::driver::BroadcastSlotHandle<Self::Message, flowscope::extract::FiveTupleKey>,
        ProtocolInitError,
    >
    where
        Self::Message: Send + Sync + Clone + 'static,
    {
        Err(ProtocolInitError(format!(
            "{} does not support broadcast (only session-shaped L7 protocols do today)",
            Self::NAME
        )))
    }

    /// 0.22 §2.5: build the runtime drain slot for this protocol's
    /// parser `handle`. The default wraps it in a
    /// [`TypedProtocolSlot<Self>`](crate::monitor::TypedProtocolSlot);
    /// [`builtin::Icmp`] overrides this to install an `IcmpSlot` that
    /// also synthesises [`IcmpError`](crate::protocol::event_typed::IcmpError)
    /// events. Called by
    /// [`MonitorBuilder::protocol`](crate::monitor::MonitorBuilder::protocol)
    /// after a successful [`Self::register`].
    fn make_slot(
        handle: flowscope::driver::SlotHandle<Self::Message, flowscope::extract::FiveTupleKey>,
    ) -> Box<dyn crate::monitor::ProtocolSlot>
    where
        Self: Sized,
    {
        Box::new(crate::monitor::TypedProtocolSlot::<Self>::new(handle))
    }
}

/// 0.22 R1: a protocol whose **flows the tracker follows** end to
/// end. Flow-tracked protocols emit the lifecycle events
/// [`FlowStarted`] / [`FlowEstablished`] / [`FlowEnded`] / [`FlowTick`]
/// and participate in the flat [`FlowPacket`] stream; they are keyed by
/// 5-tuple.
///
/// Implemented for [`builtin::Tcp`], [`builtin::Udp`], and
/// [`builtin::Icmp`] (ICMP is *both* flow-tracked — the kernel/
/// flowscope tracker follows ICMP echo + error 5-tuples — and a
/// [`MessageProtocol`]). It is **not** implemented for the L7 markers
/// (`Http`/`Dns`/`Tls`/…): their "flow" is the underlying TCP/UDP
/// flow, so `FlowStarted<Http>` is a type error — use
/// `FlowStarted<Tcp>` and scope by parser via `on::<Http>` instead.
///
/// The bound is what makes `on::<FlowStarted<Http>>(…)` fail to
/// compile (caught at build, not silently never-firing at runtime).
pub trait FlowProtocol: Protocol {}

/// 0.22 R1: a protocol that delivers **discrete parsed messages**.
/// `on::<Self>(|msg, ctx| …)` fires once per [`Protocol::Message`]
/// the parser emits.
///
/// Implemented for the L7 markers (`Http`/`Dns`/`Tls`/`TlsHandshake`)
/// and [`builtin::Icmp`]. It is **not** implemented for the
/// lifecycle-only markers [`builtin::Tcp`] / [`builtin::Udp`] (their
/// [`Protocol::Message`] is `()`), so `on::<Tcp>(…)` is a type error —
/// use a lifecycle event (`on::<FlowStarted<Tcp>>`) instead.
///
/// Also gates the broadcast surface
/// ([`MonitorBuilder::with_broadcast`](crate::monitor::MonitorBuilder::with_broadcast)
/// / [`Monitor::subscribe`](crate::monitor::Monitor::subscribe)):
/// only message protocols carry a meaningful per-message stream.
pub trait MessageProtocol: Protocol {}

/// How a protocol selects packets for its parser.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Dispatch {
    /// Match TCP flows on these ports.
    Tcp(Vec<u16>),
    /// Match UDP flows on these ports.
    Udp(Vec<u16>),
    /// Match all ICMP / ICMPv6 datagrams.
    Icmp,
    /// All TCP flows regardless of port — the L4-lifecycle case
    /// for the [`builtin::Tcp`] marker.
    AllTcp,
    /// All UDP flows regardless of port — the [`builtin::Udp`] marker.
    AllUdp,
    /// Port-agnostic dispatch via a signature function over the
    /// first ≤64 payload bytes. The function returns whether the
    /// packet matches; matching flows pin to the parser.
    Signature(fn(&[u8]) -> SignatureMatch),
}

/// 0.25 S1: the **traffic interest** of one consumer (a handler, a registered
/// protocol parser, an exporter). The Monitor folds every consumer's class
/// into the OR-union it pushes to the kernel as a conservative prefilter
/// (see the subscription-engine design). A consumer can only ever *widen* the
/// union, never narrow it — so the kernel filter is always a superset of what
/// some consumer wants, and no consumer is starved.
///
/// Kept in the `protocol` module (no `Predicate` dependency) so the [`Event`]
/// trait can declare it; the Monitor maps it to a
/// [`Predicate`](crate::monitor::subscription::Predicate) at build time.
#[derive(Debug, Clone)]
pub enum TrafficClass {
    /// Wants **all** traffic — the conservative default. Forces capture-all
    /// (no kernel narrowing) when any consumer needs it.
    Any,
    /// Wants exactly the traffic this [`Dispatch`] describes (a proto, or a
    /// proto + port set). `Dispatch::Signature` is treated as `Any` by the
    /// mapper (port-agnostic ⇒ can't narrow).
    Dispatch(Dispatch),
}

/// Result of a signature function. `Match` pins the flow to this
/// protocol's parser; `NoMatch` skips it; `NeedMoreData` says
/// "I need more bytes" — the dispatcher keeps probing until budget
/// runs out.
///
/// Mirrors [`flowscope::detect::signatures::SignatureMatch`] —
/// the [`From`] impl converts losslessly so netring users can
/// pass flowscope signature functions directly into
/// [`Dispatch::Signature`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMatch {
    /// Bytes definitively match this protocol.
    Match,
    /// Bytes definitively do not match.
    NoMatch,
    /// Not enough bytes to decide — re-check with more.
    NeedMoreData,
}

impl From<flowscope::detect::signatures::SignatureMatch> for SignatureMatch {
    fn from(s: flowscope::detect::signatures::SignatureMatch) -> Self {
        use flowscope::detect::signatures::SignatureMatch as Fs;
        match s {
            Fs::Match => SignatureMatch::Match,
            Fs::NoMatch => SignatureMatch::NoMatch,
            Fs::NeedMoreData => SignatureMatch::NeedMoreData,
        }
    }
}

/// Error type for [`Protocol::register`]. Most parsers are
/// infallible to construct; flowscope parsers that take config
/// can fail. Lifecycle-only markers (Tcp, Udp) use this to
/// indicate "no parser slot needed — handled by the central
/// flow tracker."
#[derive(Debug, thiserror::Error)]
#[error("protocol parser init failed: {0}")]
pub struct ProtocolInitError(pub String);

/// Convenience alias — the flow key produced by
/// [`flowscope::extract::FiveTuple`]. Most user code names this
/// rather than the longer fully-qualified path.
pub type FlowKey = flowscope::extract::FiveTupleKey;

#[cfg(test)]
mod plugin_tests {
    use super::*;

    #[test]
    fn signature_match_from_flowscope_roundtrip() {
        use flowscope::detect::signatures::SignatureMatch as Fs;
        assert_eq!(SignatureMatch::from(Fs::Match), SignatureMatch::Match);
        assert_eq!(SignatureMatch::from(Fs::NoMatch), SignatureMatch::NoMatch);
        assert_eq!(
            SignatureMatch::from(Fs::NeedMoreData),
            SignatureMatch::NeedMoreData
        );
    }

    #[test]
    fn dispatch_is_clone_and_debug() {
        let d = Dispatch::Tcp(vec![80, 8080]);
        let _ = format!("{d:?}");
        let _ = d.clone();
    }

    #[test]
    fn protocol_init_error_displays() {
        let e = ProtocolInitError("config missing".into());
        assert!(format!("{e}").contains("config missing"));
    }
}
