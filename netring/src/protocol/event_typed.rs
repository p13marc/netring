//! Typed event markers for handler registration.
//!
//! These types pair with the [`Event`] trait to let users write
//! `Monitor::builder().on::<E>(handler)` for typed payload
//! dispatch. They re-package the existing lifecycle variants of
//! [`super::ProtocolEvent`] into per-[`Protocol`]
//! typed structs, letting handlers scope to a single L4
//! protocol (e.g. `FlowStarted<Tcp>`) without writing a runtime
//! filter.
//!
//! In Phase A these types are defined but NOT yet consumed. Phase
//! B introduces the `Handler` trait + dispatcher that uses them.

use std::marker::PhantomData;

use flowscope::{AnomalyKind, EndReason, FlowSide, FlowStats, L4Proto, TcpInfo, Timestamp};

use crate::protocol::{FlowKey, FlowProtocol, MessageProtocol, Protocol};

/// Marker for types that handlers can subscribe to.
///
/// `Payload` is the type the handler closure receives by reference.
/// For raw protocol messages, `Payload = P::Message`. For flow
/// lifecycle events, `Payload` is the typed event struct itself.
pub trait Event: Send + Sync + 'static {
    /// The handler-visible payload type.
    type Payload: Send + Sync + 'static;

    /// 0.21 D.1: returns the [`std::any::TypeId`] of the
    /// [`Protocol`] marker this event REQUIRES on the builder's
    /// `.protocol::<P>()` list (because the event payload comes
    /// off a parser slot that wouldn't otherwise be registered),
    /// or `None` if no registration is needed.
    ///
    /// - Raw protocol message events (the blanket impl on
    ///   `P: Protocol`) return `Some(TypeId::of::<P>())` — the
    ///   handler can't fire unless the parser slot exists.
    /// - Lifecycle events (`FlowStarted<P>`, etc.), `Tick`,
    ///   `AnyFlowAnomaly` return `None` — they're driven by the
    ///   central tracker regardless of which protocols are
    ///   registered.
    ///
    /// `MonitorBuilder::build` walks the handler registry against
    /// the declared protocol set and surfaces a
    /// `BuildError::HandlerForUnregisteredProtocol` when this
    /// returns `Some(p)` and `p` isn't in the declared set.
    fn protocol_marker() -> Option<std::any::TypeId> {
        None
    }

    /// 0.21 D.1: stable slug for the protocol marker, used only
    /// for diagnostic messages on
    /// [`crate::error::BuildError::HandlerForUnregisteredProtocol`].
    /// Defaults to `"unknown"` for events without a protocol
    /// marker; the blanket `P: Protocol` impl returns `P::NAME`.
    fn protocol_name() -> &'static str {
        "unknown"
    }
}

// ─── Raw protocol message events ────────────────────────────────
//
// `monitor.on::<Http>(|msg: &HttpMessage, ctx| { ... })` dispatches
// whenever Http's parser emits an HttpMessage. The blanket impl
// below makes every `Protocol` marker an `Event` in its own right.

// 0.22 R1: only `MessageProtocol`s are directly listenable as
// `on::<P>` (their parser emits `P::Message`). Lifecycle-only markers
// (`Tcp`/`Udp`, whose `Message = ()`) are NOT `Event`s — `on::<Tcp>`
// is a type error; use `on::<FlowStarted<Tcp>>` instead.
impl<P: MessageProtocol> Event for P {
    type Payload = P::Message;

    fn protocol_marker() -> Option<std::any::TypeId> {
        Some(std::any::TypeId::of::<P>())
    }

    fn protocol_name() -> &'static str {
        P::NAME
    }
}

// ─── Flow lifecycle events, generic over the protocol marker ────

/// Emitted when a new flow begins. Scoped by `P` so a handler
/// for `FlowStarted<Tcp>` won't fire on UDP flow starts.
///
/// The `PhantomData<fn() -> P>` makes the struct covariant in `P`
/// and `Send + Sync` regardless of `P`'s bounds (we get those
/// from the `Protocol` trait anyway, but this form is robust
/// against future bound changes).
#[non_exhaustive]
pub struct FlowStarted<P: Protocol> {
    /// Flow key.
    pub key: FlowKey,
    /// L4 protocol — `Some(L4Proto::Tcp)` for `P = Tcp`, etc.
    pub l4: Option<L4Proto>,
    /// Timestamp of the first packet.
    pub ts: Timestamp,
    _marker: PhantomData<fn() -> P>,
}

impl<P: Protocol> FlowStarted<P> {
    /// Constructor — `pub(crate)` because user code obtains these
    /// via the dispatcher, not by direct construction. Exposed
    /// publicly only under the `bench-zero-alloc` feature so
    /// `benches/zero_alloc.rs` can synthesise events.
    #[cfg(feature = "bench-zero-alloc")]
    pub fn new_for_bench(key: FlowKey, l4: Option<L4Proto>, ts: Timestamp) -> Self {
        Self::new(key, l4, ts)
    }

    /// Constructor exposed for integration tests that need to
    /// synthesise events without driving a real capture.
    /// `#[doc(hidden)]` to keep the docs.rs surface clean.
    #[doc(hidden)]
    pub fn new(key: FlowKey, l4: Option<L4Proto>, ts: Timestamp) -> Self {
        Self {
            key,
            l4,
            ts,
            _marker: PhantomData,
        }
    }
}

// 0.22 R1: lifecycle events apply only to flow-tracked protocols.
// `FlowStarted<Http>` is a type error — HTTP rides a TCP flow, so use
// `FlowStarted<Tcp>` and scope by parser with `on::<Http>`.
impl<P: FlowProtocol> Event for FlowStarted<P> {
    type Payload = FlowStarted<P>;
}

impl<P: Protocol> std::fmt::Debug for FlowStarted<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowStarted")
            .field("protocol", &P::NAME)
            .field("key", &self.key)
            .field("l4", &self.l4)
            .field("ts", &self.ts)
            .finish()
    }
}

/// Emitted when a flow ends (FIN / RST / idle / eviction).
#[non_exhaustive]
pub struct FlowEnded<P: Protocol> {
    /// Flow key.
    pub key: FlowKey,
    /// What caused the flow to end.
    pub reason: EndReason,
    /// Final stats snapshot.
    pub stats: FlowStats,
    /// L4 protocol.
    pub l4: Option<L4Proto>,
    /// Timestamp of the flow's last packet.
    pub ts: Timestamp,
    _marker: PhantomData<fn() -> P>,
}

impl<P: Protocol> FlowEnded<P> {
    /// Constructor exposed for integration tests / dispatch
    /// translation. Not part of the documented public API.
    #[doc(hidden)]
    pub fn new(
        key: FlowKey,
        reason: EndReason,
        stats: FlowStats,
        l4: Option<L4Proto>,
        ts: Timestamp,
    ) -> Self {
        Self {
            key,
            reason,
            stats,
            l4,
            ts,
            _marker: PhantomData,
        }
    }
}

impl<P: FlowProtocol> Event for FlowEnded<P> {
    type Payload = FlowEnded<P>;
}

impl<P: Protocol> std::fmt::Debug for FlowEnded<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowEnded")
            .field("protocol", &P::NAME)
            .field("key", &self.key)
            .field("reason", &self.reason)
            .field("l4", &self.l4)
            .field("ts", &self.ts)
            .finish()
    }
}

/// Emitted at TCP three-way-handshake completion. UDP/ICMP never
/// fire this event.
#[non_exhaustive]
pub struct FlowEstablished<P: Protocol> {
    /// Flow key.
    pub key: FlowKey,
    /// Timestamp of the ACK that completed the handshake.
    pub ts: Timestamp,
    _marker: PhantomData<fn() -> P>,
}

impl<P: Protocol> FlowEstablished<P> {
    /// Constructor exposed for integration tests / dispatch
    /// translation. Not part of the documented public API.
    #[doc(hidden)]
    pub fn new(key: FlowKey, ts: Timestamp) -> Self {
        Self {
            key,
            ts,
            _marker: PhantomData,
        }
    }
}

impl<P: FlowProtocol> Event for FlowEstablished<P> {
    type Payload = FlowEstablished<P>;
}

impl<P: Protocol> std::fmt::Debug for FlowEstablished<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowEstablished")
            .field("protocol", &P::NAME)
            .field("key", &self.key)
            .field("ts", &self.ts)
            .finish()
    }
}

/// Emitted on every packet of an existing flow.
///
/// 0.22 R2: **not parameterised by protocol.** Per-packet handlers
/// always end up branching on `evt.proto` anyway, so the type-level
/// `<P>` was vestigial; the flat shape collapses the two
/// `FlowPacket<Tcp>` + `FlowPacket<Udp>` handlers every L4 monitor
/// wrote into one `on::<FlowPacket>(|e| match e.proto { … })`. The
/// parametric form survives only for lifecycle events
/// ([`FlowStarted`] / [`FlowEnded`] / [`FlowTick`]) where the
/// type guarantee earns its keep.
///
/// The `tcp` field is `Some(_)` only when the underlying flowscope
/// driver was built with `emit_packet_details(true)` — off by
/// default so per-packet handlers don't pay the TCP re-parse cost
/// unless they ask for it. Read `None` as "details suppressed",
/// not "no TCP details available."
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct FlowPacket {
    /// L4 protocol of this packet's flow (`Tcp` / `Udp` / `Icmp` / …).
    pub proto: L4Proto,
    /// Flow key.
    pub key: FlowKey,
    /// Initiator vs responder for this packet.
    pub side: FlowSide,
    /// Packet length on the wire.
    pub len: usize,
    /// TCP-layer details when `emit_packet_details(true)` is set.
    pub tcp: Option<TcpInfo>,
    /// Timestamp of this packet.
    pub ts: Timestamp,
}

impl FlowPacket {
    /// Constructor exposed for integration tests / dispatch
    /// translation. Not part of the documented public API.
    #[doc(hidden)]
    pub fn new(
        proto: L4Proto,
        key: FlowKey,
        side: FlowSide,
        len: usize,
        tcp: Option<TcpInfo>,
        ts: Timestamp,
    ) -> Self {
        Self {
            proto,
            key,
            side,
            len,
            tcp,
            ts,
        }
    }
}

impl Event for FlowPacket {
    type Payload = FlowPacket;
}

/// 0.22 §2.6: synthesised when a TCP flow ends with a RST — i.e. a
/// `FlowEnded<Tcp>` whose `reason == EndReason::Rst`. The
/// operationally-important close; clean FIN / idle eviction do **not**
/// synthesise one. Register via
/// [`MonitorBuilder::on_tcp_reset`](crate::monitor::MonitorBuilder::on_tcp_reset)
/// (or `on::<TcpRst>`). No flowscope dependency — purely netring
/// dispatch translation.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct TcpRst {
    /// Flow key of the reset connection.
    pub key: FlowKey,
    /// Final stats snapshot at reset.
    pub stats: FlowStats,
    /// Timestamp of the reset.
    pub ts: Timestamp,
    /// `true` when the RST landed before any payload moved
    /// (`stats.total_bytes() == 0`) — typically "connection refused"
    /// at the application layer rather than a mid-transfer abort.
    pub zero_payload: bool,
}

impl TcpRst {
    /// Constructor exposed for integration tests / dispatch
    /// translation. Not part of the documented public API.
    #[doc(hidden)]
    pub fn new(key: FlowKey, stats: FlowStats, ts: Timestamp) -> Self {
        let zero_payload = stats.total_bytes() == 0;
        Self {
            key,
            stats,
            ts,
            zero_payload,
        }
    }
}

impl Event for TcpRst {
    type Payload = TcpRst;
}

/// Periodic per-flow [`FlowStats`] snapshot. Only emitted when
/// `FlowTrackerConfig::flow_tick_interval` is set on the underlying
/// driver.
#[non_exhaustive]
pub struct FlowTick<P: Protocol> {
    /// Flow key.
    pub key: FlowKey,
    /// Snapshot of accumulated flow stats.
    pub stats: FlowStats,
    /// Timestamp the snapshot was taken.
    pub ts: Timestamp,
    _marker: PhantomData<fn() -> P>,
}

impl<P: Protocol> FlowTick<P> {
    /// Constructor exposed for integration tests / dispatch
    /// translation. Not part of the documented public API.
    #[doc(hidden)]
    pub fn new(key: FlowKey, stats: FlowStats, ts: Timestamp) -> Self {
        Self {
            key,
            stats,
            ts,
            _marker: PhantomData,
        }
    }
}

impl<P: FlowProtocol> Event for FlowTick<P> {
    type Payload = FlowTick<P>;
}

impl<P: Protocol> std::fmt::Debug for FlowTick<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowTick")
            .field("protocol", &P::NAME)
            .field("key", &self.key)
            .field("stats", &self.stats)
            .field("ts", &self.ts)
            .finish()
    }
}

/// Parser-level close — a registered parser drained its
/// `fin_*` accumulator or reported `is_done` / `is_poisoned`.
///
/// Distinct from [`FlowEnded`]: this fires per (parser, flow); the
/// flow may still be alive. Handlers scoped to `ParserClosed<P>`
/// observe only closes for the parser tied to `P`'s `parser_kind`
/// when the relevant l4 + parser context is set; for non-parser
/// protocols (`Tcp`, `Udp`, `Icmp`) the dispatch arm uses `l4` to
/// pick the marker.
#[non_exhaustive]
pub struct ParserClosed<P: Protocol> {
    /// Flow key.
    pub key: FlowKey,
    /// Parser kind tag (e.g. `"http"`, `"dns"`, `"tls"`).
    pub parser_kind: &'static str,
    /// Why the parser closed.
    pub reason: EndReason,
    /// Timestamp of the close.
    pub ts: Timestamp,
    _marker: PhantomData<fn() -> P>,
}

impl<P: Protocol> ParserClosed<P> {
    /// Constructor exposed for integration tests / dispatch
    /// translation. Not part of the documented public API.
    #[doc(hidden)]
    pub fn new(key: FlowKey, parser_kind: &'static str, reason: EndReason, ts: Timestamp) -> Self {
        Self {
            key,
            parser_kind,
            reason,
            ts,
            _marker: PhantomData,
        }
    }
}

impl<P: Protocol> Event for ParserClosed<P> {
    type Payload = ParserClosed<P>;
}

impl<P: Protocol> std::fmt::Debug for ParserClosed<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParserClosed")
            .field("protocol", &P::NAME)
            .field("key", &self.key)
            .field("parser_kind", &self.parser_kind)
            .field("reason", &self.reason)
            .field("ts", &self.ts)
            .finish()
    }
}

// ─── Cross-protocol events ──────────────────────────────────────

/// Catch-all for flowscope-side anomalies (TCP out-of-order,
/// reassembler watermark, parser poison, eviction pressure, …).
#[derive(Debug)]
#[non_exhaustive]
pub struct AnyFlowAnomaly {
    /// Flow key, or `None` for tracker-global anomalies.
    pub key: Option<FlowKey>,
    /// Concrete anomaly kind.
    pub kind: AnomalyKind,
    /// Timestamp.
    pub ts: Timestamp,
}

impl Event for AnyFlowAnomaly {
    type Payload = AnyFlowAnomaly;
}

/// Periodic tick event. Fires at the registered interval; handlers
/// can use it to drive sweeps / aging / snapshots.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Tick {
    /// Current "now" — wall-clock-ish [`Timestamp`] used for
    /// time-bound state.
    pub now: Timestamp,
    /// Configured tick period (informational).
    pub period: std::time::Duration,
}

impl Tick {
    /// Constructor exposed for integration tests that need to
    /// synthesise a [`Tick`] payload without going through the
    /// run loop. Not part of the documented public API (`Tick`
    /// is `#[non_exhaustive]` so external code can't construct
    /// it directly — this `#[doc(hidden)]` constructor lets the
    /// integration test suite synthesise one).
    #[doc(hidden)]
    pub fn new(now: Timestamp, period: std::time::Duration) -> Self {
        Self { now, period }
    }
}

impl Event for Tick {
    type Payload = Tick;
}

// ─── Re-exports for handler ergonomics ──────────────────────────

/// Side of the flow that produced this event/message.
pub use flowscope::FlowSide as Side;
// `TcpInfo` is re-exported under `crate::flow::TcpInfo` already (see
// `lib.rs` `pub mod flow`). Handlers needing it should import from
// there. The `use ... TcpInfo` at the top of this module pulls it
// in for `FlowPacket<P>`'s field type; that's enough.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::builtin::{Tcp, Udp};

    #[test]
    fn flow_started_typed_by_protocol() {
        // Distinct types — compile-time check only.
        fn _accept_tcp(_: &FlowStarted<Tcp>) {}
        fn _accept_udp(_: &FlowStarted<Udp>) {}
    }

    #[test]
    fn typed_events_are_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<FlowStarted<Tcp>>();
        assert_sync::<FlowStarted<Tcp>>();
        assert_send::<FlowEnded<Tcp>>();
        assert_sync::<FlowEnded<Tcp>>();
        assert_send::<FlowEstablished<Tcp>>();
        assert_send::<AnyFlowAnomaly>();
        assert_send::<Tick>();
    }

    #[test]
    fn event_trait_blanket_impl_for_protocol_markers() {
        // Just needs to compile: `Http` as a `Protocol` is also an
        // `Event` with `Payload = HttpMessage`.
        #[cfg(feature = "http")]
        {
            use crate::protocol::builtin::Http;
            fn _accept_event<E: Event>() {}
            _accept_event::<Http>();
        }
    }

    #[test]
    fn flow_started_debug_includes_protocol_name() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let key = flowscope::extract::FiveTupleKey {
            proto: flowscope::L4Proto::Tcp,
            a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
            b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
        };
        let evt = FlowStarted::<Tcp>::new(key, Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0));
        let s = format!("{evt:?}");
        assert!(s.contains("tcp"));
    }
}
