//! Typed event markers for handler registration.
//!
//! These types pair with the [`Event`] trait to let users write
//! `Monitor::builder().on::<E>(handler)` for typed payload
//! dispatch. They re-package the existing lifecycle variants of
//! [`super::ProtocolEvent`] into per-[`Protocol`](super::Protocol)
//! typed structs, letting handlers scope to a single L4
//! protocol (e.g. `FlowStarted<Tcp>`) without writing a runtime
//! filter.
//!
//! In Phase A these types are defined but NOT yet consumed. Phase
//! B introduces the `Handler` trait + dispatcher that uses them.

use std::marker::PhantomData;

use flowscope::{AnomalyKind, EndReason, FlowStats, L4Proto, Timestamp};

use crate::protocol::{FlowKey, Protocol};

/// Marker for types that handlers can subscribe to.
///
/// `Payload` is the type the handler closure receives by reference.
/// For raw protocol messages, `Payload = P::Message`. For flow
/// lifecycle events, `Payload` is the typed event struct itself.
pub trait Event: Send + Sync + 'static {
    /// The handler-visible payload type.
    type Payload: Send + Sync + 'static;
}

// ─── Raw protocol message events ────────────────────────────────
//
// `monitor.on::<Http>(|msg: &HttpMessage, ctx| { ... })` dispatches
// whenever Http's parser emits an HttpMessage. The blanket impl
// below makes every `Protocol` marker an `Event` in its own right.

impl<P: Protocol> Event for P {
    type Payload = P::Message;
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

impl<P: Protocol> Event for FlowStarted<P> {
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
    #[allow(dead_code)]
    pub(crate) fn new(
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

impl<P: Protocol> Event for FlowEnded<P> {
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
    #[allow(dead_code)]
    pub(crate) fn new(key: FlowKey, ts: Timestamp) -> Self {
        Self {
            key,
            ts,
            _marker: PhantomData,
        }
    }
}

impl<P: Protocol> Event for FlowEstablished<P> {
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

impl Event for Tick {
    type Payload = Tick;
}

// ─── Re-exports for handler ergonomics ──────────────────────────

/// Side of the flow that produced this event/message.
pub use flowscope::FlowSide as Side;
/// TCP-layer details emitted on `FlowPacket` events when
/// `emit_packet_details(true)` is set on the underlying driver.
pub use flowscope::TcpInfo;

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
