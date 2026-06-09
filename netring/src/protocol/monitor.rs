//! [`ProtocolMonitor`] — async stream over a single capture +
//! one flowscope-side [`Driver<E>`] that fans packets to every
//! registered parser internally.
//!
//! ## What changed in 0.19
//!
//! flowscope 0.11 (plan 121) replaced the closed `Driver<E, M>`
//! shape with a typed [`Driver<E>`](flowscope::driver::Driver)
//! that emits flow-lifecycle [`Event<K>`](flowscope::driver::Event)
//! only — per-parser typed messages flow through
//! [`SlotHandle<M, K>`](flowscope::driver::SlotHandle) returned
//! from each `session_*` / `datagram_*` builder method.
//!
//! [`ProtocolMonitor`]'s public-facing surface
//! ([`ProtocolMonitorBuilder`], the per-protocol method shortcuts,
//! the `Stream<Item = Result<ProtocolEvent<K>, Error>>` shape) is
//! unchanged from netring 0.18 *except* the stream is no longer
//! `+ Send`: flowscope's `SlotHandle` uses `Rc<RefCell<…>>`
//! internally (single-thread-by-design), which transitively makes
//! the monitor `!Send`. Users on the standard
//! `#[tokio::main(flavor = "current_thread")]` runtime (recommended
//! for packet capture anyway) see no impact.
//!
//! The internal driver loop is:
//!
//! 1. `Driver::track_into(view, &mut lifecycle_events)` —
//!    zero-alloc lifecycle event drain.
//! 2. For each registered protocol's [`SlotHandle<M, K>`], drain
//!    typed messages into a scratch buffer, lift `M` into
//!    [`ProtocolMessage`], yield as
//!    [`ProtocolEvent::Message`].
//! 3. Translate lifecycle [`Event<K>`] variants into the
//!    corresponding [`ProtocolEvent`] variants 1:1.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use flowscope::FlowExtractor;
use flowscope::driver::{Driver, DriverBuilder, Event as FsEvent, SlotHandle, SlotMessage};
use futures_core::Stream;

use super::event::{ProtocolEvent, ProtocolMessage};
use crate::async_adapters::tokio_adapter::PacketStream;
use crate::error::Error;
use crate::traits::PacketSource;
use crate::{AsyncCapture, Capture};

type BoxedEventStream<K> = Pin<Box<dyn Stream<Item = Result<ProtocolEvent<K>, Error>>>>;

/// A unified async stream of [`ProtocolEvent`]s from a single
/// underlying capture.
///
/// Produced by [`ProtocolMonitorBuilder::build`]. Owns one
/// [`AsyncCapture`] internally + a flowscope-side
/// [`Driver<E>`](flowscope::driver::Driver) with one typed
/// [`SlotHandle`](flowscope::driver::SlotHandle) per registered
/// parser.
///
/// **Note: this type is `!Send` as of netring 0.19.** flowscope
/// 0.11's slot handles use `Rc<RefCell>` for single-thread-by-design
/// efficiency. Run the monitor on `#[tokio::main(flavor =
/// "current_thread")]` (the recommended pattern for packet
/// capture) and this constraint is transparent.
pub struct ProtocolMonitor<K> {
    inner: BoxedEventStream<K>,
    /// Number of registered parser slots inside the unified driver.
    /// Excludes the always-on central flow tracker.
    slots: usize,
}

impl<K> std::fmt::Debug for ProtocolMonitor<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolMonitor")
            .field("source_count", &1usize)
            .field("slots", &self.slots)
            .finish()
    }
}

impl<K> ProtocolMonitor<K> {
    /// Number of underlying captures driving this monitor.
    /// **Always 1** as of netring 0.18.
    pub fn source_count(&self) -> usize {
        1
    }

    /// Number of sources still producing events. **Always 1**
    /// for live captures (a pcap-backed monitor returns 0 after
    /// EOF; the unified-driver flow doesn't expose that today).
    pub fn alive_sources(&self) -> usize {
        1
    }

    /// Number of parser slots registered on the underlying driver.
    /// Excludes the always-on central flow tracker. `0` means
    /// only lifecycle events are produced (no L7 messages).
    pub fn slot_count(&self) -> usize {
        self.slots
    }
}

impl<K> Stream for ProtocolMonitor<K>
where
    K: Unpin + 'static,
{
    type Item = Result<ProtocolEvent<K>, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

/// Builder for [`ProtocolMonitor`].
///
/// Declare:
/// - the interface to watch (one network device)
/// - which protocols to track (`.flow()`, `.http()`, `.dns()`,
///   `.tls()`, `.tls_handshake()`, `.icmp()` — each is an
///   additive opt-in)
///
/// Then call [`build`](Self::build) with the
/// [`FlowExtractor`](flowscope::FlowExtractor) (typically
/// `FiveTuple::bidirectional()`).
#[derive(Debug, Default)]
pub struct ProtocolMonitorBuilder {
    interface: Option<String>,
    /// Retained for API compat — the central tracker always emits
    /// lifecycle events on the unified driver, so this flag is now
    /// informational only.
    enable_flow: bool,
    #[cfg(feature = "http")]
    http_ports: Option<Vec<u16>>,
    #[cfg(feature = "dns")]
    dns_udp_ports: Option<Vec<u16>>,
    #[cfg(feature = "dns")]
    dns_tcp_ports: Option<Vec<u16>>,
    #[cfg(feature = "tls")]
    tls_ports: Option<Vec<u16>>,
    #[cfg(feature = "tls")]
    tls_handshake_ports: Option<Vec<u16>>,
    #[cfg(feature = "icmp")]
    enable_icmp: Option<IcmpScope>,
    /// Heuristic-routing slots: parser selection is driven by a
    /// signature function over the first N packets per side, not by
    /// the L4 port number. Useful for C2 / port-randomized traffic.
    #[cfg(feature = "http")]
    http_heuristic: bool,
    #[cfg(feature = "tls")]
    tls_handshake_heuristic: bool,
}

/// Which ICMP family the monitor's `.icmp()` arm parses.
#[cfg(feature = "icmp")]
#[derive(Debug, Clone, Copy)]
enum IcmpScope {
    Both,
    V4,
    V6,
}

impl ProtocolMonitorBuilder {
    /// Entry point — mirrors `Capture::builder()` and other
    /// builder constructors in netring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the network interface to watch.
    pub fn interface(mut self, name: impl Into<String>) -> Self {
        self.interface = Some(name.into());
        self
    }

    /// Enable plain flow-lifecycle tracking. As of 0.18 the central
    /// flow tracker is always on inside the unified driver; this
    /// method is retained for backwards compatibility and as an
    /// explicit marker of intent.
    pub fn flow(mut self) -> Self {
        self.enable_flow = true;
        self
    }

    /// Enable HTTP/1.x parsing on the default port set (80, 8080).
    /// See [`Self::http_on_ports`] to override.
    #[cfg(feature = "http")]
    pub fn http(self) -> Self {
        self.http_on_ports([80, 8080])
    }

    /// Enable HTTP/1.x parsing on a custom set of TCP ports.
    #[cfg(feature = "http")]
    pub fn http_on_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.http_ports = Some(ports.into_iter().collect());
        self
    }

    /// Enable DNS-over-UDP parsing on the default port set (53).
    /// Uses `DnsUdpParser::with_correlation()` so responses carry
    /// RTT and unanswered queries surface via the `on_tick` hook.
    #[cfg(feature = "dns")]
    pub fn dns(self) -> Self {
        self.dns_udp_on_ports([53])
    }

    /// Enable DNS-over-UDP parsing on a custom set of UDP ports.
    #[cfg(feature = "dns")]
    pub fn dns_udp_on_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.dns_udp_ports = Some(ports.into_iter().collect());
        self
    }

    /// Enable DNS-over-TCP parsing on a set of TCP ports
    /// (RFC 1035 §4.2.2 length-prefix framing).
    #[cfg(feature = "dns")]
    pub fn dns_tcp_on_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.dns_tcp_ports = Some(ports.into_iter().collect());
        self
    }

    /// Enable TLS handshake observation on the default port set
    /// (443, 8443).
    #[cfg(feature = "tls")]
    pub fn tls(self) -> Self {
        self.tls_on_ports([443, 8443])
    }

    /// Enable TLS handshake observation on a custom set of TCP ports.
    #[cfg(feature = "tls")]
    pub fn tls_on_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.tls_ports = Some(ports.into_iter().collect());
        self
    }

    /// Enable the TLS handshake **aggregator** parser
    /// ([`flowscope::tls::TlsHandshakeParser`], new in flowscope 0.9)
    /// on the default port set (443, 8443). Emits one
    /// `ProtocolMessage::TlsHandshake` per observed handshake
    /// instead of the message-granularity events `.tls()`
    /// produces.
    ///
    /// You can enable both `.tls()` and `.tls_handshake()` — they
    /// run independent parser slots. Most consumers want one or
    /// the other.
    #[cfg(feature = "tls")]
    pub fn tls_handshake(self) -> Self {
        self.tls_handshake_on_ports([443, 8443])
    }

    /// Enable the TLS handshake aggregator on a custom port set.
    #[cfg(feature = "tls")]
    pub fn tls_handshake_on_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.tls_handshake_ports = Some(ports.into_iter().collect());
        self
    }

    /// Enable port-agnostic HTTP/1.x parsing via the
    /// [`flowscope::detect::signatures::http_request`] signature.
    /// Routes any TCP flow whose first packet looks like
    /// `METHOD SP path SP HTTP/1.x` to the HTTP parser.
    ///
    /// Use when you suspect HTTP on non-standard ports (proxies,
    /// debug endpoints, C2 over arbitrary ports). Combines with
    /// `.http_on_ports()` — the heuristic slot fires only for
    /// flows that *aren't* already pinned to the port-based slot.
    #[cfg(feature = "http")]
    pub fn http_heuristic(mut self) -> Self {
        self.http_heuristic = true;
        self
    }

    /// Enable port-agnostic TLS handshake aggregation via the
    /// [`flowscope::detect::signatures::tls_client_hello`] signature.
    /// Routes any TCP flow whose first packet starts with a TLS
    /// ClientHello record to the
    /// [`flowscope::tls::TlsHandshakeParser`].
    ///
    /// Pair with `.tls_handshake_on_ports()` for the standard
    /// 443/8443 case + this heuristic for anything else.
    #[cfg(feature = "tls")]
    pub fn tls_handshake_heuristic(mut self) -> Self {
        self.tls_handshake_heuristic = true;
        self
    }

    /// Enable ICMP parsing (both ICMPv4 and ICMPv6). Surfaces
    /// `ProtocolMessage::Icmp(IcmpMessage)` events, including
    /// `inner: Option<IcmpInner>` on error variants — the
    /// cross-protocol correlation primitive that ties an ICMP
    /// error back to the originating TCP/UDP flow.
    #[cfg(feature = "icmp")]
    pub fn icmp(mut self) -> Self {
        self.enable_icmp = Some(IcmpScope::Both);
        self
    }

    /// Enable ICMPv4-only parsing.
    #[cfg(feature = "icmp")]
    pub fn icmp_v4_only(mut self) -> Self {
        self.enable_icmp = Some(IcmpScope::V4);
        self
    }

    /// Enable ICMPv6-only parsing.
    #[cfg(feature = "icmp")]
    pub fn icmp_v6_only(mut self) -> Self {
        self.enable_icmp = Some(IcmpScope::V6);
        self
    }

    /// Build the monitor.
    ///
    /// # Errors
    /// - `Error::Config` if no interface was set, or if opening the
    ///   underlying capture fails.
    pub fn build<E>(self, extractor: E) -> Result<ProtocolMonitor<E::Key>, Error>
    where
        E: FlowExtractor + Unpin + Clone + Send + 'static,
        E::Key: Eq + std::hash::Hash + Clone + Send + Sync + Unpin + 'static,
    {
        let iface = self.interface.ok_or_else(|| {
            Error::Config("ProtocolMonitorBuilder: .interface(...) is required".into())
        })?;

        // Build the typed Driver. Each `session_*` / `datagram_*`
        // call returns a `SlotHandle<P::Message, K>` — we wrap it
        // in a type-erased `Box<dyn ProtocolSlot<K>>` that knows
        // how to drain typed messages and lift them into
        // `ProtocolMessage`.
        let mut builder: DriverBuilder<E> = Driver::builder(extractor);
        let mut slots: Vec<Box<dyn ProtocolSlot<E::Key>>> = Vec::new();

        #[cfg(feature = "http")]
        if let Some(ports) = self.http_ports {
            let handle = builder.session_on_ports(flowscope::http::HttpParser::default(), ports);
            slots.push(Box::new(TypedSlot::new(handle, ProtocolMessage::Http)));
        }

        #[cfg(feature = "dns")]
        if let Some(ports) = self.dns_udp_ports {
            let handle =
                builder.datagram_on_ports(flowscope::dns::DnsUdpParser::with_correlation(), ports);
            slots.push(Box::new(TypedSlot::new(handle, ProtocolMessage::Dns)));
        }

        #[cfg(feature = "dns")]
        if let Some(ports) = self.dns_tcp_ports {
            let handle = builder.session_on_ports(flowscope::dns::DnsTcpParser::default(), ports);
            slots.push(Box::new(TypedSlot::new(handle, ProtocolMessage::Dns)));
        }

        #[cfg(feature = "tls")]
        if let Some(ports) = self.tls_ports {
            let handle = builder.session_on_ports(flowscope::tls::TlsParser::default(), ports);
            slots.push(Box::new(TypedSlot::new(handle, ProtocolMessage::Tls)));
        }

        #[cfg(feature = "tls")]
        if let Some(ports) = self.tls_handshake_ports {
            let handle =
                builder.session_on_ports(flowscope::tls::TlsHandshakeParser::default(), ports);
            slots.push(Box::new(TypedSlot::new(
                handle,
                ProtocolMessage::TlsHandshake,
            )));
        }

        #[cfg(feature = "icmp")]
        if let Some(scope) = self.enable_icmp {
            let parser = match scope {
                IcmpScope::Both => flowscope::icmp::IcmpParser::new(),
                IcmpScope::V4 => flowscope::icmp::IcmpParser::new().v4_only(),
                IcmpScope::V6 => flowscope::icmp::IcmpParser::new().v6_only(),
            };
            let handle = builder.datagram_broadcast(parser);
            slots.push(Box::new(TypedSlot::new(handle, ProtocolMessage::Icmp)));
        }

        #[cfg(feature = "http")]
        if self.http_heuristic {
            let handle = builder.session_heuristic(
                flowscope::http::HttpParser::default(),
                flowscope::detect::signatures::http_request,
            );
            slots.push(Box::new(TypedSlot::new(handle, ProtocolMessage::Http)));
        }

        #[cfg(feature = "tls")]
        if self.tls_handshake_heuristic {
            let handle = builder.session_heuristic(
                flowscope::tls::TlsHandshakeParser::default(),
                flowscope::detect::signatures::tls_client_hello,
            );
            slots.push(Box::new(TypedSlot::new(
                handle,
                ProtocolMessage::TlsHandshake,
            )));
        }

        let slot_count = slots.len();
        let driver = builder.build();

        // One capture — no kernel filter.
        let cap = AsyncCapture::open(&iface)?;
        let packet_stream = cap.into_stream();

        let inner: BoxedEventStream<E::Key> = Box::pin(DriverDrivenStream {
            packet_stream,
            driver,
            slots,
            pending: VecDeque::new(),
            lifecycle_buf: Vec::with_capacity(64),
        });

        Ok(ProtocolMonitor {
            inner,
            slots: slot_count,
        })
    }
}

/// Type-erased drain wrapper around a flowscope [`SlotHandle<M, K>`].
/// Each registered parser slot owns one of these; the inner stream
/// drains them on every tick.
trait ProtocolSlot<K> {
    fn drain_into(&mut self, out: &mut VecDeque<ProtocolEvent<K>>);
}

/// Concrete typed slot. Stores the typed `SlotHandle<M, K>` and a
/// pointer-cast lift function `fn(M) -> ProtocolMessage`. Per drain,
/// pulls all pending `SlotMessage<M, K>` into a scratch Vec (reused
/// across calls), lifts each `M` into [`ProtocolMessage`], and emits
/// [`ProtocolEvent::Message`].
struct TypedSlot<M, K>
where
    M: 'static,
    K: 'static,
{
    handle: SlotHandle<M, K>,
    lift: fn(M) -> ProtocolMessage,
    parser_kind: &'static str,
    scratch: Vec<SlotMessage<M, K>>,
}

impl<M, K> TypedSlot<M, K>
where
    M: 'static,
    K: 'static,
{
    fn new(handle: SlotHandle<M, K>, lift: fn(M) -> ProtocolMessage) -> Self {
        let parser_kind = handle.parser_kind();
        Self {
            handle,
            lift,
            parser_kind,
            scratch: Vec::new(),
        }
    }
}

impl<M, K> ProtocolSlot<K> for TypedSlot<M, K>
where
    M: 'static,
    K: Clone + 'static,
{
    fn drain_into(&mut self, out: &mut VecDeque<ProtocolEvent<K>>) {
        self.scratch.clear();
        let n = self.handle.drain(&mut self.scratch);
        if n == 0 {
            return;
        }
        // Cache lift + parser_kind into locals to avoid borrow
        // checker issues iterating self.scratch while reading
        // self.lift / self.parser_kind.
        let lift = self.lift;
        let parser_kind = self.parser_kind;
        for slot_msg in self.scratch.drain(..) {
            out.push_back(ProtocolEvent::Message {
                key: slot_msg.key,
                side: slot_msg.side,
                parser_kind,
                message: lift(slot_msg.message),
                ts: slot_msg.ts,
            });
        }
    }
}

/// Inner stream: pulls owned-packet batches from the underlying
/// `AsyncCapture`, feeds them through the typed `Driver<E>`, drains
/// each registered slot, and buffers the resulting events.
struct DriverDrivenStream<S, E>
where
    S: PacketSource + std::os::fd::AsRawFd,
    E: FlowExtractor,
    E::Key: 'static,
{
    packet_stream: PacketStream<S>,
    driver: Driver<E>,
    slots: Vec<Box<dyn ProtocolSlot<E::Key>>>,
    pending: VecDeque<ProtocolEvent<E::Key>>,
    /// Reused scratch buffer for `Driver::track_into` —
    /// zero-allocation on the hot path.
    lifecycle_buf: Vec<FsEvent<E::Key>>,
}

// All fields are owned values without self-references; the struct
// is Unpin whenever its field types are. flowscope's Driver and
// SlotHandle are both Unpin; PacketStream is Unpin given Unpin S.

impl<S, E> Stream for DriverDrivenStream<S, E>
where
    S: PacketSource + std::os::fd::AsRawFd + Unpin + Send + 'static,
    E: FlowExtractor + Clone + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Send + Sync + Unpin + 'static,
{
    type Item = Result<ProtocolEvent<E::Key>, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            // Drain pending first — a single packet can produce
            // many events (one lifecycle + N messages across all
            // slots).
            if let Some(ev) = self.pending.pop_front() {
                return Poll::Ready(Some(Ok(ev)));
            }

            let this = self.as_mut().get_mut();
            match Pin::new(&mut this.packet_stream).poll_next(cx) {
                Poll::Ready(Some(Ok(batch))) => {
                    for owned in batch {
                        let view = flowscope::PacketView::new(&owned.data, owned.timestamp);

                        // (1) Lifecycle events from the central
                        //     flow tracker, zero-alloc via
                        //     `track_into`.
                        this.lifecycle_buf.clear();
                        this.driver.track_into(view, &mut this.lifecycle_buf);
                        for fs_evt in this.lifecycle_buf.drain(..) {
                            if let Some(ev) = translate_lifecycle(fs_evt) {
                                this.pending.push_back(ev);
                            }
                        }

                        // (2) Typed messages from each registered
                        //     parser slot. Each `drain_into` is a
                        //     zero-alloc drain of the slot's internal
                        //     buffer (capacity reused across calls).
                        for slot in &mut this.slots {
                            slot.drain_into(&mut this.pending);
                        }
                    }
                    // Loop back and drain `this.pending`.
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Translate a flowscope lifecycle [`FsEvent<K>`] into netring's
/// owned [`ProtocolEvent<K>`]. 1:1 mapping — field names and shapes
/// match exactly, so user pattern matches (which destructure with
/// `..`) continue to compile.
///
/// Returns `None` for future `#[non_exhaustive]` flowscope variants
/// netring doesn't yet know how to translate. Forwards-compatible
/// behavior: unknown future events are silently skipped rather than
/// crashing the stream. Adding a new arm here when flowscope ships
/// a new variant is a one-line patch.
fn translate_lifecycle<K>(evt: FsEvent<K>) -> Option<ProtocolEvent<K>> {
    Some(match evt {
        FsEvent::FlowStarted { key, ts, l4 } => ProtocolEvent::FlowStarted { key, ts, l4 },
        FsEvent::FlowEstablished { key, ts, l4 } => ProtocolEvent::FlowEstablished { key, ts, l4 },
        FsEvent::FlowPacket {
            key,
            side,
            len,
            ts,
            tcp,
        } => ProtocolEvent::FlowPacket {
            key,
            side,
            len,
            ts,
            tcp,
        },
        FsEvent::FlowEnded {
            key,
            reason,
            stats,
            history,
            l4,
            ts,
        } => ProtocolEvent::FlowEnded {
            key,
            reason,
            stats,
            history,
            l4,
            ts,
        },
        FsEvent::FlowTick { key, stats, ts } => ProtocolEvent::FlowTick { key, stats, ts },
        FsEvent::ParserClosed {
            key,
            parser_kind,
            reason,
            ts,
        } => ProtocolEvent::ParserClosed {
            key,
            parser_kind,
            reason,
            ts,
        },
        FsEvent::FlowAnomaly { key, kind, ts } => ProtocolEvent::FlowAnomaly { key, kind, ts },
        FsEvent::TrackerAnomaly { kind, ts } => ProtocolEvent::TrackerAnomaly { kind, ts },
        _ => return None,
    })
}

// Allow capturing the `Capture` source via `AsyncCapture::open`
// for the default builder path.
type _NetringCapture = Capture;

#[cfg(test)]
mod tests {
    use super::*;
    use flowscope::extract::FiveTuple;

    #[test]
    fn builder_requires_interface() {
        let result = ProtocolMonitorBuilder::new()
            .flow()
            .build(FiveTuple::bidirectional());
        match result {
            Err(Error::Config(msg)) => assert!(
                msg.contains(".interface"),
                "unexpected error message: {msg}"
            ),
            Err(other) => panic!("expected Config, got {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn builder_default_has_no_protocols_enabled() {
        let b = ProtocolMonitorBuilder::new().interface("lo");
        assert!(!b.enable_flow);
        #[cfg(feature = "http")]
        assert!(b.http_ports.is_none());
        #[cfg(feature = "dns")]
        {
            assert!(b.dns_udp_ports.is_none());
            assert!(b.dns_tcp_ports.is_none());
        }
        #[cfg(feature = "tls")]
        {
            assert!(b.tls_ports.is_none());
            assert!(b.tls_handshake_ports.is_none());
        }
    }

    #[test]
    fn builder_setters_record_state() {
        let b = ProtocolMonitorBuilder::new().interface("eth0").flow();
        assert_eq!(b.interface.as_deref(), Some("eth0"));
        assert!(b.enable_flow);

        #[cfg(feature = "http")]
        {
            let b = ProtocolMonitorBuilder::new().http_on_ports([8080, 8443]);
            assert_eq!(b.http_ports, Some(vec![8080, 8443]));
        }

        #[cfg(feature = "dns")]
        {
            let b = ProtocolMonitorBuilder::new().dns();
            assert_eq!(b.dns_udp_ports, Some(vec![53]));
        }
    }
}
