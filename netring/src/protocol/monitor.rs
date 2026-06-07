//! [`ProtocolMonitor`] — async stream over a single capture +
//! one flowscope-side [`Driver<E, ProtocolMessage>`] that fans
//! packets to every registered parser internally.
//!
//! ## What changed in 0.18
//!
//! Pre-0.18 [`ProtocolMonitor`] opened **N** `AsyncCapture`s — one
//! per enabled protocol — each with a per-protocol kernel BPF
//! filter. As of netring 0.18 the monitor opens **1** capture (no
//! kernel filter) and dispatches user-side through flowscope's
//! unified [`Driver<E, M>`]. The trade-off:
//!
//! - **Memory.** 5-protocol monitor goes from 5 × `tpacket_v3`
//!   ring (typically 80–160 MiB total) to 1 × ring (16–32 MiB).
//! - **CPU.** Slightly more user-side dispatch (one match per
//!   packet to route to the right parser slot) in exchange for
//!   one fewer kernel BPF eval per packet. Net wash on typical
//!   workloads.
//! - **Filter expressiveness.** Per-protocol BPF narrowing is no
//!   longer used; parser slots route by L4 + port set
//!   user-side. Users who want a kernel-side coarse filter (e.g.
//!   "only watch a single subnet") can still pre-apply one
//!   externally and feed the source through a pcap or alternative
//!   `AsyncPacketSource`.
//!
//! ## API
//!
//! The user-facing surface
//! ([`ProtocolMonitorBuilder`] + the per-protocol method
//! shortcuts) is unchanged from 0.17. Event variant shapes
//! shifted to match flowscope — see the [`super::event`] module
//! docs for the migration table.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use flowscope::FlowExtractor;
use flowscope::driver_unified::{Driver, DriverBuilder};
use futures_core::Stream;

use super::event::{ProtocolEvent, ProtocolMessage};
use crate::async_adapters::tokio_adapter::PacketStream;
use crate::error::Error;
use crate::traits::PacketSource;
use crate::{AsyncCapture, Capture};

type BoxedEventStream<K> = Pin<Box<dyn Stream<Item = Result<ProtocolEvent<K>, Error>> + Send>>;

/// A unified async stream of [`ProtocolEvent`]s from a single
/// underlying capture.
///
/// Produced by [`ProtocolMonitorBuilder::build`]. Owns one
/// [`AsyncCapture`] internally + a flowscope-side
/// `Driver` with one slot per enabled protocol.
pub struct ProtocolMonitor<K> {
    inner: BoxedEventStream<K>,
    /// Number of registered parser slots inside the unified driver.
    /// Always at least 1 (the central flow tracker always emits
    /// lifecycle events).
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
    K: Send + Unpin + 'static,
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

        // Build the unified Driver with one slot per enabled
        // protocol. The central flow tracker always runs and
        // emits lifecycle events regardless of slots.
        let mut builder: DriverBuilder<E, ProtocolMessage> = Driver::builder(extractor);
        let mut slots: usize = 0;

        #[cfg(feature = "http")]
        if let Some(ports) = self.http_ports {
            builder = builder.session_on_ports(
                flowscope::http::HttpParser::default(),
                ports,
                ProtocolMessage::Http,
            );
            slots += 1;
        }

        #[cfg(feature = "dns")]
        if let Some(ports) = self.dns_udp_ports {
            builder = builder.datagram_on_ports(
                flowscope::dns::DnsUdpParser::with_correlation(),
                ports,
                ProtocolMessage::Dns,
            );
            slots += 1;
        }

        #[cfg(feature = "dns")]
        if let Some(ports) = self.dns_tcp_ports {
            builder = builder.session_on_ports(
                flowscope::dns::DnsTcpParser::default(),
                ports,
                ProtocolMessage::Dns,
            );
            slots += 1;
        }

        #[cfg(feature = "tls")]
        if let Some(ports) = self.tls_ports {
            builder = builder.session_on_ports(
                flowscope::tls::TlsParser::default(),
                ports,
                ProtocolMessage::Tls,
            );
            slots += 1;
        }

        #[cfg(feature = "tls")]
        if let Some(ports) = self.tls_handshake_ports {
            builder = builder.session_on_ports(
                flowscope::tls::TlsHandshakeParser::default(),
                ports,
                ProtocolMessage::TlsHandshake,
            );
            slots += 1;
        }

        #[cfg(feature = "icmp")]
        if let Some(scope) = self.enable_icmp {
            let parser = match scope {
                IcmpScope::Both => flowscope::icmp::IcmpParser::new(),
                IcmpScope::V4 => flowscope::icmp::IcmpParser::new().v4_only(),
                IcmpScope::V6 => flowscope::icmp::IcmpParser::new().v6_only(),
            };
            builder = builder.datagram_broadcast(parser, ProtocolMessage::Icmp);
            slots += 1;
        }

        #[cfg(feature = "http")]
        if self.http_heuristic {
            builder = builder.session_heuristic(
                flowscope::http::HttpParser::default(),
                flowscope::detect::signatures::http_request,
                ProtocolMessage::Http,
            );
            slots += 1;
        }

        #[cfg(feature = "tls")]
        if self.tls_handshake_heuristic {
            builder = builder.session_heuristic(
                flowscope::tls::TlsHandshakeParser::default(),
                flowscope::detect::signatures::tls_client_hello,
                ProtocolMessage::TlsHandshake,
            );
            slots += 1;
        }

        let driver = builder.build();

        // One capture — no kernel filter.
        let cap = AsyncCapture::open(&iface)?;
        let packet_stream = cap.into_stream();

        let inner: BoxedEventStream<E::Key> = Box::pin(DriverDrivenStream {
            packet_stream,
            driver,
            pending: VecDeque::new(),
        });

        Ok(ProtocolMonitor { inner, slots })
    }
}

/// Inner stream: pulls owned-packet batches from the underlying
/// `AsyncCapture` and feeds them through the unified driver,
/// buffering the resulting events.
struct DriverDrivenStream<S, E>
where
    S: PacketSource + std::os::fd::AsRawFd,
    E: FlowExtractor,
{
    packet_stream: PacketStream<S>,
    driver: Driver<E, ProtocolMessage>,
    pending: VecDeque<ProtocolEvent<E::Key>>,
}

// All fields are owned values without self-references; the struct
// is Unpin whenever its field types are. Since flowscope's Driver
// and the netring PacketStream are both Unpin given Unpin sources,
// we don't need a manual impl.

impl<S, E> Stream for DriverDrivenStream<S, E>
where
    S: PacketSource + std::os::fd::AsRawFd + Unpin + Send + 'static,
    E: FlowExtractor + Clone + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Send + Sync + Unpin + 'static,
{
    type Item = Result<ProtocolEvent<E::Key>, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            // Drain pending first — driver.track() may have queued
            // many events from a single batch.
            if let Some(ev) = self.pending.pop_front() {
                return Poll::Ready(Some(Ok(ev)));
            }

            let this = self.as_mut().get_mut();
            match Pin::new(&mut this.packet_stream).poll_next(cx) {
                Poll::Ready(Some(Ok(batch))) => {
                    for owned in batch {
                        let view = flowscope::PacketView::new(&owned.data, owned.timestamp);
                        this.pending.extend(this.driver.track(view));
                    }
                    // Loop back and drain pending.
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
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
