//! [`ProtocolMonitor`] — async stream that orchestrates one
//! filtered `AsyncCapture` per enabled L7 protocol and yields a
//! unified [`super::ProtocolEvent`].
//!
//! Implementation note: the monitor owns N inner streams (one per
//! enabled protocol). Without
//! [`AsyncCapture::broadcast`](crate::AsyncCapture) (roadmap item N6),
//! each protocol gets its own kernel ring + BPF filter. That's
//! ~N × memory cost but only the packets each parser actually
//! cares about cross the kernel→user boundary. For higher-
//! throughput workloads, replace the multi-capture orchestration
//! with a single broadcast-fanned capture once N6 ships.
//!
//! Per-protocol arms only forward `SessionEvent::Application`
//! events as [`ProtocolEvent::Message`]; the canonical lifecycle
//! (Started, Established, Ended, FlowAnomaly, TrackerAnomaly, Tick)
//! is owned by the `.flow()` arm, avoiding duplicate Started/Closed
//! events when both `.flow()` and e.g. `.http()` are enabled.

use std::pin::Pin;
use std::task::{Context, Poll};

use flowscope::FlowExtractor;
use futures_core::Stream;
use tokio_stream::StreamExt;

use super::event::ProtocolEvent;
#[cfg(any(feature = "http", feature = "dns", feature = "tls", feature = "icmp"))]
use super::event::ProtocolMessage;
use crate::AsyncCapture;
#[cfg(any(feature = "http", feature = "dns", feature = "tls", feature = "icmp"))]
use crate::config::BpfFilter;
use crate::error::Error;

/// An always-ready-None stream. Used to replace an exhausted slot
/// in `ProtocolMonitor::streams` so subsequent polls fall through
/// fast.
struct FusedEmpty<T>(std::marker::PhantomData<T>);
impl<T> Stream for FusedEmpty<T> {
    type Item = T;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<T>> {
        Poll::Ready(None)
    }
}

/// A unified async stream of [`ProtocolEvent`]s from one or more
/// per-protocol child streams.
///
/// Produced by [`ProtocolMonitorBuilder::build`]. Owns N
/// [`AsyncCapture`]s internally; see the module docs for the
/// memory trade-off vs the roadmap-N6 broadcast variant.
pub struct ProtocolMonitor<K> {
    /// Boxed per-protocol child streams. Each yields
    /// `Result<ProtocolEvent<K>, Error>`. Polled in round-robin
    /// order to keep one chatty protocol from starving the others.
    streams: Vec<BoxedEventStream<K>>,
    /// Round-robin cursor for `poll_next`.
    cursor: usize,
    /// Number of streams that have hit `Poll::Ready(None)` and
    /// won't be polled again.
    exhausted: usize,
}

impl<K> std::fmt::Debug for ProtocolMonitor<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolMonitor")
            .field("sources", &self.streams.len())
            .field("alive", &(self.streams.len() - self.exhausted))
            .finish()
    }
}

type BoxedEventStream<K> =
    Pin<Box<dyn Stream<Item = Result<ProtocolEvent<K>, Error>> + Send + 'static>>;

impl<K> ProtocolMonitor<K> {
    /// Number of underlying captures driving this monitor.
    pub fn source_count(&self) -> usize {
        self.streams.len()
    }

    /// Number of sources still producing events (i.e. not yet at
    /// `Poll::Ready(None)`).
    pub fn alive_sources(&self) -> usize {
        self.streams.len().saturating_sub(self.exhausted)
    }
}

impl ProtocolMonitorBuilder {
    /// Entry point — mirrors `Capture::builder()` and other
    /// builder constructors in netring.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<K: Send + Unpin + 'static> Stream for ProtocolMonitor<K> {
    type Item = Result<ProtocolEvent<K>, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.streams.is_empty() {
            return Poll::Ready(None);
        }

        let len = self.streams.len();
        let mut polled = 0;
        // Round-robin so one chatty stream doesn't starve others.
        while polled < len {
            let idx = (self.cursor + polled) % len;
            polled += 1;
            let s = &mut self.streams[idx];
            match s.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    self.cursor = (idx + 1) % len;
                    return Poll::Ready(Some(item));
                }
                Poll::Ready(None) => {
                    self.exhausted += 1;
                    // Replace with a fused-empty stream so future
                    // polls fall through fast.
                    let dummy: BoxedEventStream<K> = Box::pin(FusedEmpty(std::marker::PhantomData));
                    self.streams[idx] = dummy;
                }
                Poll::Pending => {
                    // Try the next stream.
                }
            }
        }

        if self.exhausted >= self.streams.len() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

/// Builder for [`ProtocolMonitor`].
///
/// Declare:
/// - the interface to watch (one network device)
/// - which protocols to track (`.flow()`, `.http()`, `.dns()`,
///   `.tls()`, `.icmp()` — each is an additive opt-in)
///
/// Then call [`build`](Self::build) with the
/// [`FlowExtractor`](flowscope::FlowExtractor) (typically
/// `FiveTuple::bidirectional()`).
#[derive(Debug, Default)]
pub struct ProtocolMonitorBuilder {
    interface: Option<String>,
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
    /// Set the network interface to watch.
    pub fn interface(mut self, name: impl Into<String>) -> Self {
        self.interface = Some(name.into());
        self
    }

    /// Enable plain flow-lifecycle tracking (Started, Established,
    /// StateChange, Ended, Tick, FlowAnomaly, TrackerAnomaly) for
    /// every ICMP/TCP/UDP flow on the interface. No BPF filter —
    /// the flow tracker sees everything.
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

    /// Enable the TLS handshake **aggregator** parser (flowscope's
    /// [`TlsHandshakeParser`](flowscope::tls::TlsHandshakeParser),
    /// new in 0.9) on the default port set (443, 8443). Emits one
    /// `ProtocolMessage::TlsHandshake` per observed handshake
    /// instead of the message-granularity events `.tls()` produces.
    ///
    /// You can enable both `.tls()` and `.tls_handshake()` — they
    /// run independent parsers. Most consumers want one or the
    /// other.
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

    /// Enable ICMP parsing (both ICMPv4 and ICMPv6). The arm
    /// surfaces `ProtocolMessage::Icmp(IcmpMessage)` events,
    /// including `inner: Option<IcmpInner>` on error variants
    /// (`DestinationUnreachable`, `TimeExceeded`, …) — the
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
    /// - `Error::Config` if no interface was set, or no protocols
    ///   were enabled, or building any of the captures fails.
    pub fn build<E>(self, extractor: E) -> Result<ProtocolMonitor<E::Key>, Error>
    where
        E: FlowExtractor + Unpin + Clone + Send + 'static,
        E::Key: Eq + std::hash::Hash + Clone + Send + Sync + Unpin + 'static,
    {
        let iface = self.interface.ok_or_else(|| {
            Error::Config("ProtocolMonitorBuilder: .interface(...) is required".into())
        })?;

        let mut streams: Vec<BoxedEventStream<E::Key>> = Vec::new();

        if self.enable_flow {
            streams.push(build_flow_stream(&iface, extractor.clone())?);
        }

        #[cfg(feature = "http")]
        if let Some(ports) = self.http_ports.as_deref() {
            streams.push(build_http_stream(&iface, extractor.clone(), ports)?);
        }

        #[cfg(feature = "dns")]
        if let Some(ports) = self.dns_udp_ports.as_deref() {
            streams.push(build_dns_udp_stream(&iface, extractor.clone(), ports)?);
        }

        #[cfg(feature = "dns")]
        if let Some(ports) = self.dns_tcp_ports.as_deref() {
            streams.push(build_dns_tcp_stream(&iface, extractor.clone(), ports)?);
        }

        #[cfg(feature = "tls")]
        if let Some(ports) = self.tls_ports.as_deref() {
            streams.push(build_tls_stream(&iface, extractor.clone(), ports)?);
        }

        #[cfg(feature = "tls")]
        if let Some(ports) = self.tls_handshake_ports.as_deref() {
            streams.push(build_tls_handshake_stream(
                &iface,
                extractor.clone(),
                ports,
            )?);
        }

        #[cfg(feature = "icmp")]
        if let Some(scope) = self.enable_icmp {
            streams.push(build_icmp_stream(&iface, extractor.clone(), scope)?);
        }

        if streams.is_empty() {
            return Err(Error::Config(
                "ProtocolMonitorBuilder: at least one protocol must be enabled".into(),
            ));
        }

        Ok(ProtocolMonitor {
            streams,
            cursor: 0,
            exhausted: 0,
        })
    }
}

// ── Per-protocol stream constructors ─────────────────────────────

fn build_flow_stream<E>(iface: &str, ext: E) -> Result<BoxedEventStream<E::Key>, Error>
where
    E: FlowExtractor + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Send + Sync + Unpin + 'static,
{
    let cap = AsyncCapture::open(iface)?;
    let stream = cap.flow_stream(ext).map(|r| r.map(ProtocolEvent::Flow));
    Ok(Box::pin(stream))
}

#[cfg(feature = "http")]
fn build_http_stream<E>(
    iface: &str,
    ext: E,
    ports: &[u16],
) -> Result<BoxedEventStream<E::Key>, Error>
where
    E: FlowExtractor + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Send + Sync + Unpin + 'static,
{
    use flowscope::http::HttpParser;

    let filter = bpf_tcp_ports(ports)?;
    let cap = AsyncCapture::open_with_filter(iface, filter)?;
    let stream = cap
        .flow_stream(ext)
        .session_stream(HttpParser::default())
        .filter_map(application_only_http);
    Ok(Box::pin(stream))
}

#[cfg(feature = "dns")]
fn build_dns_udp_stream<E>(
    iface: &str,
    ext: E,
    ports: &[u16],
) -> Result<BoxedEventStream<E::Key>, Error>
where
    E: FlowExtractor + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Send + Sync + Unpin + 'static,
{
    use flowscope::dns::DnsUdpParser;

    let filter = bpf_udp_ports(ports)?;
    let cap = AsyncCapture::open_with_filter(iface, filter)?;
    let stream = cap
        .flow_stream(ext)
        .datagram_stream(DnsUdpParser::with_correlation())
        .filter_map(application_only_dns);
    Ok(Box::pin(stream))
}

#[cfg(feature = "dns")]
fn build_dns_tcp_stream<E>(
    iface: &str,
    ext: E,
    ports: &[u16],
) -> Result<BoxedEventStream<E::Key>, Error>
where
    E: FlowExtractor + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Send + Sync + Unpin + 'static,
{
    use flowscope::dns::DnsTcpParser;

    let filter = bpf_tcp_ports(ports)?;
    let cap = AsyncCapture::open_with_filter(iface, filter)?;
    let stream = cap
        .flow_stream(ext)
        .session_stream(DnsTcpParser::default())
        .filter_map(application_only_dns);
    Ok(Box::pin(stream))
}

#[cfg(feature = "tls")]
fn build_tls_stream<E>(
    iface: &str,
    ext: E,
    ports: &[u16],
) -> Result<BoxedEventStream<E::Key>, Error>
where
    E: FlowExtractor + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Send + Sync + Unpin + 'static,
{
    use flowscope::tls::TlsParser;

    let filter = bpf_tcp_ports(ports)?;
    let cap = AsyncCapture::open_with_filter(iface, filter)?;
    let stream = cap
        .flow_stream(ext)
        .session_stream(TlsParser::default())
        .filter_map(application_only_tls);
    Ok(Box::pin(stream))
}

#[cfg(feature = "tls")]
fn build_tls_handshake_stream<E>(
    iface: &str,
    ext: E,
    ports: &[u16],
) -> Result<BoxedEventStream<E::Key>, Error>
where
    E: FlowExtractor + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Send + Sync + Unpin + 'static,
{
    use flowscope::tls::TlsHandshakeParser;

    let filter = bpf_tcp_ports(ports)?;
    let cap = AsyncCapture::open_with_filter(iface, filter)?;
    let stream = cap
        .flow_stream(ext)
        .session_stream(TlsHandshakeParser::default())
        .filter_map(application_only_tls_handshake);
    Ok(Box::pin(stream))
}

#[cfg(feature = "icmp")]
fn build_icmp_stream<E>(
    iface: &str,
    ext: E,
    scope: IcmpScope,
) -> Result<BoxedEventStream<E::Key>, Error>
where
    E: FlowExtractor + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Send + Sync + Unpin + 'static,
{
    use flowscope::icmp::IcmpParser;

    let filter = bpf_icmp(scope)?;
    let cap = AsyncCapture::open_with_filter(iface, filter)?;
    let parser = match scope {
        IcmpScope::Both => IcmpParser::new(),
        IcmpScope::V4 => IcmpParser::new().v4_only(),
        IcmpScope::V6 => IcmpParser::new().v6_only(),
    };
    let stream = cap
        .flow_stream(ext)
        .datagram_stream(parser)
        .filter_map(application_only_icmp);
    Ok(Box::pin(stream))
}

// ── Filter helpers — keep only Application events, drop lifecycle. ──

#[cfg(feature = "http")]
fn application_only_http<K>(
    r: Result<flowscope::SessionEvent<K, flowscope::http::HttpMessage>, Error>,
) -> Option<Result<ProtocolEvent<K>, Error>> {
    use flowscope::SessionEvent;
    match r {
        Err(e) => Some(Err(e)),
        Ok(SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind,
        }) => Some(Ok(ProtocolEvent::Message {
            key,
            side,
            kind: parser_kind,
            message: ProtocolMessage::Http(message),
            ts,
        })),
        Ok(_) => None,
    }
}

#[cfg(feature = "dns")]
fn application_only_dns<K>(
    r: Result<flowscope::SessionEvent<K, flowscope::dns::DnsMessage>, Error>,
) -> Option<Result<ProtocolEvent<K>, Error>> {
    use flowscope::SessionEvent;
    match r {
        Err(e) => Some(Err(e)),
        Ok(SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind,
        }) => Some(Ok(ProtocolEvent::Message {
            key,
            side,
            kind: parser_kind,
            message: ProtocolMessage::Dns(message),
            ts,
        })),
        Ok(_) => None,
    }
}

#[cfg(feature = "icmp")]
fn application_only_icmp<K>(
    r: Result<flowscope::SessionEvent<K, flowscope::icmp::IcmpMessage>, Error>,
) -> Option<Result<ProtocolEvent<K>, Error>> {
    use flowscope::SessionEvent;
    match r {
        Err(e) => Some(Err(e)),
        Ok(SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind,
        }) => Some(Ok(ProtocolEvent::Message {
            key,
            side,
            kind: parser_kind,
            message: ProtocolMessage::Icmp(message),
            ts,
        })),
        Ok(_) => None,
    }
}

#[cfg(feature = "tls")]
fn application_only_tls<K>(
    r: Result<flowscope::SessionEvent<K, flowscope::tls::TlsMessage>, Error>,
) -> Option<Result<ProtocolEvent<K>, Error>> {
    use flowscope::SessionEvent;
    match r {
        Err(e) => Some(Err(e)),
        Ok(SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind,
        }) => Some(Ok(ProtocolEvent::Message {
            key,
            side,
            kind: parser_kind,
            message: ProtocolMessage::Tls(message),
            ts,
        })),
        Ok(_) => None,
    }
}

#[cfg(feature = "tls")]
fn application_only_tls_handshake<K>(
    r: Result<flowscope::SessionEvent<K, flowscope::tls::TlsHandshake>, Error>,
) -> Option<Result<ProtocolEvent<K>, Error>> {
    use flowscope::SessionEvent;
    match r {
        Err(e) => Some(Err(e)),
        Ok(SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind,
        }) => Some(Ok(ProtocolEvent::Message {
            key,
            side,
            kind: parser_kind,
            message: ProtocolMessage::TlsHandshake(message),
            ts,
        })),
        Ok(_) => None,
    }
}

// ── BPF helpers ──────────────────────────────────────────────────

#[cfg(any(feature = "http", feature = "dns", feature = "tls"))]
fn bpf_tcp_ports(ports: &[u16]) -> Result<BpfFilter, Error> {
    if ports.is_empty() {
        return Err(Error::Config("empty port set".into()));
    }
    BpfFilter::builder()
        .tcp()
        .ports(ports.iter().copied())
        .build()
        .map_err(Error::from)
}

#[cfg(feature = "dns")]
fn bpf_udp_ports(ports: &[u16]) -> Result<BpfFilter, Error> {
    if ports.is_empty() {
        return Err(Error::Config("empty port set".into()));
    }
    BpfFilter::builder()
        .udp()
        .ports(ports.iter().copied())
        .build()
        .map_err(Error::from)
}

#[cfg(feature = "icmp")]
fn bpf_icmp(scope: IcmpScope) -> Result<BpfFilter, Error> {
    // ICMPv4 is IP proto 1; ICMPv6 is IPv6 Next Header 58.
    let b = BpfFilter::builder();
    let b = match scope {
        IcmpScope::V4 => b.icmp(),
        IcmpScope::V6 => b.ipv6().ip_proto(58),
        IcmpScope::Both => b.icmp().or(|b| b.ipv6().ip_proto(58)),
    };
    b.build().map_err(Error::from)
}

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
        // Verify that the builder state correctly leaves all
        // protocols off by default. The build-time error for "no
        // protocol enabled" is exercised at the boundary via
        // integration tests under `integration-tests`.
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
        assert!(b.tls_ports.is_none());
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
