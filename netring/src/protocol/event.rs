//! [`ProtocolEvent`] + [`ProtocolMessage`] — the unified event surface.
//!
//! ## What changed in netring 0.19
//!
//! flowscope 0.11 (plan 121) replaced the closed `Driver<E, M>` /
//! `Event<K, M>` sum-type shape with a typed `Driver<E>` that emits
//! lifecycle [`Event<K>`](flowscope::driver::Event) only — per-parser
//! typed messages now flow through `SlotHandle<M, K>` returned at
//! builder time.
//!
//! [`ProtocolEvent<K>`] used to be a `pub type` alias for flowscope's
//! `Event<K, ProtocolMessage>`. Since the new flowscope `Event<K>`
//! has no `Message` variant (messages live on the typed slot
//! handles), `ProtocolEvent<K>` is now a **netring-owned enum** that:
//!
//! - mirrors flowscope's lifecycle `Event<K>` variants
//!   (`FlowStarted`, `FlowEstablished`, `FlowPacket`, `FlowEnded`,
//!   `FlowTick`, `ParserClosed`, `FlowAnomaly`, `TrackerAnomaly`) —
//!   same field shapes, same `#[non_exhaustive]` discipline; and
//! - re-introduces the `Message { key, side, parser_kind, message,
//!   ts }` variant that netring synthesizes by draining flowscope's
//!   slot handles inside [`super::monitor::ProtocolMonitor`].
//!
//! **The user-facing variant names, field names, and pattern-match
//! shapes are unchanged from netring 0.18.** Existing detectors that
//! pattern-match `ProtocolEvent::FlowStarted { key, l4, ts, .. }` or
//! `ProtocolEvent::Message { parser_kind, message, key, ts, .. }`
//! continue to compile and run.

use flowscope::{AnomalyKind, EndReason, FlowSide, FlowStats, L4Proto, TcpInfo, Timestamp};

/// Unified protocol event surface — netring-owned sum over
/// flowscope lifecycle events plus parser-emitted messages.
///
/// Variant shapes mirror flowscope 0.11's `Event<K>`, with the
/// addition of [`Self::Message`] for L7 parser output (HTTP / DNS /
/// TLS / ICMP). `Message` carries [`ProtocolMessage`] — feature-gated
/// by the corresponding parser feature.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProtocolEvent<K> {
    /// First packet of a new flow.
    FlowStarted {
        /// Flow key (5-tuple or whatever the extractor produces).
        key: K,
        /// Timestamp of the first packet.
        ts: Timestamp,
        /// L4 protocol (TCP / UDP / ICMP / ICMPv6). `None` for
        /// unknown / non-IP frames.
        l4: Option<L4Proto>,
    },

    /// TCP flow reached the `Established` state (3-way handshake
    /// complete). Not emitted for UDP / ICMP flows.
    FlowEstablished {
        /// Flow key.
        key: K,
        /// Timestamp of the ACK that completed the handshake.
        ts: Timestamp,
        /// L4 protocol (always `Some(L4Proto::Tcp)` for this variant).
        l4: Option<L4Proto>,
    },

    /// Per-packet event on an existing flow. The `tcp` field is
    /// populated only when the underlying driver was configured
    /// with `emit_packet_details(true)`.
    FlowPacket {
        /// Flow key.
        key: K,
        /// Direction relative to the flow's initiator.
        side: FlowSide,
        /// L4 payload length in bytes.
        len: usize,
        /// Packet timestamp.
        ts: Timestamp,
        /// TCP-layer details, when packet-details emission is enabled.
        tcp: Option<TcpInfo>,
    },

    /// Flow ended (FIN / RST / idle timeout / eviction / parser
    /// close). `history` carries the TCP flag-history string for
    /// post-mortem.
    FlowEnded {
        /// Flow key.
        key: K,
        /// What caused the flow to end.
        reason: EndReason,
        /// Final stats snapshot (bytes / packets / retransmits per side).
        stats: FlowStats,
        /// TCP flag-history string (`"S>A<R"` style) for post-mortem.
        history: flowscope::HistoryString,
        /// L4 protocol.
        l4: Option<L4Proto>,
        /// Timestamp of the flow's last packet.
        ts: Timestamp,
    },

    /// Periodic [`FlowStats`] snapshot — emitted when
    /// [`flowscope::FlowTrackerConfig::flow_tick_interval`] is set.
    FlowTick {
        /// Flow key.
        key: K,
        /// Current stats snapshot.
        stats: FlowStats,
        /// Tick timestamp (sweep `now`).
        ts: Timestamp,
    },

    /// Parser-level close — a registered parser drained its
    /// `fin_*` accumulator or reported `is_done` / `is_poisoned`.
    /// Distinct from [`Self::FlowEnded`]: this fires per
    /// (parser, flow); the flow may still be alive.
    ParserClosed {
        /// Flow key.
        key: K,
        /// Stable identifier of the parser that closed (e.g.
        /// `"http/1"`).
        parser_kind: &'static str,
        /// Why the parser closed (`ParserDone` / `ParseError`).
        reason: EndReason,
        /// Timestamp of the close.
        ts: Timestamp,
    },

    /// Live per-flow anomaly forwarded from the central tracker.
    /// Emitted only when `emit_anomalies(true)` was set on the
    /// underlying driver builder.
    FlowAnomaly {
        /// Flow key.
        key: K,
        /// Concrete anomaly kind.
        kind: AnomalyKind,
        /// Timestamp of the anomaly.
        ts: Timestamp,
    },

    /// Live tracker-global anomaly.
    TrackerAnomaly {
        /// Concrete anomaly kind (e.g. eviction pressure).
        kind: AnomalyKind,
        /// Timestamp of the anomaly.
        ts: Timestamp,
    },

    /// L7 message emitted by a registered parser. netring
    /// synthesizes these by draining flowscope's typed
    /// `SlotHandle<M, K>` and lifting `M` into [`ProtocolMessage`].
    /// `parser_kind` is the stable slug returned by the underlying
    /// parser's `parser_kind()` method (e.g. `"http/1"`,
    /// `"dns-udp"`, `"tls-handshake"`).
    Message {
        /// Flow key the parser is attached to.
        key: K,
        /// Direction relative to the flow's initiator.
        side: FlowSide,
        /// Stable parser identifier — distinguishes `"dns-udp"`
        /// from `"dns-tcp"` etc. when the same `ProtocolMessage`
        /// variant can be emitted by multiple parsers.
        parser_kind: &'static str,
        /// The parsed L7 message.
        message: ProtocolMessage,
        /// Timestamp of the carrying packet.
        ts: Timestamp,
    },
}

impl<K> ProtocolEvent<K> {
    /// Borrow the flow key, if the variant has one.
    pub fn key(&self) -> Option<&K> {
        match self {
            ProtocolEvent::FlowStarted { key, .. }
            | ProtocolEvent::FlowEstablished { key, .. }
            | ProtocolEvent::FlowPacket { key, .. }
            | ProtocolEvent::FlowEnded { key, .. }
            | ProtocolEvent::FlowTick { key, .. }
            | ProtocolEvent::ParserClosed { key, .. }
            | ProtocolEvent::FlowAnomaly { key, .. }
            | ProtocolEvent::Message { key, .. } => Some(key),
            ProtocolEvent::TrackerAnomaly { .. } => None,
        }
    }

    /// Borrow the timestamp on the event.
    pub fn timestamp(&self) -> Timestamp {
        match self {
            ProtocolEvent::FlowStarted { ts, .. }
            | ProtocolEvent::FlowEstablished { ts, .. }
            | ProtocolEvent::FlowPacket { ts, .. }
            | ProtocolEvent::FlowEnded { ts, .. }
            | ProtocolEvent::FlowTick { ts, .. }
            | ProtocolEvent::ParserClosed { ts, .. }
            | ProtocolEvent::FlowAnomaly { ts, .. }
            | ProtocolEvent::TrackerAnomaly { ts, .. }
            | ProtocolEvent::Message { ts, .. } => *ts,
        }
    }

    /// For [`Self::Message`] / [`Self::ParserClosed`], returns the
    /// stable parser-kind slug. `None` for other variants.
    pub fn parser_kind(&self) -> Option<&'static str> {
        match self {
            ProtocolEvent::Message { parser_kind, .. }
            | ProtocolEvent::ParserClosed { parser_kind, .. } => Some(parser_kind),
            _ => None,
        }
    }

    /// `true` for flow-lifecycle variants (everything except
    /// [`Self::Message`] / [`Self::ParserClosed`]).
    pub fn is_flow_event(&self) -> bool {
        !matches!(
            self,
            ProtocolEvent::Message { .. } | ProtocolEvent::ParserClosed { .. }
        )
    }

    /// `true` for parser-emitted variants ([`Self::Message`] /
    /// [`Self::ParserClosed`]).
    pub fn is_parser_event(&self) -> bool {
        matches!(
            self,
            ProtocolEvent::Message { .. } | ProtocolEvent::ParserClosed { .. }
        )
    }

    /// For anomaly variants, returns the [`AnomalyKind`]. `None`
    /// otherwise.
    pub fn anomaly_kind(&self) -> Option<&AnomalyKind> {
        match self {
            ProtocolEvent::FlowAnomaly { kind, .. }
            | ProtocolEvent::TrackerAnomaly { kind, .. } => Some(kind),
            _ => None,
        }
    }
}

/// A parsed L7 message. Variants are feature-gated by the
/// corresponding parser feature (`http` / `dns` / `tls` / `icmp`);
/// enabling `all-parsers` enables all four.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProtocolMessage {
    /// HTTP/1.x request or response.
    #[cfg(feature = "http")]
    Http(flowscope::http::HttpMessage),

    /// DNS query, response (optionally with RTT), or unanswered.
    /// Emitted by `DnsUdpParser` (UDP/53) or `DnsTcpParser` (TCP/53);
    /// the `parser_kind` field on `ProtocolEvent::Message`
    /// distinguishes `"dns-udp"` from `"dns-tcp"`.
    #[cfg(feature = "dns")]
    Dns(flowscope::dns::DnsMessage),

    /// TLS handshake observation (ClientHello / ServerHello /
    /// Alert) at the message granularity. For one synthesised
    /// event per completed handshake, use
    /// [`Self::TlsHandshake`] instead.
    #[cfg(feature = "tls")]
    Tls(flowscope::tls::TlsMessage),

    /// One synthesised event per observed TLS handshake. Aggregated
    /// from ClientHello + ServerHello + Alert by
    /// [`flowscope::tls::TlsHandshakeParser`] (flowscope 0.9).
    /// Carries SNI, ALPN, optional JA3/JA4, negotiated version,
    /// cipher suite, `resumption_attempted`, and `HandshakeOutcome`
    /// (`Completed` / `AlertedByServer` / `AlertedByClient` /
    /// `Truncated`). `parser_kind` on the carrying event is
    /// `"tls-handshake"`.
    #[cfg(feature = "tls")]
    TlsHandshake(flowscope::tls::TlsHandshake),

    /// ICMPv4 / ICMPv6 message. Error variants
    /// (`DestinationUnreachable` / `TimeExceeded` / …) carry
    /// `inner: Option<IcmpInner>` — the cross-protocol correlation
    /// primitive that ties the ICMP error back to the originating
    /// TCP/UDP flow.
    #[cfg(feature = "icmp")]
    Icmp(flowscope::icmp::IcmpMessage),
}

#[cfg(test)]
mod tests {
    use super::*;

    type Key = u32;

    #[test]
    fn protocol_event_timestamp_flow_started() {
        let evt: ProtocolEvent<Key> = ProtocolEvent::FlowStarted {
            key: 7,
            l4: None,
            ts: Timestamp::new(100, 0),
        };
        assert_eq!(evt.timestamp(), Timestamp::new(100, 0));
        assert_eq!(evt.key(), Some(&7));
        assert!(evt.is_flow_event());
        assert!(!evt.is_parser_event());
        assert_eq!(evt.parser_kind(), None);
    }

    #[test]
    fn protocol_event_tracker_anomaly_has_no_key() {
        let evt: ProtocolEvent<Key> = ProtocolEvent::TrackerAnomaly {
            kind: AnomalyKind::FlowTableEvictionPressure {
                evicted_in_tick: 1,
                evicted_total: 1,
            },
            ts: Timestamp::new(200, 0),
        };
        assert_eq!(evt.key(), None);
        assert_eq!(evt.timestamp(), Timestamp::new(200, 0));
        assert!(evt.anomaly_kind().is_some());
    }

    #[test]
    fn parser_kind_visible_on_parser_events() {
        let evt: ProtocolEvent<Key> = ProtocolEvent::ParserClosed {
            key: 1,
            parser_kind: "http/1",
            reason: EndReason::Fin,
            ts: Timestamp::new(5, 0),
        };
        assert_eq!(evt.parser_kind(), Some("http/1"));
        assert!(evt.is_parser_event());
        assert!(!evt.is_flow_event());
    }
}
