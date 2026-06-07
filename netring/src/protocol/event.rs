//! [`ProtocolEvent`] + [`ProtocolMessage`] — the unified event surface.

use flowscope::{FlowEvent, FlowSide, Timestamp};

/// A unified event from a multi-protocol monitor.
///
/// Either lifecycle [`Flow`](Self::Flow) (Started, Established,
/// StateChange, Tick, Ended, FlowAnomaly, TrackerAnomaly) or
/// [`Message`](Self::Message) (a parsed L7 record).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProtocolEvent<K> {
    /// Flow-tracker lifecycle event. Always emitted when
    /// [`crate::protocol::ProtocolMonitorBuilder::flow`] is
    /// enabled.
    Flow(FlowEvent<K>),

    /// An L7 message from a session/datagram parser.
    Message {
        /// Flow identifier (typically `FiveTupleKey`).
        key: K,
        /// Initiator or responder direction.
        side: FlowSide,
        /// Parser-kind tag from
        /// [`flowscope::SessionParser::parser_kind`] /
        /// `DatagramParser::parser_kind` — e.g. `"http/1"`, `"dns-udp"`,
        /// `"tls"`. Useful for routing without downcasting.
        kind: &'static str,
        /// The parsed message itself.
        message: ProtocolMessage,
        /// Timestamp of the carrying packet (clamped if the source
        /// stream has `with_monotonic_timestamps(true)`).
        ts: Timestamp,
    },
}

impl<K> ProtocolEvent<K> {
    /// Borrow the timestamp on this event (works across both
    /// variants).
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Self::Flow(f) => flow_event_ts(f),
            Self::Message { ts, .. } => *ts,
        }
    }

    /// Borrow the key, if the event has one. `Flow(TrackerAnomaly)`
    /// is the only variant without a per-flow key.
    pub fn key(&self) -> Option<&K> {
        match self {
            Self::Flow(f) => flow_event_key(f),
            Self::Message { key, .. } => Some(key),
        }
    }
}

fn flow_event_ts<K>(e: &FlowEvent<K>) -> Timestamp {
    match e {
        FlowEvent::Started { ts, .. } => *ts,
        FlowEvent::Packet { ts, .. } => *ts,
        FlowEvent::Established { ts, .. } => *ts,
        FlowEvent::StateChange { ts, .. } => *ts,
        FlowEvent::Ended { stats, .. } => stats.last_seen,
        FlowEvent::Tick { ts, .. } => *ts,
        FlowEvent::FlowAnomaly { ts, .. } => *ts,
        FlowEvent::TrackerAnomaly { ts, .. } => *ts,
        _ => Timestamp::default(),
    }
}

fn flow_event_key<K>(e: &FlowEvent<K>) -> Option<&K> {
    match e {
        FlowEvent::Started { key, .. } => Some(key),
        FlowEvent::Packet { key, .. } => Some(key),
        FlowEvent::Established { key, .. } => Some(key),
        FlowEvent::StateChange { key, .. } => Some(key),
        FlowEvent::Ended { key, .. } => Some(key),
        FlowEvent::Tick { key, .. } => Some(key),
        FlowEvent::FlowAnomaly { key, .. } => Some(key),
        FlowEvent::TrackerAnomaly { .. } => None,
        _ => None,
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
    /// the `kind` field on `ProtocolEvent::Message` distinguishes
    /// `"dns-udp"` from `"dns-tcp"`.
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
    use flowscope::FlowStats;

    type Key = u32;

    #[test]
    fn protocol_event_timestamp_flow_started() {
        let evt: ProtocolEvent<Key> = ProtocolEvent::Flow(FlowEvent::Started {
            key: 7,
            side: FlowSide::Initiator,
            l4: None,
            ts: Timestamp::new(100, 0),
        });
        assert_eq!(evt.timestamp(), Timestamp::new(100, 0));
        assert_eq!(evt.key(), Some(&7));
    }

    #[test]
    fn protocol_event_timestamp_flow_ended_uses_last_seen() {
        let mut stats = FlowStats::default();
        stats.last_seen = Timestamp::new(150, 0);
        let evt: ProtocolEvent<Key> = ProtocolEvent::Flow(FlowEvent::Ended {
            key: 7,
            reason: flowscope::EndReason::Fin,
            stats,
            history: flowscope::HistoryString::default(),
            l4: None,
        });
        assert_eq!(evt.timestamp(), Timestamp::new(150, 0));
        assert_eq!(evt.key(), Some(&7));
    }

    #[test]
    fn protocol_event_tracker_anomaly_has_no_key() {
        let evt: ProtocolEvent<Key> = ProtocolEvent::Flow(FlowEvent::TrackerAnomaly {
            kind: flowscope::AnomalyKind::FlowTableEvictionPressure {
                evicted_in_tick: 1,
                evicted_total: 1,
            },
            ts: Timestamp::new(200, 0),
        });
        assert_eq!(evt.key(), None);
        assert_eq!(evt.timestamp(), Timestamp::new(200, 0));
    }
}
