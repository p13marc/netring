//! [`ProtocolEvent`] + [`ProtocolMessage`] — the unified event surface.
//!
//! As of netring 0.18, [`ProtocolEvent<K>`] is a **type alias** for
//! [`flowscope::driver_unified::Event<K, ProtocolMessage>`]. The
//! prior netring-owned sum-type (`Flow(FlowEvent)` + `Message{…}`)
//! collapsed onto flowscope's unified `Event<K, M>` shape so the
//! whole anomaly toolkit shares the same event vocabulary as
//! flowscope's own pipeline.
//!
//! ## Migration from netring 0.17 and earlier
//!
//! The variant shapes shifted to match flowscope. The mechanical
//! rewrites:
//!
//! | Old (netring 0.17) | New (0.18) |
//! |---|---|
//! | `ProtocolEvent::Flow(FlowEvent::Started { … })` | `ProtocolEvent::FlowStarted { … }` (no `side` field) |
//! | `ProtocolEvent::Flow(FlowEvent::Established { … })` | `ProtocolEvent::FlowEstablished { … }` |
//! | `ProtocolEvent::Flow(FlowEvent::Packet { … })` | `ProtocolEvent::FlowPacket { … }` |
//! | `ProtocolEvent::Flow(FlowEvent::Ended { … })` | `ProtocolEvent::FlowEnded { … }` |
//! | `ProtocolEvent::Flow(FlowEvent::Tick { … })` | `ProtocolEvent::FlowTick { … }` |
//! | `ProtocolEvent::Flow(FlowEvent::FlowAnomaly { … })` | `ProtocolEvent::FlowAnomaly { … }` |
//! | `ProtocolEvent::Flow(FlowEvent::TrackerAnomaly { … })` | `ProtocolEvent::TrackerAnomaly { … }` |
//! | `ProtocolEvent::Message { kind, … }` | `ProtocolEvent::Message { parser_kind, … }` |
//!
//! Accessors `key()`, `timestamp()`, `parser_kind()`,
//! `anomaly_kind()`, `is_flow_event()`, `is_parser_event()` are
//! inherited from flowscope's `Event` impl.

/// Unified protocol event surface — a thin alias over flowscope's
/// driver-unified `Event<K, M>` with `M = ProtocolMessage`. Same
/// shape, same accessors, same `#[non_exhaustive]` discipline.
pub type ProtocolEvent<K> = flowscope::driver_unified::Event<K, ProtocolMessage>;

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
    use flowscope::Timestamp;
    use flowscope::driver_unified::Event;

    type Key = u32;

    #[test]
    fn protocol_event_timestamp_flow_started() {
        let evt: ProtocolEvent<Key> = Event::FlowStarted {
            key: 7,
            l4: None,
            ts: Timestamp::new(100, 0),
        };
        assert_eq!(evt.timestamp(), Timestamp::new(100, 0));
        assert_eq!(evt.key(), Some(&7));
    }

    #[test]
    fn protocol_event_tracker_anomaly_has_no_key() {
        let evt: ProtocolEvent<Key> = Event::TrackerAnomaly {
            kind: flowscope::AnomalyKind::FlowTableEvictionPressure {
                evicted_in_tick: 1,
                evicted_total: 1,
            },
            ts: Timestamp::new(200, 0),
        };
        assert_eq!(evt.key(), None);
        assert_eq!(evt.timestamp(), Timestamp::new(200, 0));
    }
}
