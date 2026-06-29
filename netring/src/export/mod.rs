//! 0.24 Phase D — flow export.
//!
//! A **fourth** output shape beside per-event anomalies
//! ([`AnomalySink`](crate::anomaly::sink::AnomalySink)), periodic reports
//! ([`Report`](crate::report::Report)), and broadcast event streams
//! ([`EventStream`](crate::monitor::EventStream)): one
//! [`FlowRecord`](crate::export::FlowRecord) per **completed flow** — the
//! NetFlow / IPFIX / Zeek `conn.log` shape.
//!
//! Register a [`FlowExporter`](crate::export::FlowExporter) with
//! [`MonitorBuilder::export_flows`](crate::monitor::MonitorBuilder::export_flows);
//! the run loop emits a `FlowRecord` for every `FlowEnded` (FIN / RST /
//! idle / eviction / parser close) and hands it to each exporter. Works
//! identically over live capture and pcap replay.
//!
//! A bare `FnMut(&FlowRecord)` is a `FlowExporter` (blanket impl), so the
//! quick path is `.export_flows(|rec| { … })`. For NDJSON, use
//! [`JsonFlowExporter`](crate::export::JsonFlowExporter) (feature `serde`);
//! IPFIX/NetFlow v10 export lands as a `FlowExporter` impl in D3.

use std::net::SocketAddr;

use flowscope::event::{EndReason, FlowStats};
use flowscope::{KeyFields, L4Proto, Timestamp};

use crate::protocol::FlowKey;

#[cfg(feature = "ipfix")]
pub mod ipfix;
#[cfg(feature = "ipfix")]
pub use ipfix::IpfixExporter;

/// A completed-flow record, built from a `FlowEnded` event's key + stats.
///
/// `a` / `b` are the flow's two endpoints. In the default
/// (bidirectional) extractor they're canonically ordered (`a < b`), so
/// "source/destination" lives in the **directional** byte/packet counts
/// — `*_initiator` is the side that opened the flow, `*_responder` the
/// other — not in `a`/`b`. In a directional extractor `a` is the source.
// No longer `Copy` (0.20 / issue #33): the `community_id` String owns a heap
// allocation. Records are passed to exporters by `&` on the hot path, so this
// costs nothing there — only explicit `.clone()` sites pay.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct FlowRecord {
    /// L4 protocol (TCP / UDP / ICMP / …).
    pub proto: L4Proto,
    /// First endpoint (`a`).
    pub a: SocketAddr,
    /// Second endpoint (`b`).
    pub b: SocketAddr,
    /// Packets sent by the flow initiator (the side that opened it).
    pub packets_initiator: u64,
    /// Packets sent by the responder.
    pub packets_responder: u64,
    /// Bytes sent by the initiator.
    pub bytes_initiator: u64,
    /// Bytes sent by the responder.
    pub bytes_responder: u64,
    /// First-seen timestamp.
    pub start: Timestamp,
    /// Last-seen timestamp (flow end, or the snapshot time for an ongoing
    /// active-timeout record).
    pub end: Timestamp,
    /// Why the flow ended, or `None` for an **ongoing** record emitted on the
    /// active timeout (0.25 W1c) — the flow is still alive and this is a
    /// periodic interim snapshot, as NetFlow/IPFIX do for long-lived flows.
    pub reason: Option<EndReason>,
    /// [Corelight Community ID](https://github.com/corelight/community-id-spec)
    /// v1 (universal seed 0) — the portable cross-tool flow id for pivoting
    /// netring output against Zeek / Suricata / Security Onion (issue #33,
    /// flowscope #88). `Some` for full 5-tuple keys (TCP/UDP exact, ICMP
    /// stable-but-not-spec); `None` if the `flow` feature's
    /// `flowscope/community-id` is somehow disabled or the key lacks a full
    /// tuple. Derived deterministically from the canonically-ordered key, so
    /// both directions of a biflow share one id.
    pub community_id: Option<String>,
}

impl FlowRecord {
    /// Build a record from a `FlowEnded` event's key + stats + reason.
    pub(crate) fn from_ended(key: &FlowKey, stats: &FlowStats, reason: EndReason) -> Self {
        Self {
            proto: key.proto,
            a: key.a,
            b: key.b,
            packets_initiator: stats.packets_initiator,
            packets_responder: stats.packets_responder,
            bytes_initiator: stats.bytes_initiator,
            bytes_responder: stats.bytes_responder,
            start: stats.started,
            end: stats.last_seen,
            reason: Some(reason),
            // Call the `KeyFields` trait method explicitly (the inherent
            // `FiveTupleKey::community_id` is feature-gated and returns a bare
            // `String`); the trait method is the always-present `Option`.
            community_id: KeyFields::community_id(key),
        }
    }

    /// Build an **ongoing** interim record for a still-alive flow at the active
    /// timeout (0.25 W1c). `reason` is `None`; `end` is the snapshot time
    /// (`stats.last_seen`). Counters are cumulative-to-date, matching how
    /// NetFlow/IPFIX active-timeout records report long-lived flows.
    pub(crate) fn from_active(key: &FlowKey, stats: &FlowStats) -> Self {
        Self {
            proto: key.proto,
            a: key.a,
            b: key.b,
            packets_initiator: stats.packets_initiator,
            packets_responder: stats.packets_responder,
            bytes_initiator: stats.bytes_initiator,
            bytes_responder: stats.bytes_responder,
            start: stats.started,
            end: stats.last_seen,
            reason: None,
            community_id: KeyFields::community_id(key),
        }
    }

    /// Whether this is an ongoing active-timeout snapshot (`reason.is_none()`)
    /// rather than a final end-of-flow record.
    #[inline]
    pub fn is_ongoing(&self) -> bool {
        self.reason.is_none()
    }

    /// Total packets in both directions.
    #[inline]
    pub fn total_packets(&self) -> u64 {
        self.packets_initiator + self.packets_responder
    }

    /// Total bytes in both directions.
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.bytes_initiator + self.bytes_responder
    }

    /// Flow duration (`end - start`), floored at zero.
    #[inline]
    pub fn duration(&self) -> std::time::Duration {
        self.end.saturating_sub(self.start)
    }
}

/// Consumes [`FlowRecord`]s — one per completed flow. The flow-side
/// analogue of [`AnomalySink`](crate::anomaly::sink::AnomalySink) /
/// [`ReportSink`](crate::report::ReportSink).
///
/// A bare `FnMut(&FlowRecord) + Send` is a `FlowExporter` via the blanket
/// impl below, so `.export_flows(|rec| …)` works without a named type.
pub trait FlowExporter: Send {
    /// Record one completed flow.
    fn export(&mut self, record: &FlowRecord);
    /// Flush buffered output (called on drain). Default no-op.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<F: FnMut(&FlowRecord) + Send> FlowExporter for F {
    fn export(&mut self, record: &FlowRecord) {
        self(record)
    }
}

/// Writes each [`FlowRecord`] as one JSON line (newline-delimited JSON —
/// the shape Vector / Filebeat / Loki ingest). Requires `serde`.
#[cfg(feature = "serde")]
pub struct JsonFlowExporter<W: std::io::Write + Send> {
    writer: W,
}

#[cfg(feature = "serde")]
impl<W: std::io::Write + Send> JsonFlowExporter<W> {
    /// Wrap a writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Consume and recover the inner writer (tests read back the bytes).
    pub fn into_inner(self) -> W {
        self.writer
    }
}

#[cfg(feature = "serde")]
impl JsonFlowExporter<std::io::Stdout> {
    /// `JsonFlowExporter::stdout()` — NDJSON flow records on stdout.
    pub fn stdout() -> Self {
        Self::new(std::io::stdout())
    }
}

#[cfg(feature = "serde")]
impl<W: std::io::Write + Send> FlowExporter for JsonFlowExporter<W> {
    fn export(&mut self, record: &FlowRecord) {
        match serde_json::to_string(record) {
            // Swallow write errors like the other shipped sinks (broken
            // stdout is operator-recoverable, not a panic).
            Ok(line) => {
                let _ = writeln!(self.writer, "{line}");
            }
            Err(e) => eprintln!("JsonFlowExporter: serialize failed: {e}"),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key() -> FlowKey {
        FlowKey::new(
            L4Proto::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
        )
    }

    fn stats() -> FlowStats {
        let mut s = FlowStats::default();
        s.packets_initiator = 10;
        s.packets_responder = 8;
        s.bytes_initiator = 1500;
        s.bytes_responder = 12000;
        s.started = Timestamp::from_unix_f64(1000.0);
        s.last_seen = Timestamp::from_unix_f64(1002.5);
        s
    }

    #[test]
    fn from_ended_maps_key_stats_and_reason() {
        let r = FlowRecord::from_ended(&key(), &stats(), EndReason::Fin);
        assert_eq!(r.proto, L4Proto::Tcp);
        assert_eq!(r.a.port(), 1234);
        assert_eq!(r.b.port(), 80);
        assert_eq!(r.packets_initiator, 10);
        assert_eq!(r.bytes_responder, 12000);
        assert_eq!(r.reason, Some(EndReason::Fin));
        assert!(!r.is_ongoing());
        assert_eq!(r.total_packets(), 18);
        assert_eq!(r.total_bytes(), 13500);
        assert_eq!(r.duration(), std::time::Duration::from_millis(2500));
        // Community ID (issue #33): `Some` and direction-invariant — the same
        // 5-tuple in either order yields one id, matching the golden vector
        // from flowscope's `KeyFields::community_id`.
        let expect = KeyFields::community_id(&key());
        assert!(
            expect.is_some(),
            "community-id feature should be on under flow"
        );
        assert_eq!(r.community_id, expect);
        assert!(r.community_id.as_deref().unwrap().starts_with("1:"));
    }

    #[test]
    fn from_active_is_ongoing_with_no_reason() {
        // 0.25 W1c: an interim active-timeout record carries the same counters
        // but `reason == None` / `is_ongoing()`.
        let r = FlowRecord::from_active(&key(), &stats());
        assert!(r.is_ongoing());
        assert_eq!(r.reason, None);
        assert_eq!(r.packets_initiator, 10);
        assert_eq!(r.bytes_responder, 12000);
        assert_eq!(r.total_packets(), 18);
    }

    #[test]
    fn fnmut_is_a_flow_exporter() {
        let mut count = 0u32;
        let mut exporter = |_r: &FlowRecord| count += 1;
        let r = FlowRecord::from_ended(&key(), &stats(), EndReason::Fin);
        FlowExporter::export(&mut exporter, &r);
        FlowExporter::export(&mut exporter, &r);
        assert_eq!(count, 2);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn json_flow_exporter_writes_one_line_with_core_fields() {
        let mut exporter = JsonFlowExporter::new(Vec::<u8>::new());
        let r = FlowRecord::from_ended(&key(), &stats(), EndReason::Fin);
        exporter.export(&r);
        let out = String::from_utf8(exporter.into_inner()).unwrap();
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("\"packets_initiator\":10"), "out = {out}");
        assert!(out.contains("\"bytes_responder\":12000"), "out = {out}");
        // Issue #33: the portable Community ID rides the NDJSON line.
        assert!(out.contains("\"community_id\":\"1:"), "out = {out}");
    }
}
