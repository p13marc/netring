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
use flowscope::{L4Proto, Timestamp};

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
#[derive(Debug, Clone, Copy, PartialEq)]
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
    /// Last-seen timestamp (flow end).
    pub end: Timestamp,
    /// Why the flow ended.
    pub reason: EndReason,
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
            reason,
        }
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
        FlowKey {
            proto: L4Proto::Tcp,
            a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234),
            b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
        }
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
        assert_eq!(r.reason, EndReason::Fin);
        assert_eq!(r.total_packets(), 18);
        assert_eq!(r.total_bytes(), 13500);
        assert_eq!(r.duration(), std::time::Duration::from_millis(2500));
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
    }
}
