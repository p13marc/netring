//! 0.22 §3 — periodic structured reports.
//!
//! A third output stream beside anomalies (event-driven,
//! [`AnomalySink`](crate::anomaly::sink::AnomalySink)) and
//! [`EventStream`](crate::monitor::EventStream) (broadcast,
//! per-message): a **periodic snapshot of derived state**. The
//! Suricata `stats.log` / Zeek `conn.log` shape, which monitors used
//! to hand-roll on `Tick` + `println!`.
//!
//! - [`Report`](crate::report::Report) — a typed snapshot a monitor
//!   emits each cadence.
//! - [`ReportSink`](crate::report::ReportSink) — consumes reports of
//!   type `R`.
//! - [`ReportSnapshot`](crate::report::ReportSnapshot) — read view over
//!   the monitor's registered primitives, handed to the `report()` /
//!   `report_to()` closures.
//!
//! Register via
//! [`MonitorBuilder::report`](crate::monitor::MonitorBuilder::report)
//! (closure) or
//! [`MonitorBuilder::report_to`](crate::monitor::MonitorBuilder::report_to)
//! (typed `R` → a [`ReportSink`](crate::report::ReportSink)).

use crate::anomaly::Severity;
use crate::anomaly::sink::AnomalyWriter;
use crate::ctx::Ctx;
use crate::correlate::TimeBucketedCounter;

/// A periodic, structured snapshot a monitor emits. Implementors are
/// plain data structs built from monitor state each cadence tick.
pub trait Report: Send + 'static {
    /// Stable name for the report stream (sink labels / log targets).
    const NAME: &'static str;
}

/// Consumes periodic [`Report`]s of type `R`. Object-safe per `R`;
/// 3rd-party Prometheus/Influx sinks implement this.
pub trait ReportSink<R: Report>: Send + 'static {
    /// Record one report.
    fn record(&mut self, report: &R);
    /// Flush buffered output (called on drain). Default no-op.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Read-only view of a monitor's registered primitives at report time.
/// Wraps the cadence tick's `&mut Ctx` + the tick `Timestamp`, so the
/// `report*` closures never handle a raw `Timestamp` for the
/// time-windowed primitives.
pub struct ReportSnapshot<'a, 'c> {
    pub(crate) ctx: &'a mut Ctx<'c>,
    pub(crate) now: flowscope::Timestamp,
}

impl ReportSnapshot<'_, '_> {
    /// The report instant — already threaded into `bandwidth()`.
    pub fn now(&self) -> flowscope::Timestamp {
        self.now
    }

    /// The bandwidth slot, if `bandwidth_by_app`/`on_bandwidth` is set.
    #[cfg(feature = "flow")]
    pub fn bandwidth(&self) -> Option<crate::monitor::BandwidthReport<'_>> {
        self.ctx.bandwidth()
    }

    /// A registered global state slot (immutable, non-creating).
    pub fn state<T: 'static>(&self) -> Option<&T> {
        self.ctx.state::<T>()
    }

    /// A registered sliding-window counter.
    pub fn counter<K>(&self) -> Option<&TimeBucketedCounter<K>>
    where
        K: std::hash::Hash + Eq + Clone + Send + 'static,
    {
        self.ctx.counter::<K>()
    }

    /// Emit an anomaly from within the report (e.g. a periodic rollup).
    pub fn emit(&mut self, kind: &'static str, severity: Severity) -> AnomalyWriter<'_> {
        self.ctx.emit(kind, severity)
    }
}

/// Prints each report via its `Debug` impl, prefixed with `R::NAME`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdoutReportSink;

impl<R: Report + std::fmt::Debug> ReportSink<R> for StdoutReportSink {
    fn record(&mut self, report: &R) {
        println!("[{}] {report:?}", R::NAME);
    }
}

/// Writes each report as one JSON line (newline-delimited JSON, the
/// shape Vector / Filebeat / Loki ingest). Requires `serde`.
#[cfg(feature = "serde")]
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonReportSink;

#[cfg(feature = "serde")]
impl<R: Report + serde::Serialize> ReportSink<R> for JsonReportSink {
    fn record(&mut self, report: &R) {
        match serde_json::to_string(report) {
            Ok(line) => println!("{line}"),
            Err(e) => eprintln!("JsonReportSink: serialize failed: {e}"),
        }
    }
}
