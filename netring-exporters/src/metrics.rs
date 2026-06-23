//! OTLP/HTTP-JSON **metrics** exporter (issue #52).
//!
//! Pushes netring's per-source capture counters to an OTLP/HTTP collector
//! (`/v1/metrics`) as JSON over a **blocking** HTTP client (`ureq`) — the same
//! transport and sync shape as [`OtlpAnomalySink`](crate::OtlpAnomalySink), so
//! it stays out of any async runtime.
//!
//! Unlike the anomaly sink this is **not** an `AnomalySink`: capture telemetry
//! arrives through
//! [`MonitorBuilder::on_capture_stats`](netring::monitor::MonitorBuilder::on_capture_stats),
//! which hands a [`CaptureTelemetry`] to a periodic closure. The recipe:
//!
//! ```no_run
//! # #[cfg(feature = "otlp")]
//! # fn _ex() -> Result<(), netring::Error> {
//! use std::time::Duration;
//! use netring::monitor::Monitor;
//! use netring::protocol::builtin::Tcp;
//! use netring_exporters::OtlpMetricsExporter;
//!
//! let exporter = OtlpMetricsExporter::new("http://localhost:4318/v1/metrics", "netring");
//! let _m = Monitor::builder()
//!     .interface("eth0")
//!     .protocol::<Tcp>()
//!     .on_capture_stats(Duration::from_secs(10), move |t, _ctx| {
//!         let _ = exporter.export(t); // warn-and-continue; never tears down capture
//!         Ok(())
//!     })
//!     .build()?;
//! # Ok(()) }
//! ```
//!
//! The capture counters (`packets` / `drops` / `freezes`) are cumulative since
//! the monitor started, which maps directly onto OTLP **cumulative monotonic
//! Sums**; the windowed `drop_rate` is an instantaneous level, so it's a
//! **Gauge**. See the [OTLP metrics data model].
//!
//! [OTLP metrics data model]: https://opentelemetry.io/docs/specs/otel/metrics/data-model/

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use netring::monitor::CaptureTelemetry;
use serde_json::{Value, json};

/// OTLP `AggregationTemporality::CUMULATIVE`.
const CUMULATIVE: u8 = 2;

/// Wall-clock nanoseconds since the Unix epoch.
fn now_unix_nano() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// One OTLP `KeyValue` attribute (string value).
fn str_attr(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

/// Build a cumulative monotonic **Sum** metric with a single data point.
///
/// `value` is emitted as `asInt` (OTLP encodes 64-bit ints as decimal
/// strings); `start`/`now` are nanosecond timestamps. Pure — unit-tested
/// without a collector.
fn build_sum(name: &str, unit: &str, value: u64, start: u64, now: u64, source: &str) -> Value {
    json!({
        "name": name,
        "unit": unit,
        "sum": {
            "aggregationTemporality": CUMULATIVE,
            "isMonotonic": true,
            "dataPoints": [{
                "asInt": value.to_string(),
                "startTimeUnixNano": start.to_string(),
                "timeUnixNano": now.to_string(),
                "attributes": [str_attr("source", source)],
            }],
        },
    })
}

/// Build a **Gauge** metric (instantaneous level — no temporality, no start
/// time) with a single `asDouble` data point. Pure — unit-tested.
fn build_gauge(name: &str, unit: &str, value: f64, now: u64, source: &str) -> Value {
    json!({
        "name": name,
        "unit": unit,
        "gauge": {
            "dataPoints": [{
                "asDouble": value,
                "timeUnixNano": now.to_string(),
                "attributes": [str_attr("source", source)],
            }],
        },
    })
}

/// Wrap one source's capture metrics in the OTLP `metrics` request envelope
/// (`resourceMetrics` → `scopeMetrics` → `metrics`). Takes the raw sample
/// values (not the `#[non_exhaustive]` `CaptureTelemetry`) so it's fully
/// unit-testable without constructing one. Pure.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_metrics_envelope(
    service_name: &str,
    start: u64,
    now: u64,
    source: &str,
    packets: u64,
    drops: u64,
    freezes: u64,
    drop_rate: f64,
) -> Value {
    let metrics = vec![
        build_sum(
            "netring.capture.packets",
            "{packet}",
            packets,
            start,
            now,
            source,
        ),
        build_sum(
            "netring.capture.drops",
            "{packet}",
            drops,
            start,
            now,
            source,
        ),
        build_sum(
            "netring.capture.freezes",
            "{event}",
            freezes,
            start,
            now,
            source,
        ),
        build_gauge("netring.capture.drop_rate", "1", drop_rate, now, source),
    ];
    json!({
        "resourceMetrics": [{
            "resource": {
                "attributes": [str_attr("service.name", service_name)],
            },
            "scopeMetrics": [{
                "scope": { "name": "netring" },
                "metrics": metrics,
            }],
        }],
    })
}

/// Pushes netring capture telemetry to an OTLP/HTTP collector as OpenTelemetry
/// metrics.
///
/// Each [`export`](Self::export) call POSTs one OTLP `metrics` request for one
/// source's sample. The capture counters become cumulative monotonic Sums and
/// the windowed drop rate a Gauge; a fixed `startTimeUnixNano` (captured at
/// construction) anchors the cumulative series for the process lifetime.
/// Export failures are logged at `warn` and returned — an unreachable collector
/// never tears down the capture pipeline.
pub struct OtlpMetricsExporter {
    endpoint: String,
    service_name: String,
    start_unix_nano: u64,
    agent: ureq::Agent,
}

impl OtlpMetricsExporter {
    /// Create an exporter posting to `endpoint` (e.g.
    /// `http://localhost:4318/v1/metrics`), tagging records with
    /// `service_name`. The cumulative-series start time is anchored now.
    pub fn new(endpoint: impl Into<String>, service_name: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            service_name: service_name.into(),
            start_unix_nano: now_unix_nano(),
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(5))
                .build(),
        }
    }

    /// POST one source's capture telemetry as an OTLP `metrics` request.
    ///
    /// Designed to be called from an
    /// [`on_capture_stats`](netring::monitor::MonitorBuilder::on_capture_stats)
    /// handler, once per source per period. Blocks on the HTTP round-trip
    /// (short timeout); on failure it logs at `warn` and returns the error so
    /// the caller can ignore it and keep capturing.
    pub fn export(&self, t: &CaptureTelemetry) -> io::Result<()> {
        let envelope = build_metrics_envelope(
            &self.service_name,
            self.start_unix_nano,
            now_unix_nano(),
            &t.source.0.to_string(),
            t.packets,
            t.drops,
            t.freezes,
            t.drop_rate,
        );
        self.agent
            .post(&self.endpoint)
            .set("content-type", "application/json")
            .send_string(&envelope.to_string())
            .map_err(|e| io::Error::other(e.to_string()))
            .inspect_err(|e| tracing::warn!(error = %e, "OTLP metrics export failed"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sum_is_cumulative_monotonic_with_int_string_value() {
        let m = build_sum("netring.capture.packets", "{packet}", 1000, 5, 9, "0");
        assert_eq!(m["name"], "netring.capture.packets");
        assert_eq!(m["unit"], "{packet}");
        assert_eq!(m["sum"]["isMonotonic"], true);
        assert_eq!(m["sum"]["aggregationTemporality"], CUMULATIVE);
        let dp = &m["sum"]["dataPoints"][0];
        assert_eq!(dp["asInt"], "1000", "64-bit ints are decimal strings");
        assert_eq!(dp["startTimeUnixNano"], "5");
        assert_eq!(dp["timeUnixNano"], "9");
        assert_eq!(dp["attributes"][0]["key"], "source");
        assert_eq!(dp["attributes"][0]["value"]["stringValue"], "0");
    }

    #[test]
    fn gauge_has_no_temporality_and_double_value() {
        let m = build_gauge("netring.capture.drop_rate", "1", 0.25, 9, "1");
        assert!(m["gauge"]["dataPoints"][0]["asDouble"].is_number());
        assert_eq!(m["gauge"]["dataPoints"][0]["asDouble"], 0.25);
        // A Gauge carries no aggregationTemporality / isMonotonic / startTime.
        assert!(m["gauge"]["aggregationTemporality"].is_null());
        assert!(m["gauge"]["dataPoints"][0]["startTimeUnixNano"].is_null());
        assert_eq!(
            m["gauge"]["dataPoints"][0]["attributes"][0]["value"]["stringValue"],
            "1"
        );
    }

    #[test]
    fn envelope_emits_three_sums_and_one_gauge_under_resource_scope() {
        // packets=1000, drops=7, freezes=2, drop_rate=0.25, source="2".
        let env = build_metrics_envelope("svc", 1, 2, "2", 1000, 7, 2, 0.25);
        let res_attrs = env["resourceMetrics"][0]["resource"]["attributes"]
            .as_array()
            .unwrap();
        assert!(
            res_attrs
                .iter()
                .any(|a| a["key"] == "service.name" && a["value"]["stringValue"] == "svc")
        );
        let ms = env["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap();
        assert_eq!(ms.len(), 4);
        let sums = ms.iter().filter(|m| m.get("sum").is_some()).count();
        let gauges = ms.iter().filter(|m| m.get("gauge").is_some()).count();
        assert_eq!((sums, gauges), (3, 1), "3 cumulative Sums + 1 Gauge");
        // The drops Sum carries the right value as a decimal string.
        let drops_m = ms
            .iter()
            .find(|m| m["name"] == "netring.capture.drops")
            .unwrap();
        assert_eq!(drops_m["sum"]["dataPoints"][0]["asInt"], "7");
        // The drop_rate Gauge carries the windowed rate.
        let rate_m = ms
            .iter()
            .find(|m| m["name"] == "netring.capture.drop_rate")
            .unwrap();
        assert_eq!(rate_m["gauge"]["dataPoints"][0]["asDouble"], 0.25);
    }
}
