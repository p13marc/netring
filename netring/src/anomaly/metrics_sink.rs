//! 0.21 B.3: `MetricsSink` — bridge anomalies to the `metrics` crate
//! facade. Drops one Prometheus / OpenTelemetry-style counter per
//! anomaly emission and one histogram observation per numeric
//! `metric` carried on the [`AnomalyWriter`].
//!
//! Gated on the existing `metrics` Cargo feature, which already pulls
//! the `metrics` crate (the facade — concrete exporters like
//! `metrics-exporter-prometheus` / `metrics-exporter-otlp` live in
//! downstream user code).
//!
//! ## Cardinality contract
//!
//! Only `kind` and `severity` become labels (low, bounded
//! cardinality). The 5-tuple `key`, per-anomaly observation
//! strings, and metric names are **never** promoted to labels —
//! that would create unbounded cardinality and blow up
//! Prometheus / Cortex / Mimir scrape responses.
//!
//! The metric **name** is configurable (so multi-monitor apps can
//! namespace), but neither the field labels nor the cardinality
//! contract are tunable. If you need per-host counters, build a
//! second sink instead.

use std::borrow::Cow;

use flowscope::Timestamp;

use crate::anomaly::Severity;
use crate::anomaly::key::Key;
use crate::anomaly::sink::AnomalySink;

/// Sink adapter over the [`metrics`] crate facade. Increments a
/// counter per anomaly emission and records a histogram value
/// per numeric metric carried on the [`AnomalyWriter`].
///
/// Wire to a real exporter downstream (Prometheus, OTLP, statsd,
/// …) via the standard `metrics`-rs pattern — netring stays
/// agnostic.
///
/// ## Usage
///
/// ```ignore
/// use netring::prelude::*;
/// use netring::anomaly::MetricsSink;
///
/// Monitor::builder()
///     .interface("eth0")
///     .protocol::<Http>()
///     .sink(MetricsSink::default())
///     .detect(detector! { /* … */ })
///     .build()?;
/// ```
///
/// The default counter name is `netring_anomaly_total` (kind +
/// severity labels) and the default histogram name is
/// `netring_anomaly_metric` (a single `metric` label per
/// numeric observation). Override via [`Self::with_counter_name`]
/// / [`Self::with_histogram_name`] for multi-monitor namespacing.
#[derive(Clone, Debug)]
pub struct MetricsSink {
    counter_name: &'static str,
    histogram_name: &'static str,
}

impl Default for MetricsSink {
    fn default() -> Self {
        Self {
            counter_name: "netring_anomaly_total",
            histogram_name: "netring_anomaly_metric",
        }
    }
}

impl MetricsSink {
    /// Override the counter metric name. Useful for namespacing
    /// multiple monitors emitting into the same Prometheus
    /// registry.
    pub fn with_counter_name(mut self, name: &'static str) -> Self {
        self.counter_name = name;
        self
    }

    /// Override the histogram metric name.
    pub fn with_histogram_name(mut self, name: &'static str) -> Self {
        self.histogram_name = name;
        self
    }

    /// Read the configured counter name.
    pub fn counter_name(&self) -> &'static str {
        self.counter_name
    }

    /// Read the configured histogram name.
    pub fn histogram_name(&self) -> &'static str {
        self.histogram_name
    }
}

impl AnomalySink for MetricsSink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        _ts: Timestamp,
        _key: Option<&dyn Key>,
        _observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        // The `metrics` crate's `counter!` and `histogram!`
        // macros take `&'static str` labels by value, exactly
        // what we have. No allocation on the hot path.
        ::metrics::counter!(
            self.counter_name,
            "kind" => kind,
            "severity" => severity.as_str(),
        )
        .increment(1);

        for (label, value) in metrics {
            ::metrics::histogram!(
                self.histogram_name,
                "metric" => *label,
            )
            .record(*value);
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        // The `metrics` facade exposes no flush; concrete
        // exporters drain on their own cadence. A no-op here
        // matches the trait default; we override only to make
        // the intent explicit at the impl site.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::sink::AnomalySinkExt;

    #[test]
    fn default_names_match_plan() {
        let s = MetricsSink::default();
        assert_eq!(s.counter_name(), "netring_anomaly_total");
        assert_eq!(s.histogram_name(), "netring_anomaly_metric");
    }

    #[test]
    fn name_overrides_take_effect() {
        let s = MetricsSink::default()
            .with_counter_name("my_anomalies")
            .with_histogram_name("my_anomaly_metric");
        assert_eq!(s.counter_name(), "my_anomalies");
        assert_eq!(s.histogram_name(), "my_anomaly_metric");
    }

    #[test]
    fn write_through_anomalywriter_does_not_panic() {
        // With no exporter wired, metrics-rs no-ops. We just
        // exercise the path through `AnomalyWriter` to confirm
        // the trait impl compiles and runs without panic.
        let mut sink = MetricsSink::default();
        sink.begin("TestKind", Severity::Warning, Timestamp::new(0, 0))
            .with_metric("latency_ms", 42.5)
            .with_metric("size_bytes", 1024.0)
            .with("note", "synthetic")
            .emit();
    }
}
