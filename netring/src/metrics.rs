//! Metrics integration via the `metrics` façade (feature: `metrics`).
//!
//! Records a capture's packet counts and drops as monotonic counters tagged
//! with the interface label. The actual export (Prometheus, statsd, OTel,
//! ...) is whatever metrics-recorder the host application installs.
//!
//! # Examples
//!
//! ```no_run
//! # #[cfg(feature = "metrics")]
//! # fn _ex() -> Result<(), netring::Error> {
//! use netring::Capture;
//! use netring::metrics::record_capture_stats;
//!
//! let cap = Capture::open("eth0")?;
//! // ... capture some packets; then, periodically:
//! record_capture_stats("eth0", &cap.stats()?);
//! # Ok(()) }
//! ```
//!
//! Pair with a recorder such as
//! [`metrics-exporter-prometheus`](https://crates.io/crates/metrics-exporter-prometheus)
//! to actually surface the values.

use crate::stats::CaptureStats;

/// Counter name: total packets that reached the socket (passed the kernel
/// filter), **including** the dropped ones —
/// [`CaptureStats::received`]. The loss fraction is
/// `…_drops_total / …_packets_total`.
pub const COUNTER_PACKETS: &str = "netring_capture_packets_total";

/// Counter name: total packets dropped due to ring exhaustion
/// ([`CaptureStats::drops`]).
pub const COUNTER_DROPS: &str = "netring_capture_drops_total";

/// Counter name: total ring freeze events ([`CaptureStats::freezes`]).
pub const COUNTER_FREEZES: &str = "netring_capture_freezes_total";

/// Gauge name: cumulative packets delivered to userspace (excluding drops),
/// per capture source. Emitted by
/// [`CaptureTelemetry::record_metrics`](crate::monitor::CaptureTelemetry::record_metrics).
pub const GAUGE_PACKETS: &str = "netring_capture_packets";

/// Gauge name: cumulative kernel drops (no room in the ring), per capture
/// source.
pub const GAUGE_DROPS: &str = "netring_capture_drops";

/// Gauge name: cumulative ring freezes, per capture source.
pub const GAUGE_FREEZES: &str = "netring_capture_freezes";

/// Gauge name: windowed drop rate (`[0.0, 1.0]`), per capture source.
pub const GAUGE_DROP_RATE: &str = "netring_capture_drop_rate";
/// `netring_capture_dedup_dropped{source}` — cumulative frames the
/// source's [`Dedup`](crate::Dedup) dropped as duplicates
/// ([`MonitorBuilder::dedup`](crate::monitor::MonitorBuilder::dedup)).
/// New in 0.31.1.
pub const GAUGE_DEDUP_DROPPED: &str = "netring_capture_dedup_dropped";

/// Gauge name: cumulative handler errors swallowed under
/// `HandlerErrorPolicy::Isolate`. Emitted by
/// [`MonitorHealth::record_metrics`](crate::monitor::MonitorHealth::record_metrics).
pub const GAUGE_HANDLER_ERRORS: &str = "netring_monitor_handler_errors";

/// Gauge name: cumulative backend errors absorbed under
/// `BackendErrorPolicy::SkipSource` / `Reopen`.
pub const GAUGE_BACKEND_ERRORS: &str = "netring_monitor_backend_errors";

/// Gauge name: active flows in the central tracker (last event).
pub const GAUGE_ACTIVE_FLOWS: &str = "netring_monitor_active_flows";

/// Publish a capture's lifetime totals as `metrics` counters.
///
/// `totals` is what every netring stats accessor returns — totals since
/// the source was opened (e.g. [`Capture::stats`](crate::Capture::stats)).
/// The three counters — [`COUNTER_PACKETS`] (= [`CaptureStats::received`]),
/// [`COUNTER_DROPS`], [`COUNTER_FREEZES`], each tagged with `iface` — are set
/// to those **absolute** values
/// ([`Counter::absolute`](metrics::Counter::absolute)), not incremented, so
/// calling this on every scrape or timer tick never double counts, however
/// often it runs.
///
/// **One capture per `iface` label.** The `metrics` crate's counters apply
/// `absolute` as "at least" (`fetch_max`): several captures publishing their
/// totals under one label (fanout workers on one interface) leave the
/// counter at the largest of them, not their sum, and a capture re-opened
/// with fresh totals leaves it frozen until the new totals pass the old.
/// For those, add each capture's window with [`record_capture_delta`].
///
/// All three counters use the standard `netring_capture_*_total` naming
/// (Prometheus convention: `_total` suffix on monotonic counters).
pub fn record_capture_stats(iface: &str, totals: &CaptureStats) {
    let iface_label = iface.to_string();
    metrics::counter!(COUNTER_PACKETS, "iface" => iface_label.clone()).absolute(totals.received());
    metrics::counter!(COUNTER_DROPS, "iface" => iface_label.clone()).absolute(totals.drops);
    metrics::counter!(COUNTER_FREEZES, "iface" => iface_label).absolute(totals.freezes);
}

/// Add a window's counts to the same counters as [`record_capture_stats`]
/// (incremented): for an `iface` label several captures share — fanout
/// workers, a capture that is re-opened — each capture adds its own
/// windows. Feed it the counts since the previous call,
/// `now.delta_since(&before)` of two [`stats()`](crate::Capture::stats)
/// readings — **not** `stats()` itself, which since 0.32 returns lifetime
/// totals (0.31's `stats()` was a delta).
///
/// ```no_run
/// # #[cfg(feature = "metrics")]
/// # fn _ex(cap: &netring::Capture) -> Result<(), netring::Error> {
/// let mut before = cap.stats()?;
/// // … every tick:
/// let now = cap.stats()?;
/// netring::metrics::record_capture_delta("eth0", &now.delta_since(&before));
/// before = now;
/// # let _ = before; Ok(()) }
/// ```
pub fn record_capture_delta(iface: &str, delta: &CaptureStats) {
    let iface_label = iface.to_string();
    metrics::counter!(COUNTER_PACKETS, "iface" => iface_label.clone()).increment(delta.received());
    metrics::counter!(COUNTER_DROPS, "iface" => iface_label.clone()).increment(delta.drops);
    metrics::counter!(COUNTER_FREEZES, "iface" => iface_label).increment(delta.freezes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn counter_names_have_total_suffix() {
        assert!(COUNTER_PACKETS.ends_with("_total"));
        assert!(COUNTER_DROPS.ends_with("_total"));
        assert!(COUNTER_FREEZES.ends_with("_total"));
    }

    #[test]
    fn record_does_not_panic_with_no_recorder() {
        // Without a recorder installed the metrics! macros are no-ops —
        // the call should succeed regardless.
        record_capture_stats("test_iface", &CaptureStats::new(1234, 5, 0));
    }

    /// Records every counter by `name{labels}` in the `metrics` crate's own
    /// counter type (`AtomicU64`: `increment` = add, `absolute` =
    /// `fetch_max`), as the shipped recorders do.
    #[derive(Default)]
    struct TestRecorder(Mutex<HashMap<String, Arc<AtomicU64>>>);

    impl TestRecorder {
        fn value(&self, name: &str) -> u64 {
            let key = format!("{name}{{iface=eth9}}");
            self.0.lock().unwrap()[&key].load(Ordering::Relaxed)
        }
    }

    impl metrics::Recorder for TestRecorder {
        fn describe_counter(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_gauge(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_histogram(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }

        fn register_counter(
            &self,
            key: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            let name = format!("{}{{{}}}", key.name(), labels.join(","));
            let c: Arc<AtomicU64> = Arc::clone(self.0.lock().unwrap().entry(name).or_default());
            metrics::Counter::from_arc(c)
        }

        fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
            metrics::Gauge::noop()
        }

        fn register_histogram(
            &self,
            _: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    /// #186: the totals are published as absolute values, so recording the
    /// same totals twice (two scrapes with no traffic in between) leaves the
    /// counters at the totals. The 0.31 `record_capture_delta` incremented,
    /// which double counted as soon as it was fed anything but a delta.
    #[test]
    fn record_capture_stats_is_absolute() {
        let rec = TestRecorder::default();
        let totals = CaptureStats::new(1_000, 25, 2);
        metrics::with_local_recorder(&rec, || {
            record_capture_stats("eth9", &totals);
            record_capture_stats("eth9", &totals);
        });
        assert_eq!(rec.value(COUNTER_PACKETS), 1_025, "received()");
        assert_eq!(rec.value(COUNTER_DROPS), 25);
        assert_eq!(rec.value(COUNTER_FREEZES), 2);

        // Later totals move the counters to the new totals.
        metrics::with_local_recorder(&rec, || {
            record_capture_stats("eth9", &CaptureStats::new(1_500, 30, 2));
        });
        assert_eq!(rec.value(COUNTER_PACKETS), 1_530);
        assert_eq!(rec.value(COUNTER_DROPS), 30);
    }

    /// Review r1: two captures under one label (fanout workers) — the
    /// absolute counters keep only the larger total (`fetch_max`), the
    /// deltas add up.
    #[test]
    fn shared_labels_add_deltas() {
        let (a, b) = (
            CaptureStats::new(1_000, 0, 0),
            CaptureStats::new(500, 10, 0),
        );
        let absolute = TestRecorder::default();
        metrics::with_local_recorder(&absolute, || {
            record_capture_stats("eth9", &a);
            record_capture_stats("eth9", &b);
        });
        assert_eq!(
            absolute.value(COUNTER_PACKETS),
            1_000,
            "fetch_max: not a sum"
        );

        let deltas = TestRecorder::default();
        metrics::with_local_recorder(&deltas, || {
            let zero = CaptureStats::default();
            record_capture_delta("eth9", &a.delta_since(&zero));
            record_capture_delta("eth9", &b.delta_since(&zero));
            // A second window of the first capture.
            record_capture_delta("eth9", &CaptureStats::new(1_200, 0, 0).delta_since(&a));
        });
        assert_eq!(deltas.value(COUNTER_PACKETS), 1_000 + 510 + 200);
        assert_eq!(deltas.value(COUNTER_DROPS), 10);
    }
}
