//! Metrics integration via the `metrics` façade (feature: `metrics`).
//!
//! Records packet counts and drops as monotonic counters tagged with the
//! interface label. The actual export (Prometheus, statsd, OTel, ...) is
//! whatever metrics-recorder the host application installs.
//!
//! # Examples
//!
//! ```no_run
//! # #[cfg(feature = "metrics")]
//! # fn _ex() -> Result<(), netring::Error> {
//! use netring::Capture;
//! use netring::metrics::record_capture_delta;
//!
//! let cap = Capture::open("eth0")?;
//! // ... capture some packets ...
//! let delta = cap.stats()?;
//! record_capture_delta("eth0", &delta);
//! # Ok(()) }
//! ```
//!
//! Pair with a recorder such as
//! [`metrics-exporter-prometheus`](https://crates.io/crates/metrics-exporter-prometheus)
//! to actually surface the values.

use crate::stats::CaptureStats;

/// Counter name: total packets received past kernel filter.
pub const COUNTER_PACKETS: &str = "netring_capture_packets_total";

/// Counter name: total packets dropped due to ring exhaustion.
pub const COUNTER_DROPS: &str = "netring_capture_drops_total";

/// Counter name: total ring freeze events.
pub const COUNTER_FREEZES: &str = "netring_capture_freezes_total";

/// Record a capture-stats delta as `metrics` counters.
///
/// Best paired with [`crate::Capture::stats`] (which returns the delta
/// since the last read). Calls
/// [`metrics::counter!`](https://docs.rs/metrics/latest/metrics/macro.counter.html)
/// three times — packets / drops / freezes — each tagged with `iface`.
///
/// All three counters use the standard `netring_capture_*_total` naming
/// (Prometheus convention: `_total` suffix on monotonic counters).
pub fn record_capture_delta(iface: &str, delta: &CaptureStats) {
    let iface_label = iface.to_string();
    metrics::counter!(COUNTER_PACKETS, "iface" => iface_label.clone())
        .increment(delta.packets as u64);
    metrics::counter!(COUNTER_DROPS, "iface" => iface_label.clone()).increment(delta.drops as u64);
    metrics::counter!(COUNTER_FREEZES, "iface" => iface_label).increment(delta.freeze_count as u64);
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let delta = CaptureStats {
            packets: 1234,
            drops: 5,
            freeze_count: 0,
        };
        record_capture_delta("test_iface", &delta);
    }
}
