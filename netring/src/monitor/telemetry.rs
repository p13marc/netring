//! Capture-level telemetry (0.24 Phase C).
//!
//! The [`Monitor`](crate::monitor::Monitor) run loop can sample each
//! capture source's kernel counters on a fixed interval and hand the
//! result to a user callback registered with
//! [`MonitorBuilder::on_capture_stats`](crate::monitor::MonitorBuilder::on_capture_stats).
//! This is the "is my capture keeping up?" signal: packets delivered,
//! packets the kernel dropped (ring full), and ring freezes — plus a
//! windowed [`drop_rate`](CaptureTelemetry::drop_rate) so a transient
//! burst of loss is visible even when lifetime totals dwarf it.
//!
//! Sampling is **gated**: a monitor with no `on_capture_stats` handler
//! never arms the interval and pays nothing (same zero-cost pattern as
//! the tick / merge run-loop branches).

use std::time::Duration;

use crate::ctx::{Ctx, SourceIdx};
use crate::error::Result;
use crate::stats::CaptureStats;

/// A per-source snapshot of capture health, delivered to an
/// [`on_capture_stats`](crate::monitor::MonitorBuilder::on_capture_stats)
/// handler once per sample period.
///
/// `packets` / `drops` / `freezes` are **cumulative** since the monitor
/// started. (AF_PACKET kernel counters are destructive-read and
/// accumulated internally by [`Capture::cumulative_stats`](crate::Capture);
/// AF_XDP counters are monotonic.) [`drop_rate`](Self::drop_rate) is
/// computed over the most recent sample window, so it reflects *current*
/// loss rather than a lifetime average.
///
/// Counters are widened to `u64` here even though the kernel reports
/// `u32`: a busy 10 GbE link can retire more than `u32::MAX` packets in
/// a long-running capture, and `cumulative_stats` already accumulates
/// across the destructive `u32` reads.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CaptureTelemetry {
    /// Which capture source produced this sample — the interface's
    /// index in builder `.interfaces([...])` registration order.
    pub source: SourceIdx,
    /// Cumulative packets delivered to userspace (i.e. passed the
    /// kernel BPF filter and were read out of the ring).
    pub packets: u64,
    /// Cumulative packets the kernel dropped because the ring was full
    /// when they arrived. Non-zero here means the consumer isn't
    /// draining fast enough (or the ring is undersized).
    pub drops: u64,
    /// Cumulative ring-buffer freeze events. For TPACKET_V3 a freeze is
    /// the kernel running out of usable blocks; frequent freezes track
    /// with drops and point at the same backpressure.
    pub freezes: u64,
    /// Drop rate over the **most recent sample window**, in `[0.0, 1.0]`:
    /// `window_drops / (window_packets + window_drops)`. `0.0` when the
    /// window saw no traffic at all. Distinct from
    /// [`lifetime_drop_rate`](Self::lifetime_drop_rate), which averages
    /// over the whole run.
    pub drop_rate: f64,
}

impl CaptureTelemetry {
    /// Cumulative drop rate over the entire run so far:
    /// `drops / (packets + drops)`, in `[0.0, 1.0]`. `0.0` before any
    /// traffic. Use [`drop_rate`](Self::drop_rate) instead to react to a
    /// *current* loss spike — the lifetime figure is slow to move once a
    /// capture has been up for a while.
    #[inline]
    pub fn lifetime_drop_rate(&self) -> f64 {
        let total = self.packets + self.drops;
        if total == 0 {
            0.0
        } else {
            self.drops as f64 / total as f64
        }
    }

    /// `true` when the windowed [`drop_rate`](Self::drop_rate) is at or
    /// above `threshold`. Convenience for health gating, e.g.
    /// `if t.is_degraded(0.01) { warn!("losing >1% of packets") }`.
    #[inline]
    pub fn is_degraded(&self, threshold: f64) -> bool {
        self.drop_rate >= threshold
    }
}

/// A built-in [`Report`](crate::report::Report) shape for capture health —
/// the [`CaptureTelemetry`] fields flattened into a serde-friendly,
/// per-source record that rides the periodic report stream.
///
/// Register via
/// [`MonitorBuilder::capture_health`](crate::monitor::MonitorBuilder::capture_health),
/// which ships one `CaptureHealth` per source per period to a
/// [`ReportSink`](crate::report::ReportSink) (e.g.
/// [`StdoutReportSink`](crate::report::StdoutReportSink) or
/// [`JsonReportSink`](crate::report::JsonReportSink)). This is the
/// no-code-required counterpart to a hand-written
/// [`on_capture_stats`](crate::monitor::MonitorBuilder::on_capture_stats)
/// handler.
///
/// `source` is the flat `u8` index (rather than the `SourceIdx` newtype)
/// so the struct serializes cleanly to a JSON line without forcing
/// `Serialize` onto internal types.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CaptureHealth {
    /// Capture source index (interface registration order).
    pub source: u8,
    /// Cumulative packets delivered to userspace.
    pub packets: u64,
    /// Cumulative packets the kernel dropped (ring full).
    pub drops: u64,
    /// Cumulative ring freeze events.
    pub freezes: u64,
    /// Windowed drop rate over the most recent sample period, `[0.0, 1.0]`.
    pub drop_rate: f64,
    /// Cumulative drop rate over the whole run, `[0.0, 1.0]`.
    pub lifetime_drop_rate: f64,
}

impl crate::report::Report for CaptureHealth {
    const NAME: &'static str = "capture_health";
}

impl From<CaptureTelemetry> for CaptureHealth {
    fn from(t: CaptureTelemetry) -> Self {
        Self {
            source: t.source.0,
            packets: t.packets,
            drops: t.drops,
            freezes: t.freezes,
            drop_rate: t.drop_rate,
            lifetime_drop_rate: t.lifetime_drop_rate(),
        }
    }
}

/// Internal per-source accumulator that turns the monitor's cumulative
/// [`CaptureStats`] into a [`CaptureTelemetry`] with a *windowed*
/// `drop_rate`. One entry per capture source; remembers the last
/// sampled cumulative `(packets, drops)` so the next sample can compute
/// the delta over the window.
pub(crate) struct TelemetrySampler {
    /// Last sampled cumulative `(packets, drops)` per source index.
    last: Vec<(u64, u64)>,
}

impl TelemetrySampler {
    /// One slot per capture source, all starting at zero.
    pub(crate) fn new(num_sources: usize) -> Self {
        Self {
            last: vec![(0, 0); num_sources],
        }
    }

    /// Fold a fresh cumulative reading for `source` into a
    /// [`CaptureTelemetry`], computing the windowed drop rate against
    /// the previous reading. `cum` must be the source's *cumulative*
    /// stats (e.g. from [`Capture::cumulative_stats`](crate::Capture)),
    /// not a destructive single read.
    pub(crate) fn sample(&mut self, source: usize, cum: CaptureStats) -> CaptureTelemetry {
        let packets = cum.packets as u64;
        let drops = cum.drops as u64;

        let (last_packets, last_drops) = self.last[source];
        // `saturating_sub` guards the (pathological) case where a
        // counter appears to go backwards — e.g. an AF_XDP reset or a
        // wrap we failed to accumulate. Better a 0-delta window than a
        // garbage rate from underflow.
        let window_packets = packets.saturating_sub(last_packets);
        let window_drops = drops.saturating_sub(last_drops);
        self.last[source] = (packets, drops);

        let window_total = window_packets + window_drops;
        let drop_rate = if window_total == 0 {
            0.0
        } else {
            window_drops as f64 / window_total as f64
        };

        CaptureTelemetry {
            source: SourceIdx(source as u8),
            packets,
            drops,
            freezes: cum.freeze_count as u64,
            drop_rate,
        }
    }
}

/// Boxed `on_capture_stats` callback. `FnMut` (not `Fn`) so the closure
/// can keep its own running state across samples; `Send` so the run-loop
/// future that owns it stays `Send`.
pub(crate) type BoxedCaptureStatsHandler =
    Box<dyn FnMut(&CaptureTelemetry, &mut Ctx<'_>) -> Result<()> + Send>;

/// One registered `on_capture_stats` handler: the sample period plus the
/// boxed callback. Stored as `Option<CaptureStatsRegistration>` on the
/// builder/monitor — at most one telemetry handler, fired once per
/// source per period.
pub(crate) struct CaptureStatsRegistration {
    /// How often the run loop samples + fires the handler.
    pub(crate) period: Duration,
    /// The user callback, invoked once per source each period.
    pub(crate) handler: BoxedCaptureStatsHandler,
}

impl std::fmt::Debug for CaptureStatsRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureStatsRegistration")
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(packets: u32, drops: u32, freezes: u32) -> CaptureStats {
        CaptureStats {
            packets,
            drops,
            freeze_count: freezes,
        }
    }

    #[test]
    fn windowed_drop_rate_uses_the_delta_not_the_lifetime_total() {
        let mut s = TelemetrySampler::new(1);

        // First window: 1000 delivered, 0 dropped → clean.
        let t0 = s.sample(0, stats(1000, 0, 0));
        assert_eq!(t0.packets, 1000);
        assert_eq!(t0.drops, 0);
        assert_eq!(t0.drop_rate, 0.0);
        assert_eq!(t0.lifetime_drop_rate(), 0.0);

        // Second window: +100 delivered, +900 dropped. Lifetime totals
        // are now 1100/900 (45% lifetime), but the *window* lost 90%.
        let t1 = s.sample(0, stats(1100, 900, 3));
        assert_eq!(t1.packets, 1100);
        assert_eq!(t1.drops, 900);
        assert_eq!(t1.freezes, 3);
        assert!(
            (t1.drop_rate - 0.9).abs() < 1e-9,
            "window rate = {}",
            t1.drop_rate
        );
        assert!(
            (t1.lifetime_drop_rate() - 0.45).abs() < 1e-9,
            "lifetime rate = {}",
            t1.lifetime_drop_rate()
        );
        assert!(t1.is_degraded(0.5));
        assert!(!t1.is_degraded(0.95));
    }

    #[test]
    fn idle_window_reports_zero_drop_rate_not_nan() {
        let mut s = TelemetrySampler::new(1);
        let _ = s.sample(0, stats(500, 10, 0));
        // No new traffic since the last sample: window delta is 0/0.
        let t = s.sample(0, stats(500, 10, 0));
        assert_eq!(t.drop_rate, 0.0);
        assert!(!t.drop_rate.is_nan());
    }

    #[test]
    fn counter_going_backwards_saturates_to_zero_window() {
        let mut s = TelemetrySampler::new(1);
        let _ = s.sample(0, stats(1000, 50, 0));
        // Pathological reset: cumulative appears to drop. Saturating
        // sub yields a 0-delta window instead of an underflow panic /
        // garbage rate.
        let t = s.sample(0, stats(10, 1, 0));
        assert_eq!(t.drop_rate, 0.0);
        assert_eq!(t.packets, 10);
    }

    #[test]
    fn capture_health_flattens_telemetry_including_lifetime_rate() {
        let mut s = TelemetrySampler::new(1);
        let _ = s.sample(0, stats(1000, 0, 0));
        let t = s.sample(0, stats(1100, 900, 3));
        let h = CaptureHealth::from(t);
        assert_eq!(h.source, 0);
        assert_eq!(h.packets, 1100);
        assert_eq!(h.drops, 900);
        assert_eq!(h.freezes, 3);
        assert!((h.drop_rate - 0.9).abs() < 1e-9);
        assert!((h.lifetime_drop_rate - 0.45).abs() < 1e-9);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn capture_health_serializes_to_a_json_line() {
        let h = CaptureHealth {
            source: 1,
            packets: 42,
            drops: 7,
            freezes: 0,
            drop_rate: 0.25,
            lifetime_drop_rate: 0.14,
        };
        let line = serde_json::to_string(&h).expect("serialize");
        assert!(line.contains("\"source\":1"));
        assert!(line.contains("\"packets\":42"));
        assert!(line.contains("\"drop_rate\":0.25"));
    }

    #[test]
    fn sources_are_tracked_independently() {
        let mut s = TelemetrySampler::new(2);
        let _ = s.sample(0, stats(100, 0, 0));
        let _ = s.sample(1, stats(0, 0, 0));
        // Source 0 stays clean; source 1 takes all the loss.
        let a = s.sample(0, stats(200, 0, 0));
        let b = s.sample(1, stats(100, 100, 0));
        assert_eq!(a.source, SourceIdx(0));
        assert_eq!(a.drop_rate, 0.0);
        assert_eq!(b.source, SourceIdx(1));
        assert!((b.drop_rate - 0.5).abs() < 1e-9);
    }
}
