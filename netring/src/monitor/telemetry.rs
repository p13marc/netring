//! Capture-level telemetry (0.24 Phase C).
//!
//! The [`Monitor`](crate::monitor::Monitor) run loop can sample each
//! capture source's kernel counters on a fixed interval and hand the
//! result to a user callback registered with
//! [`MonitorBuilder::on_capture_stats`](crate::monitor::MonitorBuilder::on_capture_stats).
//! This is the "is my capture keeping up?" signal: packets delivered,
//! packets the kernel dropped (no room in the ring), and ring freezes — plus a
//! windowed [`drop_rate`](CaptureTelemetry::drop_rate) so a transient
//! burst of loss is visible even when lifetime totals dwarf it.
//!
//! Sampling is **gated**: a monitor with no `on_capture_stats` handler
//! never arms the interval and pays nothing (same zero-cost pattern as
//! the tick / merge run-loop branches).

use std::time::Duration;

use crate::ctx::{Ctx, SourceIdx};
use crate::error::Result;
use crate::stats::{DropBreakdown, SourceCounters};

/// A per-source snapshot of capture health, delivered to an
/// [`on_capture_stats`](crate::monitor::MonitorBuilder::on_capture_stats)
/// handler once per sample period.
///
/// `packets` / `drops` / `freezes` are **cumulative** since the monitor
/// started — including across a [`BackendErrorPolicy::Reopen`](crate::monitor::BackendErrorPolicy::Reopen)
/// of the source, whose fresh kernel counters are added onto the old
/// totals. [`drop_rate`](Self::drop_rate) is computed over the most recent
/// sample window, so it reflects *current* loss rather than a lifetime
/// average.
///
/// The counters are `u64` end to end (the monitor accumulates the kernel's
/// `u32` reads itself), so they keep counting past `u32::MAX` — a busy
/// 10 GbE link gets there in minutes.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct CaptureTelemetry {
    /// Which capture source produced this sample — the interface's
    /// index in builder `.interfaces([...])` registration order.
    pub source: SourceIdx,
    /// Cumulative packets delivered to userspace: passed the kernel BPF
    /// filter and were placed in the ring. Excludes [`drops`](Self::drops)
    /// (unlike [`CaptureStats::packets`](crate::CaptureStats::packets),
    /// which follows the kernel's AF_PACKET convention of including them).
    pub packets: u64,
    /// Cumulative packets the kernel dropped because the ring had no room
    /// for them (AF_PACKET: `tp_drops`; AF_XDP: `rx_dropped +
    /// rx_ring_full`). Non-zero here means the consumer isn't draining
    /// fast enough (or the ring is undersized).
    pub drops: u64,
    /// Cumulative ring-buffer freeze events. For TPACKET_V3 a freeze is
    /// the kernel running out of usable blocks; frequent freezes track
    /// with drops and point at the same backpressure.
    pub freezes: u64,
    /// Drop rate over the **most recent sample window**, in `[0.0, 1.0]`:
    /// the fraction of the packets that reached the socket in the window
    /// which were dropped, `window_drops / (window_packets + window_drops)`.
    /// `0.0` when the window saw no traffic at all. Distinct from
    /// [`lifetime_drop_rate`](Self::lifetime_drop_rate), which averages
    /// over the whole run.
    pub drop_rate: f64,
    /// Per-source breakdown of **where** the drops happened (issue #39):
    /// [`DropBreakdown::AfPacket`] for an AF_PACKET source,
    /// [`DropBreakdown::Xdp`] for an AF_XDP source (with each drop cause
    /// kept distinct). The flat [`drops`](Self::drops) tells you *how
    /// many*; this tells you *why*.
    pub detail: DropBreakdown,
    /// Cumulative frames this source's [`Dedup`](crate::Dedup) dropped as
    /// duplicates ([`MonitorBuilder::dedup`](crate::monitor::MonitorBuilder::dedup));
    /// `0` when no dedup is configured. New in 0.31.1.
    pub dedup_dropped: u64,
}

impl CaptureTelemetry {
    /// Cumulative drop rate over the entire run so far: the fraction of all
    /// packets that reached the socket which were dropped,
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

    /// Emit this sample as Prometheus-style gauges through the `metrics`
    /// facade (feature `metrics`).
    ///
    /// Four gauges, each tagged `source="<idx>"`:
    /// [`netring_capture_packets`](crate::metrics::GAUGE_PACKETS),
    /// [`netring_capture_drops`](crate::metrics::GAUGE_DROPS),
    /// [`netring_capture_freezes`](crate::metrics::GAUGE_FREEZES) (all
    /// cumulative), and
    /// [`netring_capture_dedup_dropped`](crate::metrics::GAUGE_DEDUP_DROPPED)
    /// (0.31.1), and
    /// [`netring_capture_drop_rate`](crate::metrics::GAUGE_DROP_RATE) (the
    /// windowed rate). Gauges, not counters: `drop_rate` is a rate and the
    /// totals are read as absolute cumulative values, so a scrape always
    /// sees the latest sample rather than an increment.
    ///
    /// Call from an [`on_capture_stats`](crate::monitor::MonitorBuilder::on_capture_stats)
    /// handler, or use the
    /// [`capture_metrics`](crate::monitor::MonitorBuilder::capture_metrics)
    /// builder sugar. A no-op until the host app installs a `metrics`
    /// recorder.
    #[cfg(feature = "metrics")]
    pub fn record_metrics(&self) {
        let source = self.source.0.to_string();
        metrics::gauge!(crate::metrics::GAUGE_PACKETS, "source" => source.clone())
            .set(self.packets as f64);
        metrics::gauge!(crate::metrics::GAUGE_DROPS, "source" => source.clone())
            .set(self.drops as f64);
        metrics::gauge!(crate::metrics::GAUGE_FREEZES, "source" => source.clone())
            .set(self.freezes as f64);
        metrics::gauge!(crate::metrics::GAUGE_DROP_RATE, "source" => source.clone())
            .set(self.drop_rate);
        metrics::gauge!(crate::metrics::GAUGE_DEDUP_DROPPED, "source" => source)
            .set(self.dedup_dropped as f64);
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
#[non_exhaustive]
pub struct CaptureHealth {
    /// Capture source index (interface registration order).
    pub source: u8,
    /// Cumulative packets delivered to userspace (excludes `drops`).
    pub packets: u64,
    /// Cumulative packets the kernel dropped for lack of ring space.
    pub drops: u64,
    /// Cumulative ring freeze events.
    pub freezes: u64,
    /// Windowed drop rate over the most recent sample period, `[0.0, 1.0]`.
    pub drop_rate: f64,
    /// Cumulative drop rate over the whole run, `[0.0, 1.0]`.
    pub lifetime_drop_rate: f64,
    /// Per-source drop breakdown (issue #39) — serializes as a tagged
    /// object (`{"AfPacket":{…}}` / `{"Xdp":{…}}`) so the report line is
    /// self-describing about *where* loss occurred.
    pub detail: DropBreakdown,
    /// Cumulative frames dropped as duplicates by the source's dedup
    /// (`0` without one). New in 0.31.1.
    pub dedup_dropped: u64,
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
            detail: t.detail,
            dedup_dropped: t.dedup_dropped,
        }
    }
}

/// Internal per-source accumulator that turns the backends' cumulative
/// [`SourceCounters`] into a [`CaptureTelemetry`] with a *windowed*
/// `drop_rate`. One slot per capture source.
///
/// A backend's counters restart from zero when the source is reopened
/// (`BackendErrorPolicy::Reopen`), so each slot keeps a `base` — the totals
/// of the backends that came before — and reports `base + current`. The
/// run loop announces a reopen with [`retire`](Self::retire); a counter
/// that goes backwards without one is treated the same way. Either way the
/// reported totals stay monotonic and no window sees a negative delta
/// (#184).
pub(crate) struct TelemetrySampler {
    slots: Vec<SamplerSlot>,
}

#[derive(Default, Clone, Copy)]
struct SamplerSlot {
    /// Totals carried over from retired backends.
    base: SourceCounters,
    base_detail: Option<DropBreakdown>,
    /// The current backend's last reading.
    last_raw: SourceCounters,
    last_raw_detail: Option<DropBreakdown>,
    /// The last cumulative value reported (`base + last_raw`).
    last_cum: SourceCounters,
}

impl SamplerSlot {
    /// Fold the current backend's counters into `base` and start over.
    fn rebase(&mut self, fin: SourceCounters, fin_detail: Option<DropBreakdown>) {
        self.base = self.base.saturating_add(fin);
        self.base_detail = match (self.base_detail, fin_detail) {
            (Some(b), Some(f)) => Some(b.saturating_add(f)),
            (b, f) => f.or(b),
        };
        self.last_raw = SourceCounters::default();
        self.last_raw_detail = None;
    }
}

impl TelemetrySampler {
    /// One slot per capture source, all starting at zero.
    pub(crate) fn new(num_sources: usize) -> Self {
        Self {
            slots: vec![SamplerSlot::default(); num_sources],
        }
    }

    /// Fold a fresh cumulative reading of `source`'s current backend into a
    /// [`CaptureTelemetry`], computing the windowed drop rate against the
    /// previous sample. `raw` must be the backend's *cumulative* counters,
    /// not a destructive single read. `detail` is the matching per-source
    /// [`DropBreakdown`] read in the same pass.
    pub(crate) fn sample(
        &mut self,
        source: usize,
        raw: SourceCounters,
        detail: DropBreakdown,
    ) -> CaptureTelemetry {
        let slot = &mut self.slots[source];
        let last = slot.last_raw;
        if raw.delivered < last.delivered || raw.drops < last.drops || raw.freezes < last.freezes {
            // The backend's counters restarted without a `retire` — keep
            // what it had counted.
            let last_detail = slot.last_raw_detail;
            slot.rebase(last, last_detail);
        }
        let cum = slot.base.saturating_add(raw);
        let window = cum.saturating_sub(slot.last_cum);
        slot.last_raw = raw;
        slot.last_raw_detail = Some(detail);
        slot.last_cum = cum;

        let window_total = window.delivered.saturating_add(window.drops);
        let drop_rate = if window_total == 0 {
            0.0
        } else {
            window.drops as f64 / window_total as f64
        };

        CaptureTelemetry {
            source: SourceIdx(source as u8),
            packets: cum.delivered,
            drops: cum.drops,
            freezes: cum.freezes,
            drop_rate,
            detail: match slot.base_detail {
                Some(b) => b.saturating_add(detail),
                None => detail,
            },
            dedup_dropped: 0,
        }
    }

    /// `source`'s backend is being replaced (`BackendErrorPolicy::Reopen`):
    /// fold its final reading — or, if that couldn't be read, its last
    /// sampled one — into the source's base. A no-op when telemetry isn't
    /// armed (no slots).
    pub(crate) fn retire(&mut self, source: usize, fin: Option<(SourceCounters, DropBreakdown)>) {
        let Some(slot) = self.slots.get_mut(source) else {
            return;
        };
        match fin {
            Some((counters, detail)) => slot.rebase(counters, Some(detail)),
            None => {
                let (last, last_detail) = (slot.last_raw, slot.last_raw_detail);
                slot.rebase(last, last_detail);
            }
        }
    }

    /// The last cumulative totals reported for `source` (for a sample whose
    /// read failed, so the health totals don't dip).
    pub(crate) fn last_cumulative(&self, source: usize) -> Option<SourceCounters> {
        self.slots.get(source).map(|s| s.last_cum)
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

    /// A backend's cumulative counters: `delivered` excludes `drops`.
    fn stats(delivered: u64, drops: u64, freezes: u64) -> SourceCounters {
        SourceCounters {
            delivered,
            drops,
            freezes,
        }
    }

    /// AF_PACKET drop breakdown for a given freeze count — the detail
    /// companion to [`stats`] in these sampler tests.
    fn afp(freezes: u64) -> DropBreakdown {
        DropBreakdown::AfPacket { freezes }
    }

    /// The counters an AF_PACKET backend reports after one kernel read of
    /// `tp_packets` / `tp_drops` (the kernel includes the drops in
    /// `tp_packets`).
    fn afp_read(tp_packets: u32, tp_drops: u32) -> SourceCounters {
        SourceCounters::default().add_tpacket_v3(crate::afpacket::ffi::tpacket_stats_v3 {
            tp_packets,
            tp_drops,
            tp_freeze_q_cnt: 0,
        })
    }

    #[test]
    fn windowed_drop_rate_uses_the_delta_not_the_lifetime_total() {
        let mut s = TelemetrySampler::new(1);

        // First window: 1000 delivered, 0 dropped → clean.
        let t0 = s.sample(0, stats(1000, 0, 0), afp(0));
        assert_eq!(t0.packets, 1000);
        assert_eq!(t0.drops, 0);
        assert_eq!(t0.drop_rate, 0.0);
        assert_eq!(t0.lifetime_drop_rate(), 0.0);

        // Second window: +100 delivered, +900 dropped. Lifetime totals
        // are now 1100/900 (45% lifetime), but the *window* lost 90%.
        let t1 = s.sample(0, stats(1100, 900, 3), afp(3));
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
        let _ = s.sample(0, stats(500, 10, 0), afp(0));
        // No new traffic since the last sample: window delta is 0/0.
        let t = s.sample(0, stats(500, 10, 0), afp(0));
        assert_eq!(t.drop_rate, 0.0);
        assert!(!t.drop_rate.is_nan());
    }

    /// #183: a fully overloaded AF_PACKET socket reports `tp_packets ==
    /// tp_drops` (the kernel adds the drops in). That is 100% loss, not the
    /// 50% the old `drops / (packets + drops)` on raw `tp_packets` gave.
    #[test]
    fn af_packet_total_loss_reads_one_not_one_half() {
        let mut s = TelemetrySampler::new(1);
        let t = s.sample(0, afp_read(1000, 1000), afp(0));
        assert_eq!(t.packets, 0);
        assert_eq!(t.drops, 1000);
        assert_eq!(t.drop_rate, 1.0);
        assert_eq!(t.lifetime_drop_rate(), 1.0);
        let mut s = TelemetrySampler::new(1);
        let t = s.sample(0, afp_read(2000, 1000), afp(0));
        assert!((t.drop_rate - 0.5).abs() < 1e-9, "rate = {}", t.drop_rate);
    }

    /// #183: an AF_XDP source now reports its received packets, so its
    /// rate is a fraction, not 0-or-1.
    #[test]
    fn xdp_rate_is_a_fraction() {
        let mut s = TelemetrySampler::new(1);
        let xdp = |n: u64, d: u64| {
            crate::afxdp::XdpStats {
                rx_dropped: d,
                ..Default::default()
            }
            .counters(n)
        };
        let _ = s.sample(0, xdp(0, 0), afp(0));
        let t = s.sample(0, xdp(900, 100), afp(0));
        assert!((t.drop_rate - 0.1).abs() < 1e-9, "rate = {}", t.drop_rate);
    }

    /// #184: past `u32::MAX` the windows keep moving.
    #[test]
    fn counters_past_u32_keep_the_window_moving() {
        let mut s = TelemetrySampler::new(1);
        let _ = s.sample(0, stats(5_000_000_000, 5_000_000_000, 0), afp(0));
        let t = s.sample(0, stats(5_000_001_000, 5_000_001_000, 0), afp(0));
        assert_eq!(t.packets, 5_000_001_000);
        assert!((t.drop_rate - 0.5).abs() < 1e-9, "rate = {}", t.drop_rate);
    }

    /// #184: a reopened backend restarts from zero; with its final reading
    /// retired into the base, totals stay monotonic and the window is
    /// exact.
    #[test]
    fn reopen_with_final_reading_rebases() {
        let mut s = TelemetrySampler::new(1);
        let _ = s.sample(0, stats(1000, 50, 2), afp(2));
        s.retire(0, Some((stats(1200, 60, 2), afp(2))));
        let t = s.sample(0, stats(100, 40, 0), afp(0));
        assert_eq!((t.packets, t.drops, t.freezes), (1300, 100, 2));
        // Window: (1300 - 1000) delivered, (100 - 50) dropped.
        assert!(
            (t.drop_rate - 50.0 / 350.0).abs() < 1e-9,
            "rate = {}",
            t.drop_rate
        );
        assert_eq!(t.detail, afp(2));
    }

    #[test]
    fn reopen_without_final_reading_keeps_the_last_sample() {
        let mut s = TelemetrySampler::new(1);
        let _ = s.sample(0, stats(1000, 50, 0), afp(0));
        s.retire(0, None);
        let t = s.sample(0, stats(100, 40, 0), afp(0));
        assert_eq!((t.packets, t.drops), (1100, 90));
        assert!(
            (t.drop_rate - 40.0 / 140.0).abs() < 1e-9,
            "rate = {}",
            t.drop_rate
        );
    }

    /// A reset nobody announced: the old code saturated each field on its
    /// own and reported a window of (0 delivered, 5 dropped) = rate 1.0.
    #[test]
    fn counter_going_backwards_is_treated_as_a_reset() {
        let mut s = TelemetrySampler::new(1);
        let _ = s.sample(0, stats(1000, 0, 0), afp(0));
        let t = s.sample(0, stats(10, 5, 0), afp(0));
        assert_eq!((t.packets, t.drops), (1010, 5));
        assert!(
            (t.drop_rate - 5.0 / 15.0).abs() < 1e-9,
            "rate = {}",
            t.drop_rate
        );
        // And it keeps counting from there.
        let t = s.sample(0, stats(20, 5, 0), afp(0));
        assert_eq!(t.packets, 1020);
        assert_eq!(t.drop_rate, 0.0);
    }

    #[test]
    fn retire_without_slots_is_a_noop() {
        let mut s = TelemetrySampler::new(0);
        s.retire(3, None);
        assert_eq!(s.last_cumulative(3), None);
    }

    #[test]
    fn capture_health_flattens_telemetry_including_lifetime_rate() {
        let mut s = TelemetrySampler::new(1);
        let _ = s.sample(0, stats(1000, 0, 0), afp(0));
        let t = s.sample(0, stats(1100, 900, 3), afp(3));
        let h = CaptureHealth::from(t);
        assert_eq!(h.source, 0);
        assert_eq!(h.packets, 1100);
        assert_eq!(h.drops, 900);
        assert_eq!(h.freezes, 3);
        assert!((h.drop_rate - 0.9).abs() < 1e-9);
        assert!((h.lifetime_drop_rate - 0.45).abs() < 1e-9);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn record_metrics_is_a_noop_without_a_recorder() {
        // With no `metrics` recorder installed the gauge! macros are
        // no-ops — recording must succeed regardless (mirrors
        // `metrics::tests::record_does_not_panic_with_no_recorder`).
        let mut s = TelemetrySampler::new(1);
        let t = s.sample(0, stats(1000, 10, 0), afp(0));
        t.record_metrics();
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
            detail: DropBreakdown::AfPacket { freezes: 0 },
            dedup_dropped: 3,
        };
        let line = serde_json::to_string(&h).expect("serialize");
        assert!(line.contains("\"dedup_dropped\":3"));
        assert!(line.contains("\"source\":1"));
        assert!(line.contains("\"packets\":42"));
        assert!(line.contains("\"drop_rate\":0.25"));
        // The drop breakdown rides the same JSON line.
        assert!(line.contains("\"detail\""));
        assert!(line.contains("\"AfPacket\""));
    }

    #[test]
    fn xdp_detail_is_carried_through_the_sample_uncollapsed() {
        let mut s = TelemetrySampler::new(1);
        let detail = DropBreakdown::Xdp {
            rx_dropped: 1,
            rx_invalid_descs: 2,
            rx_ring_full: 3,
            rx_fill_ring_empty_descs: 4,
            tx_invalid_descs: 5,
            tx_ring_empty_descs: 6,
        };
        // The unified `drops` is whatever the backend computed; the sampler
        // folds it into the windowed rate but must carry the per-source
        // breakdown through verbatim.
        let t = s.sample(0, stats(0, 8, 0), detail);
        assert_eq!(t.detail, detail);
        match t.detail {
            DropBreakdown::Xdp {
                rx_invalid_descs, ..
            } => assert_eq!(rx_invalid_descs, 2),
            _ => panic!("expected an Xdp breakdown"),
        }
    }

    #[test]
    fn sources_are_tracked_independently() {
        let mut s = TelemetrySampler::new(2);
        let _ = s.sample(0, stats(100, 0, 0), afp(0));
        let _ = s.sample(1, stats(0, 0, 0), afp(0));
        // Source 0 stays clean; source 1 takes all the loss.
        let a = s.sample(0, stats(200, 0, 0), afp(0));
        let b = s.sample(1, stats(100, 100, 0), afp(0));
        assert_eq!(a.source, SourceIdx(0));
        assert_eq!(a.drop_rate, 0.0);
        assert_eq!(b.source, SourceIdx(1));
        assert!((b.drop_rate - 0.5).abs() < 1e-9);
    }
}
