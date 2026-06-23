//! AF_XDP statistics with stable field names.
//!
//! `libc::xdp_statistics` mirrors the kernel struct directly. Wrapping it in a
//! netring-owned type insulates downstream from libc field-name churn and gives
//! us a consistent place to document the kernel semantics.

/// Decoded AF_XDP socket statistics.
///
/// Mirrors `xdp_statistics` from the Linux kernel. Counters are
/// monotonically non-decreasing for the lifetime of the socket
/// (no destructive-read semantics like AF_PACKET's `PACKET_STATISTICS`).
///
/// Returned by [`XdpSocket::statistics()`](crate::XdpSocket::statistics).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XdpStats {
    /// RX descriptors dropped because the fill ring was empty.
    ///
    /// Indicates the user-side fill cadence is too slow — increase
    /// `frame_count` or refill more aggressively.
    pub rx_dropped: u64,
    /// RX descriptors the kernel rejected as invalid.
    pub rx_invalid_descs: u64,
    /// TX descriptors the kernel rejected as invalid (bad addr / len).
    pub tx_invalid_descs: u64,
    /// RX drops attributed to the RX ring being full (slow consumer).
    pub rx_ring_full: u64,
    /// RX descriptors the kernel could not produce because the fill ring
    /// became empty in mid-batch.
    pub rx_fill_ring_empty_descs: u64,
    /// TX kicks issued while the TX ring was empty (no-ops).
    pub tx_ring_empty_descs: u64,
}

impl From<libc::xdp_statistics> for XdpStats {
    fn from(s: libc::xdp_statistics) -> Self {
        Self {
            rx_dropped: s.rx_dropped,
            rx_invalid_descs: s.rx_invalid_descs,
            tx_invalid_descs: s.tx_invalid_descs,
            rx_ring_full: s.rx_ring_full,
            rx_fill_ring_empty_descs: s.rx_fill_ring_empty_descs,
            tx_ring_empty_descs: s.tx_ring_empty_descs,
        }
    }
}

// These projections are pure logic (no AF_XDP syscall surface), so they
// compile and unit-test in any feature build. Their callers (the Monitor
// XDP backend arms + `AsyncXdpCapture`) live behind an awkward product of
// `af-xdp` × `tokio` × `flow` × `xdp-loader`, so rather than chase that cfg
// they carry a blanket dead-code allowance — under `--all-features` (CI's
// strict job) they are all exercised.
#[allow(dead_code)]
impl XdpStats {
    /// Field-wise saturating sum — used to aggregate per-queue socket
    /// statistics into one backend-wide snapshot (issue #39 / `XdpMq`).
    pub(crate) fn saturating_add(self, other: Self) -> Self {
        Self {
            rx_dropped: self.rx_dropped.saturating_add(other.rx_dropped),
            rx_invalid_descs: self.rx_invalid_descs.saturating_add(other.rx_invalid_descs),
            tx_invalid_descs: self.tx_invalid_descs.saturating_add(other.tx_invalid_descs),
            rx_ring_full: self.rx_ring_full.saturating_add(other.rx_ring_full),
            rx_fill_ring_empty_descs: self
                .rx_fill_ring_empty_descs
                .saturating_add(other.rx_fill_ring_empty_descs),
            tx_ring_empty_descs: self
                .tx_ring_empty_descs
                .saturating_add(other.tx_ring_empty_descs),
        }
    }

    /// The queue-pressure drop total: descriptors lost because the
    /// consumer/refill cadence couldn't keep up (`rx_dropped` +
    /// `rx_ring_full` + `rx_fill_ring_empty_descs`). This is what gets
    /// surfaced as the unified [`CaptureStats::drops`] so the windowed
    /// drop rate stays a "consumer too slow" signal — it deliberately
    /// **excludes** `rx_invalid_descs` (a driver/descriptor fault, not
    /// backpressure), which remains visible via [`DropBreakdown`].
    ///
    /// [`CaptureStats::drops`]: crate::stats::CaptureStats::drops
    /// [`DropBreakdown`]: crate::stats::DropBreakdown
    pub(crate) fn queue_pressure_drops(&self) -> u64 {
        self.rx_dropped
            .saturating_add(self.rx_ring_full)
            .saturating_add(self.rx_fill_ring_empty_descs)
    }

    /// Project to the unified [`CaptureStats`](crate::stats::CaptureStats).
    /// `packets` is 0 (`XDP_STATISTICS` exposes no RX packet count) and
    /// `drops` is the [queue-pressure](Self::queue_pressure_drops) total.
    pub(crate) fn to_capture_stats(self) -> crate::stats::CaptureStats {
        crate::stats::CaptureStats {
            packets: 0,
            drops: self.queue_pressure_drops().min(u32::MAX as u64) as u32,
            freeze_count: 0,
        }
    }
}

impl From<XdpStats> for crate::stats::DropBreakdown {
    fn from(s: XdpStats) -> Self {
        crate::stats::DropBreakdown::Xdp {
            rx_dropped: s.rx_dropped,
            rx_invalid_descs: s.rx_invalid_descs,
            rx_ring_full: s.rx_ring_full,
            rx_fill_ring_empty_descs: s.rx_fill_ring_empty_descs,
            tx_invalid_descs: s.tx_invalid_descs,
            tx_ring_empty_descs: s.tx_ring_empty_descs,
        }
    }
}

impl std::fmt::Display for XdpStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rx_dropped={} rx_invalid={} tx_invalid={} rx_ring_full={} rx_fill_empty={} tx_ring_empty={}",
            self.rx_dropped,
            self.rx_invalid_descs,
            self.tx_invalid_descs,
            self.rx_ring_full,
            self.rx_fill_ring_empty_descs,
            self.tx_ring_empty_descs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_libc_round_trip() {
        let raw = libc::xdp_statistics {
            rx_dropped: 1,
            rx_invalid_descs: 2,
            tx_invalid_descs: 3,
            rx_ring_full: 4,
            rx_fill_ring_empty_descs: 5,
            tx_ring_empty_descs: 6,
        };
        let s = XdpStats::from(raw);
        assert_eq!(s.rx_dropped, 1);
        assert_eq!(s.rx_invalid_descs, 2);
        assert_eq!(s.tx_invalid_descs, 3);
        assert_eq!(s.rx_ring_full, 4);
        assert_eq!(s.rx_fill_ring_empty_descs, 5);
        assert_eq!(s.tx_ring_empty_descs, 6);
    }

    #[test]
    fn display_format() {
        let s = XdpStats {
            rx_dropped: 7,
            ..XdpStats::default()
        };
        let out = s.to_string();
        assert!(out.contains("rx_dropped=7"));
        assert!(out.contains("tx_ring_empty=0"));
    }

    #[test]
    fn to_capture_stats_drops_are_queue_pressure_only() {
        // A large invalid-desc count (driver fault) must NOT inflate the
        // unified `drops` — that counter stays a "consumer too slow"
        // signal. Only rx_dropped + rx_ring_full + rx_fill_ring_empty.
        let s = XdpStats {
            rx_dropped: 1,
            rx_invalid_descs: 1000,
            rx_ring_full: 2,
            rx_fill_ring_empty_descs: 4,
            tx_invalid_descs: 9,
            tx_ring_empty_descs: 9,
        };
        let cs = s.to_capture_stats();
        assert_eq!(cs.packets, 0, "XDP_STATISTICS has no RX packet count");
        assert_eq!(cs.drops, 7, "1 + 2 + 4 — invalid_descs excluded");
        assert_eq!(cs.freeze_count, 0);
        // The full picture is still reachable via the breakdown.
        let b = crate::stats::DropBreakdown::from(s);
        assert_eq!(b.total_rx_drops(), 1007);
    }

    #[test]
    fn saturating_add_sums_each_field_independently() {
        let a = XdpStats {
            rx_dropped: 1,
            rx_invalid_descs: 2,
            tx_invalid_descs: 3,
            rx_ring_full: 4,
            rx_fill_ring_empty_descs: 5,
            tx_ring_empty_descs: 6,
        };
        let sum = a.saturating_add(a);
        assert_eq!(sum.rx_dropped, 2);
        assert_eq!(sum.rx_invalid_descs, 4);
        assert_eq!(sum.tx_invalid_descs, 6);
        assert_eq!(sum.rx_ring_full, 8);
        assert_eq!(sum.rx_fill_ring_empty_descs, 10);
        assert_eq!(sum.tx_ring_empty_descs, 12);
        // Saturates instead of wrapping.
        let big = XdpStats {
            rx_dropped: u64::MAX,
            ..XdpStats::default()
        };
        assert_eq!(big.saturating_add(big).rx_dropped, u64::MAX);
    }
}
