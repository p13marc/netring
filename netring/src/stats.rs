//! Capture statistics.

use crate::afpacket::ffi;
use std::fmt;

/// Capture statistics from the kernel.
///
/// Reading stats via [`stats()`](crate::traits::PacketSource::stats) resets the kernel counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureStats {
    /// Total packets received (passed filter).
    pub packets: u32,
    /// Packets dropped due to ring buffer full.
    pub drops: u32,
    /// Number of times the ring buffer was frozen.
    pub freeze_count: u32,
}

impl From<ffi::tpacket_stats_v3> for CaptureStats {
    fn from(s: ffi::tpacket_stats_v3) -> Self {
        Self {
            packets: s.tp_packets,
            drops: s.tp_drops,
            freeze_count: s.tp_freeze_q_cnt,
        }
    }
}

/// Per-source breakdown of **where** packets were dropped (issue #39).
///
/// The flat [`CaptureStats::drops`] (and the windowed
/// [`drop_rate`](crate::monitor::CaptureTelemetry::drop_rate)) answer *how many*
/// packets were lost; this answers *why*. A silent drop is a monitoring
/// blind spot, and the two backends fail in operationally distinct ways
/// that a single aggregate counter hides:
///
/// * **AF_PACKET** (TPACKET_V3) reports one kernel ring-overflow counter
///   (`tp_drops`, surfaced as `CaptureStats::drops`) plus a ring-freeze
///   count.
/// * **AF_XDP** (`XDP_STATISTICS`) separates several causes. netring keeps
///   them **un-collapsed** here: a full RX ring means a slow consumer; an
///   empty fill ring means slow refill; *invalid descriptors* point at a
///   driver / descriptor-management fault, not backpressure at all. Folding
///   these into one number erases the root-cause signal.
///
/// Delivered per source on [`CaptureTelemetry::detail`](crate::monitor::CaptureTelemetry::detail).
/// The unified `drops` deliberately counts only the queue-pressure sources
/// (`rx_dropped` + `rx_ring_full` + `rx_fill_ring_empty_descs`) so the
/// windowed drop rate stays a "consumer can't keep up" signal;
/// `rx_invalid_descs` and the TX counters are visible **only** here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum DropBreakdown {
    /// AF_PACKET (TPACKET_V3) drop accounting.
    AfPacket {
        /// Ring-buffer freeze events (`tp_freeze_q_cnt`): the kernel ran
        /// out of usable blocks. Tracks with `drops` under backpressure.
        /// (Also surfaced flat as [`CaptureTelemetry::freezes`](crate::monitor::CaptureTelemetry::freezes).)
        freezes: u64,
    },
    /// AF_XDP (`XDP_STATISTICS`) drop accounting — every source kept
    /// distinct rather than summed.
    Xdp {
        /// RX descriptors the kernel dropped (generic RX drop counter).
        rx_dropped: u64,
        /// RX descriptors the kernel rejected as **invalid** — a driver or
        /// descriptor-management fault, *not* backpressure. Excluded from
        /// the unified `drops` so it can't masquerade as a slow consumer.
        rx_invalid_descs: u64,
        /// RX drops because the RX ring was full (slow consumer).
        rx_ring_full: u64,
        /// RX drops because the fill ring was empty mid-batch (slow refill).
        rx_fill_ring_empty_descs: u64,
        /// TX descriptors the kernel rejected as invalid (bad addr / len).
        tx_invalid_descs: u64,
        /// TX kicks issued while the TX ring was empty (no-ops).
        tx_ring_empty_descs: u64,
    },
}

impl DropBreakdown {
    /// Total dropped-descriptor count across every RX source in this
    /// breakdown, in `u64` (no `u32` saturation).
    ///
    /// For AF_PACKET this is `0` — AF_PACKET's drop total lives in
    /// [`CaptureStats::drops`], and this variant only adds the freeze
    /// count. For AF_XDP it sums **all** RX drop causes, *including*
    /// `rx_invalid_descs` — the honest "data you didn't see" figure, which
    /// is wider than the queue-pressure `drops` surfaced flat.
    #[inline]
    pub fn total_rx_drops(&self) -> u64 {
        match *self {
            DropBreakdown::AfPacket { .. } => 0,
            DropBreakdown::Xdp {
                rx_dropped,
                rx_invalid_descs,
                rx_ring_full,
                rx_fill_ring_empty_descs,
                ..
            } => rx_dropped
                .saturating_add(rx_invalid_descs)
                .saturating_add(rx_ring_full)
                .saturating_add(rx_fill_ring_empty_descs),
        }
    }
}

impl fmt::Display for CaptureStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "packets: {}, drops: {}, freezes: {}",
            self.packets, self.drops, self.freeze_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_zero() {
        let s = CaptureStats::default();
        assert_eq!(s.packets, 0);
        assert_eq!(s.drops, 0);
        assert_eq!(s.freeze_count, 0);
    }

    #[test]
    fn from_tpacket_stats_v3() {
        let raw = ffi::tpacket_stats_v3 {
            tp_packets: 100,
            tp_drops: 5,
            tp_freeze_q_cnt: 1,
        };
        let s = CaptureStats::from(raw);
        assert_eq!(s.packets, 100);
        assert_eq!(s.drops, 5);
        assert_eq!(s.freeze_count, 1);
    }

    #[test]
    fn display_format() {
        let s = CaptureStats {
            packets: 42,
            drops: 3,
            freeze_count: 0,
        };
        assert_eq!(s.to_string(), "packets: 42, drops: 3, freezes: 0");
    }

    #[test]
    fn af_packet_breakdown_has_no_rx_drops_only_freezes() {
        let b = DropBreakdown::AfPacket { freezes: 4 };
        assert_eq!(b.total_rx_drops(), 0);
    }

    #[test]
    fn xdp_breakdown_total_rx_drops_includes_invalid_descs() {
        // total_rx_drops is the WIDE figure: it folds in rx_invalid_descs,
        // which the unified `drops` deliberately excludes.
        let b = DropBreakdown::Xdp {
            rx_dropped: 1,
            rx_invalid_descs: 2,
            rx_ring_full: 4,
            rx_fill_ring_empty_descs: 8,
            tx_invalid_descs: 16,
            tx_ring_empty_descs: 32,
        };
        // 1 + 2 + 4 + 8 = 15 (TX counters are not RX drops).
        assert_eq!(b.total_rx_drops(), 15);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn xdp_breakdown_serializes_each_source() {
        let b = DropBreakdown::Xdp {
            rx_dropped: 1,
            rx_invalid_descs: 2,
            rx_ring_full: 3,
            rx_fill_ring_empty_descs: 4,
            tx_invalid_descs: 5,
            tx_ring_empty_descs: 6,
        };
        let json = serde_json::to_string(&b).expect("serialize");
        // Externally-tagged enum: the variant name wraps the fields, and
        // every source is present (none collapsed).
        assert!(json.contains("\"Xdp\""));
        assert!(json.contains("\"rx_invalid_descs\":2"));
        assert!(json.contains("\"rx_ring_full\":3"));
        assert!(json.contains("\"tx_ring_empty_descs\":6"));
    }
}
