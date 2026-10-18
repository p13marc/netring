//! Capture statistics.

use crate::afpacket::ffi;
use std::fmt;

/// Capture statistics: totals since the source was opened.
///
/// One meaning on every backend and every accessor (#186):
///
/// * [`delivered`](Self::delivered) — packets placed in the ring for
///   userspace (they passed the socket filter and found room);
/// * [`drops`](Self::drops) — packets that passed the filter but were
///   dropped for lack of ring space;
/// * [`freezes`](Self::freezes) — ring freezes (AF_PACKET only; `0` on
///   AF_XDP).
///
/// [`received`](Self::received) is `delivered + drops`: every packet that
/// reached the socket — the kernel's own `tp_packets` — and
/// [`drop_ratio`](Self::drop_ratio) is `drops / received`.
///
/// Every public accessor returns **totals since the source was opened**
/// and never resets them: two reads with no traffic in between are equal,
/// and a rate over a window is `later.delta_since(&earlier)`. AF_PACKET's
/// kernel counters are reset by each `PACKET_STATISTICS` read, so netring
/// folds every read into a running total on the capture; AF_XDP's
/// `XDP_STATISTICS` are monotonic already. The counters are `u64` and
/// saturate rather than wrap.
///
/// ```
/// use netring::CaptureStats;
///
/// let earlier = CaptureStats::new(1_000, 0, 0);
/// let later = CaptureStats::new(1_900, 100, 1);
/// let window = later.delta_since(&earlier);
/// assert_eq!(window, CaptureStats::new(900, 100, 1));
/// assert_eq!(window.received(), 1_000);
/// assert_eq!(window.drop_ratio(), 0.1);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct CaptureStats {
    /// Packets placed in the ring for userspace: they passed the socket
    /// filter and were not dropped. Excludes [`drops`](Self::drops).
    pub delivered: u64,
    /// Packets that passed the socket filter but were dropped because the
    /// ring had no room for them (AF_PACKET: `tp_drops`; AF_XDP:
    /// `rx_dropped + rx_ring_full`). A slow consumer or an undersized ring.
    pub drops: u64,
    /// Number of times the ring buffer was frozen (AF_PACKET
    /// `tp_freeze_q_cnt`; always `0` on AF_XDP).
    pub freezes: u64,
}

impl CaptureStats {
    /// Statistics with the given totals.
    #[inline]
    pub const fn new(delivered: u64, drops: u64, freezes: u64) -> Self {
        Self {
            delivered,
            drops,
            freezes,
        }
    }

    /// Every packet that reached the socket: `delivered + drops`
    /// (saturating). This is the kernel's AF_PACKET `tp_packets`.
    #[inline]
    pub const fn received(&self) -> u64 {
        self.delivered.saturating_add(self.drops)
    }

    /// The fraction of the [`received`](Self::received) packets that were
    /// dropped, in `[0.0, 1.0]`; `0.0` when nothing was received.
    #[inline]
    pub fn drop_ratio(&self) -> f64 {
        match self.received() {
            0 => 0.0,
            received => self.drops as f64 / received as f64,
        }
    }

    /// The counts between `earlier` and `self` (field-wise saturating
    /// `self - earlier`): what a window between two reads of the same
    /// source saw.
    #[inline]
    pub const fn delta_since(&self, earlier: &Self) -> Self {
        Self {
            delivered: self.delivered.saturating_sub(earlier.delivered),
            drops: self.drops.saturating_sub(earlier.drops),
            freezes: self.freezes.saturating_sub(earlier.freezes),
        }
    }

    /// Field-wise saturating sum — the totals of two sources together.
    #[inline]
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self {
            delivered: self.delivered.saturating_add(other.delivered),
            drops: self.drops.saturating_add(other.drops),
            freezes: self.freezes.saturating_add(other.freezes),
        }
    }

    /// Fold one destructive AF_PACKET `PACKET_STATISTICS` read into these
    /// totals. The kernel reports `tp_packets` with the drops already added
    /// (in `u32`), so the delivered count is split off per read, wrapping —
    /// exact whenever fewer than 2³² packets reached the ring between two
    /// reads.
    #[inline]
    pub(crate) fn add_tpacket_v3(self, raw: ffi::tpacket_stats_v3) -> Self {
        self.saturating_add(Self {
            delivered: u64::from(raw.tp_packets.wrapping_sub(raw.tp_drops)),
            drops: u64::from(raw.tp_drops),
            freezes: u64::from(raw.tp_freeze_q_cnt),
        })
    }
}

impl std::ops::Add for CaptureStats {
    type Output = Self;

    /// Field-wise saturating sum (see [`CaptureStats::saturating_add`]).
    #[inline]
    fn add(self, other: Self) -> Self {
        self.saturating_add(other)
    }
}

impl std::ops::AddAssign for CaptureStats {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        *self = self.saturating_add(other);
    }
}

impl std::iter::Sum for CaptureStats {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), Self::saturating_add)
    }
}

impl<'a> std::iter::Sum<&'a CaptureStats> for CaptureStats {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.copied().sum()
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
///   them **un-collapsed** here: a full RX ring means a slow consumer; drops
///   for lack of a fill-ring buffer show up in `rx_dropped`; the fill-ring
///   and TX empty counters are starvation signals, not packet counts.
///
/// Delivered per source on [`CaptureTelemetry::detail`](crate::monitor::CaptureTelemetry::detail).
/// The unified `drops` counts the packets the socket lost
/// (`rx_dropped` + `rx_ring_full`) so the windowed drop rate stays a
/// "consumer can't keep up" signal; `rx_invalid_descs`, the fill-ring
/// starvation count and the TX counters are visible **only** here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum DropBreakdown {
    /// AF_PACKET (TPACKET_V3) drop accounting.
    AfPacket {
        /// Ring-buffer freeze events (`tp_freeze_q_cnt`): the kernel ran
        /// out of usable blocks. Tracks with `drops` under backpressure.
        /// (Also surfaced flat as [`CaptureTelemetry::freezes`](crate::monitor::CaptureTelemetry::freezes).)
        freezes: u64,
    },
    /// AF_XDP (`XDP_STATISTICS`) drop accounting — every source kept
    /// distinct rather than summed. See [`XdpStats`](crate::XdpStats) for
    /// the kernel semantics of each counter.
    Xdp {
        /// Packets dropped for any reason other than a full RX ring — in
        /// copy mode chiefly "no free buffer in the fill ring" (slow
        /// refill), also frames larger than the UMEM frame.
        rx_dropped: u64,
        /// RX descriptors the kernel counted as invalid. Current mainline
        /// kernels never increment it on the RX side; kept for completeness.
        rx_invalid_descs: u64,
        /// Packets dropped because the RX ring was full (slow consumer).
        rx_ring_full: u64,
        /// Times the kernel found the fill ring empty when it needed a
        /// buffer. A refill-starvation signal, **not** a packet count: in
        /// copy mode each such drop is already in `rx_dropped`; in
        /// zero-copy mode the driver counts failed refill batches and the
        /// NIC drops the packets in hardware (see `ethtool -S`).
        rx_fill_ring_empty_descs: u64,
        /// TX descriptors the kernel rejected as invalid (bad addr / len).
        tx_invalid_descs: u64,
        /// Times the kernel found the TX ring empty when it went to send.
        tx_ring_empty_descs: u64,
    },
}

impl DropBreakdown {
    /// Total dropped-descriptor count across every RX source in this
    /// breakdown, in `u64` (no `u32` saturation).
    ///
    /// For AF_PACKET this is `0` — AF_PACKET's drop total lives in
    /// [`CaptureStats::drops`], and this variant only adds the freeze
    /// count. For AF_XDP it sums the RX packet-loss counters
    /// (`rx_dropped + rx_invalid_descs + rx_ring_full`) — the "data you
    /// didn't see" figure. `rx_fill_ring_empty_descs` is not added: it
    /// counts failed fill-ring reads, and the drops they cause are already
    /// in `rx_dropped` (#182).
    #[inline]
    pub fn total_rx_drops(&self) -> u64 {
        match *self {
            DropBreakdown::AfPacket { .. } => 0,
            DropBreakdown::Xdp {
                rx_dropped,
                rx_invalid_descs,
                rx_ring_full,
                ..
            } => rx_dropped
                .saturating_add(rx_invalid_descs)
                .saturating_add(rx_ring_full),
        }
    }

    /// Field-wise sum of two breakdowns of the same backend (the Monitor
    /// carries counters across a backend reopen). Different variants: the
    /// newer one wins.
    #[cfg_attr(not(all(feature = "flow", feature = "tokio")), allow(dead_code))]
    pub(crate) fn saturating_add(self, other: Self) -> Self {
        match (self, other) {
            (DropBreakdown::AfPacket { freezes: a }, DropBreakdown::AfPacket { freezes: b }) => {
                DropBreakdown::AfPacket {
                    freezes: a.saturating_add(b),
                }
            }
            (
                DropBreakdown::Xdp {
                    rx_dropped: a1,
                    rx_invalid_descs: a2,
                    rx_ring_full: a3,
                    rx_fill_ring_empty_descs: a4,
                    tx_invalid_descs: a5,
                    tx_ring_empty_descs: a6,
                },
                DropBreakdown::Xdp {
                    rx_dropped: b1,
                    rx_invalid_descs: b2,
                    rx_ring_full: b3,
                    rx_fill_ring_empty_descs: b4,
                    tx_invalid_descs: b5,
                    tx_ring_empty_descs: b6,
                },
            ) => DropBreakdown::Xdp {
                rx_dropped: a1.saturating_add(b1),
                rx_invalid_descs: a2.saturating_add(b2),
                rx_ring_full: a3.saturating_add(b3),
                rx_fill_ring_empty_descs: a4.saturating_add(b4),
                tx_invalid_descs: a5.saturating_add(b5),
                tx_ring_empty_descs: a6.saturating_add(b6),
            },
            (_, newer) => newer,
        }
    }
}

impl fmt::Display for CaptureStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "delivered: {}, drops: {}, freezes: {}",
            self.delivered, self.drops, self.freezes
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_zero() {
        let s = CaptureStats::default();
        assert_eq!(s, CaptureStats::new(0, 0, 0));
        assert_eq!(s.received(), 0);
    }

    #[test]
    fn received_is_delivered_plus_drops() {
        let s = CaptureStats::new(100, 5, 1);
        assert_eq!(s.received(), 105);
        assert_eq!(CaptureStats::new(u64::MAX, 1, 0).received(), u64::MAX);
    }

    #[test]
    fn drop_ratio_is_drops_over_received() {
        assert_eq!(CaptureStats::new(900, 100, 0).drop_ratio(), 0.1);
        assert_eq!(CaptureStats::new(0, 7, 0).drop_ratio(), 1.0);
        assert_eq!(CaptureStats::new(7, 0, 3).drop_ratio(), 0.0);
    }

    #[test]
    fn drop_ratio_of_nothing_is_zero_not_nan() {
        let r = CaptureStats::default().drop_ratio();
        assert_eq!(r, 0.0);
        assert!(!r.is_nan());
    }

    #[test]
    fn delta_since_is_field_wise_and_saturating() {
        let earlier = CaptureStats::new(1_000, 10, 1);
        let later = CaptureStats::new(1_500, 30, 1);
        assert_eq!(later.delta_since(&earlier), CaptureStats::new(500, 20, 0));
        assert_eq!(later.delta_since(&later), CaptureStats::default());
        // Reversed operands saturate at zero rather than wrapping.
        assert_eq!(earlier.delta_since(&later), CaptureStats::default());
    }

    #[test]
    fn sum_add_and_add_assign_saturate() {
        let a = CaptureStats::new(1, 2, 3);
        let b = CaptureStats::new(10, 20, 30);
        assert_eq!(a + b, CaptureStats::new(11, 22, 33));
        let mut c = a;
        c += b;
        assert_eq!(c, a + b);
        assert_eq!(
            [a, b, a].into_iter().sum::<CaptureStats>(),
            CaptureStats::new(12, 24, 36)
        );
        assert_eq!([a, b].iter().sum::<CaptureStats>(), a + b);
        assert_eq!(
            std::iter::empty::<CaptureStats>().sum::<CaptureStats>(),
            CaptureStats::default()
        );
        let max = CaptureStats::new(u64::MAX, u64::MAX, u64::MAX);
        assert_eq!(max + a, max);
    }

    #[test]
    fn display_format() {
        let s = CaptureStats::new(42, 3, 0);
        assert_eq!(s.to_string(), "delivered: 42, drops: 3, freezes: 0");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serializes_named_fields() {
        let json = serde_json::to_string(&CaptureStats::new(42, 3, 1)).unwrap();
        assert_eq!(json, r#"{"delivered":42,"drops":3,"freezes":1}"#);
    }

    #[test]
    fn af_packet_breakdown_has_no_rx_drops_only_freezes() {
        let b = DropBreakdown::AfPacket { freezes: 4 };
        assert_eq!(b.total_rx_drops(), 0);
    }

    #[test]
    fn xdp_breakdown_total_rx_drops_includes_invalid_descs() {
        // total_rx_drops is the WIDE figure: it folds in rx_invalid_descs,
        // which the unified `drops` excludes. The fill-ring and TX counters
        // are not packet drops.
        let b = DropBreakdown::Xdp {
            rx_dropped: 1,
            rx_invalid_descs: 2,
            rx_ring_full: 4,
            rx_fill_ring_empty_descs: 8,
            tx_invalid_descs: 16,
            tx_ring_empty_descs: 32,
        };
        assert_eq!(b.total_rx_drops(), 1 + 2 + 4);
    }

    /// #182: in copy mode one packet lost for lack of a fill-ring buffer
    /// bumps both `rx_dropped` and `rx_fill_ring_empty_descs`; it is one
    /// lost packet.
    #[test]
    fn xdp_copy_mode_fill_ring_starvation_counts_once() {
        let b = DropBreakdown::Xdp {
            rx_dropped: 2_110_908,
            rx_invalid_descs: 0,
            rx_ring_full: 0,
            rx_fill_ring_empty_descs: 2_110_908,
            tx_invalid_descs: 0,
            tx_ring_empty_descs: 0,
        };
        assert_eq!(b.total_rx_drops(), 2_110_908);
    }

    /// #183: the kernel reports `tp_packets` with the drops added.
    #[test]
    fn tpacket_v3_read_splits_delivered_from_drops() {
        let c = CaptureStats::default().add_tpacket_v3(ffi::tpacket_stats_v3 {
            tp_packets: 1000,
            tp_drops: 900,
            tp_freeze_q_cnt: 3,
        });
        assert_eq!(c, CaptureStats::new(100, 900, 3));
        // `received()` is the kernel's own `tp_packets`.
        assert_eq!(c.received(), 1000);
    }

    /// The kernel adds the drops in `u32`, so `tp_packets` can wrap below
    /// `tp_drops`; the per-read split must wrap too.
    #[test]
    fn tpacket_v3_read_split_handles_u32_wrap() {
        let c = CaptureStats::default().add_tpacket_v3(ffi::tpacket_stats_v3 {
            tp_packets: 5,
            tp_drops: 11,
            tp_freeze_q_cnt: 0,
        });
        assert_eq!(c.delivered, u64::from(u32::MAX) - 5);
        assert_eq!(c.drops, 11);
    }

    /// #184 / #186: the totals are `u64` and keep counting past `u32::MAX`
    /// — no clamp anywhere.
    #[test]
    fn totals_grow_past_u32() {
        let start = CaptureStats::new(u64::from(u32::MAX) - 10, 0, 0);
        let c = start.add_tpacket_v3(ffi::tpacket_stats_v3 {
            tp_packets: 100,
            tp_drops: 0,
            tp_freeze_q_cnt: 0,
        });
        assert_eq!(c.delivered, u64::from(u32::MAX) + 90);
        let big = CaptureStats::new(4_000_000_000, 400_000_000, 0);
        assert_eq!(big.received(), 4_400_000_000);
    }

    /// Consecutive destructive reads fold into one running total.
    #[test]
    fn tpacket_v3_reads_accumulate() {
        let read = |p, d, f| ffi::tpacket_stats_v3 {
            tp_packets: p,
            tp_drops: d,
            tp_freeze_q_cnt: f,
        };
        let total = CaptureStats::default()
            .add_tpacket_v3(read(50, 0, 0))
            .add_tpacket_v3(read(0, 0, 0))
            .add_tpacket_v3(read(70, 20, 1));
        assert_eq!(total, CaptureStats::new(100, 20, 1));
    }

    #[test]
    fn breakdowns_of_the_same_backend_add_field_wise() {
        let a = DropBreakdown::AfPacket { freezes: 2 };
        let b = DropBreakdown::AfPacket { freezes: 5 };
        assert_eq!(a.saturating_add(b), DropBreakdown::AfPacket { freezes: 7 });
        let x = DropBreakdown::Xdp {
            rx_dropped: 1,
            rx_invalid_descs: 0,
            rx_ring_full: 2,
            rx_fill_ring_empty_descs: 3,
            tx_invalid_descs: 0,
            tx_ring_empty_descs: 4,
        };
        let DropBreakdown::Xdp {
            rx_dropped,
            rx_ring_full,
            rx_fill_ring_empty_descs,
            tx_ring_empty_descs,
            ..
        } = x.saturating_add(x)
        else {
            panic!("expected Xdp");
        };
        assert_eq!(
            (
                rx_dropped,
                rx_ring_full,
                rx_fill_ring_empty_descs,
                tx_ring_empty_descs
            ),
            (2, 4, 6, 8)
        );
        // Mixed variants: the newer reading wins.
        assert_eq!(a.saturating_add(x), x);
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
