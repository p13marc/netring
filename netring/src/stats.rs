//! Capture statistics.

use crate::afpacket::ffi;
use std::fmt;

/// Capture statistics from the kernel.
///
/// `packets` counts every packet the socket received (passed the filter),
/// **including the ones it then dropped**; `drops` is the dropped subset.
/// The loss fraction is therefore `drops / packets`, and the packets
/// actually handed to userspace are `packets - drops`. This is the kernel's
/// own AF_PACKET convention (`PACKET_STATISTICS` reports
/// `tp_packets += tp_drops`), and AF_XDP follows it since 0.31.2 (#183).
///
/// Reading stats via [`stats()`](crate::traits::PacketSource::stats) resets
/// the AF_PACKET kernel counters; AF_XDP counters are monotonic. The
/// cumulative accessors saturate at `u32::MAX`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CaptureStats {
    /// Packets received (passed the filter), including dropped ones.
    pub packets: u32,
    /// Packets dropped because the ring had no room for them (AF_PACKET:
    /// `tp_drops`; AF_XDP: `rx_dropped + rx_ring_full`). Included in
    /// `packets`.
    pub drops: u32,
    /// Number of times the ring buffer was frozen (AF_PACKET only).
    pub freeze_count: u32,
}

/// Crate-internal `u64` counters for one capture source: the Monitor's
/// telemetry reads these instead of the `u32` [`CaptureStats`] so it never
/// freezes on a saturated counter (#184).
///
/// Unlike `CaptureStats`, `delivered` **excludes** drops: it counts the
/// packets placed in the ring for userspace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SourceCounters {
    /// Packets placed in the ring for userspace.
    pub(crate) delivered: u64,
    /// Packets dropped for lack of ring space.
    pub(crate) drops: u64,
    /// Ring freezes (AF_PACKET only).
    pub(crate) freezes: u64,
}

impl SourceCounters {
    /// Fold one destructive `PACKET_STATISTICS` read into the totals. The
    /// kernel reports `tp_packets` with the drops already added (in `u32`),
    /// so the delivered count is split off per read, wrapping — exact
    /// whenever fewer than 2³² packets reached the ring between two reads.
    pub(crate) fn add_tpacket_v3(self, raw: ffi::tpacket_stats_v3) -> Self {
        Self {
            delivered: self
                .delivered
                .saturating_add(u64::from(raw.tp_packets.wrapping_sub(raw.tp_drops))),
            drops: self.drops.saturating_add(u64::from(raw.tp_drops)),
            freezes: self.freezes.saturating_add(u64::from(raw.tp_freeze_q_cnt)),
        }
    }

    /// Field-wise saturating sum.
    #[cfg_attr(not(all(feature = "flow", feature = "tokio")), allow(dead_code))]
    pub(crate) fn saturating_add(self, other: Self) -> Self {
        Self {
            delivered: self.delivered.saturating_add(other.delivered),
            drops: self.drops.saturating_add(other.drops),
            freezes: self.freezes.saturating_add(other.freezes),
        }
    }

    /// Field-wise saturating difference (`self - earlier`).
    #[cfg_attr(not(all(feature = "flow", feature = "tokio")), allow(dead_code))]
    pub(crate) fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            delivered: self.delivered.saturating_sub(earlier.delivered),
            drops: self.drops.saturating_sub(earlier.drops),
            freezes: self.freezes.saturating_sub(earlier.freezes),
        }
    }

    /// The public `u32` view: `packets = delivered + drops`, each field
    /// clamped at `u32::MAX` (so `drops <= packets` still holds).
    pub(crate) fn to_capture_stats(self) -> CaptureStats {
        let clamp = |v: u64| v.min(u64::from(u32::MAX)) as u32;
        CaptureStats {
            packets: clamp(self.delivered.saturating_add(self.drops)),
            drops: clamp(self.drops),
            freeze_count: clamp(self.freezes),
        }
    }
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
        let c = SourceCounters::default().add_tpacket_v3(ffi::tpacket_stats_v3 {
            tp_packets: 1000,
            tp_drops: 900,
            tp_freeze_q_cnt: 3,
        });
        assert_eq!(
            c,
            SourceCounters {
                delivered: 100,
                drops: 900,
                freezes: 3
            }
        );
        // The public view keeps the kernel convention.
        let s = c.to_capture_stats();
        assert_eq!((s.packets, s.drops, s.freeze_count), (1000, 900, 3));
    }

    /// The kernel adds the drops in `u32`, so `tp_packets` can wrap below
    /// `tp_drops`; the per-read split must wrap too.
    #[test]
    fn tpacket_v3_read_split_handles_u32_wrap() {
        let c = SourceCounters::default().add_tpacket_v3(ffi::tpacket_stats_v3 {
            tp_packets: 5,
            tp_drops: 11,
            tp_freeze_q_cnt: 0,
        });
        assert_eq!(c.delivered, u64::from(u32::MAX) - 5);
        assert_eq!(c.drops, 11);
    }

    /// #184: the internal totals keep counting past `u32::MAX`; only the
    /// public view clamps, and it keeps `drops <= packets`.
    #[test]
    fn counters_grow_past_u32_and_clamp_only_in_the_public_view() {
        let start = SourceCounters {
            delivered: u64::from(u32::MAX) - 10,
            drops: 0,
            freezes: 0,
        };
        let c = start.add_tpacket_v3(ffi::tpacket_stats_v3 {
            tp_packets: 100,
            tp_drops: 0,
            tp_freeze_q_cnt: 0,
        });
        assert_eq!(c.delivered, u64::from(u32::MAX) + 90);

        let big = SourceCounters {
            delivered: 4_000_000_000,
            drops: 400_000_000,
            freezes: 0,
        };
        let s = big.to_capture_stats();
        assert_eq!(s.packets, u32::MAX);
        assert_eq!(s.drops, 400_000_000);
        let huge = SourceCounters {
            delivered: 1,
            drops: 5_000_000_000,
            freezes: 0,
        };
        let s = huge.to_capture_stats();
        assert_eq!((s.packets, s.drops), (u32::MAX, u32::MAX));
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
