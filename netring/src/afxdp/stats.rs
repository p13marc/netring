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
#[non_exhaustive]
pub struct XdpStats {
    /// Packets dropped for any reason other than a full RX ring (the
    /// kernel's "dropped for other reasons"). In copy mode that is chiefly
    /// "no free buffer in the fill ring" — the user-side refill is too slow:
    /// increase `frame_count` or drain more often — and also frames larger
    /// than the UMEM frame. In zero-copy mode a fill-ring shortfall drops
    /// the packet in the NIC instead, so it is not counted here (see the
    /// NIC's `ethtool -S` counters).
    pub rx_dropped: u64,
    /// RX descriptors the kernel counted as invalid
    /// (`xskq_nb_invalid_descs(xs->rx)`). Current mainline kernels never
    /// increment it on the RX side (invalid fill-ring addresses are counted
    /// on the fill queue, which `XDP_STATISTICS` does not export).
    pub rx_invalid_descs: u64,
    /// TX descriptors the kernel rejected as invalid (bad addr / len).
    pub tx_invalid_descs: u64,
    /// Packets dropped because the RX ring was full (slow consumer).
    /// Disjoint from `rx_dropped`.
    pub rx_ring_full: u64,
    /// Times the kernel found the fill ring empty when it needed a buffer —
    /// a refill-starvation signal, **not** a packet count. In copy mode each
    /// packet lost this way is already counted in `rx_dropped`; in zero-copy
    /// mode the driver counts failed refill *batches*, which can rise with
    /// no loss at all. Per buffer pool: sockets sharing a UMEM report the
    /// same value.
    pub rx_fill_ring_empty_descs: u64,
    /// Times the kernel found the TX ring empty when it went to send.
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

    /// Packets the socket lost: `rx_dropped + rx_ring_full` (disjoint
    /// counters). This is what gets surfaced as the unified
    /// [`CaptureStats::drops`]. `rx_fill_ring_empty_descs` is **not** added
    /// — it counts failed fill-ring reads, and in copy mode the packets they
    /// cost are already in `rx_dropped` (#182). `rx_invalid_descs` stays
    /// visible via [`DropBreakdown`].
    ///
    /// [`CaptureStats::drops`]: crate::stats::CaptureStats::drops
    /// [`DropBreakdown`]: crate::stats::DropBreakdown
    pub(crate) fn rx_packet_drops(&self) -> u64 {
        self.rx_dropped.saturating_add(self.rx_ring_full)
    }

    /// The Monitor's `u64` counters for a socket that has `received`
    /// packets placed in its RX ring (`XDP_STATISTICS` has no RX count; the
    /// RX ring keeps one, see `XdpRing::received_total`).
    pub(crate) fn counters(self, received: u64) -> crate::stats::SourceCounters {
        crate::stats::SourceCounters {
            delivered: received,
            drops: self.rx_packet_drops(),
            freezes: 0,
        }
    }

    /// Project to the unified [`CaptureStats`](crate::stats::CaptureStats):
    /// `packets = received + drops` (every packet the socket got, as on
    /// AF_PACKET) and `drops` = [`rx_packet_drops`](Self::rx_packet_drops),
    /// each clamped at `u32::MAX`.
    pub(crate) fn to_capture_stats(self, received: u64) -> crate::stats::CaptureStats {
        self.counters(received).to_capture_stats()
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
    fn to_capture_stats_drops_are_lost_packets_only() {
        // Neither the invalid-desc count nor the fill-ring starvation count
        // is a lost packet of its own: drops = rx_dropped + rx_ring_full.
        let s = XdpStats {
            rx_dropped: 1,
            rx_invalid_descs: 1000,
            rx_ring_full: 2,
            rx_fill_ring_empty_descs: 4,
            tx_invalid_descs: 9,
            tx_ring_empty_descs: 9,
        };
        let cs = s.to_capture_stats(10);
        assert_eq!(cs.drops, 3, "1 + 2");
        assert_eq!(cs.packets, 13, "10 received + 3 dropped");
        assert_eq!(cs.freeze_count, 0);
        // The full picture is still reachable via the breakdown.
        let b = crate::stats::DropBreakdown::from(s);
        assert_eq!(b.total_rx_drops(), 1003);
    }

    /// #182, copy mode: the reporter's numbers. 4,092 packets fit the
    /// prefilled buffers; every other one bumped both rx_dropped and
    /// rx_fill_ring_empty_descs. drops must equal the real loss.
    #[test]
    fn copy_mode_fill_ring_starvation_is_counted_once() {
        let s = XdpStats {
            rx_dropped: 2_110_908,
            rx_fill_ring_empty_descs: 2_110_908,
            ..XdpStats::default()
        };
        let cs = s.to_capture_stats(4_092);
        assert_eq!(cs.drops, 2_110_908);
        assert_eq!(cs.packets, 2_115_000);
    }

    /// Zero-copy: failed refill batches bump the fill-ring counter with no
    /// packet lost in the socket — no drops.
    #[test]
    fn zero_copy_refill_attempts_are_not_drops() {
        let s = XdpStats {
            rx_fill_ring_empty_descs: 50_000,
            ..XdpStats::default()
        };
        let cs = s.to_capture_stats(1_000);
        assert_eq!((cs.packets, cs.drops), (1_000, 0));
    }

    /// The Monitor's counters are not clamped; the public view is, and
    /// keeps `drops <= packets`.
    #[test]
    fn counters_are_u64_and_the_public_view_clamps() {
        let s = XdpStats {
            rx_dropped: 5_000_000_000,
            ..XdpStats::default()
        };
        assert_eq!(s.counters(7).drops, 5_000_000_000);
        let cs = s.to_capture_stats(7);
        assert_eq!((cs.packets, cs.drops), (u32::MAX, u32::MAX));
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
