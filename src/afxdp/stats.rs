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
}
