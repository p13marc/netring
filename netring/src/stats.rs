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
}
