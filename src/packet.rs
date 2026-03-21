//! Packet types: timestamps, status flags, and owned packets.
//!
//! Zero-copy `Packet<'a>` and `PacketBatch<'a>` will be added in Phase 3.

use crate::afpacket::ffi;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Nanosecond-precision kernel timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    /// Seconds since epoch.
    pub sec: u32,
    /// Nanoseconds within the second.
    pub nsec: u32,
}

impl Timestamp {
    /// Create a new timestamp.
    pub const fn new(sec: u32, nsec: u32) -> Self {
        Self { sec, nsec }
    }

    /// Convert to [`SystemTime`].
    pub fn to_system_time(self) -> SystemTime {
        UNIX_EPOCH + Duration::new(self.sec as u64, self.nsec)
    }

    /// Convert to [`Duration`] since epoch.
    pub fn to_duration(self) -> Duration {
        Duration::new(self.sec as u64, self.nsec)
    }
}

impl From<Timestamp> for SystemTime {
    fn from(ts: Timestamp) -> Self {
        ts.to_system_time()
    }
}

impl From<Timestamp> for Duration {
    fn from(ts: Timestamp) -> Self {
        ts.to_duration()
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:09}", self.sec, self.nsec)
    }
}

/// Decoded per-packet status flags from `tpacket3_hdr.tp_status`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacketStatus {
    /// Frame was truncated (too large for the ring frame).
    pub truncated: bool,
    /// Packet drops are occurring.
    pub losing: bool,
    /// VLAN TCI field is valid.
    pub vlan_valid: bool,
    /// VLAN TPID field is valid.
    pub vlan_tpid_valid: bool,
    /// Hardware checksum is verified correct.
    pub csum_valid: bool,
    /// Checksum not yet computed (TX offload pending).
    pub csum_not_ready: bool,
    /// Packet is a TCP GSO segment.
    pub gso_tcp: bool,
}

impl PacketStatus {
    /// Decode status flags from the raw `tp_status` bitmask.
    pub(crate) fn from_raw(status: u32) -> Self {
        Self {
            truncated: status & ffi::TP_STATUS_COPY != 0,
            losing: status & ffi::TP_STATUS_LOSING != 0,
            vlan_valid: status & ffi::TP_STATUS_VLAN_VALID != 0,
            vlan_tpid_valid: status & ffi::TP_STATUS_VLAN_TPID_VALID != 0,
            csum_valid: status & ffi::TP_STATUS_CSUM_VALID != 0,
            csum_not_ready: status & ffi::TP_STATUS_CSUMNOTREADY != 0,
            gso_tcp: status & ffi::TP_STATUS_GSO_TCP != 0,
        }
    }
}

/// An owned copy of a captured packet, independent of the ring buffer.
///
/// Created via [`Packet::to_owned()`] (available in Phase 3).
#[derive(Debug, Clone)]
pub struct OwnedPacket {
    /// Raw packet bytes (from MAC header).
    pub data: Vec<u8>,
    /// Kernel timestamp.
    pub timestamp: Timestamp,
    /// Original packet length on the wire.
    pub original_len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_new() {
        let ts = Timestamp::new(1234, 567890);
        assert_eq!(ts.sec, 1234);
        assert_eq!(ts.nsec, 567890);
    }

    #[test]
    fn timestamp_to_system_time() {
        let ts = Timestamp::new(1_000_000_000, 500_000_000);
        let st = ts.to_system_time();
        let expected = UNIX_EPOCH + Duration::new(1_000_000_000, 500_000_000);
        assert_eq!(st, expected);
    }

    #[test]
    fn timestamp_to_duration() {
        let ts = Timestamp::new(5, 123456789);
        let d = ts.to_duration();
        assert_eq!(d, Duration::new(5, 123456789));
    }

    #[test]
    fn timestamp_display() {
        let ts = Timestamp::new(1234, 1);
        assert_eq!(ts.to_string(), "1234.000000001");
    }

    #[test]
    fn timestamp_ordering() {
        let a = Timestamp::new(1, 0);
        let b = Timestamp::new(1, 1);
        let c = Timestamp::new(2, 0);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn timestamp_default_is_zero() {
        let ts = Timestamp::default();
        assert_eq!(ts.sec, 0);
        assert_eq!(ts.nsec, 0);
    }

    #[test]
    fn packet_status_from_raw_empty() {
        let s = PacketStatus::from_raw(0);
        assert!(!s.truncated);
        assert!(!s.losing);
        assert!(!s.vlan_valid);
        assert!(!s.csum_valid);
        assert!(!s.gso_tcp);
    }

    #[test]
    fn packet_status_from_raw_truncated() {
        let s = PacketStatus::from_raw(ffi::TP_STATUS_COPY);
        assert!(s.truncated);
        assert!(!s.losing);
    }

    #[test]
    fn packet_status_from_raw_combined() {
        let bits = ffi::TP_STATUS_COPY
            | ffi::TP_STATUS_LOSING
            | ffi::TP_STATUS_VLAN_VALID
            | ffi::TP_STATUS_CSUM_VALID
            | ffi::TP_STATUS_GSO_TCP;
        let s = PacketStatus::from_raw(bits);
        assert!(s.truncated);
        assert!(s.losing);
        assert!(s.vlan_valid);
        assert!(s.csum_valid);
        assert!(s.gso_tcp);
        assert!(!s.vlan_tpid_valid);
        assert!(!s.csum_not_ready);
    }

    #[test]
    fn owned_packet_clone() {
        let pkt = OwnedPacket {
            data: vec![0xDE, 0xAD],
            timestamp: Timestamp::new(1, 2),
            original_len: 100,
        };
        let cloned = pkt.clone();
        assert_eq!(cloned.data, pkt.data);
        assert_eq!(cloned.timestamp, pkt.timestamp);
        assert_eq!(cloned.original_len, pkt.original_len);
    }
}
