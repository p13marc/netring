//! Packet types: zero-copy views, batch iteration, timestamps, and owned packets.

use std::marker::PhantomData;
use std::ptr::NonNull;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::afpacket::ffi;
use crate::afpacket::ring::{self, MmapRing};

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
/// Created via [`Packet::to_owned()`].
#[derive(Debug, Clone)]
pub struct OwnedPacket {
    /// Raw packet bytes (from MAC header).
    pub data: Vec<u8>,
    /// Kernel timestamp.
    pub timestamp: Timestamp,
    /// Original packet length on the wire.
    pub original_len: usize,
}

// ── Zero-copy Packet ───────────────────────────────────────────────────────

/// Zero-copy view of a received packet.
///
/// Borrows from the mmap ring via its parent [`PacketBatch`].
/// The borrow checker enforces that this reference cannot outlive the batch.
///
/// Call [`to_owned()`](Packet::to_owned) to copy data out of the ring.
pub struct Packet<'a> {
    data: &'a [u8],
    hdr: &'a ffi::tpacket3_hdr,
}

impl<'a> Packet<'a> {
    /// Raw packet bytes starting from the MAC header.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Kernel timestamp (nanosecond precision).
    pub fn timestamp(&self) -> Timestamp {
        Timestamp::new(self.hdr.tp_sec, self.hdr.tp_nsec)
    }

    /// Captured length (may be < [`original_len()`](Packet::original_len) if truncated).
    pub fn len(&self) -> usize {
        self.hdr.tp_snaplen as usize
    }

    /// Whether the captured data is empty.
    pub fn is_empty(&self) -> bool {
        self.hdr.tp_snaplen == 0
    }

    /// Original packet length on the wire.
    pub fn original_len(&self) -> usize {
        self.hdr.tp_len as usize
    }

    /// Per-packet status flags.
    pub fn status(&self) -> PacketStatus {
        PacketStatus::from_raw(self.hdr.tp_status)
    }

    /// RX flow hash (requires `fill_rxhash` — enabled by default).
    pub fn rxhash(&self) -> u32 {
        self.hdr.hv1.tp_rxhash
    }

    /// Raw VLAN TCI from kernel header. Check `status().vlan_valid` first.
    pub fn vlan_tci(&self) -> u16 {
        self.hdr.hv1.tp_vlan_tci as u16
    }

    /// Raw VLAN TPID from kernel header. Check `status().vlan_tpid_valid` first.
    pub fn vlan_tpid(&self) -> u16 {
        self.hdr.hv1.tp_vlan_tpid
    }

    /// Copy packet data out of the ring for long-lived storage.
    pub fn to_owned(&self) -> OwnedPacket {
        OwnedPacket {
            data: self.data.to_vec(),
            timestamp: self.timestamp(),
            original_len: self.original_len(),
        }
    }
}

// ── PacketBatch ────────────────────────────────────────────────────────────

/// A batch of packets from a single retired kernel block.
///
/// **RAII**: dropping the batch returns the block to the kernel by writing
/// `TP_STATUS_KERNEL` with `Release` ordering.
///
/// Only one batch can be live at a time per [`AfPacketRx`](crate::afpacket::rx::AfPacketRx)
/// (enforced by `&mut self` on [`next_batch()`](crate::traits::PacketSource::next_batch)).
pub struct PacketBatch<'a> {
    block: NonNull<ffi::tpacket_block_desc>,
    block_size: usize,
    // Cached from block header
    num_pkts: u32,
    block_status: u32,
    seq_num: u64,
    offset_to_first_pkt: u32,
    blk_len: u32,
    ts_first: Timestamp,
    ts_last: Timestamp,
    _marker: PhantomData<&'a MmapRing>,
}

impl<'a> PacketBatch<'a> {
    /// Create a batch from a block pointer. The block must be in `TP_STATUS_USER` state.
    ///
    /// # Safety
    ///
    /// - `block` must point to a valid `tpacket_block_desc` in an mmap'd region.
    /// - The block must have been read with `Acquire` ordering before calling this.
    /// - The caller must ensure the block is not released while this batch exists.
    pub(crate) unsafe fn new(
        block: NonNull<ffi::tpacket_block_desc>,
        block_size: usize,
    ) -> Self {
        // SAFETY: caller guarantees block is valid and user-owned.
        let bd = unsafe { &*block.as_ptr() };
        let bh1 = unsafe { &bd.hdr.bh1 };

        let ts_first = Timestamp::new(
            bh1.ts_first_pkt.ts_sec,
            // libc uses ts_usec but TPACKET_V3 provides nanoseconds
            bh1.ts_first_pkt.ts_usec,
        );
        let ts_last = Timestamp::new(bh1.ts_last_pkt.ts_sec, bh1.ts_last_pkt.ts_usec);

        Self {
            block,
            block_size,
            num_pkts: bh1.num_pkts,
            block_status: bh1.block_status,
            seq_num: bh1.seq_num,
            offset_to_first_pkt: bh1.offset_to_first_pkt,
            blk_len: bh1.blk_len,
            ts_first,
            ts_last,
            _marker: PhantomData,
        }
    }

    /// Number of packets in this block.
    pub fn len(&self) -> usize {
        self.num_pkts as usize
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.num_pkts == 0
    }

    /// Whether the block was retired via timeout (partially filled).
    pub fn timed_out(&self) -> bool {
        self.block_status & ffi::TP_STATUS_BLK_TMO != 0
    }

    /// Monotonic block sequence number. Gaps indicate dropped blocks.
    pub fn seq_num(&self) -> u64 {
        self.seq_num
    }

    /// Timestamp of the first packet (or block open time).
    pub fn ts_first(&self) -> Timestamp {
        self.ts_first
    }

    /// Timestamp of the last packet (or block close time).
    pub fn ts_last(&self) -> Timestamp {
        self.ts_last
    }

    /// Iterate over packets in the batch.
    pub fn iter(&self) -> BatchIter<'a> {
        if self.num_pkts == 0 {
            return BatchIter {
                current: std::ptr::null(),
                remaining: 0,
                block_end: std::ptr::null(),
                _marker: PhantomData,
            };
        }

        let base = self.block.as_ptr().cast::<u8>();
        let first = base.map_addr(|a| a + self.offset_to_first_pkt as usize);
        let end = base.map_addr(|a| a + self.blk_len as usize);

        BatchIter {
            current: first,
            remaining: self.num_pkts,
            block_end: end,
            _marker: PhantomData,
        }
    }
}

impl<'a> IntoIterator for &'a PacketBatch<'a> {
    type Item = Packet<'a>;
    type IntoIter = BatchIter<'a>;

    fn into_iter(self) -> BatchIter<'a> {
        self.iter()
    }
}

impl Drop for PacketBatch<'_> {
    fn drop(&mut self) {
        // SAFETY: self.block is valid (from construction) and we're done reading.
        unsafe { ring::release_block(self.block) };
    }
}

// ── BatchIter ──────────────────────────────────────────────────────────────

/// Iterator over packets within a [`PacketBatch`].
///
/// Walks the `tpacket3_hdr` linked list within a block, performing bounds
/// checks before constructing each packet reference.
pub struct BatchIter<'a> {
    current: *const u8,
    remaining: u32,
    block_end: *const u8,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Iterator for BatchIter<'a> {
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Packet<'a>> {
        if self.remaining == 0 {
            return None;
        }

        let hdr_size = std::mem::size_of::<ffi::tpacket3_hdr>();

        // Bounds check: header must fit within block
        if (self.current as usize) + hdr_size > self.block_end as usize {
            log::warn!("BatchIter: tpacket3_hdr extends past block boundary, stopping");
            self.remaining = 0;
            return None;
        }

        // SAFETY: bounds-checked above, TPACKET_ALIGNMENT guarantees alignment.
        let hdr = unsafe { &*(self.current as *const ffi::tpacket3_hdr) };

        let data_offset = hdr.tp_mac as usize;
        let snaplen = hdr.tp_snaplen as usize;
        let data_ptr = self.current.map_addr(|a| a + data_offset);

        // Bounds check: packet data must fit within block
        if (data_ptr as usize) + snaplen > self.block_end as usize {
            log::warn!("BatchIter: packet data extends past block boundary, stopping");
            self.remaining = 0;
            return None;
        }

        // SAFETY: bounds-checked, data is within the mmap region.
        let data = unsafe { std::slice::from_raw_parts(data_ptr, snaplen) };

        // Advance to next packet
        if hdr.tp_next_offset != 0 {
            self.current = self.current.map_addr(|a| a + hdr.tp_next_offset as usize);
        }
        self.remaining -= 1;

        Some(Packet { data, hdr })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let r = self.remaining as usize;
        (r, Some(r))
    }
}

impl ExactSizeIterator for BatchIter<'_> {}

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
