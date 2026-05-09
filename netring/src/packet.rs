//! Packet types: zero-copy views, batch iteration, timestamps, and owned packets.

use std::marker::PhantomData;
use std::ptr::NonNull;

use crate::afpacket::ffi;
use crate::afpacket::ring::{self, MmapRing};

pub use flowscope::Timestamp;

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
    #[inline]
    pub fn from_raw(status: u32) -> Self {
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
/// Created via [`Packet::to_owned()`]. Carries enough metadata for DPI,
/// flow tracking, and PCAP-style export — the trade-off is ~50 bytes per
/// owned packet vs the bare-data minimum.
#[derive(Debug, Clone)]
pub struct OwnedPacket {
    /// Raw packet bytes (from MAC header).
    pub data: Vec<u8>,
    /// Kernel timestamp.
    pub timestamp: Timestamp,
    /// Original packet length on the wire (may exceed `data.len()` if truncated).
    pub original_len: usize,
    /// Decoded per-packet status flags from `tp_status`.
    pub status: PacketStatus,
    /// Direction relative to the capturing host.
    pub direction: PacketDirection,
    /// Kernel-supplied flow hash (`tp_rxhash`); 0 if `fill_rxhash` was disabled.
    pub rxhash: u32,
    /// Raw VLAN TCI; check `status.vlan_valid`.
    pub vlan_tci: u16,
    /// Raw VLAN TPID; check `status.vlan_tpid_valid`.
    pub vlan_tpid: u16,
    /// EtherType / link-layer protocol (host byte order).
    pub ll_protocol: u16,
    /// Source link-layer address (up to 8 bytes — the kernel's
    /// `sockaddr_ll::sll_addr` capacity).
    pub source_ll_addr: [u8; 8],
    /// Valid bytes in `source_ll_addr` (matches kernel `sll_halen`,
    /// clamped to 8).
    pub source_ll_addr_len: u8,
}

impl OwnedPacket {
    /// Source link-layer address as a slice of the valid portion.
    #[inline]
    pub fn source_ll_addr(&self) -> &[u8] {
        let n = (self.source_ll_addr_len as usize).min(self.source_ll_addr.len());
        &self.source_ll_addr[..n]
    }
}

// ── Packet Direction ───────────────────────────────────────────────────────

/// Direction of a captured packet relative to the capturing host.
///
/// Decoded from `sockaddr_ll.sll_pkttype` in the TPACKET_V3 ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketDirection {
    /// Addressed to this host.
    Host,
    /// Link-layer broadcast.
    Broadcast,
    /// Link-layer multicast.
    Multicast,
    /// Destined for another host (captured in promiscuous mode).
    OtherHost,
    /// Originated from this host.
    Outgoing,
    /// Unknown direction value.
    Unknown(u8),
}

impl PacketDirection {
    /// Decode from raw `sll_pkttype` value.
    #[inline]
    pub(crate) fn from_raw(pkttype: u8) -> Self {
        match pkttype {
            ffi::PACKET_HOST => Self::Host,
            ffi::PACKET_BROADCAST => Self::Broadcast,
            ffi::PACKET_MULTICAST => Self::Multicast,
            ffi::PACKET_OTHERHOST => Self::OtherHost,
            ffi::PACKET_OUTGOING => Self::Outgoing,
            v => Self::Unknown(v),
        }
    }
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
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Kernel timestamp (nanosecond precision).
    #[inline]
    pub fn timestamp(&self) -> Timestamp {
        Timestamp::new(self.hdr.tp_sec, self.hdr.tp_nsec)
    }

    /// Captured length (may be < [`original_len()`](Packet::original_len) if truncated).
    #[inline]
    pub fn len(&self) -> usize {
        self.hdr.tp_snaplen as usize
    }

    /// Whether the captured data is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.hdr.tp_snaplen == 0
    }

    /// Original packet length on the wire.
    #[inline]
    pub fn original_len(&self) -> usize {
        self.hdr.tp_len as usize
    }

    /// Per-packet status flags.
    #[inline]
    pub fn status(&self) -> PacketStatus {
        PacketStatus::from_raw(self.hdr.tp_status)
    }

    /// RX flow hash (requires `fill_rxhash` — enabled by default).
    #[inline]
    pub fn rxhash(&self) -> u32 {
        self.hdr.hv1.tp_rxhash
    }

    /// Raw VLAN TCI from kernel header. Check `status().vlan_valid` first.
    #[inline]
    pub fn vlan_tci(&self) -> u16 {
        self.hdr.hv1.tp_vlan_tci as u16
    }

    /// Raw VLAN TPID from kernel header. Check `status().vlan_tpid_valid` first.
    #[inline]
    pub fn vlan_tpid(&self) -> u16 {
        self.hdr.hv1.tp_vlan_tpid
    }

    /// Packet direction relative to the capturing host.
    ///
    /// Decoded from `sockaddr_ll.sll_pkttype` in the ring buffer metadata.
    /// The `sockaddr_ll` is located after the `tpacket3_hdr` at offset
    /// `TPACKET_ALIGN(sizeof(tpacket3_hdr))`.
    #[inline]
    pub fn direction(&self) -> PacketDirection {
        let sll_offset = ffi::tpacket_align(std::mem::size_of::<ffi::tpacket3_hdr>());
        let hdr_ptr = self.hdr as *const ffi::tpacket3_hdr as *const u8;
        let sll_ptr = hdr_ptr.map_addr(|a| a + sll_offset);
        // SAFETY: sockaddr_ll is placed right after tpacket3_hdr in the ring.
        // The BatchIter bounds-checks the full header + sockaddr_ll region
        // before constructing a Packet.
        let sll = unsafe { &*(sll_ptr as *const ffi::sockaddr_ll) };
        PacketDirection::from_raw(sll.sll_pkttype)
    }

    /// Source link-layer address (typically MAC address) from ring metadata.
    ///
    /// Returns up to 8 bytes — the size of `sockaddr_ll::sll_addr` in the
    /// Linux kernel. For 6-byte Ethernet MAC this is sufficient. For
    /// link-layer types with longer addresses (e.g., InfiniBand's 20-byte
    /// LLE), the kernel itself truncates to 8; netring just exposes what
    /// the kernel provides. Use `RTM_GETLINK` netlink for the full address
    /// if needed.
    ///
    /// The returned slice's length matches `sockaddr_ll::sll_halen`,
    /// clamped to the `[u8; 8]` field size.
    #[inline]
    pub fn source_ll_addr(&self) -> &[u8] {
        let sll_offset = ffi::tpacket_align(std::mem::size_of::<ffi::tpacket3_hdr>());
        let hdr_ptr = self.hdr as *const ffi::tpacket3_hdr as *const u8;
        let sll_ptr = hdr_ptr.map_addr(|a| a + sll_offset);
        let sll = unsafe { &*(sll_ptr as *const ffi::sockaddr_ll) };
        let len = sll.sll_halen as usize;
        &sll.sll_addr[..len.min(8)]
    }

    /// EtherType / protocol from link-layer metadata (network byte order).
    #[inline]
    pub fn ll_protocol(&self) -> u16 {
        let sll_offset = ffi::tpacket_align(std::mem::size_of::<ffi::tpacket3_hdr>());
        let hdr_ptr = self.hdr as *const ffi::tpacket3_hdr as *const u8;
        let sll_ptr = hdr_ptr.map_addr(|a| a + sll_offset);
        let sll = unsafe { &*(sll_ptr as *const ffi::sockaddr_ll) };
        u16::from_be(sll.sll_protocol)
    }

    /// Copy packet data and metadata out of the ring for long-lived storage.
    ///
    /// Captures every metadata field the ring exposes — see [`OwnedPacket`]
    /// for the full set. Costs one heap allocation (the data Vec) plus
    /// a fixed-size struct copy.
    pub fn to_owned(&self) -> OwnedPacket {
        let sll_offset = ffi::tpacket_align(std::mem::size_of::<ffi::tpacket3_hdr>());
        let hdr_ptr = self.hdr as *const ffi::tpacket3_hdr as *const u8;
        let sll_ptr = hdr_ptr.map_addr(|a| a + sll_offset);
        // SAFETY: BatchIter's bounds check ensured sockaddr_ll fits within
        // the block before constructing this Packet.
        let sll = unsafe { &*(sll_ptr as *const ffi::sockaddr_ll) };

        OwnedPacket {
            data: self.data.to_vec(),
            timestamp: self.timestamp(),
            original_len: self.original_len(),
            status: self.status(),
            direction: PacketDirection::from_raw(sll.sll_pkttype),
            rxhash: self.hdr.hv1.tp_rxhash,
            vlan_tci: self.hdr.hv1.tp_vlan_tci as u16,
            vlan_tpid: self.hdr.hv1.tp_vlan_tpid,
            ll_protocol: u16::from_be(sll.sll_protocol),
            source_ll_addr: sll.sll_addr,
            source_ll_addr_len: sll.sll_halen.min(8),
        }
    }

    /// Parse Ethernet/IP/TCP/UDP headers from packet data (feature: `parse`).
    ///
    /// Uses [`etherparse::SlicedPacket`] for zero-copy parsing directly
    /// from the mmap ring buffer — no data is copied.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn example(pkt: &netring::Packet<'_>) {
    /// #[cfg(feature = "parse")]
    /// if let Ok(parsed) = pkt.parse() {
    ///     // Access headers without copying
    /// }
    /// # }
    /// ```
    #[cfg(feature = "parse")]
    #[inline]
    pub fn parse(
        &self,
    ) -> Result<etherparse::SlicedPacket<'a>, etherparse::err::packet::SliceError> {
        etherparse::SlicedPacket::from_ethernet(self.data)
    }

    /// View this packet as a [`flowscope::PacketView`] for use with
    /// the source-agnostic flow-tracking API.
    ///
    /// Zero-cost — borrows the same frame slice and copies the
    /// timestamp.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn example(pkt: &netring::Packet<'_>) {
    /// let view = pkt.view();
    /// // pass `view` to any FlowExtractor
    /// # let _ = view;
    /// # }
    /// ```
    #[inline]
    pub fn view(&self) -> flowscope::PacketView<'a> {
        flowscope::PacketView::new(self.data, self.timestamp())
    }
}

impl OwnedPacket {
    /// Parse Ethernet/IP/TCP/UDP headers from owned packet data (feature: `parse`).
    #[cfg(feature = "parse")]
    #[inline]
    pub fn parse(
        &self,
    ) -> Result<etherparse::SlicedPacket<'_>, etherparse::err::packet::SliceError> {
        etherparse::SlicedPacket::from_ethernet(&self.data)
    }
}

// ── PacketBatch ────────────────────────────────────────────────────────────

/// A batch of packets from a single retired kernel block.
///
/// **RAII**: dropping the batch returns the block to the kernel by writing
/// `TP_STATUS_KERNEL` with `Release` ordering.
///
/// Only one batch can be live at a time per [`Capture`](crate::Capture)
/// (enforced by `&mut self` on [`next_batch()`](crate::traits::PacketSource::next_batch)).
pub struct PacketBatch<'a> {
    block: NonNull<ffi::tpacket_block_desc>,
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
    pub(crate) unsafe fn new(block: NonNull<ffi::tpacket_block_desc>) -> Self {
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
    #[inline]
    pub fn len(&self) -> usize {
        self.num_pkts as usize
    }

    /// Whether the batch is empty.
    #[inline]
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

impl std::fmt::Debug for PacketBatch<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketBatch")
            .field("num_pkts", &self.num_pkts)
            .field("seq_num", &self.seq_num)
            .field("timed_out", &self.timed_out())
            .finish()
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

impl std::fmt::Debug for BatchIter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchIter")
            .field("remaining", &self.remaining)
            .finish()
    }
}

impl<'a> Iterator for BatchIter<'a> {
    type Item = Packet<'a>;

    #[inline]
    fn next(&mut self) -> Option<Packet<'a>> {
        if self.remaining == 0 {
            return None;
        }

        // Header + sockaddr_ll must fit within block (sockaddr_ll is used by direction())
        let hdr_plus_sll = ffi::tpacket_align(std::mem::size_of::<ffi::tpacket3_hdr>())
            + std::mem::size_of::<ffi::sockaddr_ll>();

        // Bounds check: header + sockaddr_ll must fit within block
        if (self.current as usize) + hdr_plus_sll > self.block_end as usize {
            tracing::warn!("BatchIter: tpacket3_hdr extends past block boundary, stopping");
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
            tracing::warn!("BatchIter: packet data extends past block boundary, stopping");
            self.remaining = 0;
            return None;
        }

        // SAFETY: bounds-checked, data is within the mmap region.
        let data = unsafe { std::slice::from_raw_parts(data_ptr, snaplen) };

        // Advance to next packet. tp_next_offset == 0 is the kernel's marker
        // for the last packet in the block — terminate iteration regardless of
        // the claimed `remaining` count.
        if hdr.tp_next_offset != 0 {
            self.current = self.current.map_addr(|a| a + hdr.tp_next_offset as usize);
            self.remaining -= 1;
        } else {
            self.remaining = 0;
        }

        Some(Packet { data, hdr })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // `remaining` is an upper bound — a corrupt or truncated block may
        // terminate earlier when `tp_next_offset == 0` is observed.
        (0, Some(self.remaining as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            status: PacketStatus::default(),
            direction: PacketDirection::Host,
            rxhash: 0xCAFE,
            vlan_tci: 100,
            vlan_tpid: 0x8100,
            ll_protocol: 0x0800,
            source_ll_addr: [1, 2, 3, 4, 5, 6, 0, 0],
            source_ll_addr_len: 6,
        };
        let cloned = pkt.clone();
        assert_eq!(cloned.data, pkt.data);
        assert_eq!(cloned.timestamp, pkt.timestamp);
        assert_eq!(cloned.original_len, pkt.original_len);
        assert_eq!(cloned.rxhash, 0xCAFE);
        assert_eq!(cloned.source_ll_addr(), &[1, 2, 3, 4, 5, 6]);
    }

    // ── Synthetic block builder for BatchIter tests ────────────────────

    /// Build a synthetic TPACKET_V3 block with the given packet payloads.
    /// Returns a Vec<u8> that can be used as a fake mmap block.
    fn build_synthetic_block(packets: &[&[u8]], block_status: u32) -> Vec<u8> {
        let block_desc_size = std::mem::size_of::<ffi::tpacket_block_desc>();
        let hdr_size = std::mem::size_of::<ffi::tpacket3_hdr>();

        // Calculate total size needed
        let mut total = block_desc_size;
        for payload in packets {
            let frame_size = ffi::tpacket_align(hdr_size + payload.len());
            total += frame_size;
        }
        // Round up to a reasonable block size
        let block_size = total.max(4096);

        let mut block = vec![0u8; block_size];

        // Write block descriptor
        let bd = block.as_mut_ptr().cast::<ffi::tpacket_block_desc>();
        unsafe {
            (*bd).version = 1;
            (*bd).hdr.bh1.block_status = block_status;
            (*bd).hdr.bh1.num_pkts = packets.len() as u32;
            (*bd).hdr.bh1.offset_to_first_pkt = block_desc_size as u32;
            (*bd).hdr.bh1.blk_len = block_size as u32;
            (*bd).hdr.bh1.seq_num = 1;
        }

        // Write packet headers + data
        let mut offset = block_desc_size;
        for (i, payload) in packets.iter().enumerate() {
            let frame_size = ffi::tpacket_align(hdr_size + payload.len());
            let is_last = i == packets.len() - 1;

            let hdr = block[offset..].as_mut_ptr().cast::<ffi::tpacket3_hdr>();
            unsafe {
                (*hdr).tp_next_offset = if is_last { 0 } else { frame_size as u32 };
                (*hdr).tp_sec = 1000 + i as u32;
                (*hdr).tp_nsec = i as u32 * 1000;
                (*hdr).tp_snaplen = payload.len() as u32;
                (*hdr).tp_len = payload.len() as u32;
                (*hdr).tp_status = 0;
                (*hdr).tp_mac = hdr_size as u16;
                (*hdr).tp_net = hdr_size as u16;
            }

            // Copy payload data
            let data_start = offset + hdr_size;
            block[data_start..data_start + payload.len()].copy_from_slice(payload);

            offset += frame_size;
        }

        block
    }

    /// Create a BatchIter directly from a synthetic block buffer.
    fn iter_from_block(block: &[u8], num_pkts: u32) -> BatchIter<'_> {
        let _bd = block.as_ptr().cast::<ffi::tpacket_block_desc>();
        let bd_size = std::mem::size_of::<ffi::tpacket_block_desc>();

        let first = block[bd_size..].as_ptr();
        let end = block[block.len()..].as_ptr();

        BatchIter {
            current: first,
            remaining: num_pkts,
            block_end: end,
            _marker: PhantomData,
        }
    }

    #[test]
    fn batch_iter_single_packet() {
        let data = b"hello world";
        let block = build_synthetic_block(&[data], ffi::TP_STATUS_USER);
        let mut iter = iter_from_block(&block, 1);

        let pkt = iter.next().unwrap();
        assert_eq!(pkt.data(), data);
        assert_eq!(pkt.len(), data.len());
        assert_eq!(pkt.original_len(), data.len());
        assert_eq!(pkt.timestamp().sec, 1000);

        assert!(iter.next().is_none());
    }

    #[test]
    fn batch_iter_multiple_packets() {
        let p1 = b"packet one";
        let p2 = b"packet two!!";
        let p3 = b"pkt3";
        let block = build_synthetic_block(&[p1, p2, p3], ffi::TP_STATUS_USER);
        let mut iter = iter_from_block(&block, 3);

        let pkt1 = iter.next().unwrap();
        assert_eq!(pkt1.data(), p1.as_slice());
        assert_eq!(pkt1.timestamp().sec, 1000);

        let pkt2 = iter.next().unwrap();
        assert_eq!(pkt2.data(), p2.as_slice());
        assert_eq!(pkt2.timestamp().sec, 1001);

        let pkt3 = iter.next().unwrap();
        assert_eq!(pkt3.data(), p3.as_slice());
        assert_eq!(pkt3.timestamp().sec, 1002);

        assert!(iter.next().is_none());
    }

    #[test]
    fn batch_iter_empty_block() {
        let block = build_synthetic_block(&[], ffi::TP_STATUS_USER);
        let mut iter = iter_from_block(&block, 0);
        assert!(iter.next().is_none());
    }

    #[test]
    fn batch_iter_size_hint_is_upper_bound() {
        let block = build_synthetic_block(&[b"a", b"bb", b"ccc"], ffi::TP_STATUS_USER);
        let iter = iter_from_block(&block, 3);
        // size_hint is an upper bound; lower bound is 0 because tp_next_offset
        // can terminate the walk before consuming `remaining`.
        assert_eq!(iter.size_hint(), (0, Some(3)));
        assert_eq!(iter.count(), 3);
    }

    #[test]
    fn batch_iter_terminates_on_last_packet_marker() {
        // Claim 10 packets but only 1 exists. The iterator must observe the
        // last-packet marker (tp_next_offset == 0) and stop after exactly one
        // emission rather than re-emitting the same packet.
        let block = build_synthetic_block(&[b"only one"], ffi::TP_STATUS_USER);
        let mut iter = iter_from_block(&block, 10);

        let pkt = iter.next().unwrap();
        assert_eq!(pkt.data(), b"only one");
        assert!(
            iter.next().is_none(),
            "iterator must terminate on tp_next_offset == 0 marker"
        );
        assert!(iter.next().is_none(), "subsequent calls remain None");
    }

    #[test]
    fn batch_iter_walks_three_then_stops() {
        // Well-formed three-packet block: walk all three, stop on the third's
        // tp_next_offset == 0 marker.
        let block = build_synthetic_block(&[b"a", b"bb", b"ccc"], ffi::TP_STATUS_USER);
        let mut iter = iter_from_block(&block, 3);

        assert_eq!(iter.next().unwrap().data(), b"a");
        assert_eq!(iter.next().unwrap().data(), b"bb");
        assert_eq!(iter.next().unwrap().data(), b"ccc");
        assert!(iter.next().is_none());
    }

    #[test]
    fn packet_to_owned_roundtrip() {
        let data = b"test packet data";
        let block = build_synthetic_block(&[data], ffi::TP_STATUS_USER);
        let mut iter = iter_from_block(&block, 1);
        let pkt = iter.next().unwrap();

        let owned = pkt.to_owned();
        assert_eq!(owned.data, data);
        assert_eq!(owned.timestamp.sec, 1000);
        assert_eq!(owned.original_len, data.len());
    }

    #[test]
    fn batch_timed_out_flag() {
        let block = build_synthetic_block(&[b"data"], ffi::TP_STATUS_USER | ffi::TP_STATUS_BLK_TMO);
        let bd = NonNull::new(block.as_ptr() as *mut ffi::tpacket_block_desc).unwrap();
        let batch = unsafe { PacketBatch::new(bd) };
        assert!(batch.timed_out());
        // Prevent Drop from writing to the block (it's stack memory)
        std::mem::forget(batch);
    }

    #[test]
    fn batch_not_timed_out() {
        let block = build_synthetic_block(&[b"data"], ffi::TP_STATUS_USER);
        let bd = NonNull::new(block.as_ptr() as *mut ffi::tpacket_block_desc).unwrap();
        let batch = unsafe { PacketBatch::new(bd) };
        assert!(!batch.timed_out());
        std::mem::forget(batch);
    }

    #[test]
    fn batch_seq_num() {
        let block = build_synthetic_block(&[b"data"], ffi::TP_STATUS_USER);
        let bd = NonNull::new(block.as_ptr() as *mut ffi::tpacket_block_desc).unwrap();
        let batch = unsafe { PacketBatch::new(bd) };
        assert_eq!(batch.seq_num(), 1);
        std::mem::forget(batch);
    }

    #[test]
    fn batch_len_and_is_empty() {
        let block_with = build_synthetic_block(&[b"a", b"b"], ffi::TP_STATUS_USER);
        let bd = NonNull::new(block_with.as_ptr() as *mut ffi::tpacket_block_desc).unwrap();
        let batch = unsafe { PacketBatch::new(bd) };
        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
        std::mem::forget(batch);

        let block_empty = build_synthetic_block(&[], ffi::TP_STATUS_USER);
        let bd = NonNull::new(block_empty.as_ptr() as *mut ffi::tpacket_block_desc).unwrap();
        let batch = unsafe { PacketBatch::new(bd) };
        assert_eq!(batch.len(), 0);
        assert!(batch.is_empty());
        std::mem::forget(batch);
    }
}
