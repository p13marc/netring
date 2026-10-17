//! Packet types: zero-copy views, batch iteration, timestamps, and owned packets.

use std::marker::PhantomData;
use std::ptr::NonNull;

use crate::afpacket::ffi;
use crate::afpacket::ring::{self, MmapRing};

pub use flowscope::Timestamp;

/// Decoded per-packet status flags from `tpacket3_hdr.tp_status`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
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

/// Which clock produced a packet's [`timestamp`](Packet::timestamp) (issue #40).
///
/// AF_PACKET stamps each frame and records the source in `tp_status`. A
/// hardware request silently falls back to software per-packet when the NIC
/// or driver can't honor it, so the *actual* source is only knowable here —
/// critical for forensic / PTP timing where a software stamp (taken after
/// IRQ coalescing, NAPI batching, and the kernel→user copy) can be tens of
/// microseconds to milliseconds off the wire arrival.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimestampClock {
    /// No timestamp-source flag was set — the kernel's default software
    /// stamp (taken in the RX softirq). The common case unless a hardware
    /// source was both requested *and* honored.
    #[default]
    None,
    /// Kernel software timestamp (`TP_STATUS_TS_SOFTWARE`).
    Software,
    /// System-adjusted hardware timestamp (`TP_STATUS_TS_SYS_HARDWARE`).
    /// Deprecated in the kernel; present for completeness.
    SysHardware,
    /// Raw NIC hardware timestamp (`TP_STATUS_TS_RAW_HARDWARE`) — taken at
    /// the MAC/PHY, immune to IRQ/NAPI/scheduler/copy jitter.
    ///
    /// The value is in the NIC's PTP Hardware Clock base, which is often
    /// **TAI, not UTC**, and not system time — don't compare it to a
    /// software clock without translating through the PHC offset.
    RawHardware,
}

impl TimestampClock {
    /// Decode the timestamp source from a raw `tp_status` bitmask.
    #[inline]
    pub fn from_status(status: u32) -> Self {
        if status & ffi::TP_STATUS_TS_RAW_HARDWARE != 0 {
            Self::RawHardware
        } else if status & ffi::TP_STATUS_TS_SYS_HARDWARE != 0 {
            Self::SysHardware
        } else if status & ffi::TP_STATUS_TS_SOFTWARE != 0 {
            Self::Software
        } else {
            Self::None
        }
    }

    /// `true` for a NIC hardware clock (`RawHardware` / `SysHardware`) — the
    /// jitter-immune sources. `false` for software / none.
    #[inline]
    pub fn is_hardware(self) -> bool {
        matches!(self, Self::RawHardware | Self::SysHardware)
    }
}

/// An owned copy of a captured packet, independent of the ring buffer.
///
/// Created via [`Packet::to_owned()`]. Carries enough metadata for DPI,
/// flow tracking, and PCAP-style export — the trade-off is ~50 bytes per
/// owned packet vs the bare-data minimum.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OwnedPacket {
    /// Raw packet bytes (from MAC header).
    pub data: Vec<u8>,
    /// Kernel timestamp.
    pub timestamp: Timestamp,
    /// Which clock produced [`timestamp`](Self::timestamp) (issue #40).
    /// `TimestampClock::None` for sources that don't report it (pcap replay,
    /// AF_XDP).
    pub timestamp_clock: TimestampClock,
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

    /// Which clock produced [`timestamp()`](Self::timestamp) — decoded from
    /// `tp_status` (issue #40). A hardware request can silently fall back to
    /// software per-packet, so this reports the *actual* source, not the
    /// requested one. See [`TimestampClock`].
    #[inline]
    pub fn timestamp_clock(&self) -> TimestampClock {
        TimestampClock::from_status(self.hdr.tp_status)
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
            timestamp_clock: self.timestamp_clock(),
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
/// **RAII**: dropping the batch returns the **whole** block to the kernel
/// by writing `TP_STATUS_KERNEL` with `Release` ordering — including any
/// packets of it that were not iterated. A batch taken after a partly
/// consumed [`Packets`](crate::Packets) loop holds only the packets that
/// loop left unread ([`len`](Self::len) counts those).
///
/// Only one batch can be live at a time per [`Capture`](crate::Capture)
/// (enforced by `&mut self` on [`next_batch()`](crate::traits::PacketSource::next_batch)).
pub struct PacketBatch<'a> {
    block: NonNull<ffi::tpacket_block_desc>,
    /// Packets left to iterate (the block's `num_pkts` for a fresh block).
    remaining: u32,
    block_status: u32,
    seq_num: u64,
    /// Offset of the next `tpacket3_hdr` from the block base.
    first_offset: u32,
    blk_len: u32,
    ts_first: Timestamp,
    ts_last: Timestamp,
    _marker: PhantomData<&'a MmapRing>,
}

impl<'a> PacketBatch<'a> {
    /// Create a batch over a whole block. The block must be in
    /// `TP_STATUS_USER` state.
    ///
    /// # Safety
    ///
    /// - `block` must point to a valid `tpacket_block_desc` in an mmap'd region.
    /// - The block must have been read with `Acquire` ordering before calling this.
    /// - The caller must ensure the block is not released while this batch exists.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) unsafe fn new(block: NonNull<ffi::tpacket_block_desc>) -> Self {
        // SAFETY: caller guarantees block is valid and user-owned; the
        // fields are read by value through the raw pointer.
        let (first_offset, num_pkts) = unsafe {
            let bh1 = &raw const (*block.as_ptr()).hdr.bh1;
            ((*bh1).offset_to_first_pkt, (*bh1).num_pkts)
        };
        // SAFETY: forwarded from the caller.
        unsafe { Self::resume(block, first_offset, num_pkts) }
    }

    /// Create a batch over the packets of `block` from the `tpacket3_hdr`
    /// at `first_offset` (from the block base), `remaining` of them — the
    /// rest of a block a [`Packets`](crate::Packets) loop left partly read.
    ///
    /// # Safety
    ///
    /// As [`new`](Self::new); additionally `first_offset` must be the
    /// offset of a packet header of this block (as left by
    /// [`BatchIter::position`]).
    pub(crate) unsafe fn resume(
        block: NonNull<ffi::tpacket_block_desc>,
        first_offset: u32,
        remaining: u32,
    ) -> Self {
        // SAFETY: caller guarantees block is valid and user-owned. Every
        // field is read by value through the raw pointer: no reference
        // to the block outlives this function.
        let (block_status, seq_num, blk_len, ts_first, ts_last) = unsafe {
            let bh1 = &raw const (*block.as_ptr()).hdr.bh1;
            (
                (*bh1).block_status,
                (*bh1).seq_num,
                (*bh1).blk_len,
                // libc names the field ts_usec, but TPACKET_V3 stores
                // nanoseconds there.
                Timestamp::new((*bh1).ts_first_pkt.ts_sec, (*bh1).ts_first_pkt.ts_usec),
                Timestamp::new((*bh1).ts_last_pkt.ts_sec, (*bh1).ts_last_pkt.ts_usec),
            )
        };

        Self {
            block,
            remaining,
            block_status,
            seq_num,
            first_offset,
            blk_len,
            ts_first,
            ts_last,
            _marker: PhantomData,
        }
    }

    /// Number of packets in this batch: the packets left to read in the
    /// block (all of them, unless a [`Packets`](crate::Packets) loop
    /// already lent some).
    #[inline]
    pub fn len(&self) -> usize {
        self.remaining as usize
    }

    /// Whether the batch is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining == 0
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
    ///
    /// The packets borrow the batch, not the capture: dropping the batch
    /// hands its block back to the kernel, so a packet must not outlive it.
    /// Keeping packets past the batch is a **compile error**:
    ///
    /// ```compile_fail
    /// # fn f(cap: &mut netring::Capture) {
    /// let pkts: Vec<netring::Packet<'_>> = match cap.next_batch() {
    ///     Some(batch) => batch.iter().collect(), // error: `batch` dropped while borrowed
    ///     None => Vec::new(),
    /// };
    /// # let _ = pkts;
    /// # }
    /// ```
    ///
    /// Copy a packet out with [`Packet::to_owned`] to keep it longer.
    pub fn iter(&self) -> BatchIter<'_> {
        // SAFETY: the batch holds the user-owned block for `'_`; its
        // `first_offset` / `remaining` / `blk_len` came from the block
        // header or from a `BatchIter::position` over the same block.
        unsafe { BatchIter::at(self.block, self.first_offset, self.remaining, self.blk_len) }
    }
}

impl<'b> IntoIterator for &'b PacketBatch<'_> {
    type Item = Packet<'b>;
    type IntoIter = BatchIter<'b>;

    fn into_iter(self) -> BatchIter<'b> {
        self.iter()
    }
}

impl std::fmt::Debug for PacketBatch<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketBatch")
            .field("len", &self.remaining)
            .field("seq_num", &self.seq_num)
            .field("timed_out", &self.timed_out())
            .finish()
    }
}

impl Drop for PacketBatch<'_> {
    fn drop(&mut self) {
        // SAFETY: self.block is valid (from construction) and we're done
        // reading. The whole block goes back, unread packets included.
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

impl<'a> BatchIter<'a> {
    /// An iterator over `remaining` packets of `block`, starting at the
    /// `tpacket3_hdr` `offset` bytes from the block base; `blk_len` is the
    /// block's used length (`bh1.blk_len`), the bound every header and
    /// packet is checked against.
    ///
    /// # Safety
    ///
    /// `block` must point to a user-owned block of the mmap ring (or a
    /// test buffer) at least `blk_len` bytes long that stays valid and
    /// user-owned for `'a`.
    #[inline]
    pub(crate) unsafe fn at(
        block: NonNull<ffi::tpacket_block_desc>,
        offset: u32,
        remaining: u32,
        blk_len: u32,
    ) -> Self {
        let base = block.as_ptr().cast::<u8>().cast_const();
        BatchIter {
            current: base.map_addr(|a| a + offset as usize),
            remaining,
            block_end: base.map_addr(|a| a + blk_len as usize),
            _marker: PhantomData,
        }
    }

    /// Where the iteration stands, relative to `block` (the block it was
    /// created over): the offset of the next packet header from the block
    /// base and the packets left — what [`at`](Self::at) needs to resume.
    /// `remaining == 0` once the block is exhausted (including when the
    /// kernel's last-packet marker ended it early).
    #[inline]
    pub(crate) fn position(&self, block: NonNull<ffi::tpacket_block_desc>) -> (u32, u32) {
        let offset = self.current.addr().wrapping_sub(block.as_ptr().addr());
        (offset as u32, self.remaining)
    }
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
    fn timestamp_clock_decodes_priority_raw_over_sys_over_software() {
        use crate::afpacket::ffi;
        assert_eq!(TimestampClock::from_status(0), TimestampClock::None);
        assert_eq!(
            TimestampClock::from_status(ffi::TP_STATUS_TS_SOFTWARE),
            TimestampClock::Software
        );
        assert_eq!(
            TimestampClock::from_status(ffi::TP_STATUS_TS_SYS_HARDWARE),
            TimestampClock::SysHardware
        );
        assert_eq!(
            TimestampClock::from_status(ffi::TP_STATUS_TS_RAW_HARDWARE),
            TimestampClock::RawHardware
        );
        // Raw wins if multiple bits are set (it's the most precise).
        let both = ffi::TP_STATUS_TS_RAW_HARDWARE | ffi::TP_STATUS_TS_SOFTWARE;
        assert_eq!(
            TimestampClock::from_status(both),
            TimestampClock::RawHardware
        );
        // Coexists with unrelated status bits (e.g. VLAN_VALID) without confusion.
        let mixed = ffi::TP_STATUS_TS_SOFTWARE | ffi::TP_STATUS_VLAN_VALID;
        assert_eq!(TimestampClock::from_status(mixed), TimestampClock::Software);
    }

    #[test]
    fn timestamp_clock_is_hardware_classifies_sources() {
        assert!(TimestampClock::RawHardware.is_hardware());
        assert!(TimestampClock::SysHardware.is_hardware());
        assert!(!TimestampClock::Software.is_hardware());
        assert!(!TimestampClock::None.is_hardware());
        assert_eq!(TimestampClock::default(), TimestampClock::None);
    }

    #[test]
    fn owned_packet_clone() {
        let pkt = OwnedPacket {
            data: vec![0xDE, 0xAD],
            timestamp: Timestamp::new(1, 2),
            timestamp_clock: TimestampClock::Software,
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

    /// 8-byte-aligned owned byte buffer for synthetic TPACKET_V3 blocks.
    ///
    /// A plain `Vec<u8>` is only 1-aligned; casting it to
    /// `tpacket_block_desc` / `tpacket3_hdr` (which require 8-alignment) and
    /// writing through the pointer is Undefined Behaviour — miri flags it under
    /// `-Zmiri-strict-provenance`. Backing the buffer with `Vec<u64>`
    /// guarantees 8-alignment. (In production the real mmap ring is
    /// page-aligned, so this only matters for these synthetic tests.)
    struct AlignedBlock {
        words: Vec<u64>,
        len: usize,
    }

    impl AlignedBlock {
        fn zeroed(len: usize) -> Self {
            Self {
                words: vec![0u64; len.div_ceil(8)],
                len,
            }
        }
    }

    impl std::ops::Deref for AlignedBlock {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            // SAFETY: `words` owns `len.div_ceil(8) * 8 >= len` zero-initialized,
            // 8-aligned bytes; reinterpreting the `len`-byte prefix is sound.
            unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
        }
    }

    impl std::ops::DerefMut for AlignedBlock {
        fn deref_mut(&mut self) -> &mut [u8] {
            // SAFETY: as `deref`, with unique access.
            unsafe {
                std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast::<u8>(), self.len)
            }
        }
    }

    /// Build a synthetic TPACKET_V3 block with the given packet payloads.
    /// Returns an 8-aligned buffer usable as a fake mmap block.
    fn build_synthetic_block(packets: &[&[u8]], block_status: u32) -> AlignedBlock {
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

        let mut block = AlignedBlock::zeroed(block_size);

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

    /// The (offset, remaining) a fresh iterator over `block` starts from.
    fn block_start(block: &mut AlignedBlock) -> (NonNull<ffi::tpacket_block_desc>, u32, u32, u32) {
        let bd = NonNull::new(block.as_mut_ptr().cast::<ffi::tpacket_block_desc>()).unwrap();
        // SAFETY: the synthetic block header was written by build_synthetic_block.
        let (off, n, len) = unsafe {
            let bh1 = &raw const (*bd.as_ptr()).hdr.bh1;
            ((*bh1).offset_to_first_pkt, (*bh1).num_pkts, (*bh1).blk_len)
        };
        (bd, off, n, len)
    }

    /// #211: an iterator's position resumes the walk exactly where it
    /// stopped — what `Capture` keeps across `Packets` values.
    #[test]
    fn batch_iter_resumes_from_position() {
        let mut block = build_synthetic_block(&[b"one", b"two!", b"three"], ffi::TP_STATUS_USER);
        let (bd, off, n, blk_len) = block_start(&mut block);
        assert_eq!(n, 3);

        // SAFETY: `block` outlives every iterator below and is not moved.
        let mut first = unsafe { BatchIter::at(bd, off, n, blk_len) };
        assert_eq!(first.next().unwrap().data(), b"one");
        let (pos, rem) = first.position(bd);
        assert_eq!(rem, 2);
        assert!(pos > off, "the cursor moved past the first header");

        // SAFETY: as above.
        let mut resumed = unsafe { BatchIter::at(bd, pos, rem, blk_len) };
        let pkt = resumed.next().unwrap();
        assert_eq!(pkt.data(), b"two!");
        assert_eq!(pkt.timestamp().sec, 1001, "the second packet's own header");
        assert_eq!(resumed.position(bd).1, 1);
        assert_eq!(resumed.next().unwrap().data(), b"three");
        // The last packet (tp_next_offset == 0) exhausts the walk.
        assert_eq!(resumed.position(bd).1, 0);
        assert!(resumed.next().is_none());

        // Resuming an exhausted position yields nothing.
        let (pos, rem) = resumed.position(bd);
        // SAFETY: as above.
        assert!(
            unsafe { BatchIter::at(bd, pos, rem, blk_len) }
                .next()
                .is_none()
        );
    }

    /// #211: a batch resumed mid-block counts and yields only the packets
    /// left, and dropping it hands the whole block back to the kernel.
    #[test]
    fn resumed_batch_len_is_remaining() {
        let mut block = build_synthetic_block(&[b"a", b"bb", b"ccc", b"dddd"], ffi::TP_STATUS_USER);
        let (bd, off, n, blk_len) = block_start(&mut block);
        // SAFETY: as in batch_iter_resumes_from_position.
        let mut it = unsafe { BatchIter::at(bd, off, n, blk_len) };
        it.next();
        let (pos, rem) = it.position(bd);
        assert_eq!(rem, 3);

        // SAFETY: the synthetic block is "user-owned" and outlives the batch.
        let batch = unsafe { PacketBatch::resume(bd, pos, rem) };
        assert_eq!(batch.len(), 3);
        assert!(!batch.is_empty());
        let got: Vec<&[u8]> = batch.iter().map(|p| p.data()).collect();
        assert_eq!(got, [&b"bb"[..], b"ccc", b"dddd"]);
        // Iterating does not consume the batch.
        assert_eq!(batch.iter().count(), 3);
        drop(batch);

        // SAFETY: header still in place; read by value.
        let status = unsafe { (*bd.as_ptr()).hdr.bh1.block_status };
        assert_eq!(
            status,
            ffi::TP_STATUS_KERNEL,
            "the whole block was released"
        );

        // A fresh batch over the block is the whole block.
        // SAFETY: as above.
        let whole = unsafe { PacketBatch::new(bd) };
        assert_eq!(whole.len(), 4);
        std::mem::forget(whole);
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
