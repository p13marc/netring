//! Packet types: zero-copy views, batch iteration, timestamps, and owned packets.

use std::marker::PhantomData;
use std::ptr::NonNull;

use crate::afpacket::ffi;
use crate::afpacket::ring::{self, MmapRing};
use crate::config::BpfAncillary;

pub use flowscope::Timestamp;
use flowscope::{RxMetadata, VlanProto, VlanTag};

/// Map a VLAN TPID (EtherType) to [`VlanProto`].
#[inline]
pub(crate) fn vlan_proto(tpid: u16) -> VlanProto {
    match tpid {
        0x8100 => VlanProto::Dot1Q,
        0x88a8 => VlanProto::Dot1Ad,
        other => VlanProto::Other(other),
    }
}

/// [`BpfAncillary`] for a packet whose reported tag is `vlan`, re-inserted
/// into the frame or not.
#[inline]
fn ancillary(vlan: Option<VlanTag>, reinserted: bool) -> BpfAncillary {
    match (vlan, reinserted) {
        (None, _) => BpfAncillary::NONE,
        (Some(t), false) => BpfAncillary::stripped(t),
        (Some(t), true) => BpfAncillary::reinserted(t),
    }
}

/// A [`flowscope::PacketView`] of `data` whose `rx_metadata.vlan` is the
/// tag **not** in `data` (flowscope's meaning: a tag stripped from the
/// frame), if any.
#[inline]
fn view_of<'a>(
    data: &'a [u8],
    ts: Timestamp,
    stripped: Option<VlanTag>,
) -> flowscope::PacketView<'a> {
    let view = flowscope::PacketView::new(data, ts);
    match stripped {
        None => view,
        Some(t) => {
            let mut meta = RxMetadata::default();
            meta.vlan = Some(t);
            view.with_rx_metadata(meta)
        }
    }
}

/// Decoded per-packet status flags from `tpacket3_hdr.tp_status`.
///
/// Drop notification is per **block** on TPACKET_V3 (the kernel sets
/// `TP_STATUS_LOSING` only on the block status, in `prb_close_block`):
/// see [`PacketBatch::losing`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PacketStatus {
    /// Fewer bytes were captured than the packet had on the wire
    /// ([`Packet::len`] < [`Packet::original_len`]): cut by a
    /// [snap length](crate::CaptureBuilder::snap_len) or a socket filter's
    /// return value. Always `false` for AF_XDP and pcap-replay packets.
    pub truncated: bool,
    /// VLAN TCI field is valid.
    pub vlan_valid: bool,
    /// VLAN TPID field is valid.
    pub vlan_tpid_valid: bool,
    /// The VLAN tag the kernel stripped was re-inserted into the packet
    /// data at bytes 12..16 ([`CaptureBuilder::vlan_reinsert`](crate::CaptureBuilder::vlan_reinsert)).
    /// When `false` but [`Packet::vlan`] is `Some`, the tag is only in the
    /// metadata ([`Packet::stripped_vlan`]).
    pub vlan_reinserted: bool,
    /// Hardware checksum is verified correct.
    pub csum_valid: bool,
    /// Checksum not yet computed (TX offload pending).
    pub csum_not_ready: bool,
    /// Packet is a TCP GSO segment.
    pub gso_tcp: bool,
}

impl PacketStatus {
    /// Decode status flags from the raw `tp_status` bitmask.
    ///
    /// Only the bits: `truncated` here is `TP_STATUS_COPY`, which the
    /// kernel sets on TPACKET_V1/V2 only, and `vlan_reinserted` is `false`.
    /// [`Packet::status`] derives `truncated` from the captured and wire
    /// lengths and `vlan_reinserted` from the ring header instead.
    #[inline]
    pub fn from_raw(status: u32) -> Self {
        Self {
            truncated: status & ffi::TP_STATUS_COPY != 0,
            vlan_valid: status & ffi::TP_STATUS_VLAN_VALID != 0,
            vlan_tpid_valid: status & ffi::TP_STATUS_VLAN_TPID_VALID != 0,
            vlan_reinserted: false,
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
    /// The outer VLAN tag the kernel (or, for AF_XDP, the NIC) took out of
    /// the frame — see [`Packet::vlan`]. Whether it is back in
    /// [`data`](Self::data) is [`status.vlan_reinserted`](PacketStatus::vlan_reinserted);
    /// [`stripped_vlan`](Self::stripped_vlan) is the tag when it is not.
    /// `None` for pcap replay (tags stay in the frame there).
    pub vlan: Option<VlanTag>,
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

    /// The tag in [`vlan`](Self::vlan) when it is **not** in
    /// [`data`](Self::data). See [`Packet::stripped_vlan`].
    #[inline]
    pub fn stripped_vlan(&self) -> Option<VlanTag> {
        self.vlan.filter(|_| !self.status.vlan_reinserted)
    }

    /// The ancillary data the socket filter saw for this packet: with
    /// [`BpfFilter::matches_with`](crate::BpfFilter::matches_with) it
    /// gives the kernel's verdict. See [`Packet::bpf_ancillary`].
    #[inline]
    pub fn bpf_ancillary(&self) -> BpfAncillary {
        ancillary(self.vlan, self.status.vlan_reinserted)
    }

    /// View this packet as a [`flowscope::PacketView`]; `rx_metadata.vlan`
    /// carries [`stripped_vlan`](Self::stripped_vlan). See [`Packet::view`].
    #[inline]
    pub fn view(&self) -> flowscope::PacketView<'_> {
        view_of(&self.data, self.timestamp, self.stripped_vlan())
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
    /// The `sockaddr_ll` behind the header. Its own reference (derived from
    /// the block pointer, like `hdr`), not an offset from `hdr`: a pointer
    /// derived from `&tpacket3_hdr` may only reach that header's 48 bytes.
    sll: &'a ffi::sockaddr_ll,
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

    /// Per-packet status flags. `truncated` is `len() < original_len()`;
    /// `vlan_reinserted` says whether [`vlan`](Self::vlan) is in
    /// [`data`](Self::data).
    #[inline]
    pub fn status(&self) -> PacketStatus {
        PacketStatus {
            truncated: self.hdr.tp_snaplen < self.hdr.tp_len,
            vlan_reinserted: self.vlan_reinserted(),
            ..PacketStatus::from_raw(self.hdr.tp_status)
        }
    }

    /// RX flow hash (requires `fill_rxhash` — enabled by default).
    #[inline]
    pub fn rxhash(&self) -> u32 {
        self.hdr.hv1.tp_rxhash
    }

    /// The outer VLAN tag the kernel took out of the frame (#209): Linux
    /// strips an outer 802.1Q / 802.1ad tag before packet taps run (or the
    /// NIC / veth never put it in the frame) and reports it in the ring
    /// header. `Some` whether or not netring put it back in
    /// [`data`](Self::data) — [`status().vlan_reinserted`](PacketStatus::vlan_reinserted)
    /// says which. `None` for an untagged frame and for tags that stayed in
    /// the frame (a QinQ inner tag, `0x9100`).
    ///
    /// The TPID is the reported one, or 802.1Q when the kernel reported a
    /// TCI without one (libpcap's rule).
    #[inline]
    pub fn vlan(&self) -> Option<VlanTag> {
        let hv1 = &self.hdr.hv1;
        let status = self.hdr.tp_status;
        if hv1.tp_vlan_tci == 0 && status & ffi::TP_STATUS_VLAN_VALID == 0 {
            return None;
        }
        let tpid = if status & ffi::TP_STATUS_VLAN_TPID_VALID != 0 || hv1.tp_vlan_tpid != 0 {
            hv1.tp_vlan_tpid
        } else {
            0x8100
        };
        Some(VlanTag::new(hv1.tp_vlan_tci as u16, vlan_proto(tpid)))
    }

    /// The tag the kernel stripped when it is **not** in
    /// [`data`](Self::data): VLAN re-insertion off
    /// ([`CaptureBuilder::vlan_reinsert(false)`](crate::CaptureBuilder::vlan_reinsert)),
    /// no room in front of the frame, or a non-Ethernet device. `None` when
    /// the frame was untagged or the tag is back in the data.
    #[inline]
    pub fn stripped_vlan(&self) -> Option<VlanTag> {
        self.vlan().filter(|_| !self.vlan_reinserted())
    }

    /// The ancillary data the socket filter saw for this packet (#208): the
    /// stripped tag, and whether it is back in [`data`](Self::data). For a
    /// classic filter `f` installed on the capture,
    /// `f.matches_with(pkt.data(), &pkt.bpf_ancillary())` is the verdict
    /// the kernel gave this packet.
    #[inline]
    pub fn bpf_ancillary(&self) -> BpfAncillary {
        ancillary(self.vlan(), self.vlan_reinserted())
    }

    /// Whether netring re-inserted the stripped tag into the data.
    #[inline]
    fn vlan_reinserted(&self) -> bool {
        self.hdr.hv1.tp_padding == ffi::NETRING_VLAN_REINSERTED
    }

    /// Packet direction relative to the capturing host.
    ///
    /// Decoded from `sockaddr_ll.sll_pkttype` in the ring buffer metadata.
    /// The `sockaddr_ll` is located after the `tpacket3_hdr` at offset
    /// `TPACKET_ALIGN(sizeof(tpacket3_hdr))`.
    #[inline]
    pub fn direction(&self) -> PacketDirection {
        PacketDirection::from_raw(self.sll.sll_pkttype)
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
        let len = self.sll.sll_halen as usize;
        &self.sll.sll_addr[..len.min(8)]
    }

    /// EtherType / protocol from link-layer metadata (network byte order).
    #[inline]
    pub fn ll_protocol(&self) -> u16 {
        u16::from_be(self.sll.sll_protocol)
    }

    /// Copy packet data and metadata out of the ring for long-lived storage.
    ///
    /// Captures every metadata field the ring exposes — see [`OwnedPacket`]
    /// for the full set. Costs one heap allocation (the data Vec) plus
    /// a fixed-size struct copy.
    pub fn to_owned(&self) -> OwnedPacket {
        let sll = self.sll;
        OwnedPacket {
            data: self.data.to_vec(),
            timestamp: self.timestamp(),
            timestamp_clock: self.timestamp_clock(),
            original_len: self.original_len(),
            status: self.status(),
            direction: PacketDirection::from_raw(sll.sll_pkttype),
            rxhash: self.hdr.hv1.tp_rxhash,
            vlan: self.vlan(),
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
    /// timestamp. `rx_metadata.vlan` is set only from
    /// [`stripped_vlan`](Self::stripped_vlan) — flowscope's meaning, a tag
    /// that is not in the frame; a re-inserted tag is parsed from the data.
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
        view_of(self.data, self.timestamp(), self.stripped_vlan())
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

// ── VLAN re-insertion (#209) ───────────────────────────────────────────────

/// Whether a batch re-inserts the stripped VLAN tag of each packet into its
/// data as the packet is first iterated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum VlanMode {
    /// Leave the ring as the kernel wrote it.
    #[default]
    Off,
    /// Re-insert (libpcap's behaviour); the captured length grows by the
    /// tag's 4 bytes but never past `snap_cap` (the capture's snap length).
    Reinsert { snap_cap: u32 },
}

/// Offset of the `sockaddr_ll` from a `tpacket3_hdr`.
const SLL_OFFSET: usize = ffi::tpacket_align(std::mem::size_of::<ffi::tpacket3_hdr>());

/// Move a packet's stripped VLAN tag back into its data, in place in the
/// ring — what libpcap does (pcap-linux.c, `pcap_handle_packet_mmap`): the
/// 12 MAC bytes move 4 bytes towards the header and the tag (TPID, TCI)
/// fills the gap in front of the EtherType. `tp_mac` moves back by 4,
/// `tp_len` grows by 4 and `tp_snaplen` by up to 4 (capped at `snap_cap`),
/// and [`ffi::NETRING_VLAN_REINSERTED`] in `hv1.tp_padding` makes the
/// rewrite happen once. The `tci` / `tpid` / `TP_STATUS_VLAN_VALID` fields
/// are kept, so [`Packet::vlan`] still reports the tag.
///
/// Skipped (left as the kernel wrote it) when already done, when the kernel
/// reported no tag (`tci == 0` and no `TP_STATUS_VLAN_VALID`), on a
/// non-Ethernet device, when fewer than 12 bytes were captured, or when
/// there is no room for the tag between the `sockaddr_ll` and the frame.
///
/// # Safety
///
/// `hdr` must point to a `tpacket3_hdr` of a user-owned ring block, with
/// write provenance over the packet's header, `sockaddr_ll` and data, and
/// the caller must have checked that the header, the `sockaddr_ll` and
/// `tp_mac + tp_snaplen` bytes from `hdr` lie in the block. No reference to
/// this packet's header, `sockaddr_ll` or data may be live.
unsafe fn reinsert_vlan(hdr: *mut ffi::tpacket3_hdr, snap_cap: u32) {
    const ETH_ADDRS: usize = 12;
    // SAFETY: all reads and writes below go through `hdr` (or pointers
    // derived from it) and stay inside the checked region: the header, the
    // `sockaddr_ll` at SLL_OFFSET, and `[mac - 4, mac + 12)` with
    // `mac - 4 >= SLL_OFFSET + sizeof(sockaddr_ll)` and `12 <= snaplen`.
    unsafe {
        let hv1 = &raw mut (*hdr).hv1;
        if (*hv1).tp_padding == ffi::NETRING_VLAN_REINSERTED {
            return;
        }
        let status = (*hdr).tp_status;
        let tci = (*hv1).tp_vlan_tci;
        if tci == 0 && status & ffi::TP_STATUS_VLAN_VALID == 0 {
            return;
        }
        let sll = hdr.cast::<u8>().add(SLL_OFFSET).cast::<ffi::sockaddr_ll>();
        if (*sll).sll_hatype != ffi::ARPHRD_ETHER {
            return;
        }
        let snaplen = (*hdr).tp_snaplen;
        if (snaplen as usize) < ETH_ADDRS {
            return;
        }
        let mac = usize::from((*hdr).tp_mac);
        if mac < SLL_OFFSET + std::mem::size_of::<ffi::sockaddr_ll>() + ffi::VLAN_TAG_LEN {
            return;
        }
        let tpid = if status & ffi::TP_STATUS_VLAN_TPID_VALID != 0 || (*hv1).tp_vlan_tpid != 0 {
            (*hv1).tp_vlan_tpid
        } else {
            0x8100
        };

        let data = hdr.cast::<u8>().add(mac);
        let moved = data.sub(ffi::VLAN_TAG_LEN);
        std::ptr::copy(data, moved, ETH_ADDRS);
        std::ptr::copy_nonoverlapping(tpid.to_be_bytes().as_ptr(), moved.add(ETH_ADDRS), 2);
        std::ptr::copy_nonoverlapping(
            (tci as u16).to_be_bytes().as_ptr(),
            moved.add(ETH_ADDRS + 2),
            2,
        );
        (*hdr).tp_mac = (mac - ffi::VLAN_TAG_LEN) as u16;
        (*hdr).tp_len = (*hdr).tp_len.saturating_add(ffi::VLAN_TAG_LEN as u32);
        (*hdr).tp_snaplen = snaplen
            .saturating_add(ffi::VLAN_TAG_LEN as u32)
            .min(snap_cap);
        (*hv1).tp_padding = ffi::NETRING_VLAN_REINSERTED;
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
    /// Re-insert stripped VLAN tags while iterating.
    vlan: VlanMode,
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
            vlan: VlanMode::Off,
            _marker: PhantomData,
        }
    }

    /// Re-insert (or not) the stripped VLAN tag of each packet as it is
    /// first iterated (see [`VlanMode`]).
    #[inline]
    pub(crate) fn with_vlan_mode(mut self, vlan: VlanMode) -> Self {
        self.vlan = vlan;
        self
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

    /// Whether the socket was dropping packets when the kernel closed this
    /// block: `TP_STATUS_LOSING` on the block status, set when the drop
    /// counter was non-zero — that is, packets were dropped **since the
    /// previous kernel statistics read** ([`Capture::stats`](crate::Capture::stats)
    /// resets it). TPACKET_V3 reports loss per block, not per packet.
    pub fn losing(&self) -> bool {
        self.block_status & ffi::TP_STATUS_LOSING != 0
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
            .with_vlan_mode(self.vlan)
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
/// checks before constructing each packet reference. On a capture with
/// [`vlan_reinsert`](crate::CaptureBuilder::vlan_reinsert) on (the
/// default), it moves each packet's stripped VLAN tag back into the data
/// before lending the packet.
pub struct BatchIter<'a> {
    /// The next `tpacket3_hdr`; carries the block's (write) provenance.
    current: *mut u8,
    remaining: u32,
    block_end: *mut u8,
    vlan: VlanMode,
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
        let base = block.as_ptr().cast::<u8>();
        BatchIter {
            current: base.map_addr(|a| a + offset as usize),
            remaining,
            block_end: base.map_addr(|a| a + blk_len as usize),
            vlan: VlanMode::Off,
            _marker: PhantomData,
        }
    }

    /// See [`PacketBatch::with_vlan_mode`].
    #[inline]
    pub(crate) fn with_vlan_mode(mut self, vlan: VlanMode) -> Self {
        self.vlan = vlan;
        self
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
        let hdr_plus_sll = SLL_OFFSET + std::mem::size_of::<ffi::sockaddr_ll>();

        // Bounds check: header + sockaddr_ll must fit within block
        if self.current.addr() + hdr_plus_sll > self.block_end.addr() {
            tracing::warn!("BatchIter: tpacket3_hdr extends past block boundary, stopping");
            self.remaining = 0;
            return None;
        }

        let hdr_ptr = self.current.cast::<ffi::tpacket3_hdr>();
        // Bounds check: the packet data must fit within the block.
        // SAFETY: the header lies in the block (checked above) and is
        // TPACKET_ALIGNMENT-aligned; its fields are read through the raw
        // pointer — no reference to this packet exists yet.
        let data_end = |hdr: *mut ffi::tpacket3_hdr| unsafe {
            hdr.addr()
                .saturating_add(usize::from((*hdr).tp_mac))
                .saturating_add((*hdr).tp_snaplen as usize)
        };
        if data_end(hdr_ptr) > self.block_end.addr() {
            tracing::warn!("BatchIter: packet data extends past block boundary, stopping");
            self.remaining = 0;
            return None;
        }

        if let VlanMode::Reinsert { snap_cap } = self.vlan {
            // SAFETY: header, sockaddr_ll and data lie in the user-owned
            // block (checked above); `current` carries the block's write
            // provenance; no reference to this packet has been created yet
            // (a packet is rewritten before it is first lent, and only once
            // — the marker makes later passes read-only).
            unsafe { reinsert_vlan(hdr_ptr, snap_cap) };
            // The rewrite only moves the data start back into the gap in
            // front of it; re-check anyway.
            if data_end(hdr_ptr) > self.block_end.addr() {
                tracing::warn!("BatchIter: packet data extends past block boundary, stopping");
                self.remaining = 0;
                return None;
            }
        }

        // SAFETY: bounds-checked above, TPACKET_ALIGNMENT guarantees
        // alignment; the block stays user-owned for `'a` and nothing writes
        // this packet's header, sockaddr_ll or data again (the rewrite above
        // was the last write, and it is marked done).
        let hdr = unsafe { &*hdr_ptr };
        // SAFETY: as above; the sockaddr_ll lies at SLL_OFFSET (4-aligned)
        // inside the checked header + sockaddr_ll region.
        let sll = unsafe {
            &*self
                .current
                .map_addr(|a| a + SLL_OFFSET)
                .cast::<ffi::sockaddr_ll>()
        };
        let data_ptr = self.current.map_addr(|a| a + usize::from(hdr.tp_mac));
        // SAFETY: as above — `[data_ptr, data_ptr + snaplen)` is in the block.
        let data =
            unsafe { std::slice::from_raw_parts(data_ptr.cast_const(), hdr.tp_snaplen as usize) };

        // Advance to next packet. tp_next_offset == 0 is the kernel's marker
        // for the last packet in the block — terminate iteration regardless of
        // the claimed `remaining` count.
        if hdr.tp_next_offset != 0 {
            self.current = self.current.map_addr(|a| a + hdr.tp_next_offset as usize);
            self.remaining -= 1;
        } else {
            self.remaining = 0;
        }

        Some(Packet { data, hdr, sll })
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
        assert!(!s.vlan_valid);
        assert!(!s.csum_valid);
        assert!(!s.gso_tcp);
    }

    #[test]
    fn packet_status_from_raw_truncated() {
        let s = PacketStatus::from_raw(ffi::TP_STATUS_COPY);
        assert!(s.truncated);
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
            vlan: Some(VlanTag::new(100, VlanProto::Dot1Q)),
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

    /// One packet of a synthetic block, laid out the way `tpacket_rcv`
    /// lays it out for a `SOCK_RAW` socket on an Ethernet device: header,
    /// `sockaddr_ll` at `TPACKET_ALIGN(48)`, data at the kernel's `macoff =
    /// TPACKET_ALIGN(TPACKET3_HDRLEN + 16) + reserve - 14`.
    #[derive(Clone, Copy)]
    struct SynthPkt<'a> {
        data: &'a [u8],
        /// `tp_len` (wire length); `data.len()` by default.
        wire_len: u32,
        tp_status: u32,
        tci: u32,
        tpid: u16,
        hatype: u16,
        pkttype: u8,
        /// `PACKET_RESERVE` headroom (netring reserves 4 for re-insertion).
        reserve: usize,
        /// Force `tp_mac` (to model a frame with no headroom).
        mac: Option<usize>,
    }

    impl<'a> SynthPkt<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self {
                data,
                wire_len: data.len() as u32,
                tp_status: 0,
                tci: 0,
                tpid: 0,
                hatype: ffi::ARPHRD_ETHER,
                pkttype: ffi::PACKET_HOST,
                reserve: 4,
                mac: None,
            }
        }

        /// The kernel reported a stripped tag (`TP_STATUS_VLAN_VALID |
        /// TP_STATUS_VLAN_TPID_VALID`).
        fn tagged(self, tpid: u16, tci: u16) -> Self {
            Self {
                tp_status: self.tp_status
                    | ffi::TP_STATUS_VLAN_VALID
                    | ffi::TP_STATUS_VLAN_TPID_VALID,
                tci: u32::from(tci),
                tpid,
                ..self
            }
        }

        fn macoff(&self) -> usize {
            self.mac
                .unwrap_or(ffi::tpacket_align(ffi::TPACKET3_HDRLEN + 16) + self.reserve - 14)
        }
    }

    /// Build a synthetic TPACKET_V3 block of `packets`. Writes go through
    /// the buffer's mutable pointer only (a write through a pointer derived
    /// from `as_ptr()` would be UB under tree borrows).
    fn build_block(packets: &[SynthPkt<'_>], block_status: u32) -> AlignedBlock {
        let block_desc_size = std::mem::size_of::<ffi::tpacket_block_desc>();
        let frame = |p: &SynthPkt<'_>| ffi::tpacket_align(p.macoff() + p.data.len());
        let total = block_desc_size + packets.iter().map(frame).sum::<usize>();
        let block_size = total.max(4096);

        let mut block = AlignedBlock::zeroed(block_size);
        let base = block.as_mut_ptr();
        // SAFETY: every write below lies inside the `block_size` buffer
        // (frames are laid out within `total <= block_size`), through
        // `base`'s mutable provenance; the buffer is 8-aligned and every
        // header offset is TPACKET_ALIGNMENT-aligned.
        unsafe {
            let bd = base.cast::<ffi::tpacket_block_desc>();
            (*bd).version = 1;
            (*bd).hdr.bh1.block_status = block_status;
            (*bd).hdr.bh1.num_pkts = packets.len() as u32;
            (*bd).hdr.bh1.offset_to_first_pkt = block_desc_size as u32;
            (*bd).hdr.bh1.blk_len = block_size as u32;
            (*bd).hdr.bh1.seq_num = 1;

            let mut offset = block_desc_size;
            for (i, p) in packets.iter().enumerate() {
                let is_last = i == packets.len() - 1;
                let raw = base.add(offset);
                let hdr = raw.cast::<ffi::tpacket3_hdr>();
                (*hdr).tp_next_offset = if is_last { 0 } else { frame(p) as u32 };
                (*hdr).tp_sec = 1000 + i as u32;
                (*hdr).tp_nsec = i as u32 * 1000;
                (*hdr).tp_snaplen = p.data.len() as u32;
                (*hdr).tp_len = p.wire_len;
                (*hdr).tp_status = p.tp_status;
                (*hdr).tp_mac = p.macoff() as u16;
                (*hdr).tp_net = (p.macoff() + 14) as u16;
                (*hdr).hv1.tp_vlan_tci = p.tci;
                (*hdr).hv1.tp_vlan_tpid = p.tpid;
                (*hdr).hv1.tp_padding = 0; // the kernel zeroes it per packet

                let sll = raw.add(SLL_OFFSET).cast::<ffi::sockaddr_ll>();
                (*sll).sll_family = libc::AF_PACKET as u16;
                (*sll).sll_hatype = p.hatype;
                (*sll).sll_pkttype = p.pkttype;
                (*sll).sll_halen = 6;
                (*sll).sll_addr = [2, 0, 0, 0, 0, 0x5a, 0, 0];

                std::ptr::copy_nonoverlapping(p.data.as_ptr(), raw.add(p.macoff()), p.data.len());
                offset += frame(p);
            }
        }
        block
    }

    /// Build a synthetic TPACKET_V3 block with the given packet payloads.
    /// Returns an 8-aligned buffer usable as a fake mmap block.
    fn build_synthetic_block(packets: &[&[u8]], block_status: u32) -> AlignedBlock {
        let pkts: Vec<SynthPkt<'_>> = packets.iter().map(|d| SynthPkt::new(d)).collect();
        build_block(&pkts, block_status)
    }

    /// Create a BatchIter directly from a synthetic block buffer.
    fn iter_from_block(block: &[u8], num_pkts: u32) -> BatchIter<'_> {
        let _bd = block.as_ptr().cast::<ffi::tpacket_block_desc>();
        let bd_size = std::mem::size_of::<ffi::tpacket_block_desc>();

        let first = block[bd_size..].as_ptr();
        let end = block[block.len()..].as_ptr();

        // Read-only provenance: these iterators never write (VLAN
        // re-insertion off).
        BatchIter {
            current: first.cast_mut(),
            remaining: num_pkts,
            block_end: end.cast_mut(),
            vlan: VlanMode::Off,
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

    /// #210: a packet cut by a snap length (socket-filter return value)
    /// has `tp_snaplen < tp_len`; TPACKET_V3 never sets `TP_STATUS_COPY`,
    /// so that is what `truncated` reports.
    #[test]
    fn truncated_is_snaplen_below_len() {
        let mut block = build_synthetic_block(&[b"0123456789", b"whole"], ffi::TP_STATUS_USER);
        let (bd, off, n, blk_len) = block_start(&mut block);
        // The first packet was 1000 bytes on the wire, 10 captured.
        let hdr = bd
            .as_ptr()
            .cast::<u8>()
            .wrapping_add(off as usize)
            .cast::<ffi::tpacket3_hdr>();
        // SAFETY: the first header lies inside the synthetic block; written
        // through the block's mutable provenance before any reference to it.
        unsafe { (*hdr).tp_len = 1000 };

        // SAFETY: `block` outlives the iterator.
        let mut it = unsafe { BatchIter::at(bd, off, n, blk_len) };
        let cut = it.next().unwrap();
        assert_eq!((cut.len(), cut.original_len()), (10, 1000));
        assert!(cut.status().truncated);
        assert!(cut.to_owned().status.truncated);
        assert_eq!(cut.to_owned().original_len, 1000);
        let whole = it.next().unwrap();
        assert!(!whole.status().truncated);
        assert!(!whole.to_owned().status.truncated);
    }

    #[test]
    fn batch_losing_reads_block_status() {
        let block = build_synthetic_block(&[b"x"], ffi::TP_STATUS_USER | ffi::TP_STATUS_LOSING);
        let bd = NonNull::new(block.as_ptr() as *mut ffi::tpacket_block_desc).unwrap();
        // SAFETY: synthetic user-owned block, forgotten below (no release).
        let batch = unsafe { PacketBatch::new(bd) };
        assert!(batch.losing());
        assert!(!batch.timed_out());
        std::mem::forget(batch);

        let block = build_synthetic_block(&[b"x"], ffi::TP_STATUS_USER | ffi::TP_STATUS_BLK_TMO);
        let bd = NonNull::new(block.as_ptr() as *mut ffi::tpacket_block_desc).unwrap();
        // SAFETY: as above.
        let batch = unsafe { PacketBatch::new(bd) };
        assert!(!batch.losing());
        std::mem::forget(batch);
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

    // ── VLAN re-insertion (#209) ───────────────────────────────────────

    use crate::config::BpfFilter;

    /// An untagged Ethernet/IPv4/UDP frame (dst port 53), 60 bytes.
    fn eth_udp() -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02, 0x08, 0x00];
        f.extend_from_slice(&[0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        f.extend_from_slice(&[0x9c, 0x40, 0, 53, 0, 12, 0, 0, b'n', b'r', b'v', b'l']);
        f.resize(60, 0);
        f
    }

    /// The same frame with `tpid` / `tci` at bytes 12..16.
    fn with_tag(frame: &[u8], tpid: u16, tci: u16) -> Vec<u8> {
        let mut f = frame[..12].to_vec();
        f.extend_from_slice(&tpid.to_be_bytes());
        f.extend_from_slice(&tci.to_be_bytes());
        f.extend_from_slice(&frame[12..]);
        f
    }

    /// A batch over `block` that re-inserts tags (capped at `snap_cap`).
    /// `block` is not touched again by the caller: every access goes
    /// through the returned batch's (mutable) provenance.
    fn reinsert_batch(block: &mut AlignedBlock, snap_cap: u32) -> PacketBatch<'_> {
        let bd = NonNull::new(block.as_mut_ptr().cast::<ffi::tpacket_block_desc>()).unwrap();
        // SAFETY: a synthetic "user-owned" block that outlives the batch.
        unsafe { PacketBatch::new(bd) }.with_vlan_mode(VlanMode::Reinsert { snap_cap })
    }

    #[test]
    fn reinserts_a_stripped_8021ad_tag() {
        let frame = eth_udp();
        let mut block = build_block(
            &[SynthPkt::new(&frame).tagged(0x88a8, 0x2064)],
            ffi::TP_STATUS_USER,
        );
        let batch = reinsert_batch(&mut block, u32::MAX);
        let pkt = batch.iter().next().unwrap();

        assert_eq!(pkt.data(), with_tag(&frame, 0x88a8, 0x2064));
        assert_eq!(&pkt.data()[12..18], &[0x88, 0xa8, 0x20, 0x64, 0x08, 0x00]);
        assert_eq!((pkt.len(), pkt.original_len()), (64, 64));
        let st = pkt.status();
        assert!(st.vlan_reinserted && st.vlan_valid && !st.truncated);
        let tag = VlanTag::new(0x2064, VlanProto::Dot1Ad);
        assert_eq!(pkt.vlan(), Some(tag));
        assert_eq!(pkt.vlan().unwrap().vid(), 100);
        assert_eq!(pkt.stripped_vlan(), None, "the tag is in the data");
        assert_eq!(pkt.bpf_ancillary(), BpfAncillary::reinserted(tag));
        // The metadata is untouched; direction etc. still read the sll.
        assert_eq!(pkt.direction(), PacketDirection::Host);
        assert_eq!(pkt.source_ll_addr(), &[2, 0, 0, 0, 0, 0x5a]);

        // The verdict of the kernel's filter on the packet as it saw it.
        let vlan100 = BpfFilter::builder()
            .vlan()
            .vlan_id(100)
            .udp()
            .dst_port(53)
            .build()
            .unwrap();
        assert!(vlan100.matches_with(pkt.data(), &pkt.bpf_ancillary()));
        assert!(vlan100.matches(pkt.data()), "and offline, tag in the frame");
        drop(batch);
    }

    #[test]
    fn reinsertion_is_idempotent_across_iterations() {
        let frame = eth_udp();
        let mut block = build_block(
            &[
                SynthPkt::new(&frame).tagged(0x8100, 7),
                SynthPkt::new(&frame),
                SynthPkt::new(&frame).tagged(0x8100, 8),
            ],
            ffi::TP_STATUS_USER,
        );
        let batch = reinsert_batch(&mut block, u32::MAX);
        let first: Vec<Vec<u8>> = batch.iter().map(|p| p.data().to_vec()).collect();
        let second: Vec<(Vec<u8>, usize, bool)> = batch
            .iter()
            .map(|p| {
                (
                    p.data().to_vec(),
                    p.original_len(),
                    p.status().vlan_reinserted,
                )
            })
            .collect();
        assert_eq!(first[0], with_tag(&frame, 0x8100, 7));
        assert_eq!(first[1], frame, "untagged packets are left alone");
        assert_eq!(first[2], with_tag(&frame, 0x8100, 8));
        for (i, (data, orig, reinserted)) in second.iter().enumerate() {
            assert_eq!(data, &first[i], "a second pass rewrites nothing");
            assert_eq!(*orig, data.len());
            assert_eq!(*reinserted, i != 1);
        }
        // Packets lent by the first pass stay valid while a second pass runs.
        let held: Vec<Packet<'_>> = batch.iter().collect();
        let again: Vec<Packet<'_>> = batch.iter().collect();
        assert_eq!(held[0].data(), again[0].data());
    }

    #[test]
    fn no_headroom_leaves_the_packet_alone() {
        let frame = eth_udp();
        // Data right behind the sockaddr_ll: no 4 bytes in front of it.
        let pkt = SynthPkt {
            mac: Some(SLL_OFFSET + std::mem::size_of::<ffi::sockaddr_ll>() + 2),
            ..SynthPkt::new(&frame).tagged(0x8100, 100)
        };
        let mut block = build_block(&[pkt], ffi::TP_STATUS_USER);
        let batch = reinsert_batch(&mut block, u32::MAX);
        let p = batch.iter().next().unwrap();
        assert_eq!(p.data(), frame);
        assert!(!p.status().vlan_reinserted);
        let tag = VlanTag::new(100, VlanProto::Dot1Q);
        assert_eq!(p.vlan(), Some(tag));
        assert_eq!(p.stripped_vlan(), Some(tag));
        assert_eq!(p.bpf_ancillary(), BpfAncillary::stripped(tag));
        // flowscope sees the tag as stripped metadata.
        assert_eq!(p.view().rx_metadata.vlan, Some(tag));
        let o = p.to_owned();
        assert_eq!((o.vlan, o.stripped_vlan()), (Some(tag), Some(tag)));
        assert_eq!(o.bpf_ancillary(), BpfAncillary::stripped(tag));
        assert_eq!(o.view().rx_metadata.vlan, Some(tag));
    }

    #[test]
    fn non_ethernet_devices_are_left_alone() {
        let frame = eth_udp();
        let pkt = SynthPkt {
            hatype: 772, // ARPHRD_LOOPBACK
            ..SynthPkt::new(&frame).tagged(0x8100, 100)
        };
        let mut block = build_block(&[pkt], ffi::TP_STATUS_USER);
        let batch = reinsert_batch(&mut block, u32::MAX);
        let p = batch.iter().next().unwrap();
        assert_eq!(p.data(), frame);
        assert!(!p.status().vlan_reinserted);
        assert!(p.stripped_vlan().is_some());
    }

    /// Old kernels report a TCI without `TP_STATUS_VLAN_VALID` / a TPID:
    /// libpcap's rule is "a non-zero TCI is a tag", TPID 802.1Q.
    #[test]
    fn tci_without_vlan_valid_gets_the_8021q_tpid() {
        let frame = eth_udp();
        let pkt = SynthPkt {
            tci: 0x0064,
            ..SynthPkt::new(&frame)
        };
        let mut block = build_block(&[pkt], ffi::TP_STATUS_USER);
        let batch = reinsert_batch(&mut block, u32::MAX);
        let p = batch.iter().next().unwrap();
        assert_eq!(p.data(), with_tag(&frame, 0x8100, 0x0064));
        assert_eq!(p.vlan(), Some(VlanTag::new(100, VlanProto::Dot1Q)));
    }

    #[test]
    fn no_vlan_valid_and_zero_tci_is_untagged() {
        let frame = eth_udp();
        // A TPID without TCI or VLAN_VALID: not a tag.
        let pkt = SynthPkt {
            tpid: 0x8100,
            ..SynthPkt::new(&frame)
        };
        let mut block = build_block(&[pkt], ffi::TP_STATUS_USER);
        let batch = reinsert_batch(&mut block, u32::MAX);
        let p = batch.iter().next().unwrap();
        assert_eq!(p.data(), frame);
        assert_eq!(p.vlan(), None);
        assert_eq!(p.bpf_ancillary(), BpfAncillary::NONE);
        // VLAN_VALID with TCI 0 (priority tag, VID 0) is a tag.
        let mut block = build_block(
            &[SynthPkt::new(&frame).tagged(0x8100, 0)],
            ffi::TP_STATUS_USER,
        );
        let batch = reinsert_batch(&mut block, u32::MAX);
        assert_eq!(
            batch.iter().next().unwrap().data(),
            with_tag(&frame, 0x8100, 0)
        );
    }

    #[test]
    fn fewer_than_12_captured_bytes_are_left_alone() {
        let frame = eth_udp();
        let pkt = SynthPkt {
            wire_len: frame.len() as u32,
            ..SynthPkt::new(&frame[..10]).tagged(0x8100, 5)
        };
        let mut block = build_block(&[pkt], ffi::TP_STATUS_USER);
        let batch = reinsert_batch(&mut block, u32::MAX);
        let p = batch.iter().next().unwrap();
        assert_eq!(p.data(), &frame[..10]);
        assert!(!p.status().vlan_reinserted);
    }

    /// The snap length caps the captured length: the tag pushes the last
    /// 4 captured bytes out (as libpcap does) while the wire length grows.
    #[test]
    fn snap_cap_keeps_the_captured_length() {
        let mut frame = eth_udp();
        frame.resize(100, 0xee);
        let pkt = SynthPkt {
            wire_len: 100,
            ..SynthPkt::new(&frame[..64]).tagged(0x8100, 9)
        };
        let mut block = build_block(&[pkt], ffi::TP_STATUS_USER);
        let batch = reinsert_batch(&mut block, 64);
        let p = batch.iter().next().unwrap();
        assert_eq!((p.len(), p.original_len()), (64, 104));
        assert!(p.status().truncated && p.status().vlan_reinserted);
        assert_eq!(p.data(), &with_tag(&frame, 0x8100, 9)[..64]);
    }

    #[test]
    fn owned_and_view_of_a_reinserted_packet() {
        let frame = eth_udp();
        let mut block = build_block(
            &[SynthPkt::new(&frame).tagged(0x8100, 100)],
            ffi::TP_STATUS_USER,
        );
        let batch = reinsert_batch(&mut block, u32::MAX);
        let p = batch.iter().next().unwrap();
        let tag = VlanTag::new(100, VlanProto::Dot1Q);
        // flowscope parses the tag from the frame: no metadata copy.
        assert_eq!(p.view().rx_metadata.vlan, None);
        assert_eq!(p.view().frame, p.data());
        let o = p.to_owned();
        assert_eq!(o.data, with_tag(&frame, 0x8100, 100));
        assert_eq!(o.vlan, Some(tag));
        assert!(o.status.vlan_reinserted);
        assert_eq!(o.stripped_vlan(), None);
        assert_eq!(o.bpf_ancillary(), BpfAncillary::reinserted(tag));
        assert_eq!(o.view().rx_metadata.vlan, None);
        assert_eq!(o.original_len, 64);
    }

    /// Re-insertion off: the ring is left as the kernel wrote it and the
    /// tag is reported as stripped.
    #[test]
    fn vlan_mode_off_leaves_the_ring_alone() {
        let frame = eth_udp();
        let mut block = build_block(
            &[SynthPkt::new(&frame).tagged(0x8100, 100)],
            ffi::TP_STATUS_USER,
        );
        let bd = NonNull::new(block.as_mut_ptr().cast::<ffi::tpacket_block_desc>()).unwrap();
        // SAFETY: as in reinsert_batch.
        let batch = unsafe { PacketBatch::new(bd) };
        let p = batch.iter().next().unwrap();
        assert_eq!(p.data(), frame);
        assert_eq!(p.stripped_vlan(), Some(VlanTag::new(100, VlanProto::Dot1Q)));
    }

    #[test]
    fn vlan_proto_maps_tpids() {
        assert_eq!(vlan_proto(0x8100), VlanProto::Dot1Q);
        assert_eq!(vlan_proto(0x88a8), VlanProto::Dot1Ad);
        assert_eq!(vlan_proto(0x9100), VlanProto::Other(0x9100));
    }
}
