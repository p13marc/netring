//! AF_XDP RX hardware metadata (issue #13).
//!
//! Kernel 6.3+ lets an XDP program read NIC-provided **RX timestamp**, **RSS
//! hash**, and **VLAN tag** via the `bpf_xdp_metadata_*` kfuncs and stash them
//! in the frame's metadata headroom (`bpf_xdp_adjust_meta`). The companion
//! program [`programs/redirect_meta.bpf.c`](../loader/programs/redirect_meta.bpf.c)
//! writes one fixed-layout [`XdpRxMeta`] per redirected frame; userspace reads
//! it back from the UMEM headroom immediately preceding the packet.
//!
//! The metadata area is **not zeroed** by the kernel, so a frame whose program
//! did not run (or a driver that returned `-EOPNOTSUPP`) holds stale garbage.
//! [`XdpRxMeta::from_headroom`] gates on a 32-bit magic+version word, then on a
//! per-field validity [`RxMetaFlags`] bitmask, so only fields the program
//! actually populated survive into the public [`flowscope::RxMetadata`].
//!
//! The hash type and VLAN protocol are **normalised by the BPF program** to the
//! codes below (rather than the raw kernel `xdp_rss_hash_type` bitfield), so the
//! Rust-side translation stays a trivial, kernel-version-independent match.

use flowscope::{RssHashType, RxHash, RxMetadata, Timestamp, VlanProto, VlanTag};

bitflags::bitflags! {
    /// Per-field validity bitmask. The BPF program sets a bit only when the
    /// matching kfunc returned a value for the frame; consumers must ignore
    /// any field whose bit is clear (the bytes are otherwise undefined).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct RxMetaFlags: u32 {
        /// `rx_timestamp` holds a valid hardware receive timestamp.
        const TIMESTAMP = 1 << 0;
        /// `rx_hash` / `rx_hash_type` hold a valid RSS hash.
        const HASH      = 1 << 1;
        /// `vlan_tci` / `vlan_proto` hold a valid stripped VLAN tag.
        const VLAN      = 1 << 2;
    }
}

/// `"nrm"` + layout version `1`, written verbatim by the BPF program. A frame
/// whose headroom does not start with this exact word is treated as carrying no
/// metadata — the degrade path for non-6.3 kernels, drivers without the kfuncs,
/// and the un-reserved (garbage) headroom case.
pub(crate) const META_MAGIC: u32 = 0x6E_72_6D_01;

/// Fixed BPF↔userspace metadata layout. Mirrored byte-for-byte by
/// `struct netring_xdp_meta` in `redirect_meta.bpf.c`; the `size_of` assertion
/// in the tests pins the contract.
///
/// Field order keeps every field naturally aligned (no padding), so the C and
/// Rust views agree without `#[repr(packed)]`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct XdpRxMeta {
    magic: u32,
    flags: u32,
    rx_timestamp: u64,
    rx_hash: u32,
    /// Normalised [`RssHashType`] discriminant (see [`rss_hash_type`]).
    rx_hash_type: u32,
    /// VLAN TCI in the low 16 bits.
    vlan_tci: u32,
    /// VLAN TPID EtherType (`0x8100` / `0x88A8` / raw) in the low 16 bits.
    vlan_proto: u32,
}

impl XdpRxMeta {
    /// Byte length the BPF program writes, and the UMEM headroom the socket
    /// must reserve so the struct fits ahead of every frame.
    pub(crate) const LEN: usize = std::mem::size_of::<Self>();

    /// Parse the metadata struct from the `LEN` headroom bytes preceding a
    /// frame. Returns `None` when the area is too short or fails the
    /// magic+version check — i.e. no program-written metadata is present.
    pub(crate) fn from_headroom(headroom: &[u8]) -> Option<Self> {
        if headroom.len() < Self::LEN {
            return None;
        }
        // SAFETY: `XdpRxMeta` is `repr(C)` and POD (only integers, no padding);
        // any `LEN`-byte sequence is a valid bit pattern. Read unaligned because
        // the headroom slice has no alignment guarantee.
        let meta = unsafe { (headroom.as_ptr() as *const Self).read_unaligned() };
        (meta.magic == META_MAGIC).then_some(meta)
    }

    /// Project the validity-gated fields into the public metadata type. Fields
    /// whose flag is clear stay at their `RxMetadata::default()` (absent) value.
    pub(crate) fn rx_metadata(&self) -> RxMetadata {
        // `RxMetadata` is `#[non_exhaustive]`; build via field assignment.
        let flags = RxMetaFlags::from_bits_truncate(self.flags);
        let mut m = RxMetadata::default();
        if flags.contains(RxMetaFlags::TIMESTAMP) {
            m.hw_timestamp = Some(timestamp_from_nanos(self.rx_timestamp));
        }
        if flags.contains(RxMetaFlags::HASH) {
            m.rx_hash = Some(RxHash::new(self.rx_hash, rss_hash_type(self.rx_hash_type)));
        }
        if flags.contains(RxMetaFlags::VLAN) {
            m.vlan = Some(VlanTag::new(
                self.vlan_tci as u16,
                vlan_proto(self.vlan_proto as u16),
            ));
        }
        m
    }
}

/// Split a nanosecond count into a [`Timestamp`]. The clock domain is
/// driver-defined (commonly `CLOCK_TAI`); consumers comparing against software
/// timestamps must account for that offset.
fn timestamp_from_nanos(ns: u64) -> Timestamp {
    Timestamp::new((ns / 1_000_000_000) as u32, (ns % 1_000_000_000) as u32)
}

/// Map the BPF-normalised hash-type code to [`RssHashType`]. The codes match
/// the enum's declaration order; the program collapses the raw kernel
/// `xdp_rss_hash_type` bitfield down to one of these.
fn rss_hash_type(code: u32) -> RssHashType {
    match code {
        0 => RssHashType::L2,
        1 => RssHashType::L3Ipv4,
        2 => RssHashType::L3Ipv6,
        3 => RssHashType::L4TcpIpv4,
        4 => RssHashType::L4UdpIpv4,
        5 => RssHashType::L4SctpIpv4,
        6 => RssHashType::L4TcpIpv6,
        7 => RssHashType::L4UdpIpv6,
        8 => RssHashType::L4SctpIpv6,
        _ => RssHashType::Unknown,
    }
}

/// Map a VLAN TPID EtherType to [`VlanProto`].
fn vlan_proto(tpid: u16) -> VlanProto {
    match tpid {
        0x8100 => VlanProto::Dot1Q,
        0x88A8 => VlanProto::Dot1Ad,
        other => VlanProto::Other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the BPF↔userspace contract: the C struct must match this size.
    #[test]
    fn layout_is_32_bytes() {
        assert_eq!(XdpRxMeta::LEN, 32);
    }

    fn encode(meta: &XdpRxMeta) -> [u8; XdpRxMeta::LEN] {
        // SAFETY: POD `repr(C)` struct → byte view of its exact layout.
        unsafe { std::mem::transmute_copy(meta) }
    }

    fn valid_all() -> XdpRxMeta {
        XdpRxMeta {
            magic: META_MAGIC,
            flags: (RxMetaFlags::TIMESTAMP | RxMetaFlags::HASH | RxMetaFlags::VLAN).bits(),
            rx_timestamp: 1_500_000_000_750_000_000,
            rx_hash: 0xDEAD_BEEF,
            rx_hash_type: 3,  // L4TcpIpv4
            vlan_tci: 0x0064, // VID 100
            vlan_proto: 0x8100,
        }
    }

    #[test]
    fn parses_all_fields() {
        let bytes = encode(&valid_all());
        let m = XdpRxMeta::from_headroom(&bytes)
            .expect("valid magic")
            .rx_metadata();

        assert_eq!(
            m.hw_timestamp,
            Some(Timestamp::new(1_500_000_000, 750_000_000))
        );
        let h = m.rx_hash.expect("hash flagged");
        assert_eq!(h.value, 0xDEAD_BEEF);
        assert_eq!(h.ty, RssHashType::L4TcpIpv4);
        let v = m.vlan.expect("vlan flagged");
        assert_eq!(v.vid(), 100);
        assert_eq!(v.proto, VlanProto::Dot1Q);
    }

    #[test]
    fn honours_per_field_flags() {
        // Only HASH flagged: timestamp + vlan must stay absent even though the
        // (garbage-representing) bytes are non-zero.
        let meta = XdpRxMeta {
            flags: RxMetaFlags::HASH.bits(),
            ..valid_all()
        };
        let m = XdpRxMeta::from_headroom(&encode(&meta))
            .unwrap()
            .rx_metadata();
        assert!(m.hw_timestamp.is_none());
        assert!(m.vlan.is_none());
        assert!(m.rx_hash.is_some());
    }

    #[test]
    fn rejects_bad_magic() {
        // Stale, never-written headroom: any word other than META_MAGIC is the
        // degrade path → no metadata, software timestamp fallback upstream.
        let mut bytes = encode(&valid_all());
        bytes[0] ^= 0xFF;
        assert!(XdpRxMeta::from_headroom(&bytes).is_none());
    }

    #[test]
    fn rejects_short_headroom() {
        let bytes = encode(&valid_all());
        assert!(XdpRxMeta::from_headroom(&bytes[..XdpRxMeta::LEN - 1]).is_none());
    }

    #[test]
    fn all_zero_headroom_is_absent() {
        // A reserved-but-unwritten (zeroed) area parses to no metadata.
        assert!(XdpRxMeta::from_headroom(&[0u8; XdpRxMeta::LEN]).is_none());
    }

    #[test]
    fn unknown_hash_type_degrades() {
        let meta = XdpRxMeta {
            flags: RxMetaFlags::HASH.bits(),
            rx_hash_type: 99,
            ..valid_all()
        };
        let m = XdpRxMeta::from_headroom(&encode(&meta))
            .unwrap()
            .rx_metadata();
        assert_eq!(m.rx_hash.unwrap().ty, RssHashType::Unknown);
    }

    #[test]
    fn maps_vlan_protocols() {
        assert_eq!(vlan_proto(0x8100), VlanProto::Dot1Q);
        assert_eq!(vlan_proto(0x88A8), VlanProto::Dot1Ad);
        assert_eq!(vlan_proto(0x9100), VlanProto::Other(0x9100));
    }
}
