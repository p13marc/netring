//! Re-exports of AF_XDP constants and structs from `libc`.
//!
//! All values verified against libc 0.2.169 and Linux kernel headers.

// Many re-exports are only consumed when `af-xdp` feature is active.
#![allow(unused_imports, dead_code)]

// Socket family + option level
pub use libc::AF_XDP; // 44 (c_int — cast to u16 for sockaddr_xdp.sxdp_family)
pub use libc::SOL_XDP; // 283

// setsockopt/getsockopt options
pub use libc::XDP_MMAP_OFFSETS; // 1
pub use libc::XDP_RX_RING; // 2
pub use libc::XDP_STATISTICS;
pub use libc::XDP_TX_RING; // 3
pub use libc::XDP_UMEM_COMPLETION_RING; // 6
pub use libc::XDP_UMEM_FILL_RING; // 5
pub use libc::XDP_UMEM_REG; // 4 // 7

// mmap page offsets
// NOTE: RX/TX are off_t (i64), FILL/COMPLETION are c_ulonglong (u64)
pub use libc::XDP_PGOFF_RX_RING; // 0x000000000
pub use libc::XDP_PGOFF_TX_RING; // 0x080000000
pub use libc::XDP_UMEM_PGOFF_COMPLETION_RING; // 0x180000000
pub use libc::XDP_UMEM_PGOFF_FILL_RING; // 0x100000000

// Bind flags (for sockaddr_xdp.sxdp_flags) — all __u16
pub use libc::XDP_COPY; // 2
pub use libc::XDP_SHARED_UMEM; // 1
pub use libc::XDP_USE_NEED_WAKEUP; // 8
pub use libc::XDP_ZEROCOPY; // 4

// Structs
pub use libc::sockaddr_xdp; // sxdp_family(u16), sxdp_flags(u16), sxdp_ifindex(u32), sxdp_queue_id(u32), sxdp_shared_umem_fd(u32)
pub use libc::xdp_desc; // addr(u64), len(u32), options(u32)
pub use libc::xdp_mmap_offsets; // rx, tx, fr, cr (each xdp_ring_offset)
// NOTE: fill ring field is .fr (NOT .fill)
// NOTE: completion ring field is .cr (NOT .completion)
pub use libc::xdp_ring_offset; // producer(u64), consumer(u64), desc(u64), flags(u64)
pub use libc::xdp_statistics;
pub use libc::xdp_umem_reg; // addr, len, chunk_size, headroom, flags, tx_metadata_len

// Ring flag (not exported by libc)
/// Flag set in ring's flags field when kernel needs a wakeup via `sendto`/`poll`.
pub const XDP_RING_NEED_WAKEUP: u32 = 1;

// ── ethtool channel discovery (queue-count auto-detect, issue #6) ───────────
// `libc` exports neither `SIOCETHTOOL`, `ETHTOOL_GCHANNELS`, nor
// `struct ethtool_channels`, so we vendor the minimal definitions from
// <linux/ethtool.h> / <linux/sockios.h>. Used by `crate::xdp::queue_count` to
// read the NIC's combined RSS queue count without privilege.

/// `ioctl` request: pass an ethtool command to a netdev. From `<linux/sockios.h>`.
pub const SIOCETHTOOL: libc::c_ulong = 0x8946;

/// ethtool sub-command: get channel (queue) counts. From `<linux/ethtool.h>`.
pub const ETHTOOL_GCHANNELS: u32 = 0x0000_003c;

/// `struct ethtool_channels` from `<linux/ethtool.h>`. The RSS queue count for
/// AF_XDP capture is `combined_count` (or `rx_count` on rx/tx-split NICs).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ethtool_channels {
    pub cmd: u32,
    pub max_rx: u32,
    pub max_tx: u32,
    pub max_other: u32,
    pub max_combined: u32,
    pub rx_count: u32,
    pub tx_count: u32,
    pub other_count: u32,
    pub combined_count: u32,
}

/// Minimal `struct ifreq` for the `SIOCETHTOOL` ioctl: interface name + a
/// pointer to the ethtool command struct (the `ifr_data` union member). We
/// vendor this rather than use `libc::ifreq` to avoid its `ifr_ifru` union.
#[repr(C)]
pub struct ethtool_ifreq {
    pub ifr_name: [libc::c_char; libc::IFNAMSIZ],
    pub ifr_data: *mut libc::c_void,
}

// ── ethtool RSS hash configuration (symmetric RSS, issue #43) ────────────────
// Vendored from <linux/ethtool.h>. Used by `crate::xdp::rss` to make the NIC's
// RX-side hashing direction-symmetric so both halves of a bidirectional flow
// land on the same RSS queue (and thus the same sharded capture worker).

/// ethtool sub-command: get the RX flow-hash (RSS) configuration.
pub const ETHTOOL_GRSSH: u32 = 0x0000_0046;
/// ethtool sub-command: set the RX flow-hash (RSS) configuration.
pub const ETHTOOL_SRSSH: u32 = 0x0000_0047;

/// `input_xfrm`: XOR-fold the source/destination fields before hashing, making
/// the hash symmetric (`hash(a→b) == hash(b→a)`). Kernel ≥ 6.8; driver-gated.
pub const RXH_XFRM_SYM_XOR: u8 = 1 << 0;
/// `input_xfrm` sentinel: leave the transform unchanged on `ETHTOOL_SRSSH`.
pub const RXH_XFRM_NO_CHANGE: u8 = 0xff;
/// `hfunc` sentinel: leave the hash function unchanged on `ETHTOOL_SRSSH`.
pub const ETH_RSS_HASH_NO_CHANGE: u8 = 0;
/// `indir_size` sentinel: leave the indirection table unchanged.
pub const ETH_RXFH_INDIR_NO_CHANGE: u32 = 0xffff_ffff;

/// Header of `struct ethtool_rxfh` from `<linux/ethtool.h>`. The on-wire struct
/// has a trailing flexible `__u32 rss_config[]` holding the indirection table
/// (`indir_size` × `u32`) followed by the hash key (`key_size` bytes) — callers
/// allocate `size_of::<ethtool_rxfh>() + indir_size*4 + key_size` and treat the
/// tail as raw bytes.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ethtool_rxfh {
    pub cmd: u32,
    pub rss_context: u32,
    pub indir_size: u32,
    pub key_size: u32,
    pub hfunc: u8,
    pub input_xfrm: u8,
    pub rsvd8: [u8; 2],
    pub rsvd32: u32,
    // `rss_config[]` flexible array follows in the heap buffer.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn constant_values() {
        assert_eq!(AF_XDP, 44);
        assert_eq!(SOL_XDP, 283);
        assert_eq!(XDP_MMAP_OFFSETS, 1);
        assert_eq!(XDP_RX_RING, 2);
        assert_eq!(XDP_TX_RING, 3);
        assert_eq!(XDP_UMEM_REG, 4);
        assert_eq!(XDP_UMEM_FILL_RING, 5);
        assert_eq!(XDP_UMEM_COMPLETION_RING, 6);
        assert_eq!(XDP_STATISTICS, 7);
    }

    #[test]
    fn struct_sizes() {
        assert_eq!(size_of::<xdp_umem_reg>(), 32);
        assert_eq!(size_of::<sockaddr_xdp>(), 16);
        assert_eq!(size_of::<xdp_desc>(), 16);
        assert_eq!(size_of::<xdp_mmap_offsets>(), 128);
        assert_eq!(size_of::<xdp_ring_offset>(), 32);
    }

    #[test]
    fn bind_flag_values() {
        assert_eq!(XDP_SHARED_UMEM, 1);
        assert_eq!(XDP_COPY, 2);
        assert_eq!(XDP_ZEROCOPY, 4);
        assert_eq!(XDP_USE_NEED_WAKEUP, 8);
    }

    #[test]
    fn ring_need_wakeup() {
        assert_eq!(XDP_RING_NEED_WAKEUP, 1);
    }
}
