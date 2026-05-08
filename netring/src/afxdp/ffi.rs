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
