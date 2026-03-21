//! Kernel struct re-exports from `libc` and supplemental constants.
//!
//! All TPACKET_V3 `#[repr(C)]` types come from `libc 0.2.183`.
//! We re-export them here to insulate the crate from libc API changes.

// Re-exports are consumed by later phases (socket.rs, ring.rs, rx.rs, tx.rs).
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(dead_code)]

use libc::c_int;

// ── Struct re-exports ──────────────────────────────────────────────────────

pub use libc::sock_filter;
pub use libc::sock_fprog;
pub use libc::sockaddr_ll;
pub use libc::tpacket_bd_ts;
pub use libc::tpacket_block_desc;
pub use libc::tpacket_hdr_v1;
pub use libc::tpacket_hdr_variant1;
pub use libc::tpacket_req3;
pub use libc::tpacket_stats_v3;
pub use libc::tpacket3_hdr;

// ── Socket level & options ─────────────────────────────────────────────────

pub use libc::SOL_PACKET;

pub use libc::PACKET_ADD_MEMBERSHIP;
pub use libc::PACKET_FANOUT;
pub use libc::PACKET_IGNORE_OUTGOING;
pub use libc::PACKET_MR_PROMISC;
pub use libc::PACKET_QDISC_BYPASS;
pub use libc::PACKET_RX_RING;
pub use libc::PACKET_STATISTICS;
pub use libc::PACKET_TIMESTAMP;
pub use libc::PACKET_TX_RING;
pub use libc::PACKET_VERSION;

// ── Protocol ───────────────────────────────────────────────────────────────

pub use libc::ETH_P_ALL;

// ── TPACKET version ────────────────────────────────────────────────────────

/// TPACKET_V3 as a plain integer for `setsockopt(PACKET_VERSION)`.
///
/// `libc` exports this as an enum variant `libc::tpacket_versions::TPACKET_V3`.
pub const TPACKET_V3_INT: c_int = libc::tpacket_versions::TPACKET_V3 as c_int;

// ── Alignment ──────────────────────────────────────────────────────────────

pub use libc::TPACKET_ALIGNMENT;
pub use libc::TPACKET3_HDRLEN;

/// Align `x` up to `TPACKET_ALIGNMENT` (16 bytes).
pub const fn tpacket_align(x: usize) -> usize {
    (x + TPACKET_ALIGNMENT - 1) & !(TPACKET_ALIGNMENT - 1)
}

// ── Feature request flags ──────────────────────────────────────────────────

pub use libc::TP_FT_REQ_FILL_RXHASH;

// ── Block status flags (RX) ────────────────────────────────────────────────

pub use libc::TP_STATUS_BLK_TMO;
pub use libc::TP_STATUS_KERNEL;
pub use libc::TP_STATUS_USER;

// ── Per-packet status flags ────────────────────────────────────────────────

pub use libc::TP_STATUS_COPY;
pub use libc::TP_STATUS_CSUM_VALID;
pub use libc::TP_STATUS_CSUMNOTREADY;
pub use libc::TP_STATUS_LOSING;
pub use libc::TP_STATUS_VLAN_TPID_VALID;
pub use libc::TP_STATUS_VLAN_VALID;

/// TCP GSO segment — not exported by `libc` as of 0.2.183.
pub const TP_STATUS_GSO_TCP: u32 = 0x100;

// ── TX frame status flags ──────────────────────────────────────────────────

/// Frame is available for userspace to write.
pub const TP_STATUS_AVAILABLE: u32 = 0;
/// Userspace requests kernel to send this frame.
pub const TP_STATUS_SEND_REQUEST: u32 = 1;
/// Kernel is currently sending this frame (transient).
pub const TP_STATUS_SENDING: u32 = 2;
/// Kernel rejected this frame (bad format).
pub const TP_STATUS_WRONG_FORMAT: u32 = 4;

// ── Fanout modes ───────────────────────────────────────────────────────────

pub use libc::PACKET_FANOUT_CPU;
pub use libc::PACKET_FANOUT_HASH;
pub use libc::PACKET_FANOUT_LB;
pub use libc::PACKET_FANOUT_QM;
pub use libc::PACKET_FANOUT_RND;
pub use libc::PACKET_FANOUT_ROLLOVER;

// ── Fanout flags ───────────────────────────────────────────────────────────

pub use libc::PACKET_FANOUT_FLAG_DEFRAG;
pub use libc::PACKET_FANOUT_FLAG_IGNORE_OUTGOING;
pub use libc::PACKET_FANOUT_FLAG_ROLLOVER;
pub use libc::PACKET_FANOUT_FLAG_UNIQUEID;

// ── Timestamp note ─────────────────────────────────────────────────────────
//
// `tpacket_bd_ts` in libc has field `ts_usec`, not `ts_nsec`. The kernel
// header defines this as a union; libc flattened it. TPACKET_V3 always
// provides nanosecond resolution, so read `ts_usec` and interpret as
// nanoseconds.

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn tpacket_req3_layout() {
        assert_eq!(size_of::<tpacket_req3>(), 28);
        assert_eq!(offset_of!(tpacket_req3, tp_block_size), 0);
        assert_eq!(offset_of!(tpacket_req3, tp_block_nr), 4);
        assert_eq!(offset_of!(tpacket_req3, tp_frame_size), 8);
        assert_eq!(offset_of!(tpacket_req3, tp_frame_nr), 12);
        assert_eq!(offset_of!(tpacket_req3, tp_retire_blk_tov), 16);
        assert_eq!(offset_of!(tpacket_req3, tp_sizeof_priv), 20);
        assert_eq!(offset_of!(tpacket_req3, tp_feature_req_word), 24);
    }

    #[test]
    fn tpacket3_hdr_layout() {
        assert_eq!(size_of::<tpacket3_hdr>(), 48);
        assert_eq!(offset_of!(tpacket3_hdr, tp_next_offset), 0);
        assert_eq!(offset_of!(tpacket3_hdr, tp_sec), 4);
        assert_eq!(offset_of!(tpacket3_hdr, tp_nsec), 8);
        assert_eq!(offset_of!(tpacket3_hdr, tp_snaplen), 12);
        assert_eq!(offset_of!(tpacket3_hdr, tp_len), 16);
        assert_eq!(offset_of!(tpacket3_hdr, tp_status), 20);
        assert_eq!(offset_of!(tpacket3_hdr, tp_mac), 24);
        assert_eq!(offset_of!(tpacket3_hdr, tp_net), 26);
    }

    #[test]
    fn tpacket_hdr_variant1_layout() {
        let s = size_of::<tpacket_hdr_variant1>();
        // rxhash(4) + vlan_tci(4) + vlan_tpid(2) + padding(2) = 12
        assert!(s >= 8, "tpacket_hdr_variant1 too small: {s}");
    }

    #[test]
    fn tpacket_bd_ts_layout() {
        assert_eq!(size_of::<tpacket_bd_ts>(), 8);
    }

    #[test]
    fn tpacket_stats_v3_layout() {
        assert_eq!(size_of::<tpacket_stats_v3>(), 12);
    }

    #[test]
    fn sockaddr_ll_layout() {
        assert_eq!(size_of::<sockaddr_ll>(), 20);
    }

    #[test]
    fn sock_filter_layout() {
        assert_eq!(size_of::<sock_filter>(), 8);
    }

    #[test]
    fn constants_match_kernel() {
        assert_eq!(SOL_PACKET, 263);
        assert_eq!(PACKET_VERSION, 10);
        assert_eq!(PACKET_RX_RING, 5);
        assert_eq!(PACKET_TX_RING, 13);
        assert_eq!(PACKET_FANOUT, 18);
        assert_eq!(PACKET_STATISTICS, 6);
        assert_eq!(PACKET_ADD_MEMBERSHIP, 1);
        assert_eq!(PACKET_MR_PROMISC, 1);
        assert_eq!(PACKET_QDISC_BYPASS, 20);
        assert_eq!(PACKET_IGNORE_OUTGOING, 23);
        assert_eq!(PACKET_TIMESTAMP, 17);
        assert_eq!(ETH_P_ALL as u32, 0x0003);
        assert_eq!(TPACKET_ALIGNMENT as u32, 16);
        assert_eq!(TPACKET3_HDRLEN as u32, 68);
        assert_eq!(TP_STATUS_KERNEL, 0);
        assert_eq!(TP_STATUS_USER, 1);
        assert_eq!(TP_STATUS_BLK_TMO, 1 << 5);
        assert_eq!(TP_STATUS_COPY, 1 << 1);
        assert_eq!(TP_STATUS_LOSING, 1 << 2);
        assert_eq!(TP_STATUS_VLAN_VALID, 1 << 4);
        assert_eq!(TP_STATUS_CSUM_VALID, 1 << 7);
        assert_eq!(TP_STATUS_GSO_TCP, 1 << 8);
        assert_eq!(TPACKET_V3_INT, 2);
    }

    #[test]
    fn tpacket_align_helper() {
        assert_eq!(tpacket_align(0), 0);
        assert_eq!(tpacket_align(1), 16);
        assert_eq!(tpacket_align(16), 16);
        assert_eq!(tpacket_align(17), 32);
        assert_eq!(tpacket_align(48), 48);
        assert_eq!(tpacket_align(49), 64);
    }

    #[test]
    fn fanout_constants() {
        assert_eq!(PACKET_FANOUT_HASH, 0);
        assert_eq!(PACKET_FANOUT_LB, 1);
        assert_eq!(PACKET_FANOUT_CPU, 2);
        assert_eq!(PACKET_FANOUT_ROLLOVER, 3);
        assert_eq!(PACKET_FANOUT_RND, 4);
        assert_eq!(PACKET_FANOUT_QM, 5);
    }
}
