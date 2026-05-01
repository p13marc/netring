//! Fanout group management.
//!
//! Fanout distributes packets across multiple sockets in the same group.
//! Must be called AFTER `bind()`.

use std::os::fd::BorrowedFd;

use crate::afpacket::ffi;
use crate::config::{FanoutFlags, FanoutMode};
use crate::error::Error;
use crate::sockopt::raw_setsockopt;

/// Join a fanout group.
///
/// Encodes the fanout argument as: lower 16 bits = `group_id`,
/// upper 16 bits = `mode | flags`. Must be called after `bind()`.
pub(crate) fn join_fanout(
    fd: BorrowedFd<'_>,
    group_id: u16,
    mode: FanoutMode,
    flags: FanoutFlags,
) -> Result<(), Error> {
    let type_flags = mode.as_raw() as u16 | flags.bits();
    let val: u32 = (group_id as u32) | ((type_flags as u32) << 16);
    let val_int = val as libc::c_int;
    raw_setsockopt(
        fd,
        ffi::SOL_PACKET,
        ffi::PACKET_FANOUT,
        &val_int,
        "PACKET_FANOUT",
    )
}

/// Attach an eBPF program to the fanout group for custom distribution.
///
/// Must be called after [`join_fanout()`] on a socket whose builder used
/// [`FanoutMode::Ebpf`](crate::FanoutMode::Ebpf). The program receives packets
/// and returns the socket index (0-based) within the fanout group.
pub(crate) fn attach_fanout_ebpf(sock: BorrowedFd<'_>, prog: BorrowedFd<'_>) -> Result<(), Error> {
    use std::os::fd::AsRawFd;
    let prog_raw: libc::c_int = prog.as_raw_fd();
    raw_setsockopt(
        sock,
        ffi::SOL_PACKET,
        ffi::PACKET_FANOUT_DATA,
        &prog_raw,
        "PACKET_FANOUT_DATA",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fanout_encoding_hash_no_flags() {
        let group_id: u16 = 42;
        let mode = FanoutMode::Hash;
        let flags = FanoutFlags::empty();
        let type_flags = mode.as_raw() as u16 | flags.bits();
        let val: u32 = (group_id as u32) | ((type_flags as u32) << 16);
        // group_id = 42 in lower 16, mode=0 in upper 16
        assert_eq!(val, 42);
    }

    #[test]
    fn fanout_encoding_cpu_with_flags() {
        let group_id: u16 = 7;
        let mode = FanoutMode::Cpu;
        let flags = FanoutFlags::ROLLOVER | FanoutFlags::DEFRAG;
        let type_flags = mode.as_raw() as u16 | flags.bits();
        let val: u32 = (group_id as u32) | ((type_flags as u32) << 16);
        // lower 16: 7, upper 16: 2 (CPU) | 0x9000 = 0x9002
        assert_eq!(val & 0xFFFF, 7);
        assert_eq!((val >> 16) & 0xFFFF, 0x9002);
    }

    #[test]
    fn fanout_encoding_rollover_unique_id() {
        let group_id: u16 = 0;
        let mode = FanoutMode::Rollover;
        let flags = FanoutFlags::UNIQUE_ID;
        let type_flags = mode.as_raw() as u16 | flags.bits();
        let val: u32 = (group_id as u32) | ((type_flags as u32) << 16);
        // lower 16: 0, upper 16: 3 (ROLLOVER) | 0x2000 = 0x2003
        assert_eq!(val & 0xFFFF, 0);
        assert_eq!((val >> 16) & 0xFFFF, 0x2003);
    }
}
