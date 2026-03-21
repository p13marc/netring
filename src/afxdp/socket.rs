//! AF_XDP socket creation, setsockopt/getsockopt wrappers, and bind.

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use super::ffi;
use crate::error::Error;
use crate::sockopt::raw_setsockopt;

// ── Socket creation ──────────────────────────────────────────────────────

/// Create an AF_XDP socket with `SOCK_RAW | SOCK_CLOEXEC`.
pub(crate) fn create_xdp_socket() -> Result<OwnedFd, Error> {
    let fd = unsafe {
        // SAFETY: standard socket() syscall with valid constants.
        libc::socket(ffi::AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0)
    };
    if fd == -1 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => Err(Error::PermissionDenied),
            _ => Err(Error::Socket(err)),
        };
    }
    // SAFETY: fd is valid, just returned by socket().
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// ── UMEM registration ────────────────────────────────────────────────────

/// Register a UMEM region with the kernel via `XDP_UMEM_REG`.
pub(crate) fn register_umem(fd: BorrowedFd<'_>, reg: &ffi::xdp_umem_reg) -> Result<(), Error> {
    raw_setsockopt(fd, ffi::SOL_XDP, ffi::XDP_UMEM_REG, reg, "XDP_UMEM_REG")
}

// ── Ring size configuration ──────────────────────────────────────────────

/// Set a ring size via setsockopt. `opt` is one of `XDP_RX_RING`, `XDP_TX_RING`,
/// `XDP_UMEM_FILL_RING`, or `XDP_UMEM_COMPLETION_RING`.
///
/// Ring sizes must be a power of 2.
pub(crate) fn set_ring_size(
    fd: BorrowedFd<'_>,
    opt: libc::c_int,
    size: u32,
    option_name: &'static str,
) -> Result<(), Error> {
    raw_setsockopt(fd, ffi::SOL_XDP, opt, &size, option_name)
}

// ── mmap offsets ─────────────────────────────────────────────────────────

/// Get ring mmap offsets via `getsockopt(XDP_MMAP_OFFSETS)`.
pub(crate) fn get_mmap_offsets(fd: BorrowedFd<'_>) -> Result<ffi::xdp_mmap_offsets, Error> {
    let mut offsets: ffi::xdp_mmap_offsets = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<ffi::xdp_mmap_offsets>() as libc::socklen_t;
    let ret = unsafe {
        // SAFETY: fd is valid, offsets is zeroed stack memory of correct size.
        libc::getsockopt(
            fd.as_raw_fd(),
            ffi::SOL_XDP,
            ffi::XDP_MMAP_OFFSETS,
            (&mut offsets as *mut ffi::xdp_mmap_offsets).cast(),
            &mut len,
        )
    };
    if ret == -1 {
        Err(Error::SockOpt {
            option: "XDP_MMAP_OFFSETS",
            source: std::io::Error::last_os_error(),
        })
    } else {
        Ok(offsets)
    }
}

// ── Bind ─────────────────────────────────────────────────────────────────

/// Bind the XDP socket to an interface + queue.
///
/// `flags` controls the bind mode:
/// - `0`: auto-negotiate (kernel tries zero-copy, falls back to copy)
/// - `XDP_USE_NEED_WAKEUP`: enable wakeup optimization
/// - `XDP_ZEROCOPY`: force zero-copy (fails with EOPNOTSUPP if unsupported)
pub(crate) fn bind_xdp(
    fd: BorrowedFd<'_>,
    ifindex: u32,
    queue_id: u32,
    flags: u16,
) -> Result<(), Error> {
    let sxdp = ffi::sockaddr_xdp {
        sxdp_family: ffi::AF_XDP as u16,
        sxdp_flags: flags,
        sxdp_ifindex: ifindex,
        sxdp_queue_id: queue_id,
        sxdp_shared_umem_fd: 0,
    };
    let ret = unsafe {
        // SAFETY: fd is valid, sxdp is a valid sockaddr_xdp on the stack.
        libc::bind(
            fd.as_raw_fd(),
            (&sxdp as *const ffi::sockaddr_xdp).cast(),
            std::mem::size_of::<ffi::sockaddr_xdp>() as libc::socklen_t,
        )
    };
    if ret == -1 {
        Err(Error::Bind(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

// ── Statistics ───────────────────────────────────────────────────────────

/// Get XDP socket statistics via `getsockopt(XDP_STATISTICS)`.
pub(crate) fn get_statistics(fd: BorrowedFd<'_>) -> Result<ffi::xdp_statistics, Error> {
    let mut stats: ffi::xdp_statistics = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<ffi::xdp_statistics>() as libc::socklen_t;
    let ret = unsafe {
        // SAFETY: fd is valid, stats is zeroed stack memory of correct size.
        libc::getsockopt(
            fd.as_raw_fd(),
            ffi::SOL_XDP,
            ffi::XDP_STATISTICS,
            (&mut stats as *mut ffi::xdp_statistics).cast(),
            &mut len,
        )
    };
    if ret == -1 {
        Err(Error::SockOpt {
            option: "XDP_STATISTICS",
            source: std::io::Error::last_os_error(),
        })
    } else {
        Ok(stats)
    }
}
