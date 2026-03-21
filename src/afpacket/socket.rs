//! AF_PACKET socket creation, setsockopt wrappers, and bind.

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::afpacket::ffi;
use crate::config::TimestampSource;
use crate::error::Error;

// ── Shared setsockopt helper ───────────────────────────────────────────────

/// Generic wrapper around `libc::setsockopt`.
///
/// # Safety
///
/// `T` must be a plain-old-data type matching what the kernel expects for
/// the given `level`/`optname` combination.
pub(super) fn raw_setsockopt<T>(
    fd: BorrowedFd<'_>,
    level: libc::c_int,
    optname: libc::c_int,
    val: &T,
    option_name: &'static str,
) -> Result<(), Error> {
    let ret = unsafe {
        // SAFETY: fd is valid (borrowed), val points to a stack-local T,
        // size matches the type. setsockopt is a synchronous syscall.
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            optname,
            (val as *const T).cast(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret == -1 {
        Err(Error::SockOpt {
            option: option_name,
            source: std::io::Error::last_os_error(),
        })
    } else {
        Ok(())
    }
}

// ── Socket creation ────────────────────────────────────────────────────────

/// Create an AF_PACKET raw socket with `SOCK_CLOEXEC`.
pub(crate) fn create_packet_socket() -> Result<OwnedFd, Error> {
    let fd = unsafe {
        // SAFETY: standard socket() syscall with valid constants.
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            (ffi::ETH_P_ALL as u16).to_be() as libc::c_int,
        )
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

// ── Interface resolution ───────────────────────────────────────────────────

/// Resolve an interface name to its index.
pub(crate) fn resolve_interface(name: &str) -> Result<i32, Error> {
    match nix::net::if_::if_nametoindex(name) {
        Ok(idx) => Ok(idx as i32),
        Err(_) => Err(Error::InterfaceNotFound(name.to_string())),
    }
}

// ── setsockopt wrappers ────────────────────────────────────────────────────

/// Set `PACKET_VERSION` to `TPACKET_V3`.
pub(crate) fn set_packet_version(fd: BorrowedFd<'_>) -> Result<(), Error> {
    raw_setsockopt(
        fd,
        ffi::SOL_PACKET,
        ffi::PACKET_VERSION,
        &ffi::TPACKET_V3_INT,
        "PACKET_VERSION",
    )
}

/// Set up the RX ring via `PACKET_RX_RING`.
pub(crate) fn set_rx_ring(fd: BorrowedFd<'_>, req: &ffi::tpacket_req3) -> Result<(), Error> {
    raw_setsockopt(fd, ffi::SOL_PACKET, ffi::PACKET_RX_RING, req, "PACKET_RX_RING")
}

/// Set up the TX ring via `PACKET_TX_RING`.
pub(crate) fn set_tx_ring(fd: BorrowedFd<'_>, req: &ffi::tpacket_req3) -> Result<(), Error> {
    raw_setsockopt(fd, ffi::SOL_PACKET, ffi::PACKET_TX_RING, req, "PACKET_TX_RING")
}

/// Bind the socket to a specific interface.
pub(crate) fn bind_to_interface(fd: BorrowedFd<'_>, ifindex: i32) -> Result<(), Error> {
    let mut sll: ffi::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (ffi::ETH_P_ALL as u16).to_be();
    sll.sll_ifindex = ifindex;

    let ret = unsafe {
        // SAFETY: fd is valid, sll is a valid sockaddr_ll on the stack.
        libc::bind(
            fd.as_raw_fd(),
            (&sll as *const ffi::sockaddr_ll).cast(),
            std::mem::size_of::<ffi::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret == -1 {
        Err(Error::Bind(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

/// Enable promiscuous mode on the interface.
pub(crate) fn set_promiscuous(fd: BorrowedFd<'_>, ifindex: i32) -> Result<(), Error> {
    let mreq = libc::packet_mreq {
        mr_ifindex: ifindex,
        mr_type: ffi::PACKET_MR_PROMISC as u16,
        mr_alen: 0,
        mr_address: [0; 8],
    };
    raw_setsockopt(
        fd,
        ffi::SOL_PACKET,
        ffi::PACKET_ADD_MEMBERSHIP,
        &mreq,
        "PACKET_ADD_MEMBERSHIP",
    )
}

/// Set `PACKET_IGNORE_OUTGOING` to skip outgoing packets.
pub(crate) fn set_ignore_outgoing(fd: BorrowedFd<'_>) -> Result<(), Error> {
    let val: libc::c_int = 1;
    raw_setsockopt(
        fd,
        ffi::SOL_PACKET,
        ffi::PACKET_IGNORE_OUTGOING,
        &val,
        "PACKET_IGNORE_OUTGOING",
    )
}

/// Set `SO_BUSY_POLL` for kernel-side NIC driver polling.
pub(crate) fn set_busy_poll(fd: BorrowedFd<'_>, us: u32) -> Result<(), Error> {
    let val = us as libc::c_int;
    raw_setsockopt(fd, libc::SOL_SOCKET, libc::SO_BUSY_POLL, &val, "SO_BUSY_POLL")
}

/// Set `PACKET_TIMESTAMP` source.
pub(crate) fn set_timestamp_source(
    fd: BorrowedFd<'_>,
    source: TimestampSource,
) -> Result<(), Error> {
    let val = source.as_raw();
    raw_setsockopt(
        fd,
        ffi::SOL_PACKET,
        ffi::PACKET_TIMESTAMP,
        &val,
        "PACKET_TIMESTAMP",
    )
}

/// Get `PACKET_STATISTICS` (tpacket_stats_v3). Resets kernel counters.
pub(crate) fn get_packet_stats(fd: BorrowedFd<'_>) -> Result<ffi::tpacket_stats_v3, Error> {
    let mut stats: ffi::tpacket_stats_v3 = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<ffi::tpacket_stats_v3>() as libc::socklen_t;
    let ret = unsafe {
        // SAFETY: fd is valid, stats is zeroed stack memory of correct size.
        libc::getsockopt(
            fd.as_raw_fd(),
            ffi::SOL_PACKET,
            ffi::PACKET_STATISTICS,
            (&mut stats as *mut ffi::tpacket_stats_v3).cast(),
            &mut len,
        )
    };
    if ret == -1 {
        Err(Error::SockOpt {
            option: "PACKET_STATISTICS",
            source: std::io::Error::last_os_error(),
        })
    } else {
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_loopback() {
        let idx = resolve_interface("lo").unwrap();
        assert!(idx > 0);
    }

    #[test]
    fn resolve_nonexistent() {
        let err = resolve_interface("nonexistent_iface_xyz").unwrap_err();
        assert!(matches!(err, Error::InterfaceNotFound(_)));
    }
}
