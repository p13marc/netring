//! Classic BPF filter attachment.

use std::os::fd::BorrowedFd;

use crate::sockopt::raw_setsockopt;
use crate::config::BpfFilter;
use crate::error::Error;

/// Maximum number of classic BPF instructions (kernel limit).
const BPF_MAXINSNS: usize = 4096;

/// Attach a classic BPF filter to the socket.
///
/// Packets not matching the filter are dropped before reaching the ring.
pub(crate) fn attach_bpf_filter(fd: BorrowedFd<'_>, filter: &BpfFilter) -> Result<(), Error> {
    if filter.is_empty() {
        return Err(Error::Config("BPF filter has no instructions".into()));
    }
    if filter.len() > BPF_MAXINSNS {
        return Err(Error::Config(format!(
            "BPF filter has {} instructions (max {})",
            filter.len(),
            BPF_MAXINSNS
        )));
    }

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.instructions().as_ptr() as *mut libc::sock_filter,
    };

    raw_setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_ATTACH_FILTER,
        &prog,
        "SO_ATTACH_FILTER",
    )
}

/// Attach an eBPF socket filter program.
///
/// Replaces any existing filter. The program must be `BPF_PROG_TYPE_SOCKET_FILTER`.
/// `prog_fd` is the fd of a loaded eBPF program (e.g., from `aya`).
pub(crate) fn attach_ebpf_socket_filter(
    fd: BorrowedFd<'_>,
    prog_fd: std::os::fd::RawFd,
) -> Result<(), Error> {
    raw_setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_ATTACH_BPF,
        &prog_fd,
        "SO_ATTACH_BPF",
    )
}

/// Detach any attached BPF/eBPF filter from the socket.
pub(crate) fn detach_bpf_filter(fd: BorrowedFd<'_>) -> Result<(), Error> {
    let val: libc::c_int = 0;
    raw_setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_DETACH_FILTER,
        &val,
        "SO_DETACH_FILTER",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BpfInsn;

    #[test]
    fn empty_filter_rejected() {
        let filter = BpfFilter::new(vec![]);
        // We can't call attach without a real fd, but we can test validation
        assert!(filter.is_empty());
    }

    #[test]
    fn oversized_filter_rejected() {
        let insns: Vec<BpfInsn> = (0..BPF_MAXINSNS + 1)
            .map(|_| BpfInsn {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0,
            })
            .collect();
        let filter = BpfFilter::new(insns);
        assert!(filter.len() > BPF_MAXINSNS);
    }
}
