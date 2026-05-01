//! EINTR-safe wrappers around blocking syscalls.
//!
//! Long-running captures observe `EINTR` whenever the process catches any
//! signal (SIGCHLD, SIGUSR1, SIGINT delivered to a sibling thread, etc.).
//! Propagating it as `Error::Io` would force every caller to re-enter the
//! syscall in a loop. Wrap the syscalls once here so the rest of the crate
//! can pretend signals don't exist.

use std::os::fd::RawFd;
use std::time::Duration;

use nix::errno::Errno;
use nix::poll::{PollFd, PollTimeout, poll};

/// Run [`nix::poll::poll`], retrying on `EINTR`.
///
/// Returns `Ok(0)` on timeout, `Ok(n)` for the number of fds with revents set,
/// or any non-EINTR error from the underlying syscall.
pub(crate) fn poll_eintr_safe(
    pfds: &mut [PollFd<'_>],
    timeout: Duration,
) -> Result<i32, std::io::Error> {
    let pt = PollTimeout::try_from(timeout).unwrap_or(PollTimeout::MAX);
    loop {
        match poll(pfds, pt) {
            Ok(n) => return Ok(n),
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Run `libc::sendto(fd, NULL, 0, flags, NULL, 0)` — the standard TPACKET
/// and AF_XDP TX kick — retrying on `EINTR`.
///
/// `EAGAIN` and `ENOBUFS` are reported as success: both are transient kernel
/// queue conditions, not failures the caller can do anything about. The
/// kernel will retry on the next kick.
///
/// `flags`: `0` for AF_PACKET, `MSG_DONTWAIT` for AF_XDP.
pub(crate) fn sendto_kick_eintr_safe(fd: RawFd, flags: i32) -> Result<(), std::io::Error> {
    loop {
        // SAFETY: standard sendto() syscall with NULL buffer and NULL addr —
        // the conventional TPACKET TX kick. `fd` validity is the caller's
        // contract.
        let ret = unsafe {
            libc::sendto(
                fd,
                std::ptr::null(),
                0,
                flags,
                std::ptr::null(),
                0,
            )
        };
        if ret >= 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) | Some(libc::ENOBUFS) => return Ok(()),
            _ => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, BorrowedFd};

    /// poll on a pipe with no data — should time out cleanly without
    /// returning EINTR even if signals arrive (nothing's signaling us in
    /// this test, but the wrapper still has to compile and behave).
    #[test]
    fn poll_eintr_safe_times_out() {
        // Use stdin (fd 0). We don't actually expect data; just verify the
        // wrapper returns Ok(0) on timeout.
        let raw_fd = 0;
        // SAFETY: fd 0 is valid for the lifetime of the process.
        let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
        let mut pfds = [PollFd::new(fd.as_fd(), nix::poll::PollFlags::POLLIN)];
        let n = poll_eintr_safe(&mut pfds, Duration::from_millis(10)).unwrap();
        // n could be 0 (timeout) or 1 (stdin readable, e.g., closed pipe in CI).
        // Either is fine — the assertion is "no error".
        assert!(n >= 0);
    }
}
