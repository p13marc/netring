//! EINTR-safe wrappers around blocking syscalls.
//!
//! Long-running captures observe `EINTR` whenever the process catches any
//! signal (SIGCHLD, SIGUSR1, SIGINT delivered to a sibling thread, etc.).
//! Propagating it as `Error::Io` would force every caller to re-enter the
//! syscall in a loop. Wrap the syscalls once here so the rest of the crate
//! can pretend signals don't exist.

use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::poll::{PollFd, PollTimeout, poll};

/// Run [`nix::poll::poll`], retrying on `EINTR`.
///
/// Returns `Ok(0)` on timeout, `Ok(n)` for the number of fds with revents set,
/// or any non-EINTR error from the underlying syscall. A retry polls for what
/// is left of `timeout`, so periodic signals cannot keep it from expiring.
pub(crate) fn poll_eintr_safe(
    pfds: &mut [PollFd<'_>],
    timeout: Duration,
) -> Result<i32, std::io::Error> {
    // `None` (a timeout past `Instant`'s range) waits like `PollTimeout::MAX`.
    let deadline = Instant::now().checked_add(timeout);
    let mut remaining = timeout;
    loop {
        match poll(pfds, poll_timeout(remaining)) {
            Ok(n) => return Ok(n),
            Err(Errno::EINTR) => {
                if let Some(deadline) = deadline {
                    remaining = deadline.saturating_duration_since(Instant::now());
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// `timeout` in whole milliseconds, rounded **up**: a sub-millisecond
/// remainder would otherwise become `poll(0)`, which returns at once and
/// turns a caller's wait-until-deadline loop into a spin.
fn poll_timeout(timeout: Duration) -> PollTimeout {
    PollTimeout::try_from(timeout.as_nanos().div_ceil(1_000_000)).unwrap_or(PollTimeout::MAX)
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
    sendto_kick_status(fd, flags).map(|_| ())
}

/// How a TX kick ended, when it didn't fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KickStatus {
    /// `sendto` returned success.
    Done,
    /// `EAGAIN`: the kernel stopped with work left — an AF_XDP copy-mode
    /// kick transmits at most one batch; a TPACKET kick found the socket's
    /// send buffer full before its first frame.
    Again,
    /// `ENOBUFS`: the device (or its qdisc) dropped the frame being sent —
    /// no carrier, a queue at its limit. A TPACKET kick leaves that frame
    /// queued and tries it again on the next kick.
    NoBufs,
}

/// [`sendto_kick_eintr_safe`], telling `EAGAIN` and `ENOBUFS` apart.
pub(crate) fn sendto_kick_status(fd: RawFd, flags: i32) -> Result<KickStatus, std::io::Error> {
    loop {
        // SAFETY: standard sendto() syscall with NULL buffer and NULL addr —
        // the conventional TPACKET TX kick. `fd` validity is the caller's
        // contract.
        let ret = unsafe { libc::sendto(fd, std::ptr::null(), 0, flags, std::ptr::null(), 0) };
        if ret >= 0 {
            return Ok(KickStatus::Done);
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(KickStatus::Again),
            Some(libc::ENOBUFS) => return Ok(KickStatus::NoBufs),
            _ => return Err(err),
        }
    }
}

/// `recvfrom(fd, NULL, 0, MSG_DONTWAIT, NULL, NULL)` — the AF_XDP RX wakeup
/// (it runs the driver's NAPI when the FILL ring asked for a wakeup).
/// Best-effort: `EINTR` is retried, any other result ignored, as in libxdp.
#[cfg(feature = "af-xdp")]
pub(crate) fn recvfrom_kick(fd: RawFd) {
    let _ = recvfrom_probe(fd);
}

/// `recvfrom(fd, NULL, 0, MSG_DONTWAIT, NULL, NULL)`, reporting its error
/// (`EINTR` retried). On an AF_XDP socket this is the RX wakeup, and fails
/// with `ENXIO` once the socket is unbound.
#[cfg(feature = "af-xdp")]
pub(crate) fn recvfrom_probe(fd: RawFd) -> Result<(), std::io::Error> {
    loop {
        // SAFETY: zero-length recvfrom() with NULL buffer and address — the
        // kernel writes nothing. `fd` validity is the caller's contract.
        let ret = unsafe {
            libc::recvfrom(
                fd,
                std::ptr::null_mut(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret >= 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
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

    extern "C" fn ignore_signal(_: libc::c_int) {}

    /// A signal every 20 ms interrupts poll() over and over; the timeout
    /// still expires on time instead of restarting in full each time.
    #[test]
    fn poll_eintr_safe_timeout_survives_periodic_signals() {
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // SAFETY: a no-op handler without SA_RESTART, so poll() fails with
        // EINTR. Process-wide, but nothing else in the crate uses SIGUSR1.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = ignore_signal as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()), 0);
        }
        let mut fds = [0; 2];
        // SAFETY: pipe2 writes two fds into `fds`.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: both fds were just returned by pipe2 and are owned here.
        let (read, _write) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

        let me = unsafe { libc::pthread_self() };
        let stop = Arc::new(AtomicBool::new(false));
        let signaler = std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                // Bounded, so the old behaviour fails instead of hanging.
                let give_up = Instant::now() + Duration::from_secs(3);
                while !stop.load(Ordering::Relaxed) && Instant::now() < give_up {
                    // SAFETY: `me` stays alive until `stop` is set.
                    unsafe { libc::pthread_kill(me, libc::SIGUSR1) };
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        });

        let start = Instant::now();
        let mut pfds = [PollFd::new(read.as_fd(), nix::poll::PollFlags::POLLIN)];
        let n = poll_eintr_safe(&mut pfds, Duration::from_millis(200)).unwrap();
        let elapsed = start.elapsed();
        stop.store(true, Ordering::Relaxed);
        signaler.join().unwrap();

        assert_eq!(n, 0, "timed out, nothing to read");
        assert!(
            elapsed < Duration::from_millis(400),
            "a 200 ms poll took {elapsed:?} under periodic signals"
        );
    }

    /// A sub-millisecond timeout waits about a millisecond rather than
    /// becoming poll(0), which callers looping until a deadline spin on.
    #[test]
    fn poll_timeout_rounds_sub_millisecond_up() {
        assert_eq!(poll_timeout(Duration::ZERO), PollTimeout::ZERO);
        assert_eq!(
            poll_timeout(Duration::from_micros(1)),
            PollTimeout::from(1u8)
        );
        assert_eq!(
            poll_timeout(Duration::from_micros(999)),
            PollTimeout::from(1u8)
        );
        assert_eq!(
            poll_timeout(Duration::from_micros(1001)),
            PollTimeout::from(2u8)
        );
        assert_eq!(poll_timeout(Duration::MAX), PollTimeout::MAX);
    }
}
