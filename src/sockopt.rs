//! Shared `setsockopt` helper used by both AF_PACKET and AF_XDP backends.

use std::os::fd::{AsRawFd, BorrowedFd};

use crate::error::Error;

/// Generic wrapper around `libc::setsockopt`.
///
/// # Safety
///
/// `T` must be a plain-old-data type matching what the kernel expects for
/// the given `level`/`optname` combination.
pub(crate) fn raw_setsockopt<T>(
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
