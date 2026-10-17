//! tokio reactor registration on a private dup of a source's fd.
//!
//! tokio 1.53.3 deprecated the safe `AsyncFd::{new, with_interest}` as
//! unsound (tokio#8587): the fd an `AsyncFd` registers must stay open, and
//! keep referring to the same file description, for as long as the `AsyncFd`
//! lives. The adapters hand out `&mut` to their source (`get_mut`,
//! `ReadableGuard::get_inner_mut`), so a caller could swap the source out
//! from under a registration on its own fd. Registering a dup that only this
//! module can close makes the contract hold whatever happens to the source,
//! for the price of one extra fd per adapter.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::task::{Context, Poll};

use tokio::io::Interest;
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};

/// Register a private dup of `fd` with the current tokio reactor.
///
/// Readiness is per file description, so the dup reports exactly what `fd`
/// would. Must be called in the context of a tokio runtime.
pub(crate) fn register_dup(fd: BorrowedFd<'_>, interest: Interest) -> io::Result<AsyncFd<OwnedFd>> {
    let dup = fd.try_clone_to_owned()?;
    // SAFETY: `dup` is an `OwnedFd` moved into the `AsyncFd`: it is open, its
    // `as_raw_fd()` never changes, and nothing but the `AsyncFd` (on drop or
    // `into_inner`) can close it.
    unsafe { AsyncFd::register_with_interest(dup, interest) }.map_err(io::Error::from)
}

/// A source plus a reactor registration on a dup of its fd — the subset of
/// the `AsyncFd<T>` API the adapters use.
pub(crate) struct Registered<T> {
    // Declared first, so the dup is deregistered and closed before `inner`
    // drops.
    ready: AsyncFd<OwnedFd>,
    inner: T,
}

impl<T: AsFd> Registered<T> {
    /// Register a dup of `inner`'s fd for `interest`.
    pub(crate) fn new(inner: T, interest: Interest) -> io::Result<Self> {
        let ready = register_dup(inner.as_fd(), interest)?;
        Ok(Self { ready, inner })
    }
}

impl<T> Registered<T> {
    pub(crate) fn get_ref(&self) -> &T {
        &self.inner
    }

    pub(crate) fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Deregister and return the source.
    pub(crate) fn into_inner(self) -> T {
        self.inner
    }

    /// Wait for read readiness.
    pub(crate) async fn readable_mut(&mut self) -> io::Result<ReadyMut<'_, T>> {
        let guard = self.ready.readable().await?;
        Ok(ReadyMut {
            guard,
            inner: &mut self.inner,
        })
    }

    /// Wait for write readiness.
    pub(crate) async fn writable_mut(&mut self) -> io::Result<ReadyMut<'_, T>> {
        let guard = self.ready.writable().await?;
        Ok(ReadyMut {
            guard,
            inner: &mut self.inner,
        })
    }

    /// Poll for read readiness (same waker rules as
    /// `AsyncFd::poll_read_ready`).
    pub(crate) fn poll_read_ready_mut(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<ReadyMut<'_, T>>> {
        match self.ready.poll_read_ready(cx) {
            Poll::Ready(Ok(guard)) => Poll::Ready(Ok(ReadyMut {
                guard,
                inner: &mut self.inner,
            })),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Readiness guard plus mutable access to the source, mirroring
/// `AsyncFdReadyMutGuard`.
pub(crate) struct ReadyMut<'a, T> {
    guard: AsyncFdReadyGuard<'a, OwnedFd>,
    inner: &'a mut T,
}

impl<T> ReadyMut<'_, T> {
    pub(crate) fn get_inner_mut(&mut self) -> &mut T {
        self.inner
    }

    /// Clear tokio's readiness so the next wait re-arms via epoll.
    pub(crate) fn clear_ready(&mut self) {
        self.guard.clear_ready();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;

    #[tokio::test]
    async fn readiness_follows_the_source_after_it_is_swapped_out() {
        let (a, b) = UnixDatagram::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let mut reg = Registered::new(a, Interest::READABLE).unwrap();
        // The registration is on a dup, not on the source's own fd.
        assert_ne!(reg.ready.as_raw_fd(), reg.get_ref().as_raw_fd());

        b.send(b"x").unwrap();
        let mut guard = reg.readable_mut().await.unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(guard.get_inner_mut().recv(&mut buf).unwrap(), 1);
        guard.clear_ready();

        // What `AsyncCapture::get_mut` allows: replace the source and close
        // the old one. The registration keeps its own fd open, so it stays
        // valid (the readiness it reports is the old socket's, which is the
        // caller's problem, not undefined behaviour).
        let (c, _d) = UnixDatagram::pair().unwrap();
        let old = std::mem::replace(reg.get_mut(), c);
        let old_fd = old.as_raw_fd();
        drop(old);
        assert_ne!(reg.ready.as_raw_fd(), old_fd);
        // SAFETY: fcntl(F_GETFD) only queries the fd.
        assert!(unsafe { libc::fcntl(reg.ready.as_raw_fd(), libc::F_GETFD) } >= 0);
        drop(reg);
    }
}
