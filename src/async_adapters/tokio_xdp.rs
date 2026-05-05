//! Async wrapper for AF_XDP sockets via tokio [`AsyncFd`].
//!
//! Mirrors [`AsyncCapture`](crate::AsyncCapture) and
//! [`AsyncInjector`](crate::AsyncInjector) for the AF_XDP backend, but
//! covers both RX and TX in a single type since `XdpSocket` shares one
//! fd for both directions.
//!
//! # Three reception entry points
//!
//! - [`AsyncXdpSocket::readable`] — guarded zero-copy. Recommended.
//! - [`AsyncXdpSocket::try_recv_batch`] — single-call zero-copy.
//! - [`AsyncXdpSocket::recv`] — owned copies (`Vec<OwnedPacket>`); use
//!   when the surrounding future must be `Send` (e.g. `tokio::spawn`).
//!
//! # TX with backpressure
//!
//! [`AsyncXdpSocket::send`] awaits `POLLOUT` if the ring or UMEM is
//! exhausted, instead of returning `Ok(false)` from the sync API.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "af-xdp")]
//! # async fn _ex() -> Result<(), netring::Error> {
//! use netring::{AsyncXdpSocket, XdpMode, XdpSocket};
//!
//! let socket = XdpSocket::builder()
//!     .interface("eth0")
//!     .queue_id(0)
//!     .mode(XdpMode::Tx)
//!     .build()?;
//! let mut xdp = AsyncXdpSocket::new(socket)?;
//!
//! xdp.send(&[0xff; 64]).await?;
//! xdp.flush().await?;
//! # Ok(()) }
//! ```

#![cfg(feature = "af-xdp")]

use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::time::Duration;

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::error::Error;
use crate::packet::OwnedPacket;
use crate::{XdpBatch, XdpSocket, XdpStats};

/// Async wrapper around an [`XdpSocket`].
///
/// Registers the socket's fd with tokio's reactor for both
/// `POLLIN` (RX readiness) and `POLLOUT` (TX slot reclamation).
///
/// # Cancel safety
///
/// All `async` methods are cancel-safe. Dropping the future between
/// awaits abandons the readiness wait without affecting the kernel
/// rings — the next call re-arms via tokio's reactor.
pub struct AsyncXdpSocket {
    inner: AsyncFd<XdpSocket>,
}

impl AsyncXdpSocket {
    /// Wrap an [`XdpSocket`] in an async adapter.
    ///
    /// Registers the fd for both `POLLIN` and `POLLOUT`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if `AsyncFd` registration fails.
    pub fn new(socket: XdpSocket) -> Result<Self, Error> {
        let fd = AsyncFd::with_interest(socket, Interest::READABLE | Interest::WRITABLE)
            .map_err(Error::Io)?;
        Ok(Self { inner: fd })
    }

    /// Open an async XDP socket on `interface` with default settings.
    ///
    /// Default mode is [`XdpMode::RxTx`](crate::XdpMode); for TX-only
    /// workloads use the builder directly with `.mode(XdpMode::Tx)`.
    pub fn open(interface: &str) -> Result<Self, Error> {
        Self::new(XdpSocket::open(interface)?)
    }

    // ── RX ──────────────────────────────────────────────────────────────

    /// Wait until readable and return a guard for zero-copy batch retrieval.
    ///
    /// Mirrors [`AsyncCapture::readable`](crate::AsyncCapture::readable)
    /// for the AF_XDP backend.
    pub async fn readable(&mut self) -> Result<XdpReadableGuard<'_>, Error> {
        let guard = self.inner.readable_mut().await.map_err(Error::Io)?;
        Ok(XdpReadableGuard { guard })
    }

    /// Wait until readable and return the next batch as a zero-copy view.
    ///
    /// Sugar over `readable().await?.next_batch()` plus a spurious-wakeup
    /// retry loop. The returned [`XdpBatch`] borrows from `&mut self`;
    /// only one batch can be live at a time.
    ///
    /// # Send-ness
    ///
    /// The returned future is `!Send` because [`XdpBatch`] borrows from
    /// the UMEM region. Use [`recv`](Self::recv) instead when the future
    /// must cross task boundaries (e.g. `tokio::spawn`,
    /// `mpsc::Sender::send().await`).
    pub async fn try_recv_batch(&mut self) -> Result<XdpBatch<'_>, Error> {
        loop {
            // Same polonius workaround as AsyncCapture::try_recv_batch:
            // raw-pointer reborrow lets us return the batch while we'd
            // otherwise still be holding the readiness guard.
            let self_ptr: *mut Self = self;
            // SAFETY: self_ptr is derived from &mut self; only one
            // reborrow is live at any instant.
            let mut guard = unsafe { (*self_ptr).inner.readable_mut() }
                .await
                .map_err(Error::Io)?;
            if let Some(batch) = guard.get_inner_mut().next_batch() {
                // SAFETY: batch borrows transitively from `&mut self`
                // through the guard. Returning extends the borrow over
                // the function's `'_` lifetime.
                let batch: XdpBatch<'_> = unsafe { std::mem::transmute(batch) };
                return Ok(batch);
            }
            // Spurious wakeup — clear ready and retry.
            guard.clear_ready();
        }
    }

    /// Receive the next batch as owned copies.
    ///
    /// Returns `Vec<OwnedPacket>` — `Send + 'static`, so the future is
    /// `Send`. Use this when the future will cross task boundaries.
    /// Internally retries on spurious wakeups.
    pub async fn recv(&mut self) -> Result<Vec<OwnedPacket>, Error> {
        loop {
            let mut guard = self.inner.readable_mut().await.map_err(Error::Io)?;
            // recv() on the inner XdpSocket already returns owned copies.
            let packets = guard.get_inner_mut().recv()?;
            if !packets.is_empty() {
                return Ok(packets);
            }
            guard.clear_ready();
        }
    }

    // ── TX ──────────────────────────────────────────────────────────────

    /// Send a raw packet, awaiting `POLLOUT` if the ring/UMEM is exhausted.
    ///
    /// The sync `XdpSocket::send` returns `Ok(false)` when no UMEM frame
    /// can be allocated or the TX ring is full; this async variant waits
    /// for the kernel to reclaim a slot via `POLLOUT` and retries.
    ///
    /// Call [`flush`](Self::flush) afterward to actually kick the kernel.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`] if `data.len()` exceeds the UMEM frame size.
    /// - [`Error::Io`] if the readiness wait fails.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        loop {
            // Try non-blocking first.
            if self.inner.get_mut().send(data)? {
                return Ok(());
            }
            // Backpressure: wait for POLLOUT (kernel reclaiming TX
            // descriptors / completion-ring frames). clear_ready re-arms
            // tokio's reactor so the next iteration awaits the kernel.
            let mut guard = self.inner.writable_mut().await.map_err(Error::Io)?;
            guard.clear_ready();
        }
    }

    /// Kick the kernel to drain queued TX frames.
    ///
    /// Forwards to [`XdpSocket::flush`] (which is non-blocking — `EAGAIN`
    /// and `ENOBUFS` are reported as transient success). Async signature
    /// reserves room for future enhancements.
    pub async fn flush(&mut self) -> Result<(), Error> {
        self.inner.get_mut().flush()
    }

    // ── Stream + accessors ──────────────────────────────────────────────

    /// Convert into a [`Stream`](futures_core::Stream) yielding
    /// `Vec<OwnedPacket>` per RX batch.
    pub fn into_stream(self) -> XdpStream {
        XdpStream { socket: self }
    }

    /// XDP socket statistics (monotonic; non-destructive read).
    pub fn statistics(&self) -> Result<XdpStats, Error> {
        self.inner.get_ref().statistics()
    }

    /// Borrow the inner socket.
    pub fn get_ref(&self) -> &XdpSocket {
        self.inner.get_ref()
    }

    /// Mutable inner-socket access.
    pub fn get_mut(&mut self) -> &mut XdpSocket {
        self.inner.get_mut()
    }

    /// Unwrap into the inner socket.
    pub fn into_inner(self) -> XdpSocket {
        self.inner.into_inner()
    }
}

impl AsFd for AsyncXdpSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.get_ref().as_fd()
    }
}

impl AsRawFd for AsyncXdpSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}

/// Guard returned by [`AsyncXdpSocket::readable`].
pub struct XdpReadableGuard<'a> {
    guard: tokio::io::unix::AsyncFdReadyMutGuard<'a, XdpSocket>,
}

impl<'a> XdpReadableGuard<'a> {
    /// Try to take the next batch; clears ready on `None` (spurious wakeup).
    pub fn next_batch(&mut self) -> Option<XdpBatch<'_>> {
        // Same polonius workaround as ReadableGuard::next_batch in tokio_adapter.
        let guard_ptr: *mut tokio::io::unix::AsyncFdReadyMutGuard<'a, XdpSocket> =
            &raw mut self.guard;
        // SAFETY: guard_ptr came from &mut self.guard; reborrowing once for
        // get_inner_mut() and once for clear_ready() is sequential.
        let batch = unsafe { (*guard_ptr).get_inner_mut().next_batch() };
        if batch.is_none() {
            // SAFETY: no live borrow at this point.
            unsafe { (*guard_ptr).clear_ready() };
        }
        batch
    }

    /// Borrow the inner socket mutably.
    pub fn get_inner_mut(&mut self) -> &mut XdpSocket {
        self.guard.get_inner_mut()
    }
}

/// Stream adapter over [`AsyncXdpSocket`] yielding owned packets per batch.
///
/// Cancel-safe between polls. `futures::StreamExt` combinators (`next`,
/// `take`, `filter`, ...) work directly on this type.
pub struct XdpStream {
    socket: AsyncXdpSocket,
}

impl XdpStream {
    /// Unwrap back into the underlying [`AsyncXdpSocket`].
    pub fn into_inner(self) -> AsyncXdpSocket {
        self.socket
    }
}

impl futures_core::Stream for XdpStream {
    type Item = Result<Vec<OwnedPacket>, Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            let mut ready = match this.socket.inner.poll_read_ready_mut(cx) {
                std::task::Poll::Ready(Ok(g)) => g,
                std::task::Poll::Ready(Err(e)) => {
                    return std::task::Poll::Ready(Some(Err(Error::Io(e))));
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };
            match ready.get_inner_mut().recv() {
                Ok(pkts) if !pkts.is_empty() => {
                    return std::task::Poll::Ready(Some(Ok(pkts)));
                }
                Ok(_) => {
                    ready.clear_ready();
                }
                Err(e) => return std::task::Poll::Ready(Some(Err(e))),
            }
        }
    }
}

/// `wait_drained` — block until `pending_count` reaches zero.
///
/// Provided as a small convenience for symmetry with
/// [`AsyncInjector::wait_drained`](crate::AsyncInjector::wait_drained).
/// AF_XDP does not currently expose `pending_count` on `XdpSocket`; this
/// implementation simply awaits writability once. A richer drain helper
/// will land alongside the planned XDP statistics expansion.
impl AsyncXdpSocket {
    /// Best-effort drain: awaits one writable wakeup, then returns.
    ///
    /// For AF_XDP, frames in the TX ring are drained on each `flush` —
    /// once `flush` returns and `POLLOUT` re-fires the queue is being
    /// processed. There is no `pending_count` accessor today.
    pub async fn wait_drained(&mut self, timeout: Duration) -> Result<(), Error> {
        tokio::select! {
            ready = self.inner.writable_mut() => {
                let mut guard = ready.map_err(Error::Io)?;
                guard.clear_ready();
                Ok(())
            }
            _ = tokio::time::sleep(timeout) => {
                Err(Error::Io(std::io::Error::from(std::io::ErrorKind::TimedOut)))
            }
        }
    }
}
