//! Async packet injection using tokio [`AsyncFd`].
//!
//! Pairs with [`AsyncCapture`](crate::AsyncCapture): the same `AsyncFd`-based
//! readiness machinery, but for the TX path. `AsyncInjector::send` waits on
//! `POLLOUT` (kernel reclaims a TX slot) when the ring is full, instead of
//! returning `None` and forcing the caller to retry.
//!
//! # Example
//!
//! ```no_run
//! # async fn _ex() -> Result<(), netring::Error> {
//! use netring::{AsyncInjector, Injector};
//!
//! let mut atx = AsyncInjector::new(Injector::open("lo")?)?;
//! atx.send(&[0xff; 64]).await?;
//! atx.flush().await?;
//! # Ok(()) }
//! ```

use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::time::Duration;

use tokio::io::unix::AsyncFd;

use crate::afpacket::tx::Injector;
use crate::error::Error;

/// Async wrapper around [`Injector`] using tokio's [`AsyncFd`].
///
/// Provides three async-friendly entry points:
///
/// - [`send`](Self::send) — copies a packet into a TX slot, waiting on
///   `POLLOUT` if the ring is full. Returns once the slot is queued.
/// - [`flush`](Self::flush) — kicks the kernel to drain queued frames.
/// - [`wait_drained`](Self::wait_drained) — awaits `POLLOUT` until every
///   queued frame has been transmitted (or the timeout expires).
///
/// # Cancel safety
///
/// All three methods are cancel-safe: dropping the future between awaits
/// abandons the readiness wait without losing in-flight frames. Frames
/// already `slot.send()`'d before cancellation remain queued and will be
/// transmitted by the next `flush()`.
pub struct AsyncInjector {
    inner: AsyncFd<Injector>,
}

impl AsyncInjector {
    /// Wrap an [`Injector`] in an async adapter.
    ///
    /// Registers the source's fd with tokio's reactor for `POLLOUT` and
    /// `POLLIN` (the kernel signals slot reclamation via `POLLOUT`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if `AsyncFd` registration fails.
    pub fn new(tx: Injector) -> Result<Self, Error> {
        let fd = AsyncFd::with_interest(tx, tokio::io::Interest::WRITABLE).map_err(Error::Io)?;
        Ok(Self { inner: fd })
    }

    /// Open an async injector on `interface` with default settings.
    ///
    /// One-liner shortcut for `AsyncInjector::new(Injector::open(interface)?)`.
    /// For configured injectors, use the builder via
    /// `AsyncInjector::new(Injector::builder()...build()?)`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn _ex() -> Result<(), netring::Error> {
    /// let mut tx = netring::AsyncInjector::open("eth0")?;
    /// tx.send(&[0xff; 64]).await?;
    /// tx.flush().await?;
    /// # Ok(()) }
    /// ```
    pub fn open(interface: &str) -> Result<Self, Error> {
        Self::new(Injector::open(interface)?)
    }

    /// Queue a packet for transmission, waiting if the TX ring is full.
    ///
    /// Equivalent to repeatedly trying [`Injector::allocate`] +
    /// `slot.set_len(len) + slot.send()` and awaiting `POLLOUT` between
    /// failed attempts. Returns once the frame is queued — call
    /// [`flush`](Self::flush) to actually kick the kernel.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::Config`] if `data.len()` exceeds the TX frame
    ///   capacity (set at builder time).
    /// - Returns [`Error::Io`] if the underlying readiness wait fails.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        let cap = self.inner.get_ref().frame_capacity();
        if data.len() > cap {
            return Err(Error::Config(format!(
                "packet length {} exceeds TX frame capacity {}",
                data.len(),
                cap
            )));
        }
        loop {
            // Try non-blocking allocate first — common-case fast path.
            if let Some(mut slot) = self.inner.get_mut().allocate(data.len()) {
                slot.data_mut()[..data.len()].copy_from_slice(data);
                slot.set_len(data.len());
                slot.send();
                return Ok(());
            }
            // Ring full: wait for kernel to reclaim a slot via POLLOUT.
            let mut guard = self.inner.writable_mut().await.map_err(Error::Io)?;
            // The reclamation might be partial; clear_ready re-arms the
            // reactor so the next iteration's writable_mut() will block.
            // We do not consult pending_count here (would re-borrow self.inner
            // while guard is alive); the next allocate() attempt will tell us.
            guard.clear_ready();
            drop(guard);
        }
    }

    /// Kick the kernel to transmit queued frames.
    ///
    /// Forwards to [`Injector::flush`]; awaits no I/O readiness today
    /// (the underlying syscall is non-blocking with `EAGAIN`/`ENOBUFS`
    /// reported as transient success). Async signature reserves room for
    /// future enhancements.
    pub async fn flush(&mut self) -> Result<usize, Error> {
        self.inner.get_mut().flush()
    }

    /// Wait until every queued frame has been transmitted.
    ///
    /// Polls `POLLOUT` (kernel signals slot reclamation) and re-checks
    /// [`Injector::pending_count`] until it hits zero or `timeout`
    /// elapses. Use before drop when you need to observe transmission
    /// failures or guarantee the kernel has finished.
    pub async fn wait_drained(&mut self, timeout: Duration) -> Result<(), Error> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.inner.get_ref().pending_count() == 0 {
                return Ok(());
            }
            let remaining = match deadline.checked_duration_since(tokio::time::Instant::now()) {
                Some(r) => r,
                None => {
                    return Err(Error::Io(std::io::Error::from(
                        std::io::ErrorKind::TimedOut,
                    )));
                }
            };
            // Cap each wait so we re-check pending_count even on partial
            // reclamation events.
            let slice = remaining.min(Duration::from_millis(10));
            tokio::select! {
                ready = self.inner.writable_mut() => {
                    let mut guard = ready.map_err(Error::Io)?;
                    guard.clear_ready();
                }
                _ = tokio::time::sleep(slice) => {}
            }
        }
    }

    /// Borrow the inner sink (e.g., for `cumulative_stats`-style accessors).
    pub fn get_ref(&self) -> &Injector {
        self.inner.get_ref()
    }

    /// Mutable inner-sink access.
    pub fn get_mut(&mut self) -> &mut Injector {
        self.inner.get_mut()
    }

    /// Unwrap into the inner sink.
    pub fn into_inner(self) -> Injector {
        self.inner.into_inner()
    }

    // ── Inherent passthroughs to Injector ─────────────────────────────
    //
    // Saves a `use netring::PacketSink;` (or direct field access via
    // `get_ref()`) at the call site for the most common observability
    // accessors.

    /// Maximum payload bytes that fit in a single TX frame.
    /// See [`Injector::frame_capacity`].
    #[inline]
    pub fn frame_capacity(&self) -> usize {
        self.inner.get_ref().frame_capacity()
    }

    /// Total number of frames in the TX ring.
    /// See [`Injector::frame_count`].
    #[inline]
    pub fn frame_count(&self) -> usize {
        self.inner.get_ref().frame_count()
    }

    /// Slots currently `TP_STATUS_AVAILABLE` (reclaimed by kernel).
    /// See [`Injector::available_slots`].
    pub fn available_slots(&self) -> usize {
        self.inner.get_ref().available_slots()
    }

    /// Slots currently `TP_STATUS_WRONG_FORMAT` (kernel-rejected).
    /// See [`Injector::rejected_slots`].
    pub fn rejected_slots(&self) -> usize {
        self.inner.get_ref().rejected_slots()
    }

    /// Slots in `TP_STATUS_SEND_REQUEST` / `TP_STATUS_SENDING`.
    /// See [`Injector::pending_count`].
    pub fn pending_count(&self) -> usize {
        self.inner.get_ref().pending_count()
    }
}

impl AsFd for AsyncInjector {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.get_ref().as_fd()
    }
}

impl AsRawFd for AsyncInjector {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}
