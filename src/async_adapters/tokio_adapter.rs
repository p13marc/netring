//! Async capture using tokio [`AsyncFd`].
//!
//! Three reception patterns, in order of preference:
//!
//! - **Guarded zero-copy** ([`AsyncCapture::readable`] + [`ReadableGuard::next_batch`]):
//!   single await, zero-copy view, ready-flag managed for you. Recommended
//!   for new code.
//! - **Owned** ([`AsyncCapture::recv`]): single await, returns
//!   `Vec<OwnedPacket>`. Simpler when you want to fan packets out across
//!   tasks or store them.
//! - **Two-step zero-copy** ([`AsyncCapture::wait_readable`] +
//!   `get_mut().next_batch()`): the original pattern; deprecated in favor
//!   of `readable()` because eager `clear_ready()` opens a race window.

use std::os::fd::{AsFd, AsRawFd};

use tokio::io::unix::AsyncFd;

use crate::error::Error;
use crate::packet::{OwnedPacket, PacketBatch};
use crate::traits::PacketSource;

/// Async wrapper around any [`PacketSource`] using tokio's [`AsyncFd`].
///
/// Provides two async receive patterns:
///
/// ## Zero-copy (two-step)
///
/// ```no_run
/// # use netring::{AfPacketRxBuilder, PacketSource};
/// # use netring::async_adapters::tokio_adapter::AsyncCapture;
/// # async fn example() -> Result<(), netring::Error> {
/// let rx = AfPacketRxBuilder::default().interface("lo").build()?;
/// let mut cap = AsyncCapture::new(rx)?;
/// loop {
///     cap.wait_readable().await?;
///     if let Some(batch) = cap.get_mut().next_batch() {
///         for pkt in &batch {
///             println!("{} bytes", pkt.len());
///         }
///     }
/// }
/// # }
/// ```
///
/// ## Owned (single call, copies data)
///
/// ```no_run
/// # use netring::{AfPacketRxBuilder};
/// # use netring::async_adapters::tokio_adapter::AsyncCapture;
/// # async fn example() -> Result<(), netring::Error> {
/// let rx = AfPacketRxBuilder::default().interface("lo").build()?;
/// let mut cap = AsyncCapture::new(rx)?;
/// let packets = cap.recv().await?;
/// for pkt in &packets {
///     println!("{} bytes", pkt.data.len());
/// }
/// # Ok(()) }
/// ```
pub struct AsyncCapture<S: PacketSource + AsRawFd> {
    inner: AsyncFd<S>,
}

impl<S: PacketSource + AsRawFd> AsyncCapture<S> {
    /// Wrap a packet source in an async adapter.
    ///
    /// Registers the source's fd with tokio's reactor for `POLLIN` readiness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if `AsyncFd` registration fails.
    pub fn new(source: S) -> Result<Self, Error> {
        let fd = AsyncFd::new(source).map_err(Error::Io)?;
        Ok(Self { inner: fd })
    }

    /// Wait until readable and return a guard for zero-copy batch retrieval.
    ///
    /// The guard borrows `&mut self` and exposes a single
    /// [`next_batch()`](ReadableGuard::next_batch) entry that returns the
    /// batch as a zero-copy view. If `next_batch` returns `None`, the guard
    /// also clears tokio's readiness flag so the next `readable()` call
    /// re-arms via epoll.
    ///
    /// Preferred over [`wait_readable`](Self::wait_readable) — same
    /// efficiency, no race window between waiting and reading.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use netring::AfPacketRxBuilder;
    /// # use netring::async_adapters::tokio_adapter::AsyncCapture;
    /// # async fn _ex() -> Result<(), netring::Error> {
    /// let rx = AfPacketRxBuilder::default().interface("lo").build()?;
    /// let mut cap = AsyncCapture::new(rx)?;
    /// loop {
    ///     let mut guard = cap.readable().await?;
    ///     if let Some(batch) = guard.next_batch() {
    ///         for pkt in &batch {
    ///             let _ = pkt.len();
    ///         }
    ///     }
    /// }
    /// # }
    /// ```
    pub async fn readable(&mut self) -> Result<ReadableGuard<'_, S>, Error> {
        let guard = self.inner.readable_mut().await.map_err(Error::Io)?;
        Ok(ReadableGuard { guard })
    }

    /// Wait until the socket becomes readable (kernel retires a block).
    ///
    /// After this returns, call [`get_mut().next_batch()`](PacketSource::next_batch)
    /// to retrieve the batch as a zero-copy view.
    ///
    /// Deprecated: `clear_ready()` is called eagerly here, before the user
    /// performs any I/O. If a new block arrives between this method
    /// returning and the user calling `next_batch()`, tokio's reactor has
    /// already been re-armed; the wakeup is not lost but the user-side
    /// cycle adds latency. Use [`readable()`](Self::readable) instead — it
    /// only clears readiness when `next_batch()` returns `None`.
    #[deprecated(since = "0.3.0", note = "Use `readable().await?.next_batch()` instead")]
    pub async fn wait_readable(&self) -> Result<(), Error> {
        let mut guard = self.inner.readable().await.map_err(Error::Io)?;
        guard.clear_ready();
        Ok(())
    }

    /// Receive the next batch of packets as owned copies.
    ///
    /// Waits for the socket to become readable, then returns all packets
    /// from the next retired block as [`OwnedPacket`]s. The block is
    /// returned to the kernel before this method returns.
    ///
    /// This is simpler than the two-step `wait_readable()` + `next_batch()`
    /// pattern but involves copying packet data out of the ring.
    pub async fn recv(&mut self) -> Result<Vec<OwnedPacket>, Error> {
        loop {
            {
                let mut guard = self.inner.readable_mut().await.map_err(Error::Io)?;
                if let Some(batch) = guard.get_inner_mut().next_batch() {
                    let packets: Vec<OwnedPacket> = batch.iter().map(|p| p.to_owned()).collect();
                    // batch dropped here → block returned to kernel
                    return Ok(packets);
                }
                guard.clear_ready();
            }
        }
    }

    /// Shared access to the inner source.
    pub fn get_ref(&self) -> &S {
        self.inner.get_ref()
    }

    /// Mutable access to the inner source.
    ///
    /// Use this after [`wait_readable()`](AsyncCapture::wait_readable) to
    /// call [`next_batch()`](PacketSource::next_batch) for zero-copy access.
    pub fn get_mut(&mut self) -> &mut S {
        self.inner.get_mut()
    }

    /// Unwrap into the inner source.
    pub fn into_inner(self) -> S {
        self.inner.into_inner()
    }
}

impl<S: PacketSource + AsRawFd> AsFd for AsyncCapture<S> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.get_ref().as_fd()
    }
}

/// Guard returned by [`AsyncCapture::readable`].
///
/// Holds tokio's readiness flag and exposes `next_batch()` as the single
/// extraction point. If `next_batch()` reports no batch (spurious wakeup),
/// the guard clears tokio's readiness so the next `readable()` re-arms via
/// epoll. Otherwise the readiness stays set, and the next `readable()`
/// returns immediately to attempt another drain — matching the AsyncFd
/// idiom for level-triggered fds.
pub struct ReadableGuard<'a, S: PacketSource + AsRawFd> {
    guard: tokio::io::unix::AsyncFdReadyMutGuard<'a, S>,
}

impl<'a, S: PacketSource + AsRawFd> ReadableGuard<'a, S> {
    /// Try to take the next batch from the underlying source.
    ///
    /// Returns `Some(batch)` when a block has been retired, or `None` for
    /// a spurious wakeup. On `None`, clears tokio's readiness so the next
    /// [`AsyncCapture::readable`] call awaits epoll.
    pub fn next_batch(&mut self) -> Option<PacketBatch<'_>> {
        // The natural form of this is:
        //   match self.guard.get_inner_mut().next_batch() {
        //       Some(b) => Some(b),
        //       None => { self.guard.clear_ready(); None }
        //   }
        // …but stable's NLL can't see that the Some-branch's borrow doesn't
        // outlive the None-branch's clear_ready. Polonius would handle this;
        // until then, split the borrow through a raw pointer. Sound because:
        //   - guard is owned exclusively by self (no aliases)
        //   - inner_mut and clear_ready never run concurrently
        let guard_ptr: *mut tokio::io::unix::AsyncFdReadyMutGuard<'a, S> = &raw mut self.guard;
        // SAFETY: guard_ptr came from &mut self.guard; reborrowing once for
        // get_inner_mut() and once for clear_ready() is sequential, not
        // overlapping. The returned batch borrows transitively from
        // self.guard, satisfying the function's `&mut self` borrow.
        let batch = unsafe { (*guard_ptr).get_inner_mut().next_batch() };
        if batch.is_none() {
            // SAFETY: no live borrow of *guard_ptr at this point.
            unsafe { (*guard_ptr).clear_ready() };
        }
        batch
    }

    /// Borrow the inner source mutably (for `stats()` and similar).
    pub fn get_inner_mut(&mut self) -> &mut S {
        self.guard.get_inner_mut()
    }
}
