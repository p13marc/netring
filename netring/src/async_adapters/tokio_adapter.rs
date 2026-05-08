//! Async capture using tokio [`AsyncFd`].
//!
//! Three reception patterns, in order of preference:
//!
//! - **Guarded zero-copy** ([`AsyncCapture::readable`] + [`ReadableGuard::next_batch`]):
//!   single await, zero-copy view, ready-flag managed for you. Recommended
//!   for new code.
//! - **Single-call zero-copy** ([`AsyncCapture::try_recv_batch`]): same
//!   thing without the explicit guard.
//! - **Owned** ([`AsyncCapture::recv`]): single await, returns
//!   `Vec<OwnedPacket>`. Use this when the resulting future must be `Send`
//!   (e.g. `tokio::spawn`, `mpsc::Sender::send().await`) — `PacketBatch`
//!   is `!Send` because it borrows from the mmap ring.
//! - **Stream** ([`AsyncCapture::into_stream`]): consumes the capture and
//!   returns a [`PacketStream`] yielding `Vec<OwnedPacket>` per retired
//!   block.

use std::os::fd::{AsFd, AsRawFd};

use tokio::io::unix::AsyncFd;

use crate::error::Error;
use crate::packet::{OwnedPacket, PacketBatch};
use crate::traits::PacketSource;

/// Async wrapper around any [`PacketSource`] using tokio's [`AsyncFd`].
///
/// Three reception entry points (in order of recommended use):
///
/// ## Guarded zero-copy
///
/// ```no_run
/// # use netring::{Capture, AsyncCapture};
/// # async fn example() -> Result<(), netring::Error> {
/// let mut cap = AsyncCapture::new(Capture::open("lo")?)?;
/// loop {
///     let mut guard = cap.readable().await?;
///     if let Some(batch) = guard.next_batch() {
///         for pkt in &batch {
///             println!("{} bytes", pkt.len());
///         }
///     }
/// }
/// # }
/// ```
///
/// ## Single-call zero-copy
///
/// ```no_run
/// # use netring::{Capture, AsyncCapture};
/// # async fn example() -> Result<(), netring::Error> {
/// let mut cap = AsyncCapture::new(Capture::open("lo")?)?;
/// let batch = cap.try_recv_batch().await?;
/// for pkt in &batch {
///     println!("{} bytes", pkt.len());
/// }
/// # Ok(()) }
/// ```
///
/// ## Owned (use when the future must be `Send`, e.g. `tokio::spawn`)
///
/// ```no_run
/// # use netring::{Capture, AsyncCapture};
/// # async fn example() -> Result<(), netring::Error> {
/// let mut cap = AsyncCapture::new(Capture::open("lo")?)?;
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
}

impl AsyncCapture<crate::Capture> {
    /// Open an async AF_PACKET capture on `interface` with default settings.
    ///
    /// One-liner shortcut for `AsyncCapture::new(Capture::open(interface)?)`.
    /// For configured captures, use `AsyncCapture::new(Capture::builder()...build()?)`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn _ex() -> Result<(), netring::Error> {
    /// let mut cap = netring::AsyncCapture::open("eth0")?;
    /// let mut guard = cap.readable().await?;
    /// if let Some(batch) = guard.next_batch() {
    ///     for pkt in &batch {
    ///         println!("{} bytes", pkt.len());
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    pub fn open(interface: &str) -> Result<Self, Error> {
        Self::new(crate::Capture::open(interface)?)
    }
}

impl<S: PacketSource + AsRawFd> AsyncCapture<S> {
    /// Poll-based readability check for use inside custom `Stream`
    /// impls that need to drive their own state from `poll_next`.
    /// Returns the same `AsyncFdReadyMutGuard` shape as
    /// `AsyncFd::poll_read_ready_mut`.
    #[doc(hidden)]
    pub(crate) fn poll_read_ready_mut(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<tokio::io::unix::AsyncFdReadyMutGuard<'_, S>>> {
        self.inner.poll_read_ready_mut(cx)
    }

    /// Wait until readable and return a guard for zero-copy batch retrieval.
    ///
    /// The guard borrows `&mut self` and exposes a single
    /// [`next_batch()`](ReadableGuard::next_batch) entry that returns the
    /// batch as a zero-copy view. If `next_batch` returns `None`, the guard
    /// also clears tokio's readiness flag so the next `readable()` call
    /// re-arms via epoll.
    ///
    ///
    /// # Cancel safety
    ///
    /// This method is cancel-safe. Dropping the future before it resolves
    /// abandons the readiness wait but does not lose data — tokio's reactor
    /// re-arms on the next call. Once the future resolves and a guard is
    /// returned, the kernel ring is unaffected; if you then drop the guard
    /// without calling `next_batch`, no data is consumed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use netring::CaptureBuilder;
    /// # use netring::async_adapters::tokio_adapter::AsyncCapture;
    /// # async fn _ex() -> Result<(), netring::Error> {
    /// let rx = CaptureBuilder::default().interface("lo").build()?;
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

    /// Wait until readable and return the next batch as a zero-copy view.
    ///
    /// Sugar over `self.readable().await?.next_batch()` plus a spurious-
    /// wakeup retry loop. Equivalent to:
    ///
    /// ```ignore
    /// loop {
    ///     let mut guard = self.readable().await?;
    ///     if let Some(batch) = guard.next_batch() {
    ///         return Ok(batch);
    ///     }
    /// }
    /// ```
    ///
    /// Borrows `&mut self` for the lifetime of the returned batch — same
    /// "one batch live at a time" rule as [`PacketSource::next_batch`].
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe between iterations: if cancelled while awaiting
    /// readability, no data is consumed; if cancelled while holding a
    /// resolved guard but before extracting the batch, the guard drops
    /// without consuming. Once `next_batch()` returns `Some(batch)`, the
    /// borrow is committed — drop the batch normally to release it.
    pub async fn try_recv_batch(&mut self) -> Result<PacketBatch<'_>, Error> {
        loop {
            // SAFETY: same polonius workaround as ReadableGuard::next_batch.
            // We need to call self.inner.readable_mut() multiple times across
            // loop iterations, but the borrow checker can't tell that the
            // returned batch on success doesn't outlive the next iteration's
            // call. Split via raw pointer; access is sequential, never aliased.
            let self_ptr: *mut Self = self;
            // SAFETY: self_ptr is derived from &mut self for the duration of
            // the call; only one reborrow is live at any instant.
            let guard = unsafe { (*self_ptr).inner.readable_mut() }
                .await
                .map_err(Error::Io)?;
            // Move the guard into a stack slot so we can either return its
            // batch or drop it before re-looping.
            let mut guard = guard;
            if let Some(batch) = guard.get_inner_mut().next_batch() {
                // SAFETY: the batch borrows from the inner source through
                // the guard. Returning extends the borrow over `'_` of the
                // function — the same lifetime as `&mut self`. The guard
                // itself drops at function return, releasing tokio's
                // readiness flag (PacketBatch's Drop returns the kernel
                // block; tokio's guard sees no I/O so it stays "ready",
                // which is correct for level-triggered fds).
                let batch: PacketBatch<'_> = unsafe { std::mem::transmute(batch) };
                return Ok(batch);
            }
            // Spurious wakeup — clear ready and try again.
            guard.clear_ready();
            // guard drops here; next iteration re-arms via readable_mut().
        }
    }

    /// Receive the next batch of packets as owned copies.
    ///
    /// Waits for the socket to become readable, then returns all packets
    /// from the next retired block as [`OwnedPacket`]s. The block is
    /// returned to the kernel before this method returns.
    ///
    /// Internally retries on spurious wakeups (the inner `next_batch()`
    /// may return `None` even after readability fires; we re-arm and
    /// re-wait). For zero-copy access without the per-packet `Vec<u8>`
    /// copy, use [`try_recv_batch`](Self::try_recv_batch) instead.
    ///
    /// # When to use this vs `try_recv_batch`
    ///
    /// `recv` returns `Vec<OwnedPacket>` (`Send + 'static`), so the future
    /// it produces is `Send`. Use this when you want to:
    /// - `tokio::spawn` the await, or
    /// - cross await points that involve sending packets through a
    ///   `tokio::sync::mpsc::Sender` (or any other `Send`-requiring sink).
    ///
    /// [`try_recv_batch`](Self::try_recv_batch) yields `PacketBatch<'_>`,
    /// which is `!Send` because it borrows from the mmap ring (whose
    /// `NonNull<u8>` base is not `Sync`). That makes the surrounding
    /// future `!Send` and incompatible with `tokio::spawn`. Use
    /// `try_recv_batch` only when staying on a single task / runtime
    /// thread (or when using `LocalSet` / `tokio::task::spawn_local`).
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
    /// Borrow the inner source mutably (e.g. for stats accessors). Most
    /// users want [`readable()`](AsyncCapture::readable) to
    /// call [`next_batch()`](PacketSource::next_batch) for zero-copy access.
    pub fn get_mut(&mut self) -> &mut S {
        self.inner.get_mut()
    }

    /// Unwrap into the inner source.
    pub fn into_inner(self) -> S {
        self.inner.into_inner()
    }

    /// Convert this capture into a [`Stream`](futures_core::Stream).
    ///
    /// Yields one `Vec<OwnedPacket>` per retired block — see
    /// [`PacketStream`] for the `Stream::Item` type and cancel-safety
    /// details. Equivalent to `PacketStream::new(self)` but reads more
    /// fluently in builder-style chains:
    ///
    /// ```no_run
    /// # async fn _ex() -> Result<(), netring::Error> {
    /// use netring::{AsyncCapture, Capture};
    ///
    /// let stream = AsyncCapture::new(Capture::open("eth0")?)?.into_stream();
    /// # let _ = stream;
    /// # Ok(()) }
    /// ```
    pub fn into_stream(self) -> PacketStream<S> {
        PacketStream::new(self)
    }

    /// Capture statistics — passthrough to [`PacketSource::stats`].
    ///
    /// Saves `use netring::PacketSource;` at the call site. **Resets kernel
    /// counters on each read** — see [`PacketSource::stats`] for the full
    /// contract or [`cumulative_stats`](Self::cumulative_stats) for monotonic
    /// totals.
    pub fn stats(&self) -> Result<crate::stats::CaptureStats, Error> {
        self.inner.get_ref().stats()
    }

    /// Accumulated statistics since the source was created — passthrough to
    /// [`PacketSource::cumulative_stats`].
    pub fn cumulative_stats(&self) -> Result<crate::stats::CaptureStats, Error> {
        self.inner.get_ref().cumulative_stats()
    }
}

impl<S: PacketSource + AsRawFd> AsFd for AsyncCapture<S> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.get_ref().as_fd()
    }
}

// AsyncPacketSource trait impl — sugar for `try_recv_batch()` so callers
// can hold a generic `T: AsyncPacketSource` instead of a concrete
// `AsyncCapture<S>`.
impl<S: PacketSource + AsRawFd + Send> crate::traits::AsyncPacketSource for AsyncCapture<S> {
    fn next_batch(
        &mut self,
    ) -> impl std::future::Future<Output = Result<crate::packet::PacketBatch<'_>, Error>> + Send
    {
        self.try_recv_batch()
    }
}

/// Adapter implementing [`futures_core::Stream`] over an [`AsyncCapture`].
///
/// Yields one `Vec<OwnedPacket>` per retired block — the standard
/// "borrow-then-copy" idiom for Streams (the `Stream::Item` lifetime can't
/// outlive a single `poll_next`, so we copy data out of the ring before
/// yielding).
///
/// For zero-copy access without copies, hold the underlying `AsyncCapture`
/// directly and use [`AsyncCapture::try_recv_batch`] in a loop.
///
/// # Cancel safety
///
/// `Stream::poll_next` is cancel-safe: dropping the future between polls
/// abandons the in-flight readiness wait without losing data (the next
/// poll will re-arm via tokio's reactor).
///
/// # Idiomatic consumption
///
/// netring re-exports only `futures_core::Stream` (the trait). To use the
/// usual `.next().await`, `.filter()`, `.take()`, etc. combinators, add
/// `futures` (or `tokio_stream`) to your `Cargo.toml`:
///
/// ```toml
/// futures = "0.3"
/// ```
///
/// then:
///
/// ```ignore
/// use futures::StreamExt;
///
/// let cap = netring::AsyncCapture::new(rx)?;
/// let mut stream = netring::PacketStream::new(cap);
/// while let Some(batch) = stream.next().await {
///     for pkt in batch? { /* ... */ }
/// }
/// ```
///
/// Hand-polling without `StreamExt` is also possible — see
/// `examples/async_stream.rs` for that variant.
///
/// # Examples
///
/// ```no_run
/// # async fn _ex() -> Result<(), netring::Error> {
/// use futures_core::Stream;
/// use netring::CaptureBuilder;
/// use netring::async_adapters::tokio_adapter::{AsyncCapture, PacketStream};
///
/// let rx = CaptureBuilder::default().interface("lo").build()?;
/// let cap = AsyncCapture::new(rx)?;
/// let stream = PacketStream::new(cap);
///
/// // Pin and consume:
/// let mut stream = Box::pin(stream);
/// // .. then use Stream combinators or hand-poll. See StreamExt examples.
/// # let _: std::pin::Pin<Box<dyn Stream<Item = Result<Vec<netring::OwnedPacket>, netring::Error>>>> = stream;
/// # Ok(()) }
/// ```
pub struct PacketStream<S: PacketSource + AsRawFd> {
    cap: AsyncCapture<S>,
}

impl<S: PacketSource + AsRawFd> PacketStream<S> {
    /// Wrap an [`AsyncCapture`] as a [`Stream`](futures_core::Stream).
    pub fn new(cap: AsyncCapture<S>) -> Self {
        Self { cap }
    }

    /// Unwrap into the underlying [`AsyncCapture`].
    pub fn into_inner(self) -> AsyncCapture<S> {
        self.cap
    }
}

impl<S: PacketSource + AsRawFd + Unpin> futures_core::Stream for PacketStream<S> {
    type Item = Result<Vec<OwnedPacket>, Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            // Wait for readability.
            let mut ready = match this.cap.inner.poll_read_ready_mut(cx) {
                std::task::Poll::Ready(Ok(g)) => g,
                std::task::Poll::Ready(Err(e)) => {
                    return std::task::Poll::Ready(Some(Err(Error::Io(e))));
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            // Try to drain a batch. If None (spurious wakeup), clear ready
            // and let the next loop iteration re-poll.
            if let Some(batch) = ready.get_inner_mut().next_batch() {
                let pkts: Vec<OwnedPacket> = batch.iter().map(|p| p.to_owned()).collect();
                // batch dropped here → block returned to kernel
                return std::task::Poll::Ready(Some(Ok(pkts)));
            }
            ready.clear_ready();
        }
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
