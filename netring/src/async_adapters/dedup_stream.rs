//! [`DedupStream`] — `futures_core::Stream` of [`OwnedPacket`]s with
//! duplicates filtered out via [`crate::Dedup`].
//!
//! Available under the `tokio` feature. The headline API:
//!
//! ```no_run
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! use futures::StreamExt;
//! use netring::{AsyncCapture, Dedup};
//!
//! let cap = AsyncCapture::open("lo")?;
//! let mut stream = cap.dedup_stream(Dedup::loopback());
//! while let Some(pkt) = stream.next().await {
//!     let _pkt = pkt?;
//!     # break;
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;

use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::dedup::Dedup;
use crate::error::Error;
use crate::packet::OwnedPacket;
use crate::traits::PacketSource;

/// Stream of unique [`OwnedPacket`]s — duplicates filtered out by
/// the embedded [`Dedup`].
///
/// Yields `OwnedPacket` (not `Packet<'_>`) because the kernel ring
/// batch is consumed inside `poll_next` and we can't borrow across
/// stream yields. Users who want zero-copy use the manual
/// [`Dedup::keep`] loop with `AsyncCapture::readable()`.
pub struct DedupStream<S>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
{
    cap: AsyncCapture<S>,
    dedup: Dedup,
    /// Buffer of kept packets pending yield.
    pending: VecDeque<OwnedPacket>,
}

impl<S> DedupStream<S>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
{
    pub(crate) fn new(cap: AsyncCapture<S>, dedup: Dedup) -> Self {
        Self {
            cap,
            dedup,
            pending: VecDeque::new(),
        }
    }

    /// Borrow the embedded [`Dedup`] — useful for inspecting
    /// counters (`dedup.dropped()`, `dedup.seen()`).
    pub fn dedup(&self) -> &Dedup {
        &self.dedup
    }

    /// Borrow the embedded [`Dedup`] mutably.
    pub fn dedup_mut(&mut self) -> &mut Dedup {
        &mut self.dedup
    }
}

impl<S> Stream for DedupStream<S>
where
    S: PacketSource + std::os::unix::io::AsRawFd + Unpin,
{
    type Item = Result<OwnedPacket, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(pkt) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(pkt)));
            }

            let mut guard = match this.cap.poll_read_ready_mut(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(Error::Io(e)))),
                Poll::Pending => return Poll::Pending,
            };

            let got_batch = {
                let inner = guard.get_inner_mut();
                if let Some(batch) = inner.next_batch() {
                    for pkt in &batch {
                        if this.dedup.keep(&pkt) {
                            this.pending.push_back(pkt.to_owned());
                        }
                    }
                    drop(batch);
                    true
                } else {
                    false
                }
            };
            if !got_batch {
                guard.clear_ready();
            }
        }
    }
}

// ── AsyncCapture::dedup_stream entry point ──────────────────────────

impl<S> AsyncCapture<S>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
{
    /// Convert this capture into a stream of [`OwnedPacket`]s with
    /// duplicates filtered out by `dedup`.
    ///
    /// Consumes the capture. Yields `OwnedPacket` (not `Packet<'_>`)
    /// because the underlying batch is processed inside `poll_next`.
    /// Users who need zero-copy should use the manual loop:
    ///
    /// ```no_run
    /// # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
    /// use netring::{AsyncCapture, Dedup};
    ///
    /// let mut cap = AsyncCapture::open("lo")?;
    /// let mut dedup = Dedup::loopback();
    /// loop {
    ///     let mut g = cap.readable().await?;
    ///     if let Some(batch) = g.next_batch() {
    ///         for pkt in &batch {
    ///             if dedup.keep(&pkt) {
    ///                 // process pkt
    ///                 # break;
    ///             }
    ///         }
    ///     }
    ///     # break;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn dedup_stream(self, dedup: Dedup) -> DedupStream<S> {
        DedupStream::new(self, dedup)
    }
}
