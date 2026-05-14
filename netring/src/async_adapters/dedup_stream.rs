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
    /// Plan 20: optional pcap tap. Records packets that pass dedup
    /// before they're yielded to the consumer.
    #[cfg(feature = "pcap")]
    tap: Option<crate::pcap_tap::PcapTap>,
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
            #[cfg(feature = "pcap")]
            tap: None,
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

    /// Plan 20: tap every kept packet into `writer`. Packets that
    /// the dedup drops are not recorded. Default error policy:
    /// [`TapErrorPolicy::Continue`](crate::pcap_tap::TapErrorPolicy::Continue).
    #[cfg(feature = "pcap")]
    pub fn with_pcap_tap<W>(self, writer: crate::pcap::CaptureWriter<W>) -> Self
    where
        W: std::io::Write + Send + 'static,
    {
        self.with_pcap_tap_policy(writer, crate::pcap_tap::TapErrorPolicy::default())
    }

    /// Plan 20: variant of [`with_pcap_tap`](Self::with_pcap_tap)
    /// with an explicit [`TapErrorPolicy`](crate::pcap_tap::TapErrorPolicy).
    #[cfg(feature = "pcap")]
    pub fn with_pcap_tap_policy<W>(
        mut self,
        writer: crate::pcap::CaptureWriter<W>,
        policy: crate::pcap_tap::TapErrorPolicy,
    ) -> Self
    where
        W: std::io::Write + Send + 'static,
    {
        self.tap = Some(crate::pcap_tap::PcapTap::new(writer, policy));
        self
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
                    #[cfg(feature = "pcap")]
                    let mut tap_error: Option<Error> = None;
                    for pkt in &batch {
                        if this.dedup.keep(&pkt) {
                            // Plan 20: pcap tap — record before yielding.
                            #[cfg(feature = "pcap")]
                            if let Some(tap) = this.tap.as_mut()
                                && let Some(err) = tap.write_or_handle(&pkt)
                            {
                                tap_error = Some(err);
                                break;
                            }
                            this.pending.push_back(pkt.to_owned());
                        }
                    }
                    drop(batch);
                    #[cfg(feature = "pcap")]
                    if let Some(err) = tap_error {
                        return Poll::Ready(Some(Err(err)));
                    }
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

// ── StreamCapture trait impl ───────────────────────────────────────

use crate::async_adapters::stream_capture::{Sealed, StreamCapture};

impl<S> Sealed for DedupStream<S> where S: PacketSource + std::os::unix::io::AsRawFd {}

impl<S> StreamCapture for DedupStream<S>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
{
    type Source = S;

    fn capture(&self) -> &AsyncCapture<S> {
        &self.cap
    }
}
