//! [`StreamCapture`] — sealed trait giving async stream types
//! uniform read-access to their underlying capture.
//!
//! Implemented for [`FlowStream`](super::flow_stream::FlowStream),
//! [`SessionStream`](super::session_stream::SessionStream),
//! [`DatagramStream`](super::datagram_stream::DatagramStream),
//! and [`DedupStream`](super::dedup_stream::DedupStream). External
//! crates cannot implement this trait — adding new stream
//! adapters is netring's concern.
//!
//! # Why it exists
//!
//! Once a stream is built (`cap.flow_stream(...)`, etc.) the
//! underlying [`AsyncCapture`] moves into the stream. Without
//! this trait, kernel-ring statistics, BPF filter swap, and other
//! capture-level operations become unreachable. The accessor lets
//! callers reach back through:
//!
//! ```no_run
//! # use netring::{AsyncCapture, StreamCapture};
//! # use netring::flow::extract::FiveTuple;
//! # async fn _ex() -> Result<(), netring::Error> {
//! let cap = AsyncCapture::open("eth0")?;
//! let stream = cap.flow_stream(FiveTuple::bidirectional());
//!
//! // Poll kernel ring stats while the stream is running:
//! let stats = stream.capture_stats()?;
//! eprintln!("ring drops: {}", stats.drops);
//!
//! // Or reach the AsyncCapture directly for richer operations:
//! let _fd = stream.capture();
//! # Ok(()) }
//! ```
//!
//! The trait's default methods cover the common cases
//! ([`capture_stats`](StreamCapture::capture_stats),
//! [`capture_cumulative_stats`](StreamCapture::capture_cumulative_stats));
//! impls supply only the [`capture`](StreamCapture::capture) hook.

use std::os::unix::io::AsRawFd;

use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::error::Error;
use crate::stats::CaptureStats;
use crate::traits::PacketSource;

/// Sealing module — keeps external crates from implementing
/// [`StreamCapture`] on their own types.
mod sealed {
    pub trait Sealed {}
}

pub(crate) use sealed::Sealed;

/// Uniform read-access to the underlying [`AsyncCapture`] for an
/// async stream adapter. Sealed — implemented only by netring's
/// own stream types.
///
/// See the module-level docs for rationale and examples.
pub trait StreamCapture: Sealed {
    /// The underlying packet source type.
    type Source: PacketSource + AsRawFd;

    /// Borrow the underlying capture.
    ///
    /// Use this to reach any [`AsyncCapture`] method (or, via
    /// [`AsyncCapture::get_ref`], any [`PacketSource`] method
    /// on the source type itself). For the AF_PACKET case this
    /// includes `set_filter` (plan 21), `detach_filter`, etc.
    fn capture(&self) -> &AsyncCapture<Self::Source>;

    /// Kernel ring statistics for the underlying capture.
    ///
    /// **Resets the kernel counters** on read (AF_PACKET semantics).
    /// Pair with [`capture_cumulative_stats`](Self::capture_cumulative_stats)
    /// if you want monotonic totals.
    ///
    /// For offline sources (plan 23's `AsyncPcapSource`), this
    /// returns `packets = #packets read so far`, `drops = 0`,
    /// `freeze_count = 0`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SockOpt`](crate::Error::SockOpt) if
    /// `getsockopt(PACKET_STATISTICS)` fails — typically only when
    /// the socket has been closed.
    fn capture_stats(&self) -> Result<CaptureStats, Error> {
        self.capture().stats()
    }

    /// Monotonic counterpart of [`capture_stats`](Self::capture_stats).
    /// Accumulates across reads, so callers polling on a timer see
    /// non-decreasing values.
    fn capture_cumulative_stats(&self) -> Result<CaptureStats, Error> {
        self.capture().cumulative_stats()
    }
}
