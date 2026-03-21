//! Core traits for packet capture and injection.
//!
//! - [`PacketSource`] — RX path (batch-oriented, zero-copy)
//! - [`PacketSink`] — TX path (frame-based)
//! - [`AsyncPacketSource`] — async RX (feature: `tokio`)

use std::os::fd::AsFd;
use std::time::Duration;

use crate::afpacket::tx::TxSlot;
use crate::error::Error;
use crate::packet::PacketBatch;
use crate::stats::CaptureStats;

/// A source of packet batches (RX path).
///
/// The core abstraction for receiving packets. Implement this trait to add
/// new backends (AF_XDP, mock sources, pcap replay).
///
/// # Ownership Model
///
/// Only **one [`PacketBatch`] can be live at a time** — enforced by `&mut self`
/// on [`next_batch()`](PacketSource::next_batch). When the batch is dropped,
/// the underlying block is returned to the kernel (RAII).
///
/// # AsFd
///
/// Requires [`AsFd`] so the fd can be used with `epoll`, tokio's `AsyncFd`,
/// or for attaching eBPF programs via `aya`.
///
/// # Examples
///
/// ```no_run
/// use netring::{AfPacketRxBuilder, PacketSource};
/// use std::time::Duration;
///
/// let mut rx = AfPacketRxBuilder::default().interface("lo").build().unwrap();
/// while let Some(batch) = rx.next_batch_blocking(Duration::from_millis(100)).unwrap() {
///     for pkt in &batch {
///         println!("{} bytes", pkt.len());
///     }
///     // batch dropped → block returned to kernel
/// }
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be used as a packet source",
    label = "this type does not implement `PacketSource`",
    note = "consider using `AfPacketRx` or implementing this trait for your backend"
)]
pub trait PacketSource: AsFd {
    /// Non-blocking poll for the next retired block.
    ///
    /// Returns `None` if no block is currently available. The returned
    /// [`PacketBatch`] holds a mutable borrow on `self` — you must drop it
    /// before calling `next_batch()` again.
    ///
    /// Dropping the batch writes `TP_STATUS_KERNEL` to return the block
    /// to the kernel.
    fn next_batch(&mut self) -> Option<PacketBatch<'_>>;

    /// Block until a batch is available or `timeout` expires.
    ///
    /// Uses `poll(2)` internally. Returns `Ok(None)` on timeout.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the underlying `poll()` syscall fails.
    fn next_batch_blocking(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<PacketBatch<'_>>, Error>;

    /// Capture statistics since last read.
    ///
    /// Returns packet counts, drop counts, and freeze counts from the kernel.
    /// **Reading resets the kernel counters** — call periodically for rate
    /// calculations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SockOpt`] if `getsockopt(PACKET_STATISTICS)` fails.
    fn stats(&self) -> Result<CaptureStats, Error>;
}

/// A sink for outgoing packets (TX path).
///
/// Provides a two-step send model: [`allocate()`](PacketSink::allocate) a
/// frame, write data into it, then [`send()`](TxSlot::send) it. Call
/// [`flush()`](PacketSink::flush) to trigger kernel transmission.
///
/// # Frame Lifecycle
///
/// ```text
/// allocate() → TxSlot → write data → send() → flush() → kernel transmits
///                      → drop (no send) → frame discarded
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be used as a packet sink",
    label = "this type does not implement `PacketSink`",
    note = "consider using `AfPacketTx` or implementing this trait for your backend"
)]
pub trait PacketSink: AsFd {
    /// Allocate a mutable TX frame for a packet of up to `len` bytes.
    ///
    /// Returns `None` if the TX ring is full (all frames are pending
    /// transmission). The returned [`TxSlot`] must have
    /// [`send()`](TxSlot::send) called to queue it; dropping without
    /// `send()` discards the frame.
    fn allocate(&mut self, len: usize) -> Option<TxSlot<'_>>;

    /// Flush all frames queued via [`TxSlot::send()`] to the wire.
    ///
    /// Calls `sendto(fd, NULL, 0, ...)` to trigger kernel transmission.
    /// Returns the number of frames that were pending.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the `sendto` syscall fails.
    fn flush(&mut self) -> Result<usize, Error>;
}

/// Async packet source (feature: `tokio`).
///
/// Uses native `async fn` in traits (stable since Rust 1.75 — no
/// `#[async_trait]` proc macro needed).
#[cfg(feature = "tokio")]
pub trait AsyncPacketSource: AsFd {
    /// Await the next packet batch.
    ///
    /// Implementations should wait for the socket to become readable
    /// (via `AsyncFd` or similar) and then return the next retired block.
    fn next_batch(
        &mut self,
    ) -> impl std::future::Future<Output = Result<PacketBatch<'_>, Error>> + Send;
}
