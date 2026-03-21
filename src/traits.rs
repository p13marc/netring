//! Core traits: `PacketSource` and `PacketSink`.

use std::os::fd::AsFd;
use std::time::Duration;

use crate::error::Error;
use crate::packet::PacketBatch;
use crate::stats::CaptureStats;

/// A source of packet batches (RX path).
///
/// Implement this trait to add new backends (AF_XDP, mock sources, pcap replay).
/// The trait requires [`AsFd`] so the fd can be used with `epoll`/`AsyncFd`
/// or for attaching eBPF programs via `aya`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be used as a packet source",
    label = "this type does not implement `PacketSource`",
    note = "consider using `AfPacketRx` or implementing this trait for your backend"
)]
pub trait PacketSource: AsFd {
    /// Non-blocking poll for the next batch.
    ///
    /// Returns `None` if no block is currently retired by the kernel.
    /// The returned [`PacketBatch`] borrows from the ring; dropping it
    /// returns the block to the kernel.
    fn next_batch(&mut self) -> Option<PacketBatch<'_>>;

    /// Block until a batch is available or timeout expires.
    fn next_batch_blocking(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<PacketBatch<'_>>, Error>;

    /// Capture statistics since last read. Resets kernel counters.
    fn stats(&self) -> Result<CaptureStats, Error>;
}
