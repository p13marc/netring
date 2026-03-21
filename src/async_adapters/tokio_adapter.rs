//! Async capture using tokio [`AsyncFd`].

use std::os::fd::{AsFd, AsRawFd};

use tokio::io::unix::AsyncFd;

use crate::error::Error;
use crate::traits::PacketSource;

/// Async wrapper around any [`PacketSource`] using tokio's [`AsyncFd`].
///
/// Due to Rust's borrow checker limitations with `AsyncFd` and lending
/// returns, [`wait_readable()`](AsyncCapture::wait_readable) provides
/// the async wait, and the caller then calls
/// [`get_mut().next_batch()`](PacketSource::next_batch) to get the batch.
///
/// # Examples
///
/// ```no_run
/// use netring::{AfPacketRx, AfPacketRxBuilder, PacketSource};
/// use netring::async_adapters::tokio_adapter::AsyncCapture;
///
/// # async fn example() -> Result<(), netring::Error> {
/// let rx = AfPacketRxBuilder::default().interface("lo").build()?;
/// let mut async_cap = AsyncCapture::new(rx)?;
///
/// loop {
///     async_cap.wait_readable().await?;
///     if let Some(batch) = async_cap.get_mut().next_batch() {
///         for pkt in &batch {
///             println!("{} bytes", pkt.len());
///         }
///     }
/// }
/// # }
/// ```
pub struct AsyncCapture<S: PacketSource + AsRawFd> {
    inner: AsyncFd<S>,
}

impl<S: PacketSource + AsRawFd> AsyncCapture<S> {
    /// Wrap a packet source in an async adapter.
    pub fn new(source: S) -> Result<Self, Error> {
        let fd = AsyncFd::new(source).map_err(Error::Io)?;
        Ok(Self { inner: fd })
    }

    /// Wait until the socket becomes readable (kernel retires a block).
    ///
    /// After this returns, call [`get_mut().next_batch()`](PacketSource::next_batch)
    /// to retrieve the batch. Note: spurious wakeups are possible — `next_batch()`
    /// may return `None`.
    pub async fn wait_readable(&self) -> Result<(), Error> {
        let mut guard = self.inner.readable().await.map_err(Error::Io)?;
        guard.clear_ready();
        Ok(())
    }

    /// Access the inner source.
    pub fn get_ref(&self) -> &S {
        self.inner.get_ref()
    }

    /// Mutable access to the inner source for calling `next_batch()`.
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
