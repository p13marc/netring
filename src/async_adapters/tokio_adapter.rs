//! Async capture using tokio [`AsyncFd`].
//!
//! # Design Note
//!
//! The spec originally defined `AsyncCapture::recv() -> PacketBatch<'_>`, but
//! Rust's borrow checker prevents returning a lending reference through
//! `AsyncFd`'s guard-based API. Instead, this module provides two patterns:
//!
//! - **Zero-copy**: `wait_readable()` + `get_mut().next_batch()` (two calls)
//! - **Owned**: `recv()` returns `Vec<OwnedPacket>` (copies, but simpler)

use std::os::fd::{AsFd, AsRawFd};

use tokio::io::unix::AsyncFd;

use crate::error::Error;
use crate::packet::OwnedPacket;
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

    /// Wait until the socket becomes readable (kernel retires a block).
    ///
    /// After this returns, call [`get_mut().next_batch()`](PacketSource::next_batch)
    /// to retrieve the batch as a zero-copy view. Spurious wakeups are possible —
    /// `next_batch()` may return `None`.
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
