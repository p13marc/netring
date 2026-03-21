//! High-level packet injection.

use std::os::fd::{AsFd, BorrowedFd};

use crate::afpacket::tx::{AfPacketTx, AfPacketTxBuilder, TxSlot};
use crate::error::Error;

/// High-level packet injection handle.
///
/// Wraps [`AfPacketTx`]. TPACKET_V3 TX uses V1 frame-based semantics.
///
/// # Examples
///
/// ```no_run
/// let mut tx = netring::Injector::builder()
///     .interface("lo")
///     .build()
///     .unwrap();
///
/// if let Some(mut slot) = tx.allocate(64) {
///     slot.data_mut()[0..6].copy_from_slice(&[0xff; 6]);
///     slot.set_len(64);
///     slot.send();
/// }
/// tx.flush().unwrap();
/// ```
#[must_use]
pub struct Injector {
    tx: AfPacketTx,
}

impl Injector {
    /// Start building a new injector.
    pub fn builder() -> InjectorBuilder {
        InjectorBuilder::default()
    }

    /// Allocate a TX frame. Returns `None` if the ring is full.
    pub fn allocate(&mut self, len: usize) -> Option<TxSlot<'_>> {
        self.tx.allocate(len)
    }

    /// Flush all pending frames to the wire. Returns the count flushed.
    pub fn flush(&mut self) -> Result<usize, Error> {
        self.tx.flush()
    }

    /// Unwrap into the low-level [`AfPacketTx`].
    pub fn into_inner(self) -> AfPacketTx {
        self.tx
    }
}

impl AsFd for Injector {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.tx.as_fd()
    }
}

impl std::fmt::Debug for Injector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Injector")
            .field("tx", &self.tx)
            .finish()
    }
}

/// Builder for [`Injector`].
#[must_use]
#[derive(Default)]
pub struct InjectorBuilder {
    inner: AfPacketTxBuilder,
}

impl InjectorBuilder {
    /// Set the network interface name (required).
    pub fn interface(mut self, name: &str) -> Self {
        self.inner = self.inner.interface(name);
        self
    }

    /// TX frame size. Default: 2048.
    pub fn frame_size(mut self, bytes: usize) -> Self {
        self.inner = self.inner.frame_size(bytes);
        self
    }

    /// Number of TX frames. Default: 256.
    pub fn frame_count(mut self, n: usize) -> Self {
        self.inner = self.inner.frame_count(n);
        self
    }

    /// Bypass qdisc for lower latency. Default: false.
    pub fn qdisc_bypass(mut self, enable: bool) -> Self {
        self.inner = self.inner.qdisc_bypass(enable);
        self
    }

    /// Validate and create the [`Injector`].
    pub fn build(self) -> Result<Injector, Error> {
        let tx = self.inner.build()?;
        Ok(Injector { tx })
    }
}
