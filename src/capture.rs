//! High-level packet capture API.

use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, BorrowedFd};
use std::time::Duration;

use crate::afpacket::ffi;
use crate::afpacket::rx::{AfPacketRx, AfPacketRxBuilder};
use crate::config::{BpfInsn, FanoutFlags, FanoutMode, TimestampSource};
use crate::error::Error;
use crate::packet::{Packet, PacketBatch};
use crate::stats::CaptureStats;
use crate::traits::PacketSource;

/// High-level packet capture handle.
///
/// Wraps [`AfPacketRx`] and provides a flat packet iterator that
/// manages block retirement automatically.
///
/// # Examples
///
/// ```no_run
/// let mut cap = netring::Capture::new("lo").unwrap();
/// for pkt in cap.packets().take(10) {
///     println!("{} bytes", pkt.len());
/// }
/// ```
#[must_use]
pub struct Capture {
    rx: AfPacketRx,
    timeout: Duration,
}

impl Capture {
    /// Open capture on the named interface with default settings.
    ///
    /// Equivalent to `Capture::builder().interface(name).build()`.
    ///
    /// # Errors
    ///
    /// - [`Error::InterfaceNotFound`] if the interface doesn't exist
    /// - [`Error::PermissionDenied`] without `CAP_NET_RAW`
    /// - [`Error::Mmap`] if ring buffer allocation fails
    pub fn new(interface: &str) -> Result<Self, Error> {
        Self::builder().interface(interface).build()
    }

    /// Start building a capture with custom configuration.
    pub fn builder() -> CaptureBuilder {
        CaptureBuilder::default()
    }

    /// Blocking iterator over received packets.
    ///
    /// Handles block advancement and retirement automatically. Each
    /// [`Packet`] is a zero-copy view into the mmap ring buffer.
    ///
    /// The iterator blocks when no packets are available (using
    /// [`poll_timeout`](CaptureBuilder::poll_timeout)) and retries
    /// indefinitely. It only stops on I/O error.
    ///
    /// # Note
    ///
    /// For tests or bounded loops, use the low-level
    /// [`next_batch_blocking()`](crate::PacketSource::next_batch_blocking)
    /// with a deadline instead — this iterator never returns `None` on timeout.
    pub fn packets(&mut self) -> PacketIter<'_> {
        PacketIter {
            rx: &mut self.rx as *mut AfPacketRx,
            timeout: self.timeout,
            batch: None,
            remaining: 0,
            current_ptr: std::ptr::null(),
            block_end: std::ptr::null(),
            _marker: PhantomData,
        }
    }

    /// Capture statistics. **Resets kernel counters on each read.**
    ///
    /// # Errors
    ///
    /// Returns [`Error::SockOpt`] if `getsockopt(PACKET_STATISTICS)` fails.
    pub fn stats(&self) -> Result<CaptureStats, Error> {
        self.rx.stats()
    }

    /// Unwrap into the low-level [`AfPacketRx`].
    pub fn into_inner(self) -> AfPacketRx {
        self.rx
    }
}

impl AsFd for Capture {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.rx.as_fd()
    }
}

impl std::fmt::Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capture")
            .field("rx", &self.rx)
            .field("timeout", &self.timeout)
            .finish()
    }
}

// ── CaptureBuilder ─────────────────────────────────────────────────────────

/// Builder for [`Capture`].
///
/// On `ENOMEM`, retries with progressively smaller ring sizes (down to 25%
/// of requested) before returning an error.
#[must_use]
#[derive(Clone)]
pub struct CaptureBuilder {
    interface: Option<String>,
    block_size: usize,
    block_count: usize,
    frame_size: usize,
    block_timeout_ms: u32,
    promiscuous: bool,
    ignore_outgoing: bool,
    busy_poll_us: Option<u32>,
    timestamp_source: TimestampSource,
    poll_timeout: Duration,
    fanout: Option<(FanoutMode, u16)>,
    fanout_flags: FanoutFlags,
    bpf_filter: Option<Vec<BpfInsn>>,
}

impl Default for CaptureBuilder {
    fn default() -> Self {
        Self {
            interface: None,
            block_size: 1 << 22,
            block_count: 64,
            frame_size: 2048,
            block_timeout_ms: 60,
            promiscuous: false,
            ignore_outgoing: false,
            busy_poll_us: None,
            timestamp_source: TimestampSource::default(),
            poll_timeout: Duration::from_millis(100),
            fanout: None,
            fanout_flags: FanoutFlags::empty(),
            bpf_filter: None,
        }
    }
}

impl CaptureBuilder {
    /// Set the network interface name (required).
    pub fn interface(mut self, name: &str) -> Self {
        self.interface = Some(name.to_string());
        self
    }

    /// Block size in bytes. Default: 4 MiB.
    pub fn block_size(mut self, bytes: usize) -> Self {
        self.block_size = bytes;
        self
    }

    /// Number of blocks. Default: 64.
    pub fn block_count(mut self, n: usize) -> Self {
        self.block_count = n;
        self
    }

    /// Minimum frame size. Default: 2048.
    pub fn frame_size(mut self, bytes: usize) -> Self {
        self.frame_size = bytes;
        self
    }

    /// Block retirement timeout in ms. Default: 60.
    pub fn block_timeout_ms(mut self, ms: u32) -> Self {
        self.block_timeout_ms = ms;
        self
    }

    /// Enable promiscuous mode. Default: false.
    pub fn promiscuous(mut self, enable: bool) -> Self {
        self.promiscuous = enable;
        self
    }

    /// Ignore outgoing packets. Default: false.
    pub fn ignore_outgoing(mut self, enable: bool) -> Self {
        self.ignore_outgoing = enable;
        self
    }

    /// Enable `SO_BUSY_POLL` with the given timeout in microseconds.
    pub fn busy_poll_us(mut self, us: u32) -> Self {
        self.busy_poll_us = Some(us);
        self
    }

    /// Set the kernel timestamp source.
    pub fn timestamp_source(mut self, source: TimestampSource) -> Self {
        self.timestamp_source = source;
        self
    }

    /// Timeout for blocking poll in `packets()` iterator. Default: 100ms.
    pub fn poll_timeout(mut self, timeout: Duration) -> Self {
        self.poll_timeout = timeout;
        self
    }

    /// Join a fanout group.
    pub fn fanout(mut self, mode: FanoutMode, group_id: u16) -> Self {
        self.fanout = Some((mode, group_id));
        self
    }

    /// Set fanout flags.
    pub fn fanout_flags(mut self, flags: FanoutFlags) -> Self {
        self.fanout_flags = flags;
        self
    }

    /// Attach a classic BPF filter.
    pub fn bpf_filter(mut self, insns: Vec<BpfInsn>) -> Self {
        self.bpf_filter = Some(insns);
        self
    }

    /// Build an [`AfPacketRxBuilder`] with the given block_count.
    fn make_rx_builder(&self, block_count: usize) -> AfPacketRxBuilder {
        let mut b = AfPacketRxBuilder::default()
            .block_size(self.block_size)
            .block_count(block_count)
            .frame_size(self.frame_size)
            .block_timeout_ms(self.block_timeout_ms)
            .promiscuous(self.promiscuous)
            .ignore_outgoing(self.ignore_outgoing)
            .timestamp_source(self.timestamp_source);

        if let Some(name) = &self.interface {
            b = b.interface(name);
        }
        if let Some(us) = self.busy_poll_us {
            b = b.busy_poll_us(us);
        }
        if let Some((mode, gid)) = self.fanout {
            b = b.fanout(mode, gid).fanout_flags(self.fanout_flags);
        }
        if let Some(insns) = &self.bpf_filter {
            b = b.bpf_filter(insns.clone());
        }
        b
    }

    /// Validate and create the [`Capture`].
    pub fn build(self) -> Result<Capture, Error> {
        let mut current_count = self.block_count;
        let min_count = (self.block_count / 4).max(1);

        loop {
            let builder = self.make_rx_builder(current_count);
            match builder.build() {
                Ok(rx) => {
                    return Ok(Capture {
                        rx,
                        timeout: self.poll_timeout,
                    });
                }
                Err(Error::Mmap(ref e)) if is_enomem(e) && current_count > min_count => {
                    current_count = (current_count * 3 / 4).max(min_count);
                    tracing::warn!(
                        "ENOMEM: retrying with {current_count} blocks (was {})",
                        self.block_count
                    );
                }
                Err(Error::SockOpt { ref source, .. })
                    if is_enomem(source) && current_count > min_count =>
                {
                    current_count = (current_count * 3 / 4).max(min_count);
                    tracing::warn!(
                        "ENOMEM: retrying with {current_count} blocks (was {})",
                        self.block_count
                    );
                }
                Err(e) => return Err(e),
            }
        }
    }
}

fn is_enomem(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOMEM)
}

// ── PacketIter ─────────────────────────────────────────────────────────────

/// Flat iterator over packets, managing block retirement automatically.
///
/// Created by [`Capture::packets()`]. Designed for `for` loop consumption.
pub struct PacketIter<'cap> {
    rx: *mut AfPacketRx,
    timeout: Duration,
    batch: Option<ManuallyDrop<PacketBatch<'static>>>,
    remaining: u32,
    current_ptr: *const u8,
    block_end: *const u8,
    _marker: PhantomData<&'cap mut Capture>,
}

impl<'cap> Iterator for PacketIter<'cap> {
    type Item = Packet<'cap>;

    fn next(&mut self) -> Option<Packet<'cap>> {
        loop {
            if self.remaining > 0 {
                let hdr_size = std::mem::size_of::<ffi::tpacket3_hdr>();

                if (self.current_ptr as usize) + hdr_size > self.block_end as usize {
                    self.remaining = 0;
                    continue;
                }

                // SAFETY: bounds-checked, TPACKET_ALIGNMENT guarantees alignment.
                let hdr: &'cap ffi::tpacket3_hdr =
                    unsafe { &*(self.current_ptr as *const ffi::tpacket3_hdr) };

                let data_offset = hdr.tp_mac as usize;
                let snaplen = hdr.tp_snaplen as usize;
                let data_ptr = self.current_ptr.map_addr(|a| a + data_offset);

                if (data_ptr as usize) + snaplen > self.block_end as usize {
                    self.remaining = 0;
                    continue;
                }

                // SAFETY: bounds-checked, within mmap region.
                let data: &'cap [u8] = unsafe { std::slice::from_raw_parts(data_ptr, snaplen) };

                if hdr.tp_next_offset != 0 {
                    self.current_ptr = self
                        .current_ptr
                        .map_addr(|a| a + hdr.tp_next_offset as usize);
                }
                self.remaining -= 1;

                return Some(Packet::from_raw(data, hdr));
            }

            // Drop exhausted batch
            if let Some(batch) = self.batch.take() {
                let _ = ManuallyDrop::into_inner(batch);
            }

            // Get next batch
            // SAFETY: rx is valid for 'cap and no batch is live.
            let rx = unsafe { &mut *self.rx };
            match rx.next_batch_blocking(self.timeout) {
                Ok(Some(batch)) => {
                    self.remaining = batch.len() as u32;
                    if self.remaining == 0 {
                        drop(batch);
                        continue;
                    }

                    let base = batch.block_ptr().cast::<u8>();
                    self.current_ptr = base.map_addr(|a| a + batch.offset_to_first_pkt() as usize);
                    self.block_end = base.map_addr(|a| a + batch.blk_len() as usize);

                    // SAFETY: Lifetime erasure from PacketBatch<'_> to PacketBatch<'static>.
                    //
                    // This is sound because:
                    // 1. The mmap ring is valid for 'cap (owned by Capture, which
                    //    PacketIter borrows via PhantomData<&'cap mut Capture>).
                    // 2. The block is only released when we explicitly call
                    //    ManuallyDrop::into_inner (in the drop-exhausted-batch
                    //    branch above or in PacketIter::drop).
                    // 3. We never dereference self.rx while a batch is live
                    //    (checked by the if/else structure of next()).
                    //
                    // This exists because Rust's LendingIterator / StreamingIterator
                    // is not stabilized — standard Iterator cannot express a
                    // lifetime tied to the iterator itself.
                    //
                    // WARNING: collecting Packets across block boundaries (e.g.,
                    // iter.collect::<Vec<_>>()) is unsound because earlier blocks
                    // may be returned to the kernel. This iterator is designed
                    // for for-loop consumption only.
                    let erased: PacketBatch<'static> = unsafe { std::mem::transmute(batch) };
                    self.batch = Some(ManuallyDrop::new(erased));
                }
                Ok(None) => continue,
                Err(_) => return None,
            }
        }
    }
}

impl Drop for PacketIter<'_> {
    fn drop(&mut self) {
        if let Some(batch) = self.batch.take() {
            let _ = ManuallyDrop::into_inner(batch);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults() {
        let b = CaptureBuilder::default();
        assert_eq!(b.block_size, 1 << 22);
        assert_eq!(b.block_count, 64);
        assert_eq!(b.frame_size, 2048);
        assert_eq!(b.block_timeout_ms, 60);
        assert!(!b.promiscuous);
        assert!(!b.ignore_outgoing);
    }

    #[test]
    fn builder_rejects_missing_interface() {
        let err = CaptureBuilder::default().build().unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }
}
