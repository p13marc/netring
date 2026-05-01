//! High-level packet capture API.

use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, BorrowedFd};
use std::time::Duration;

use crate::afpacket::ffi;
use crate::afpacket::rx::{AfPacketRx, AfPacketRxBuilder};
use crate::config::{BpfInsn, FanoutFlags, FanoutMode, RingProfile, TimestampSource};
use crate::error::Error;
use crate::packet::{BatchIter, Packet, PacketBatch};
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
    /// indefinitely. It returns `None` only on I/O error; inspect the cause via
    /// [`PacketIter::take_error()`].
    ///
    /// # Soundness — do not collect across blocks
    ///
    /// Each [`Packet`] borrows from the *current* ring block. The iterator
    /// returns a block to the kernel before yielding packets from the next
    /// block, so any `Packet` retained from a prior block becomes a dangling
    /// reference. Use [`Packet::to_owned()`] if you need to keep a packet:
    ///
    /// ```no_run
    /// # let mut cap = netring::Capture::new("lo").unwrap();
    /// // ✓ Sound: each packet copied out of the ring as it's yielded.
    /// let owned: Vec<_> = cap.packets().take(100).map(|p| p.to_owned()).collect();
    /// ```
    ///
    /// # Bounded loops
    ///
    /// For tests or deadline-driven loops, use the low-level
    /// [`next_batch_blocking()`](crate::PacketSource::next_batch_blocking)
    /// instead — this iterator never returns `None` on idle timeout.
    pub fn packets(&mut self) -> PacketIter<'_> {
        PacketIter {
            rx: &mut self.rx as *mut AfPacketRx,
            timeout: self.timeout,
            batch: None,
            iter: None,
            last_error: None,
            _marker: PhantomData,
        }
    }

    /// Capture statistics. **Resets kernel counters on each read.**
    ///
    /// For monotonic totals (no kernel-counter reset surface), use
    /// [`cumulative_stats()`](Self::cumulative_stats) instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SockOpt`] if `getsockopt(PACKET_STATISTICS)` fails.
    pub fn stats(&self) -> Result<CaptureStats, Error> {
        self.rx.stats()
    }

    /// Accumulated statistics since this capture was created.
    ///
    /// Same kernel call as [`stats()`](Self::stats) but the delta is added
    /// to a running total kept on the capture, so the returned counters
    /// are monotonically non-decreasing across calls. **Do not mix with
    /// `stats()` calls on the same capture** — each `stats()` call also
    /// resets the kernel counter and bypasses the running total.
    pub fn cumulative_stats(&self) -> Result<CaptureStats, Error> {
        self.rx.cumulative_stats()
    }

    /// Unwrap into the low-level [`AfPacketRx`].
    pub fn into_inner(self) -> AfPacketRx {
        self.rx
    }

    /// Attach an eBPF socket filter program.
    ///
    /// See [`AfPacketRx::attach_ebpf_filter()`] for details.
    pub fn attach_ebpf_filter(&self, prog_fd: std::os::fd::RawFd) -> Result<(), Error> {
        self.rx.attach_ebpf_filter(prog_fd)
    }

    /// Attach an eBPF program to govern fanout distribution.
    ///
    /// See [`AfPacketRx::attach_fanout_ebpf()`] for details. Use this when
    /// the builder was configured with
    /// `.fanout(FanoutMode::Ebpf, group_id)`.
    pub fn attach_fanout_ebpf<F: AsFd>(&self, prog: F) -> Result<(), Error> {
        self.rx.attach_fanout_ebpf(prog)
    }

    /// Detach any attached BPF/eBPF filter.
    pub fn detach_filter(&self) -> Result<(), Error> {
        self.rx.detach_filter()
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
    fill_rxhash: bool,
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
            fill_rxhash: true,
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

    /// Apply a ring buffer profile. Sets block_size, block_count, frame_size,
    /// and block_timeout_ms in one call. Individual settings can be overridden
    /// after calling this.
    pub fn profile(mut self, profile: RingProfile) -> Self {
        let (bs, bc, fs, timeout) = profile.params();
        self.block_size = bs;
        self.block_count = bc;
        self.frame_size = fs;
        self.block_timeout_ms = timeout;
        self
    }

    /// Capture only the first `len` bytes of each packet (snap length).
    ///
    /// Reduces memory pressure and increases batch density when full payload
    /// isn't needed. Packets larger than `len` will have
    /// `original_len() > len()`.
    ///
    /// Internally sets `frame_size` to `snap_len + TPACKET3_HDRLEN` (aligned).
    pub fn snap_len(mut self, len: u32) -> Self {
        let frame = ffi::tpacket_align(ffi::TPACKET3_HDRLEN + len as usize);
        self.frame_size = frame;
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

    /// Request the kernel to populate `tp_rxhash` on every received packet.
    ///
    /// Default: `true`. Disable to shave a few percent of kernel-side overhead
    /// when [`Packet::rxhash()`](crate::Packet::rxhash) is unused.
    pub fn fill_rxhash(mut self, enable: bool) -> Self {
        self.fill_rxhash = enable;
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
            .fill_rxhash(self.fill_rxhash)
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
///
/// Walks blocks via the low-level [`BatchIter`] so bounds checking is uniform
/// with [`PacketBatch::iter()`] — `Packet::direction()` and friends are sound.
pub struct PacketIter<'cap> {
    rx: *mut AfPacketRx,
    timeout: Duration,
    /// Active batch with `'static` lifetime erasure. The actual lifetime is tied
    /// to `'cap` via the `PhantomData<&'cap mut Capture>` marker; `'static` is a
    /// placeholder so we can store `batch` and `iter` in the same struct without
    /// running into self-referential borrow restrictions.
    batch: Option<ManuallyDrop<PacketBatch<'static>>>,
    /// Iterator borrowing from `batch`. Lifetime is also erased to `'static`;
    /// always dropped together with `batch`.
    iter: Option<BatchIter<'static>>,
    /// Last I/O error encountered, exposed via [`PacketIter::take_error`].
    last_error: Option<Error>,
    _marker: PhantomData<&'cap mut Capture>,
}

impl<'cap> PacketIter<'cap> {
    /// Take the most recent error that caused iteration to terminate.
    ///
    /// Returns `None` if iteration is still active or terminated cleanly. The
    /// error is consumed; a second call returns `None`.
    pub fn take_error(&mut self) -> Option<Error> {
        self.last_error.take()
    }

    /// Drop the active batch (if any), returning its block to the kernel.
    fn drop_batch(&mut self) {
        // The iter borrows from the batch — drop it first.
        self.iter = None;
        if let Some(batch) = self.batch.take() {
            let _ = ManuallyDrop::into_inner(batch);
        }
    }
}

impl<'cap> Iterator for PacketIter<'cap> {
    type Item = Packet<'cap>;

    fn next(&mut self) -> Option<Packet<'cap>> {
        loop {
            if let Some(it) = self.iter.as_mut() {
                if let Some(pkt) = it.next() {
                    // SAFETY: the packet borrows from `self.batch` via the
                    // erased `'static` lifetime. The actual lifetime upper-bound
                    // is `'cap` (the `PhantomData<&'cap mut Capture>` marker on
                    // `PacketIter`), and the batch is held in `self.batch` until
                    // the next iterator call drops it. Transmuting to `'cap`
                    // re-imposes that bound for the caller.
                    let pkt: Packet<'cap> = unsafe { std::mem::transmute(pkt) };
                    return Some(pkt);
                }
                // BatchIter exhausted — drop the batch before requesting another
                // (releases the block back to the kernel).
                self.drop_batch();
            }

            // SAFETY: `rx` is valid for `'cap`; no batch is live (we just dropped
            // it). The pointer dereference is guarded by `&mut self` on next().
            let rx = unsafe { &mut *self.rx };
            match rx.next_batch_blocking(self.timeout) {
                Ok(Some(batch)) => {
                    if batch.is_empty() {
                        drop(batch);
                        continue;
                    }
                    // SAFETY: lifetime erasure from `PacketBatch<'_>` to
                    // `PacketBatch<'static>`. Sound because:
                    //   1. The mmap ring is valid for `'cap` (Capture owns rx,
                    //      and PacketIter borrows via `PhantomData<&'cap mut Capture>`).
                    //   2. We only release the block by explicitly calling
                    //      `ManuallyDrop::into_inner` (in `drop_batch` or `Drop`).
                    //   3. The yielded `Packet<'cap>` lifetime is bounded by `'cap`
                    //      via the transmute back, so the borrow checker prevents
                    //      retention past the next `drop_batch` call (provided the
                    //      caller does not collect — see Capture::packets soundness
                    //      note).
                    // LendingIterator would let us avoid the transmute; until it
                    // stabilizes, this is the standard workaround.
                    let erased_batch: PacketBatch<'static> = unsafe { std::mem::transmute(batch) };
                    self.batch = Some(ManuallyDrop::new(erased_batch));

                    // SAFETY: same lifetime erasure logic. The iter borrows from
                    // the batch we just stored; both share the erased `'static`
                    // and are dropped together.
                    let iter: BatchIter<'_> = self.batch.as_ref().unwrap().iter();
                    let iter_erased: BatchIter<'static> = unsafe { std::mem::transmute(iter) };
                    self.iter = Some(iter_erased);
                }
                Ok(None) => continue,
                Err(e) => {
                    self.last_error = Some(e);
                    return None;
                }
            }
        }
    }
}

impl Drop for PacketIter<'_> {
    fn drop(&mut self) {
        self.drop_batch();
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
        assert!(b.fill_rxhash);
        assert!(!b.promiscuous);
        assert!(!b.ignore_outgoing);
    }

    #[test]
    fn builder_fill_rxhash_setter() {
        let b = CaptureBuilder::default().fill_rxhash(false);
        assert!(!b.fill_rxhash);
    }

    #[test]
    fn builder_rejects_missing_interface() {
        let err = CaptureBuilder::default().build().unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }
}
