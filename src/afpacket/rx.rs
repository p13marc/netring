//! AF_PACKET TPACKET_V3 capture (RX path).

use std::cell::Cell;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use crate::afpacket::ring::MmapRing;
use crate::afpacket::{fanout, ffi, filter, ring, socket};
use crate::config::{BpfFilter, BpfInsn, FanoutFlags, FanoutMode, RingProfile, TimestampSource};
use crate::error::Error;
use crate::packet::{BatchIter, Packet, PacketBatch};
use crate::stats::CaptureStats;
use crate::traits::PacketSource;

/// AF_PACKET TPACKET_V3 packet capture.
///
/// Implements [`PacketSource`] and [`AsFd`]. Use [`Capture::open`] for the
/// common case or [`Capture::builder`] for full configuration.
///
/// # Examples
///
/// ```no_run
/// // Simplest form — captures forever, blocks on each iteration.
/// let mut cap = netring::Capture::open("lo")?;
/// for pkt in cap.packets().take(10) {
///     println!("{} bytes", pkt.len());
/// }
/// # Ok::<(), netring::Error>(())
/// ```
///
/// ```no_run
/// // Configured for high-throughput capture with fanout.
/// use netring::{Capture, FanoutMode, FanoutFlags, RingProfile};
///
/// let mut cap = Capture::builder()
///     .interface("eth0")
///     .profile(RingProfile::HighThroughput)
///     .promiscuous(true)
///     .fanout(FanoutMode::Cpu, 42)
///     .fanout_flags(FanoutFlags::ROLLOVER | FanoutFlags::DEFRAG)
///     .build()?;
/// # Ok::<(), netring::Error>(())
/// ```
pub struct Capture {
    // Drop order: ring (munmap) before fd (close).
    ring: MmapRing,
    fd: OwnedFd,
    current_block: usize,
    expected_seq: u64,
    /// Default poll timeout used by [`packets()`](Self::packets).
    /// Configured via [`CaptureBuilder::poll_timeout`].
    poll_timeout: Duration,
    /// Running totals across calls to [`cumulative_stats`](Self::cumulative_stats).
    /// `stats()` (the destructive variant) does not touch this.
    cumulative: Cell<CaptureStats>,
}

impl Capture {
    /// Open a capture on `interface` with default settings.
    ///
    /// Equivalent to `Capture::builder().interface(interface).build()`.
    /// For configuration beyond defaults, use [`Capture::builder`].
    ///
    /// # Errors
    ///
    /// - [`Error::InterfaceNotFound`] if the interface doesn't exist.
    /// - [`Error::PermissionDenied`] without `CAP_NET_RAW`.
    /// - [`Error::Mmap`] if ring buffer allocation fails.
    pub fn open(interface: &str) -> Result<Self, Error> {
        Self::builder().interface(interface).build()
    }

    /// Start building a configured capture.
    pub fn builder() -> CaptureBuilder {
        CaptureBuilder::default()
    }

    // ── Stats ────────────────────────────────────────────────────────────

    /// Capture statistics since the last call. **Resets kernel counters.**
    ///
    /// For monotonic totals (no kernel-counter reset), use
    /// [`cumulative_stats`](Self::cumulative_stats).
    pub fn stats(&self) -> Result<CaptureStats, Error> {
        let raw = socket::get_packet_stats(self.fd.as_fd())?;
        Ok(CaptureStats::from(raw))
    }

    /// Accumulated statistics since this capture was opened.
    ///
    /// Internally calls `stats()` (which resets kernel counters) and adds
    /// the delta to a running total stored on `self`. Returned counters
    /// are monotonically non-decreasing across calls. **Do not mix with
    /// `stats()` on the same capture** — each `stats()` call also resets
    /// the kernel counter and bypasses the running total.
    pub fn cumulative_stats(&self) -> Result<CaptureStats, Error> {
        let delta = socket::get_packet_stats(self.fd.as_fd())?;
        let total = self.cumulative.get();
        let new_total = CaptureStats {
            packets: total.packets.saturating_add(delta.tp_packets),
            drops: total.drops.saturating_add(delta.tp_drops),
            freeze_count: total.freeze_count.saturating_add(delta.tp_freeze_q_cnt),
        };
        self.cumulative.set(new_total);
        Ok(new_total)
    }

    // ── Flat packet iterators ────────────────────────────────────────────

    /// Blocking iterator over received packets.
    ///
    /// Handles block advancement and retirement automatically. Each
    /// [`Packet`] is a zero-copy view into the mmap ring. The iterator
    /// blocks (using the configured [`poll_timeout`](CaptureBuilder::poll_timeout))
    /// and retries indefinitely; it returns `None` only on I/O error —
    /// inspect via [`Packets::take_error`].
    ///
    /// # Soundness — do not collect across blocks
    ///
    /// Each [`Packet`] borrows from the *current* ring block. The iterator
    /// returns a block to the kernel before yielding packets from the next
    /// block, so any `Packet` retained from a prior block becomes a dangling
    /// reference. Use [`Packet::to_owned()`] when you need to keep a packet:
    ///
    /// ```no_run
    /// # let mut cap = netring::Capture::open("lo").unwrap();
    /// let owned: Vec<_> = cap.packets().take(100).map(|p| p.to_owned()).collect();
    /// ```
    ///
    /// # Bounded iteration
    ///
    /// For deadline-driven loops, see [`packets_for`](Self::packets_for) /
    /// [`packets_until`](Self::packets_until).
    pub fn packets(&mut self) -> Packets<'_> {
        Packets {
            cap: self as *mut Capture,
            timeout: self.poll_timeout,
            deadline: None,
            batch: None,
            iter: None,
            last_error: None,
            _marker: PhantomData,
        }
    }

    /// Iterator that stops at `deadline`.
    pub fn packets_until(&mut self, deadline: Instant) -> Packets<'_> {
        Packets {
            cap: self as *mut Capture,
            timeout: self.poll_timeout,
            deadline: Some(deadline),
            batch: None,
            iter: None,
            last_error: None,
            _marker: PhantomData,
        }
    }

    /// Iterator that runs for at most `total` from now.
    pub fn packets_for(&mut self, total: Duration) -> Packets<'_> {
        self.packets_until(Instant::now() + total)
    }

    // ── Filter / fanout management ───────────────────────────────────────

    /// Attach an eBPF socket filter program.
    ///
    /// Replaces any existing filter (classic BPF or eBPF). The program
    /// must be `BPF_PROG_TYPE_SOCKET_FILTER`. Packets not accepted by
    /// the program are dropped before reaching the ring.
    ///
    /// `prog` is borrowed for the call — the kernel keeps its own
    /// reference until you detach or close the socket.
    pub fn attach_ebpf_filter<F: AsFd>(&self, prog: F) -> Result<(), Error> {
        filter::attach_ebpf_socket_filter(self.fd.as_fd(), prog.as_fd())
    }

    /// Attach an eBPF program to govern fanout distribution.
    ///
    /// Must be called on a capture whose builder used
    /// `.fanout(FanoutMode::Ebpf, group_id)`.
    pub fn attach_fanout_ebpf<F: AsFd>(&self, prog: F) -> Result<(), Error> {
        fanout::attach_fanout_ebpf(self.fd.as_fd(), prog.as_fd())
    }

    /// Detach any attached BPF/eBPF filter.
    pub fn detach_filter(&self) -> Result<(), Error> {
        filter::detach_bpf_filter(self.fd.as_fd())
    }

    // ── Advanced ─────────────────────────────────────────────────────────

    /// Mmap base pointer for advanced use (e.g., `madvise`).
    ///
    /// # Safety
    ///
    /// The caller must not write to the returned pointer region or
    /// interfere with block status fields.
    pub unsafe fn ring_ptr(&self) -> *const u8 {
        self.ring.base().as_ptr()
    }

    /// Total size of the mmap region in bytes.
    pub fn ring_len(&self) -> usize {
        self.ring.size()
    }

    // ── Batch reception (inherent — no PacketSource import required) ────

    /// Take the next retired block as a [`PacketBatch`] (non-blocking).
    ///
    /// Returns `None` if the kernel hasn't retired a block yet. The batch
    /// borrows `&mut self`; only one batch can be live at a time.
    pub fn next_batch(&mut self) -> Option<PacketBatch<'_>> {
        let bd = self.ring.block_ptr(self.current_block);

        // SAFETY: bd points to a valid block descriptor in our mmap region.
        let status = unsafe { ring::read_block_status(bd) };

        if status & ffi::TP_STATUS_USER == 0 {
            return None;
        }

        // Read sequence number for gap detection
        // SAFETY: block is user-owned (Acquire fence done in read_block_status).
        let seq = unsafe { (*bd.as_ptr()).hdr.bh1.seq_num };
        if seq != self.expected_seq && self.expected_seq != 0 {
            tracing::warn!(
                expected = self.expected_seq,
                actual = seq,
                dropped = seq.saturating_sub(self.expected_seq),
                "block sequence gap"
            );
        }
        self.expected_seq = seq + 1;

        // SAFETY: block is user-owned, bd is valid, block_size is correct.
        let batch = unsafe { PacketBatch::new(bd) };
        self.current_block = (self.current_block + 1) % self.ring.block_count();
        Some(batch)
    }

    /// Block until a batch is available, or `timeout` elapses.
    ///
    /// EINTR is handled internally — callers see `Ok(None)` on timeout, not
    /// a spurious error from a signal interrupting the underlying `poll(2)`.
    pub fn next_batch_blocking(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<PacketBatch<'_>>, Error> {
        // Check if a batch is already available (non-blocking).
        {
            let bd = self.ring.block_ptr(self.current_block);
            let status = unsafe { ring::read_block_status(bd) };
            if status & ffi::TP_STATUS_USER != 0 {
                return Ok(self.next_batch());
            }
        }

        let mut pfds = [nix::poll::PollFd::new(
            self.fd.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        crate::syscall::poll_eintr_safe(&mut pfds, timeout).map_err(Error::Io)?;

        Ok(self.next_batch())
    }
}

// PacketSource trait impl — delegates to the inherent methods. The trait is
// useful for generic code (AsyncCapture<S>, custom backends); inherent
// methods are useful so users don't need an extra `use PacketSource;`.
impl PacketSource for Capture {
    fn next_batch(&mut self) -> Option<PacketBatch<'_>> {
        Capture::next_batch(self)
    }

    fn next_batch_blocking(&mut self, timeout: Duration) -> Result<Option<PacketBatch<'_>>, Error> {
        Capture::next_batch_blocking(self, timeout)
    }

    fn stats(&self) -> Result<CaptureStats, Error> {
        Capture::stats(self)
    }

    fn cumulative_stats(&self) -> Result<CaptureStats, Error> {
        Capture::cumulative_stats(self)
    }
}

impl std::fmt::Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capture")
            .field("ring_size", &self.ring.size())
            .field("block_count", &self.ring.block_count())
            .field("current_block", &self.current_block)
            .field("poll_timeout", &self.poll_timeout)
            .finish()
    }
}

impl AsFd for Capture {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Capture {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

// SAFETY: Capture owns its fd and ring exclusively. Safe to move across threads.
unsafe impl Send for Capture {}

// ── Packets iterator ────────────────────────────────────────────────────

/// Flat iterator over packets, managing block retirement automatically.
///
/// Created by [`Capture::packets`] / [`Capture::packets_for`] /
/// [`Capture::packets_until`]. Designed for `for` loop consumption — see
/// the soundness note on [`Capture::packets`] before retaining yielded
/// packets across iterations.
pub struct Packets<'cap> {
    cap: *mut Capture,
    timeout: Duration,
    /// Optional deadline; `next()` returns `None` once it elapses.
    deadline: Option<Instant>,
    batch: Option<ManuallyDrop<PacketBatch<'static>>>,
    iter: Option<BatchIter<'static>>,
    last_error: Option<Error>,
    _marker: PhantomData<&'cap mut Capture>,
}

impl<'cap> Packets<'cap> {
    /// Take the most recent error that caused iteration to terminate.
    ///
    /// Returns `None` if iteration is still active or terminated cleanly.
    /// The error is consumed; a second call returns `None`.
    pub fn take_error(&mut self) -> Option<Error> {
        self.last_error.take()
    }

    fn drop_batch(&mut self) {
        // The iter borrows from the batch — drop it first.
        self.iter = None;
        if let Some(batch) = self.batch.take() {
            let _ = ManuallyDrop::into_inner(batch);
        }
    }
}

impl<'cap> Iterator for Packets<'cap> {
    type Item = Packet<'cap>;

    fn next(&mut self) -> Option<Packet<'cap>> {
        loop {
            if let Some(it) = self.iter.as_mut() {
                if let Some(pkt) = it.next() {
                    // SAFETY: see the lifetime erasure note in the
                    // PacketBatch transmute below — the transmute back
                    // to 'cap re-imposes the right upper bound.
                    let pkt: Packet<'cap> = unsafe { std::mem::transmute(pkt) };
                    return Some(pkt);
                }
                // BatchIter exhausted — drop the batch before requesting
                // another (releases the block back to the kernel).
                self.drop_batch();
            }

            // SAFETY: `cap` is valid for `'cap`; no batch is live (we just
            // dropped it). The pointer dereference is guarded by `&mut self`
            // on next() — only one Packets exists per Capture.
            let cap = unsafe { &mut *self.cap };

            // Effective timeout = min(self.timeout, deadline - now).
            let effective_timeout = match self.deadline {
                Some(d) => match d.checked_duration_since(Instant::now()) {
                    Some(remaining) => remaining.min(self.timeout),
                    None => return None,
                },
                None => self.timeout,
            };
            match cap.next_batch_blocking(effective_timeout) {
                Ok(Some(batch)) => {
                    if batch.is_empty() {
                        drop(batch);
                        continue;
                    }
                    // SAFETY: lifetime erasure from `PacketBatch<'_>` to
                    // `PacketBatch<'static>`. Sound because:
                    //   1. The Capture (and its mmap ring) is valid for `'cap`.
                    //   2. We only release the block via ManuallyDrop in
                    //      drop_batch / Drop.
                    //   3. The yielded `Packet<'cap>` is bounded by `'cap`
                    //      via the transmute back (assuming the caller doesn't
                    //      retain across iterations — soundness note above).
                    let erased_batch: PacketBatch<'static> = unsafe { std::mem::transmute(batch) };
                    self.batch = Some(ManuallyDrop::new(erased_batch));

                    // SAFETY: same erasure logic — iter borrows from the
                    // batch we just stored; both share `'static` and are
                    // dropped together.
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

impl Drop for Packets<'_> {
    fn drop(&mut self) {
        self.drop_batch();
    }
}

// ── Builder ────────────────────────────────────────────────────────────────

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
    reuseport: bool,
    rcvbuf: Option<usize>,
    rcvbuf_force: bool,
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
            block_size: 1 << 22, // 4 MiB
            block_count: 64,
            frame_size: 2048,
            block_timeout_ms: 60,
            fill_rxhash: true,
            promiscuous: false,
            ignore_outgoing: false,
            busy_poll_us: None,
            reuseport: false,
            rcvbuf: None,
            rcvbuf_force: false,
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

    /// Apply a ring buffer profile.
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
    /// Internally sets `frame_size` to `snap_len + TPACKET3_HDRLEN` (aligned).
    pub fn snap_len(mut self, len: u32) -> Self {
        let frame = ffi::tpacket_align(ffi::TPACKET3_HDRLEN + len as usize);
        self.frame_size = frame;
        self
    }

    /// Block size in bytes (must be power of 2 and multiple of PAGE_SIZE). Default: 4 MiB.
    pub fn block_size(mut self, bytes: usize) -> Self {
        self.block_size = bytes;
        self
    }

    /// Number of blocks. Default: 64.
    pub fn block_count(mut self, n: usize) -> Self {
        self.block_count = n;
        self
    }

    /// Minimum frame size (multiple of 16, >= 68). Default: 2048.
    pub fn frame_size(mut self, bytes: usize) -> Self {
        self.frame_size = bytes;
        self
    }

    /// Block retirement timeout in milliseconds. Default: 60.
    pub fn block_timeout_ms(mut self, ms: u32) -> Self {
        self.block_timeout_ms = ms;
        self
    }

    /// Request the kernel to populate `tp_rxhash` on every received packet.
    /// Default: `true`.
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

    /// Enable SO_BUSY_POLL with the given microsecond timeout.
    pub fn busy_poll_us(mut self, us: u32) -> Self {
        self.busy_poll_us = Some(us);
        self
    }

    /// Enable `SO_REUSEPORT`. Default: false.
    pub fn reuseport(mut self, enable: bool) -> Self {
        self.reuseport = enable;
        self
    }

    /// Set the socket receive buffer size via `SO_RCVBUF`.
    pub fn rcvbuf(mut self, bytes: usize) -> Self {
        self.rcvbuf = Some(bytes);
        self
    }

    /// Use `SO_RCVBUFFORCE` instead of `SO_RCVBUF`. Default: false.
    pub fn rcvbuf_force(mut self, enable: bool) -> Self {
        self.rcvbuf_force = enable;
        self
    }

    /// Set the kernel timestamp source.
    pub fn timestamp_source(mut self, source: TimestampSource) -> Self {
        self.timestamp_source = source;
        self
    }

    /// Default poll timeout used by [`Capture::packets`]. Default: 100ms.
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

    /// Validate and create the [`Capture`].
    ///
    /// Retries on `ENOMEM` with progressively smaller ring sizes (down to
    /// 25 % of requested) before returning an error.
    pub fn build(self) -> Result<Capture, Error> {
        let mut current_count = self.block_count;
        let min_count = (self.block_count / 4).max(1);
        loop {
            match build_inner(&self, current_count) {
                Ok(cap) => return Ok(cap),
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

/// Single attempt at building a Capture with `block_count` blocks.
fn build_inner(b: &CaptureBuilder, block_count: usize) -> Result<Capture, Error> {
    let interface = b
        .interface
        .as_deref()
        .ok_or_else(|| Error::Config("interface is required".into()))?;

    if !b.block_size.is_power_of_two() {
        return Err(Error::Config(format!(
            "block_size {} is not a power of 2",
            b.block_size
        )));
    }

    let page_size = 4096usize;
    if b.block_size % page_size != 0 {
        return Err(Error::Config(format!(
            "block_size {} is not a multiple of PAGE_SIZE ({})",
            b.block_size, page_size
        )));
    }

    crate::afpacket::validate_frame_size(b.frame_size)?;

    if b.frame_size > b.block_size {
        return Err(Error::Config(format!(
            "frame_size {} exceeds block_size {}",
            b.frame_size, b.block_size
        )));
    }

    if block_count == 0 {
        return Err(Error::Config("block_count must be > 0".into()));
    }

    let frame_nr = (b.block_size / b.frame_size) * block_count;

    // Create socket
    let fd = socket::create_packet_socket()?;

    // Set TPACKET_V3
    socket::set_packet_version(fd.as_fd())?;

    // Configure RX ring
    let mut req: ffi::tpacket_req3 = unsafe { std::mem::zeroed() };
    req.tp_block_size = b.block_size as u32;
    req.tp_block_nr = block_count as u32;
    req.tp_frame_size = b.frame_size as u32;
    req.tp_frame_nr = frame_nr as u32;
    req.tp_retire_blk_tov = b.block_timeout_ms;
    req.tp_sizeof_priv = 0;
    req.tp_feature_req_word = if b.fill_rxhash {
        ffi::TP_FT_REQ_FILL_RXHASH
    } else {
        0
    };

    socket::set_rx_ring(fd.as_fd(), &req)?;

    // mmap
    let ring_size = b.block_size * block_count;
    let ring = MmapRing::new(fd.as_fd(), ring_size, b.block_size, block_count)?;

    // Bind to interface
    let ifindex = socket::resolve_interface(interface)?;
    socket::bind_to_interface(fd.as_fd(), ifindex)?;

    if b.promiscuous {
        socket::set_promiscuous(fd.as_fd(), ifindex)?;
    }
    if b.ignore_outgoing {
        socket::set_ignore_outgoing(fd.as_fd())?;
    }
    if let Some(us) = b.busy_poll_us {
        socket::set_busy_poll(fd.as_fd(), us)?;
    }
    if b.reuseport {
        socket::set_reuseport(fd.as_fd(), true)?;
    }
    if let Some(bytes) = b.rcvbuf {
        if b.rcvbuf_force {
            socket::set_rcvbuf_force(fd.as_fd(), bytes)?;
        } else {
            socket::set_rcvbuf(fd.as_fd(), bytes)?;
        }
    }
    if b.timestamp_source != TimestampSource::Software {
        socket::set_timestamp_source(fd.as_fd(), b.timestamp_source)?;
    }
    if let Some((mode, group_id)) = b.fanout {
        fanout::join_fanout(fd.as_fd(), group_id, mode, b.fanout_flags)?;
    }
    if let Some(insns) = &b.bpf_filter {
        let filt = BpfFilter::new(insns.clone());
        filter::attach_bpf_filter(fd.as_fd(), &filt)?;
    }

    Ok(Capture {
        ring,
        fd,
        current_block: 0,
        expected_seq: 0,
        poll_timeout: b.poll_timeout,
        cumulative: Cell::new(CaptureStats::default()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_missing_interface() {
        let err = CaptureBuilder::default().build().unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_bad_block_size() {
        let err = CaptureBuilder::default()
            .interface("lo")
            .block_size(3000) // not power of 2
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_bad_frame_size() {
        let err = CaptureBuilder::default()
            .interface("lo")
            .frame_size(100) // not multiple of 16
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_small_frame_size() {
        let err = CaptureBuilder::default()
            .interface("lo")
            .frame_size(32) // < TPACKET3_HDRLEN (68)
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_zero_block_count() {
        let err = CaptureBuilder::default()
            .interface("lo")
            .block_count(0)
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

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
        assert_eq!(b.poll_timeout, Duration::from_millis(100));
    }

    #[test]
    fn builder_fill_rxhash_setter() {
        let b = CaptureBuilder::default().fill_rxhash(false);
        assert!(!b.fill_rxhash);
        let b = CaptureBuilder::default().fill_rxhash(true);
        assert!(b.fill_rxhash);
    }

    #[test]
    fn builder_poll_timeout_setter() {
        let b = CaptureBuilder::default().poll_timeout(Duration::from_millis(25));
        assert_eq!(b.poll_timeout, Duration::from_millis(25));
    }
}
