//! AF_PACKET TPACKET_V3 capture (RX path).

use std::cell::Cell;
use std::marker::PhantomData;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use crate::afpacket::ring::{MmapRing, RingGeometry};
use crate::afpacket::{fanout, ffi, filter, ring, socket};
use crate::config::{
    BpfFilter, BpfInsn, BusyPollConfig, FanoutFlags, FanoutMode, RingProfile, TimestampSource,
};
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
/// // Simplest form — a lending loop, blocks on each packet.
/// let mut cap = netring::Capture::open("lo")?;
/// let mut pkts = cap.packets();
/// while let Some(pkt) = pkts.next_packet() {
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
    /// The next block to take from the kernel.
    current_block: usize,
    expected_seq: u64,
    /// A user-owned block a [`Packets`] loop has partly read (#211): kept
    /// across `Packets` values and handed to the next `packets()` /
    /// `next_batch()` call, so packets nobody read are never released.
    pending: Option<PendingBlock>,
    /// Default poll timeout used by [`packets()`](Self::packets).
    /// Configured via [`CaptureBuilder::poll_timeout`].
    poll_timeout: Duration,
    /// Running totals behind [`stats`](Self::stats): every destructive
    /// `PACKET_STATISTICS` read is folded in here.
    cumulative: Cell<CaptureStats>,
    /// Busy-poll trio applied at build time. Inspected via
    /// [`busy_poll_config`](Self::busy_poll_config). Empty (all
    /// `None`) when no busy-poll knobs were set.
    busy_poll: BusyPollConfig,
    /// Created by [`Capture::stop_handle`]; polled with the socket.
    stop: Option<std::sync::Arc<StopSignal>>,
}

/// The cursor into a user-owned block that has packets left to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingBlock {
    /// Ring index of the block.
    index: usize,
    /// Offset of the next `tpacket3_hdr` from the block base.
    offset: u32,
    /// Packets left in the block (`0` once the last one was lent; the
    /// block is then released on the next read or when `Packets` drops).
    remaining: u32,
}

/// The eventfd behind [`StopHandle`].
#[derive(Debug)]
struct StopSignal {
    fd: OwnedFd,
    stopped: std::sync::atomic::AtomicBool,
    /// Held across each update of `stopped` + the eventfd counter, so a
    /// `raise` racing a `clear` cannot leave the flag clear while the
    /// eventfd stays readable (every poll would then return at once).
    update: std::sync::Mutex<()>,
}

impl StopSignal {
    fn new() -> Result<Self, Error> {
        // SAFETY: plain eventfd(2); the returned fd is owned below.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: `fd` is a fresh, valid descriptor we own.
        let fd = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        Ok(Self {
            fd,
            stopped: std::sync::atomic::AtomicBool::new(false),
            update: std::sync::Mutex::new(()),
        })
    }

    fn raise(&self) {
        let _update = self.update.lock().unwrap_or_else(|e| e.into_inner());
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let one: u64 = 1;
        // SAFETY: 8-byte write to an eventfd we own. A failure (the
        // counter saturated) still leaves it readable, i.e. raised.
        unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                (&one as *const u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
    }

    fn is_raised(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn clear(&self) {
        let _update = self.update.lock().unwrap_or_else(|e| e.into_inner());
        let mut v: u64 = 0;
        // SAFETY: 8-byte read from a non-blocking eventfd we own.
        unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                (&mut v as *mut u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        self.stopped
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Stops a [`Capture`]'s blocking reads from another thread (issue
/// #146). Returned by [`Capture::stop_handle`]; clone it freely.
///
/// [`stop`](Self::stop) wakes a thread blocked in
/// [`Packets::next_packet`], [`Packets::for_each`] or
/// [`Capture::next_batch_blocking`] immediately (an eventfd is polled
/// alongside the socket): `next_packet` returns `None`, `for_each`
/// returns, `next_batch_blocking` returns `Ok(None)` — and keep doing
/// so until [`Capture::clear_stop`].
///
/// ```no_run
/// # fn f() -> Result<(), netring::Error> {
/// let mut cap = netring::Capture::open("eth0")?;
/// let stop = cap.stop_handle()?;
/// std::thread::spawn(move || {
///     std::thread::sleep(std::time::Duration::from_secs(30));
///     stop.stop();
/// });
/// cap.packets().for_each(|pkt| { let _ = pkt.len(); });
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct StopHandle {
    signal: std::sync::Arc<StopSignal>,
}

impl StopHandle {
    /// Ask the capture to stop reading. Idempotent.
    pub fn stop(&self) {
        self.signal.raise();
    }

    /// Whether a stop was requested (and not cleared).
    pub fn is_stopped(&self) -> bool {
        self.signal.is_raised()
    }
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

    /// Capture statistics: totals since this capture was opened.
    ///
    /// Reads (and thereby resets) the kernel's `PACKET_STATISTICS`
    /// counters, folds them into a running total kept on the capture and
    /// returns that total, so the result never goes backwards and repeated
    /// calls never lose a count. Two reads with no traffic in between are
    /// equal; the counts of a window are
    /// [`later.delta_since(&earlier)`](CaptureStats::delta_since). See
    /// [`CaptureStats`] for the meaning of each field.
    ///
    /// # Errors
    ///
    /// [`Error::SockOpt`] if `getsockopt(PACKET_STATISTICS)` fails.
    pub fn stats(&self) -> Result<CaptureStats, Error> {
        let raw = socket::get_packet_stats(self.fd.as_fd())?;
        let total = self.cumulative.get().add_tpacket_v3(raw);
        self.cumulative.set(total);
        Ok(total)
    }

    // ── Flat packet iterators ────────────────────────────────────────────

    /// Blocking iterator over received packets.
    ///
    /// Handles block advancement and retirement automatically. Each
    /// [`Packets`] is a **lending iterator** — pull each packet with
    /// [`next_packet`](Packets::next_packet) (or [`for_each`](Packets::for_each)).
    /// It blocks (using the configured
    /// [`poll_timeout`](CaptureBuilder::poll_timeout)) and retries indefinitely;
    /// `next_packet` returns `None` only on I/O error — inspect via
    /// [`Packets::take_error`].
    ///
    /// # Stopping early keeps the rest of the block
    ///
    /// The kernel hands packets over a block at a time. Dropping a
    /// [`Packets`] (or stopping it — a deadline, a [`StopHandle`]) after
    /// some packets of a block leaves the **unread ones in place**: the
    /// next `packets()` loop, or [`next_batch`](Self::next_batch), starts
    /// with them, in order (#211). Only a fully read block goes back to
    /// the kernel. (Before 0.32 the rest of the block was released and
    /// lost.)
    ///
    /// # Soundness
    ///
    /// Each [`Packet`] is a zero-copy view into a ring block, which is
    /// recycled to the kernel once all of its packets were lent.
    /// `next_packet` borrows `&mut self`, so the borrow checker forbids
    /// holding two packets at once or collecting them into a `Vec` — the
    /// constraint that makes it sound. (This replaced an earlier `Iterator`
    /// impl whose `.collect()` could dangle into recycled blocks.)
    /// [`to_owned`](Packet::to_owned) a packet to retain it:
    ///
    /// ```no_run
    /// # let mut cap = netring::Capture::open("lo").unwrap();
    /// let mut owned = Vec::new();
    /// let mut pkts = cap.packets();
    /// while owned.len() < 100 {
    ///     let Some(pkt) = pkts.next_packet() else { break };
    ///     owned.push(pkt.to_owned());
    /// }
    /// drop(pkts); // packets past the 100th stay in the ring for the next loop
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
            last_error: None,
            _marker: PhantomData,
        }
    }

    /// Iterator that stops at `deadline`. Packets of a block it already
    /// started are lent past the deadline only until that block is
    /// exhausted; no new block is taken once it passed.
    pub fn packets_until(&mut self, deadline: Instant) -> Packets<'_> {
        Packets {
            cap: self as *mut Capture,
            timeout: self.poll_timeout,
            deadline: Some(deadline),
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

    /// Plan 21: replace the BPF filter on this capture without
    /// disturbing the ring buffer or any in-flight user-space
    /// stream. Atomic at the kernel level — there's no window
    /// where the old filter has been removed and the new one not
    /// yet installed.
    ///
    /// To **remove** a filter without replacing it, use
    /// [`detach_filter`](Self::detach_filter).
    ///
    /// **Note**: any packets already buffered in the ring at the
    /// moment of the swap were captured under the old filter. For
    /// strict cutover, drain a few batches after `set_filter` or
    /// install a `(old OR new)` filter first, drain old matches,
    /// then narrow.
    pub fn set_filter(&self, filter: &crate::config::BpfFilter) -> Result<(), Error> {
        filter::attach_bpf_filter(self.fd.as_fd(), filter)
    }

    // ── Busy-poll introspection ──────────────────────────────────────────

    /// Borrow the busy-poll trio applied at build time.
    ///
    /// Empty (all fields `None`) when no busy-poll knob was set on
    /// the builder. Use [`BusyPollConfig::is_active`] to check.
    ///
    /// Reachable from a built async stream via
    /// `stream.capture().get_ref().busy_poll_config()`.
    pub fn busy_poll_config(&self) -> &BusyPollConfig {
        &self.busy_poll
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
    /// borrows `&mut self`; only one batch can be live at a time. If a
    /// [`Packets`] loop stopped part-way through a block, the batch is the
    /// **rest of that block** (its [`len`](PacketBatch::len) counts the
    /// unread packets). Dropping the batch returns the whole block to the
    /// kernel.
    pub fn next_batch(&mut self) -> Option<PacketBatch<'_>> {
        if !self.acquire() {
            return None;
        }
        let p = self.pending.take()?;
        let bd = self.ring.block_ptr(p.index);
        // SAFETY: `acquire` observed the block in `TP_STATUS_USER` (with
        // Acquire ordering) and nothing released it since; the batch
        // borrows `&mut self`, so it is the only user of the block and
        // releases it on drop. `offset` / `remaining` came from the block
        // header or a `BatchIter::position` over this block.
        Some(unsafe { PacketBatch::resume(bd, p.offset, p.remaining) })
    }

    /// Make sure a user-owned block with unread packets is pending: `true`
    /// if one is (already, or newly taken from the kernel), `false` if the
    /// kernel has not retired the next block yet.
    ///
    /// A retired block with no packets (the kernel does not normally close
    /// empty blocks) is released and skipped.
    fn acquire(&mut self) -> bool {
        self.release_pending_if_exhausted();
        if self.pending.is_some() {
            return true;
        }
        for _ in 0..self.ring.block_count() {
            let bd = self.ring.block_ptr(self.current_block);

            // SAFETY: bd points to a valid block descriptor in our mmap region.
            let status = unsafe { ring::read_block_status(bd) };
            if status & ffi::TP_STATUS_USER == 0 {
                return false;
            }

            // SAFETY: the block is user-owned (Acquire fence done in
            // read_block_status); the header fields are read by value.
            let (seq, num_pkts, first_offset) = unsafe {
                let bh1 = &raw const (*bd.as_ptr()).hdr.bh1;
                ((*bh1).seq_num, (*bh1).num_pkts, (*bh1).offset_to_first_pkt)
            };
            // Sequence number for gap detection.
            if seq != self.expected_seq && self.expected_seq != 0 {
                tracing::warn!(
                    expected = self.expected_seq,
                    actual = seq,
                    dropped = seq.saturating_sub(self.expected_seq),
                    "block sequence gap"
                );
            }
            self.expected_seq = seq + 1;

            let index = self.current_block;
            self.current_block = (self.current_block + 1) % self.ring.block_count();
            if num_pkts == 0 {
                // SAFETY: user-owned block we are done with.
                unsafe { ring::release_block(bd) };
                continue;
            }
            self.pending = Some(PendingBlock {
                index,
                offset: first_offset,
                remaining: num_pkts,
            });
            return true;
        }
        false
    }

    /// Lend the next unread packet of the pending block, advancing the
    /// cursor. A pending block whose packets were all lent is released
    /// here (the borrow of its last packet ended when this `&mut self`
    /// call began) and `None` is returned; `None` too when nothing is
    /// pending.
    fn next_pending_packet(&mut self) -> Option<Packet<'_>> {
        let p = self.pending?;
        let bd = self.ring.block_ptr(p.index);
        if p.remaining > 0 {
            // SAFETY: the block is user-owned (taken by `acquire`, not yet
            // released) and its header is read by value.
            let blk_len = unsafe { (*bd.as_ptr()).hdr.bh1.blk_len };
            // SAFETY: as above; the iterator and the packet it lends
            // borrow `&mut self`, so the block cannot be released while
            // the packet lives.
            let mut it = unsafe { BatchIter::at(bd, p.offset, p.remaining, blk_len) };
            if let Some(pkt) = it.next() {
                let (offset, remaining) = it.position(bd);
                self.pending = Some(PendingBlock {
                    index: p.index,
                    offset,
                    remaining,
                });
                return Some(pkt);
            }
            // A header or packet ran past the block: the iterator logged
            // it; treat the block as exhausted.
        }
        self.pending = None;
        // SAFETY: user-owned block; no packet of it is borrowed any more.
        unsafe { ring::release_block(bd) };
        None
    }

    /// Release the pending block if all of its packets were lent.
    fn release_pending_if_exhausted(&mut self) {
        if let Some(p) = self.pending
            && p.remaining == 0
        {
            self.pending = None;
            // SAFETY: user-owned block; no packet of it is borrowed (the
            // caller holds `&mut self`).
            unsafe { ring::release_block(self.ring.block_ptr(p.index)) };
        }
    }

    /// Block until a block with unread packets is pending, `timeout`
    /// elapses, or a stop is requested: `Ok(true)` when one is pending.
    fn wait_for_block(&mut self, timeout: Duration) -> Result<bool, Error> {
        if self.stop_requested() {
            return Ok(false);
        }
        // Unread packets, or a retired block, are ready now.
        if self.acquire() {
            return Ok(true);
        }

        let revents = match self.stop.as_ref() {
            None => {
                let mut pfds = [nix::poll::PollFd::new(
                    self.fd.as_fd(),
                    nix::poll::PollFlags::POLLIN,
                )];
                crate::syscall::poll_eintr_safe(&mut pfds, timeout).map_err(Error::Io)?;
                pfds[0].revents()
            }
            Some(stop) => {
                let mut pfds = [
                    nix::poll::PollFd::new(self.fd.as_fd(), nix::poll::PollFlags::POLLIN),
                    nix::poll::PollFd::new(stop.fd.as_fd(), nix::poll::PollFlags::POLLIN),
                ];
                crate::syscall::poll_eintr_safe(&mut pfds, timeout).map_err(Error::Io)?;
                pfds[0].revents()
            }
        };
        if self.stop_requested() {
            return Ok(false);
        }
        socket::poll_error(self.fd.as_fd(), revents)?;
        Ok(self.acquire())
    }

    /// Block until a batch is available, or `timeout` elapses.
    ///
    /// The rest of a block a [`Packets`] loop left partly read is
    /// available at once (see [`next_batch`](Self::next_batch)).
    ///
    /// EINTR is handled internally — callers see `Ok(None)` on timeout, not
    /// a spurious error from a signal interrupting the underlying `poll(2)`.
    /// Also returns `Ok(None)` right away once a stop was requested
    /// through a [`StopHandle`].
    ///
    /// # Errors
    ///
    /// [`Error::Io`] with `ENETDOWN` when the interface was removed, and
    /// for a failed `poll(2)`. An interface that is merely down (or was
    /// down when the capture was opened) is not an error: the read waits
    /// out its timeout, logging a warning, and packets flow again once the
    /// interface is back up.
    pub fn next_batch_blocking(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<PacketBatch<'_>>, Error> {
        if self.wait_for_block(timeout)? {
            Ok(self.next_batch())
        } else {
            Ok(None)
        }
    }

    /// A handle that stops blocking reads on this capture from another
    /// thread (see [`StopHandle`]). Creates the eventfd on first call;
    /// later calls return handles to the same signal.
    pub fn stop_handle(&mut self) -> Result<StopHandle, Error> {
        let signal = match &self.stop {
            Some(s) => std::sync::Arc::clone(s),
            None => {
                let s = std::sync::Arc::new(StopSignal::new()?);
                self.stop = Some(std::sync::Arc::clone(&s));
                s
            }
        };
        Ok(StopHandle { signal })
    }

    /// Whether a stop was requested through a [`StopHandle`].
    pub fn stop_requested(&self) -> bool {
        self.stop.as_ref().is_some_and(|s| s.is_raised())
    }

    /// Re-arm after a stop: reads block again.
    pub fn clear_stop(&mut self) {
        if let Some(s) = &self.stop {
            s.clear();
        }
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
}

// Plan 21: Capture supports atomic BPF filter swap.
impl crate::traits::PacketSetFilter for Capture {
    fn set_filter(&self, filter: &crate::config::BpfFilter) -> Result<(), Error> {
        Capture::set_filter(self, filter)
    }
}

impl std::fmt::Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capture")
            .field("ring_size", &self.ring.size())
            .field("block_count", &self.ring.block_count())
            .field("current_block", &self.current_block)
            .field("pending", &self.pending)
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
/// packets across iterations. The read position lives in the [`Capture`],
/// so dropping a `Packets` part-way through a block keeps that block's
/// unread packets for the next loop.
pub struct Packets<'cap> {
    cap: *mut Capture,
    timeout: Duration,
    /// Optional deadline; `next()` returns `None` once it elapses.
    deadline: Option<Instant>,
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
}

impl<'cap> Packets<'cap> {
    /// Lend the next captured packet, borrowed from the mmap ring.
    ///
    /// This is a **lending** accessor, not [`Iterator`]: the returned
    /// [`Packet`] borrows `&mut self`, so the borrow checker forbids holding
    /// two at once or collecting them — exactly the constraint that makes it
    /// sound. The previous packet's block is recycled to the kernel on the next
    /// call, so a borrowed packet must not outlive that call; the `&mut self`
    /// borrow enforces this at compile time.
    ///
    /// Copy a packet out of the ring with [`Packet::to_owned`] if you need to
    /// retain it past the next call. For the high-throughput zero-copy path use
    /// [`Capture::next_batch`]; for a simple processing loop use
    /// [`Self::for_each`].
    ///
    /// ```no_run
    /// # use netring::Capture;
    /// # fn f(cap: &mut Capture) {
    /// let mut pkts = cap.packets();
    /// while let Some(pkt) = pkts.next_packet() {
    ///     println!("{} bytes at {:?}", pkt.len(), pkt.timestamp());
    /// }
    /// # }
    /// ```
    ///
    /// Retaining a packet across calls is a **compile error** (the old
    /// `Iterator`-based `.collect()` was an unsoundness — it let packets escape
    /// into recycled ring blocks):
    ///
    /// ```compile_fail
    /// # use netring::Capture;
    /// # fn f(cap: &mut Capture) {
    /// let mut pkts = cap.packets();
    /// let a = pkts.next_packet();
    /// let b = pkts.next_packet(); // error: cannot borrow `pkts` while `a` lives
    /// let _ = (a, b);
    /// # }
    /// ```
    ///
    /// Blocks until a packet arrives, the deadline passes, a stop is
    /// requested through a [`StopHandle`], or an error occurs (see
    /// [`take_error`](Self::take_error)); poll timeouts are retried.
    /// Use [`next_packet_timeout`](Self::next_packet_timeout) to get
    /// control back on every poll timeout instead.
    pub fn next_packet(&mut self) -> Option<Packet<'_>> {
        self.next_inner(true)
    }

    /// Like [`next_packet`](Self::next_packet), but returns `Ok(None)`
    /// when a poll times out (after the capture's `poll_timeout`), the
    /// deadline passes, or a stop is requested — so the caller can
    /// check its own stop flag or deadline on an idle interface
    /// (issue #146). Errors are returned, not stashed.
    ///
    /// ```no_run
    /// # use std::sync::atomic::{AtomicBool, Ordering};
    /// # fn f(cap: &mut netring::Capture, shutdown: &AtomicBool) -> Result<(), netring::Error> {
    /// let mut pkts = cap.packets();
    /// while !shutdown.load(Ordering::Relaxed) {
    ///     if let Some(pkt) = pkts.next_packet_timeout()? {
    ///         let _ = pkt.len();
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    pub fn next_packet_timeout(&mut self) -> Result<Option<Packet<'_>>, Error> {
        let this: *mut Self = self;
        // SAFETY: reborrow through a raw pointer to work around the
        // borrow checker's conditional-return limitation: the `Some`
        // arm returns the packet bound to this call's `&mut self`, and
        // the `None` arm touches `self` only when no packet exists.
        match unsafe { (*this).next_inner(false) } {
            Some(pkt) => Ok(Some(pkt)),
            None => match self.last_error.take() {
                Some(e) => Err(e),
                None => Ok(None),
            },
        }
    }

    /// The body of [`next_packet`](Self::next_packet): `retry` keeps
    /// waiting across poll timeouts. Errors land in `last_error`.
    ///
    /// A stop request or the deadline returns `None` **without** releasing
    /// the pending block: its unread packets stay for the next loop.
    fn next_inner(&mut self, retry: bool) -> Option<Packet<'_>> {
        loop {
            // SAFETY: `cap` is valid and exclusively ours for `'cap` (the
            // `PhantomData<&'cap mut Capture>`); each access goes through a
            // fresh reborrow of the raw pointer.
            if unsafe { (*self.cap).stop_requested() } {
                return None;
            }
            // SAFETY: as above. The packet borrows the pending block, which
            // the capture releases only on a later `&mut` call — after this
            // `&mut self` borrow (and so the packet) has ended. This is the
            // lending-iterator pattern; binding the packet to `&mut self`
            // (not `'cap`) is what keeps `.collect()` from dangling.
            if let Some(pkt) = unsafe { (*self.cap).next_pending_packet() } {
                return Some(pkt);
            }

            // Nothing unread: take a new block, or wait for one. Never
            // past the deadline.
            let effective_timeout = match self.deadline {
                Some(d) => d.checked_duration_since(Instant::now())?.min(self.timeout),
                None => self.timeout,
            };
            // SAFETY: as above; no packet is borrowed here.
            match unsafe { (*self.cap).wait_for_block(effective_timeout) } {
                Ok(true) => continue,
                Ok(false) if retry => continue,
                Ok(false) => return None,
                Err(e) => {
                    self.last_error = Some(e);
                    return None;
                }
            }
        }
    }

    /// Process every packet — until the deadline passes, a stop is
    /// requested through a [`StopHandle`], or an error occurs (see
    /// [`take_error`](Self::take_error)); poll timeouts are waited
    /// through — with a closure: ergonomic internal iteration that keeps
    /// the zero-copy borrow without the lending-loop boilerplate. The closure
    /// receives each [`Packet`] bounded to that call, so it can read or
    /// [`to_owned`](Packet::to_owned) it but not retain the borrow.
    ///
    /// ```no_run
    /// # use netring::Capture;
    /// # fn f(cap: &mut Capture) {
    /// let mut count = 0u64;
    /// cap.packets().for_each(|pkt| { count += pkt.len() as u64; });
    /// # }
    /// ```
    pub fn for_each(&mut self, mut f: impl FnMut(Packet<'_>)) {
        while let Some(pkt) = self.next_packet() {
            f(pkt);
        }
    }
}

impl Drop for Packets<'_> {
    fn drop(&mut self) {
        // Release the block of the last lent packet if it was the block's
        // last one (no packet can be borrowed past `self`). A partly read
        // block stays pending in the capture.
        // SAFETY: `cap` is valid for `'cap`.
        unsafe { (*self.cap).release_pending_if_exhausted() };
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
    prefer_busy_poll: Option<bool>,
    busy_poll_budget: Option<u16>,
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
            prefer_busy_poll: None,
            busy_poll_budget: None,
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

    /// Enable `SO_BUSY_POLL` with the given microsecond timeout. Kernel ≥ 4.5.
    ///
    /// For low-latency AF_PACKET capture, pair with [`prefer_busy_poll`](Self::prefer_busy_poll)
    /// and [`busy_poll_budget`](Self::busy_poll_budget). See
    /// <https://docs.kernel.org/networking/af_xdp.html>.
    pub fn busy_poll_us(mut self, us: u32) -> Self {
        self.busy_poll_us = Some(us);
        self
    }

    /// Enable `SO_PREFER_BUSY_POLL`. Kernel ≥ 5.11.
    ///
    /// Tells the kernel to prefer the busy-polling path over softirq for
    /// this socket. Has no effect without [`busy_poll_us`](Self::busy_poll_us)
    /// also set.
    ///
    /// Enabling it needs `CAP_NET_ADMIN` in the **initial** user namespace
    /// (the kernel uses `capable()`, not `ns_capable()`): a rootless
    /// container's `--cap-add NET_ADMIN` is not enough, and `build()` fails
    /// with [`Error::SockOpt`] (`EPERM`).
    pub fn prefer_busy_poll(mut self, enable: bool) -> Self {
        self.prefer_busy_poll = Some(enable);
        self
    }

    /// Set `SO_BUSY_POLL_BUDGET` (per-poll packet cap). Kernel ≥ 5.11.
    ///
    /// Default kernel budget is 8 in 6.x; 64 is a common production value
    /// for AF_PACKET / AF_XDP. Values above
    /// `/proc/sys/net/core/busy_poll_budget_max` (typically 64) require
    /// `CAP_NET_ADMIN` in the initial user namespace; otherwise the kernel
    /// returns `EPERM`.
    pub fn busy_poll_budget(mut self, budget: u16) -> Self {
        self.busy_poll_budget = Some(budget);
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
    ///
    /// Pair with the typed [`BpfFilter::builder`] API:
    ///
    /// ```no_run
    /// use netring::{BpfFilter, Capture};
    ///
    /// let filter = BpfFilter::builder()
    ///     .tcp()
    ///     .dst_port(443)
    ///     .build()
    ///     .unwrap();
    /// let cap = Capture::builder()
    ///     .interface("eth0")
    ///     .bpf_filter(filter)
    ///     .build();
    /// ```
    ///
    /// To attach pre-built bytecode (e.g. from `tcpdump -dd`), wrap it
    /// in [`BpfFilter::new`] first.
    pub fn bpf_filter(mut self, filter: BpfFilter) -> Self {
        self.bpf_filter = Some(filter.into_instructions());
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

    /// Build this `Capture` inside a network namespace (issue #126).
    ///
    /// The AF_PACKET socket is created on a scoped thread that has `setns(2)`'d
    /// into `ns`, so it binds to that namespace's interfaces; the returned
    /// `Capture` is then usable from the caller's threads (including the tokio
    /// runtime). Requires `CAP_SYS_ADMIN` at runtime. See [`crate::netns`].
    pub fn netns(self, ns: &crate::netns::NetNs) -> Result<Capture, Error> {
        // Two failure layers: entering the namespace, and building once inside.
        // Keep them apart — the outer one is `setns` (CAP_SYS_ADMIN) and used to
        // surface as a bare `Error::Io(EPERM)`, which points an operator at the
        // wrong capability and does not say which namespace failed.
        match ns.run_in(move || self.build()) {
            Ok(built) => built,
            Err(source) => Err(Error::Netns {
                label: ns.label().to_string(),
                source,
            }),
        }
    }
}

fn is_enomem(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOMEM)
}

/// A classic BPF program that drops every packet (`ret #0`).
fn reject_all_filter() -> BpfFilter {
    let ret_0 = BpfInsn {
        code: 0x06, // BPF_RET | BPF_K
        jt: 0,
        jf: 0,
        k: 0,
    };
    BpfFilter::new(vec![ret_0]).expect("one instruction")
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
    if !b.block_size.is_multiple_of(page_size) {
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

    let geometry = RingGeometry::new(b.block_size, block_count, b.frame_size)?;

    // Create the socket with protocol 0: `socket(ETH_P_ALL)` hooks it into
    // every interface at once (packet_create() registers the prot_hook,
    // packet_set_ring() re-registers it), so whatever arrived while the ring
    // was mapped landed in its first blocks — from any interface, before
    // the BPF filter. Everything that shapes what the ring receives is set
    // up first; bind() below is what starts reception.
    let fd = socket::create_packet_socket_proto(0)?;

    // Set TPACKET_V3
    socket::set_packet_version(fd.as_fd(), ffi::TPACKET_V3_INT)?;

    // Configure RX ring
    let mut req: ffi::tpacket_req3 = unsafe { std::mem::zeroed() };
    req.tp_block_size = geometry.block_size;
    req.tp_block_nr = geometry.block_nr;
    req.tp_frame_size = geometry.frame_size;
    req.tp_frame_nr = geometry.frame_nr;
    req.tp_retire_blk_tov = b.block_timeout_ms;
    req.tp_sizeof_priv = 0;
    req.tp_feature_req_word = if b.fill_rxhash {
        ffi::TP_FT_REQ_FILL_RXHASH
    } else {
        0
    };

    socket::set_rx_ring(fd.as_fd(), &req)?;

    // mmap
    let ring = MmapRing::new(fd.as_fd(), geometry.size, b.block_size, block_count)?;

    if b.ignore_outgoing {
        socket::set_ignore_outgoing(fd.as_fd())?;
    }
    if let Some(us) = b.busy_poll_us {
        socket::set_busy_poll(fd.as_fd(), us)?;
    }
    if let Some(prefer) = b.prefer_busy_poll {
        socket::set_prefer_busy_poll(fd.as_fd(), prefer)?;
    }
    if let Some(budget) = b.busy_poll_budget {
        socket::set_busy_poll_budget(fd.as_fd(), budget)?;
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
    let bpf_filter = b
        .bpf_filter
        .as_ref()
        .map(|insns| BpfFilter::new(insns.clone()))
        .transpose()?;
    if b.fanout.is_some() {
        // PACKET_FANOUT needs a bound socket, and until it joins the group
        // the socket gets every packet on the interface: drop them all
        // until the group decides what this member sees.
        filter::attach_bpf_filter(fd.as_fd(), &reject_all_filter())?;
    } else if let Some(filt) = &bpf_filter {
        filter::attach_bpf_filter(fd.as_fd(), filt)?;
    }

    // Bind to interface: the socket starts receiving here.
    let ifindex = socket::resolve_interface(interface)?;
    socket::bind_to_interface(fd.as_fd(), ifindex)?;

    if b.promiscuous {
        socket::set_promiscuous(fd.as_fd(), ifindex)?;
    }
    if let Some((mode, group_id)) = b.fanout {
        fanout::join_fanout(fd.as_fd(), group_id, mode, b.fanout_flags)?;
        match &bpf_filter {
            Some(filt) => filter::attach_bpf_filter(fd.as_fd(), filt)?,
            None => filter::detach_bpf_filter(fd.as_fd())?,
        }
    }

    let busy_poll = BusyPollConfig {
        busy_poll_us: b.busy_poll_us,
        prefer_busy_poll: b.prefer_busy_poll,
        busy_poll_budget: b.busy_poll_budget,
    };
    if busy_poll.is_active() {
        tracing::info!(
            target: "netring::capture::busy_poll",
            busy_poll_us = ?busy_poll.busy_poll_us,
            prefer_busy_poll = ?busy_poll.prefer_busy_poll,
            busy_poll_budget = ?busy_poll.busy_poll_budget,
            interface = %interface,
            "busy-poll trio applied",
        );
    }

    Ok(Capture {
        ring,
        fd,
        current_block: 0,
        expected_seq: 0,
        pending: None,
        poll_timeout: b.poll_timeout,
        cumulative: Cell::new(CaptureStats::default()),
        busy_poll,
        stop: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readable(sig: &StopSignal, timeout_ms: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd: sig.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        n == 1 && pfd.revents & libc::POLLIN != 0
    }

    /// #146: raising the stop signal makes its eventfd readable (so a
    /// thread polling it with the socket wakes at once) from another
    /// thread; clearing re-arms it.
    #[test]
    fn stop_signal_wakes_poll_and_clears() {
        let sig = std::sync::Arc::new(StopSignal::new().unwrap());
        let handle = StopHandle {
            signal: std::sync::Arc::clone(&sig),
        };
        assert!(!handle.is_stopped());
        assert!(!readable(&sig, 0));
        let t = std::thread::spawn({
            let h = handle.clone();
            move || {
                std::thread::sleep(std::time::Duration::from_millis(20));
                h.stop();
            }
        });
        let start = std::time::Instant::now();
        assert!(readable(&sig, 5_000), "woken by stop()");
        assert!(start.elapsed() < std::time::Duration::from_secs(4));
        t.join().unwrap();
        assert!(handle.is_stopped());
        handle.stop(); // idempotent
        sig.clear();
        assert!(!handle.is_stopped());
        assert!(!readable(&sig, 0), "cleared");
    }

    /// A `stop()` racing `clear_stop()` leaves the signal raised or
    /// cleared, never the flag clear with the eventfd still readable —
    /// which made every `next_batch_blocking` poll return at once (a spin).
    #[test]
    fn stop_signal_raise_racing_clear_stays_consistent() {
        use std::sync::{Arc, Barrier};

        const ROUNDS: usize = 20_000;
        let sig = Arc::new(StopSignal::new().unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let spawn = |raise: bool| {
            let (sig, barrier) = (Arc::clone(&sig), Arc::clone(&barrier));
            std::thread::spawn(move || {
                for _ in 0..ROUNDS {
                    barrier.wait();
                    if raise {
                        sig.raise();
                    } else {
                        sig.clear();
                    }
                    barrier.wait();
                }
            })
        };
        let (raiser, clearer) = (spawn(true), spawn(false));
        let mut inconsistent = 0;
        for round in 0..ROUNDS {
            if round % 2 == 0 {
                sig.raise(); // start half the rounds raised
            }
            barrier.wait();
            barrier.wait();
            if sig.is_raised() != readable(&sig, 0) {
                inconsistent += 1;
            }
            sig.clear();
        }
        raiser.join().unwrap();
        clearer.join().unwrap();
        assert_eq!(
            inconsistent, 0,
            "flag and eventfd disagreed in {inconsistent} rounds"
        );
    }

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

    /// A block count whose ring size overflows `usize` (or whose block /
    /// frame counts do not fit the kernel's `u32` fields) is a config error,
    /// caught before the socket exists — it used to wrap into a one-block
    /// kernel ring that `next_batch` walked past.
    #[test]
    fn builder_rejects_ring_geometry_overflow() {
        let err = CaptureBuilder::default()
            .interface("lo")
            .block_size(1 << 22)
            .block_count((1 << 42) + 1)
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)), "{err:?}");
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

    #[test]
    fn builder_busy_poll_trio_chain() {
        let b = CaptureBuilder::default()
            .busy_poll_us(50)
            .prefer_busy_poll(true)
            .busy_poll_budget(64);
        assert_eq!(b.busy_poll_us, Some(50));
        assert_eq!(b.prefer_busy_poll, Some(true));
        assert_eq!(b.busy_poll_budget, Some(64));
    }

    #[test]
    fn builder_busy_poll_default_unset() {
        let b = CaptureBuilder::default();
        assert_eq!(b.busy_poll_us, None);
        assert_eq!(b.prefer_busy_poll, None);
        assert_eq!(b.busy_poll_budget, None);
    }
}
