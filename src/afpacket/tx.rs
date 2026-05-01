//! AF_PACKET TX path (V1 frame-based semantics).
//!
//! TPACKET_V3 TX falls back to V1 frame-based operation. Each frame has a
//! `tpacket_hdr` at its start and is walked by index with `frame_size` stride.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::afpacket::{ffi, ring::MmapRing, socket};
use crate::error::Error;

// ── TxSlot ─────────────────────────────────────────────────────────────────

/// A mutable frame in the TX ring.
///
/// Calling [`send()`](TxSlot::send) marks the frame for transmission.
/// Dropping without calling `send()` discards the frame and returns it
/// to the available pool.
pub struct TxSlot<'a> {
    frame_ptr: NonNull<u8>,
    data_offset: usize,
    max_len: usize,
    len: usize,
    sent: bool,
    pending: &'a mut u32,
}

impl<'a> TxSlot<'a> {
    /// Mutable access to the packet data buffer.
    ///
    /// Returns a slice of `max_len` bytes. Write your Ethernet frame
    /// starting at offset 0 (destination MAC). Call [`set_len()`](TxSlot::set_len)
    /// to specify the actual packet length before [`send()`](TxSlot::send).
    pub fn data_mut(&mut self) -> &mut [u8] {
        let ptr = self.frame_ptr.as_ptr().map_addr(|a| a + self.data_offset);
        // SAFETY: frame is user-owned, ptr is within mmap region, max_len is valid.
        unsafe { std::slice::from_raw_parts_mut(ptr, self.max_len) }
    }

    /// Set the actual packet length to send.
    ///
    /// Must be called before [`send()`](TxSlot::send). Only the first
    /// `len` bytes of [`data_mut()`](TxSlot::data_mut) will be transmitted.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds the frame capacity. This is intentional:
    /// the frame capacity is known at [`allocate()`](crate::AfPacketTx::allocate)
    /// time, so exceeding it is a programming error (like indexing past a Vec).
    pub fn set_len(&mut self, len: usize) {
        assert!(
            len <= self.max_len,
            "packet length {len} exceeds frame capacity {}",
            self.max_len
        );
        self.len = len;
    }

    /// Mark this frame for transmission and consume the slot.
    ///
    /// The frame is queued in the TX ring. Call
    /// [`flush()`](crate::traits::PacketSink::flush) to trigger
    /// kernel transmission of all queued frames.
    pub fn send(mut self) {
        // Write tp_len, tp_snaplen, tp_mac into the tpacket_hdr at frame start
        let hdr = self.frame_ptr.as_ptr().cast::<libc::tpacket_hdr>();
        // SAFETY: frame_ptr points to valid tpacket_hdr in mmap region.
        unsafe {
            (*hdr).tp_len = self.len as u32;
            (*hdr).tp_snaplen = self.len as u32;
            (*hdr).tp_mac = self.data_offset as u16;
            (*hdr).tp_net = self.data_offset as u16;
        }

        // Atomic store: TP_STATUS_SEND_REQUEST with Release ordering
        // ensures all data writes are visible before kernel reads the frame.
        let status_ptr = hdr.cast::<AtomicU32>();
        // SAFETY: tp_status is at offset 0 of tpacket_hdr, naturally aligned u32.
        unsafe { &*status_ptr }.store(ffi::TP_STATUS_SEND_REQUEST, Ordering::Release);

        self.sent = true;
        *self.pending += 1;
    }
}

impl Drop for TxSlot<'_> {
    fn drop(&mut self) {
        if !self.sent {
            // Discard: return frame to available pool.
            let status_ptr = self.frame_ptr.as_ptr().cast::<AtomicU32>();
            // SAFETY: frame_ptr points to valid tpacket_hdr, tp_status at offset 0.
            unsafe { &*status_ptr }.store(ffi::TP_STATUS_AVAILABLE, Ordering::Release);
        }
    }
}

// ── AfPacketTx ─────────────────────────────────────────────────────────────

/// AF_PACKET TX ring (V1 frame-based semantics).
///
/// Implements [`PacketSink`](crate::traits::PacketSink) and [`AsFd`].
///
/// # Drop semantics
///
/// `Drop` performs a best-effort [`flush()`](Self::flush) to push any pending
/// frames to the kernel before unmapping the ring. Errors from this final
/// flush are logged at `warn` level via `tracing` but cannot be returned —
/// call [`flush()`](Self::flush) explicitly before dropping if you need to
/// observe transmission failures.
pub struct AfPacketTx {
    // Drop order: ring (munmap) before fd (close).
    ring: MmapRing,
    fd: OwnedFd,
    current_frame: usize,
    frame_count: usize,
    frame_size: usize,
    data_offset: usize,
    pending: u32,
}

impl std::fmt::Debug for AfPacketTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfPacketTx")
            .field("frame_count", &self.frame_count)
            .field("frame_size", &self.frame_size)
            .field("pending", &self.pending)
            .finish()
    }
}

impl AfPacketTx {
    /// Start building a new TX handle.
    pub fn builder() -> AfPacketTxBuilder {
        AfPacketTxBuilder::default()
    }

    fn frame_ptr(&self, index: usize) -> NonNull<u8> {
        let offset = index * self.frame_size;
        let ptr = self.ring.base().as_ptr().map_addr(|a| a + offset);
        // SAFETY: offset is within ring (index < frame_count).
        unsafe { NonNull::new_unchecked(ptr) }
    }

    fn read_frame_status(&self, index: usize) -> u32 {
        let ptr = self.frame_ptr(index).as_ptr().cast::<AtomicU32>();
        // SAFETY: points to tp_status at start of tpacket_hdr.
        unsafe { &*ptr }.load(Ordering::Acquire)
    }

    /// Maximum payload bytes that fit in a single TX frame.
    ///
    /// Equal to `frame_size - data_offset` where `data_offset` is the
    /// `tpacket_align(sizeof(tpacket_hdr))` reservation at the start of
    /// each frame.
    #[inline]
    pub fn frame_capacity(&self) -> usize {
        self.frame_size - self.data_offset
    }

    /// Number of slots currently in `TP_STATUS_AVAILABLE` (reclaimed by kernel).
    ///
    /// Useful after [`flush()`](Self::flush) to estimate transmission progress —
    /// the count grows as the kernel finishes transmitting each frame and
    /// returns its slot to the user. O(frame_count); avoid in hot paths.
    pub fn available_slots(&self) -> usize {
        (0..self.frame_count)
            .filter(|&i| self.read_frame_status(i) == ffi::TP_STATUS_AVAILABLE)
            .count()
    }

    /// Number of slots currently in `TP_STATUS_WRONG_FORMAT` (kernel rejection).
    ///
    /// A non-zero value indicates the kernel rejected one or more frames —
    /// typically because of a malformed header or unsupported feature flag.
    /// O(frame_count); avoid in hot paths.
    pub fn rejected_slots(&self) -> usize {
        (0..self.frame_count)
            .filter(|&i| self.read_frame_status(i) == ffi::TP_STATUS_WRONG_FORMAT)
            .count()
    }

    /// Number of slots currently held by the kernel (`TP_STATUS_SEND_REQUEST`
    /// or `TP_STATUS_SENDING`) — i.e., still pending transmission.
    ///
    /// Reaches zero once every queued frame has been fully transmitted (or
    /// rejected). O(frame_count); avoid in hot paths.
    pub fn pending_count(&self) -> usize {
        (0..self.frame_count)
            .filter(|&i| {
                let s = self.read_frame_status(i);
                s == ffi::TP_STATUS_SEND_REQUEST || s == ffi::TP_STATUS_SENDING
            })
            .count()
    }

    /// Block until [`pending_count`](Self::pending_count) reaches zero or
    /// `timeout` elapses.
    ///
    /// Useful before [`Drop`](Self::drop): the destructor's best-effort
    /// flush returns immediately after `sendto` succeeds, so frames may
    /// still be in flight when the ring is unmapped. Calling
    /// `wait_drained(...)` first ensures the kernel has finished.
    ///
    /// Internally polls `POLLOUT` (re-arms when slots become available) and
    /// re-checks `pending_count`. Polling is bounded by the remaining
    /// timeout slice each iteration so wakeups don't oversleep.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] with `ErrorKind::TimedOut` if the timeout elapses
    ///   with frames still pending.
    /// - [`Error::Io`] for any underlying poll failure.
    pub fn wait_drained(&mut self, timeout: std::time::Duration) -> Result<(), Error> {
        use std::time::Instant;
        let deadline = Instant::now() + timeout;
        loop {
            if self.pending_count() == 0 {
                return Ok(());
            }
            let remaining = match deadline.checked_duration_since(Instant::now()) {
                Some(r) => r,
                None => {
                    return Err(Error::Io(std::io::Error::from(
                        std::io::ErrorKind::TimedOut,
                    )));
                }
            };
            // Cap each poll at 10ms so we re-check pending_count even if
            // POLLOUT triggers spuriously on a partial drain.
            let slice = remaining.min(std::time::Duration::from_millis(10));
            let mut pfds = [nix::poll::PollFd::new(
                self.fd.as_fd(),
                nix::poll::PollFlags::POLLOUT,
            )];
            crate::syscall::poll_eintr_safe(&mut pfds, slice).map_err(Error::Io)?;
        }
    }

    /// Allocate a TX frame for a packet of up to `len` bytes.
    ///
    /// Returns `None` if the packet is too large for the frame or if every
    /// slot in the ring is currently in `TP_STATUS_SEND_REQUEST` /
    /// `TP_STATUS_SENDING` (all frames pending kernel transmission).
    ///
    /// Implementation notes — for two latent issues this method works around:
    ///
    /// 1. A `TxSlot` dropped without `send()` resets its frame status to
    ///    AVAILABLE but the cursor has already advanced past it. To reuse
    ///    the gap, this scans forward up to `frame_count` slots looking
    ///    for the next AVAILABLE.
    /// 2. Slots in `TP_STATUS_WRONG_FORMAT` (kernel-rejected frames) are
    ///    treated as available: we reset them back to AVAILABLE and reuse
    ///    them. Without this the only signal a user gets is "ring full"
    ///    forever — diagnose via [`rejected_slots()`](Self::rejected_slots).
    ///
    /// Worst-case O(N) scan but typical O(1) on the happy path.
    pub fn allocate(&mut self, len: usize) -> Option<TxSlot<'_>> {
        if len > self.frame_size - self.data_offset {
            return None; // frame can't hold this packet
        }

        // Scan up to frame_count slots from current_frame.
        let mut wrong_format_seen = 0u32;
        for _ in 0..self.frame_count {
            let status = self.read_frame_status(self.current_frame);
            match status {
                ffi::TP_STATUS_AVAILABLE => {
                    let slot = TxSlot {
                        frame_ptr: self.frame_ptr(self.current_frame),
                        data_offset: self.data_offset,
                        max_len: self.frame_size - self.data_offset,
                        len: 0,
                        sent: false,
                        pending: &mut self.pending,
                    };
                    self.current_frame = (self.current_frame + 1) % self.frame_count;
                    return Some(slot);
                }
                ffi::TP_STATUS_WRONG_FORMAT => {
                    // Kernel rejected this slot; reset it and continue
                    // scanning. We do not reuse the slot in this allocate()
                    // call because the caller didn't ask to retry — they
                    // called allocate() once and we should give them a
                    // genuinely-available frame, not a recovered-rejected
                    // one (which might trick them into thinking nothing
                    // went wrong).
                    self.reset_slot(self.current_frame);
                    wrong_format_seen += 1;
                    self.current_frame = (self.current_frame + 1) % self.frame_count;
                }
                _ => {
                    // SEND_REQUEST or SENDING — kernel hasn't reclaimed.
                    // Keep scanning in case a later slot is AVAILABLE
                    // (happens when a previous allocate() saw a Drop
                    // without send(), then rolled the cursor past it).
                    self.current_frame = (self.current_frame + 1) % self.frame_count;
                }
            }
        }

        if wrong_format_seen > 0 {
            tracing::warn!(
                count = wrong_format_seen,
                "AF_PACKET TX: kernel rejected frames (WRONG_FORMAT) — check packet contents"
            );
        }
        None
    }

    fn reset_slot(&self, idx: usize) {
        let ptr = self.frame_ptr(idx).as_ptr().cast::<AtomicU32>();
        // SAFETY: ptr points to the tp_status u32 at the start of a
        // tpacket_hdr in the mmap region; AtomicU32 has the same layout.
        unsafe { &*ptr }.store(ffi::TP_STATUS_AVAILABLE, Ordering::Release);
    }

    /// Kick the kernel to transmit all frames queued via [`TxSlot::send()`].
    ///
    /// Returns the number of frames that were *queued* (had
    /// `TP_STATUS_SEND_REQUEST` set) when this call started. **This is not
    /// necessarily the number of frames transmitted** — the kernel may take
    /// additional time to process them, may reject frames with malformed
    /// headers (`TP_STATUS_WRONG_FORMAT`), or may not yet have reclaimed
    /// their slots (`TP_STATUS_SENDING`). Inspect slot status afterward to
    /// distinguish queued from transmitted.
    ///
    /// EINTR is handled internally; transient `EAGAIN` and `ENOBUFS` are
    /// reported as success since the kernel will absorb the kick on the
    /// next attempt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the underlying `sendto` syscall fails with
    /// a non-transient error.
    pub fn flush(&mut self) -> Result<usize, Error> {
        if self.pending == 0 {
            return Ok(0);
        }

        crate::syscall::sendto_kick_eintr_safe(self.fd.as_raw_fd(), 0).map_err(Error::Io)?;

        let count = self.pending as usize;
        self.pending = 0;
        Ok(count)
    }
}

impl AsFd for AfPacketTx {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl crate::traits::PacketSink for AfPacketTx {
    fn allocate(&mut self, len: usize) -> Option<TxSlot<'_>> {
        self.allocate(len)
    }

    fn flush(&mut self) -> Result<usize, Error> {
        self.flush()
    }
}

impl Drop for AfPacketTx {
    fn drop(&mut self) {
        // Best-effort flush before unmapping. Errors are logged at warn
        // level rather than discarded silently — explicit `flush()` before
        // drop remains the only way to observe transmission failures
        // (Drop can't return Result).
        if let Err(e) = self.flush() {
            tracing::warn!(error = %e, "AfPacketTx::drop final flush failed");
        }
    }
}

// SAFETY: AfPacketTx owns its fd and ring exclusively.
unsafe impl Send for AfPacketTx {}

// ── Builder ────────────────────────────────────────────────────────────────

/// Builder for [`AfPacketTx`].
#[must_use]
pub struct AfPacketTxBuilder {
    interface: Option<String>,
    frame_size: usize,
    frame_count: usize,
    qdisc_bypass: bool,
}

impl Default for AfPacketTxBuilder {
    fn default() -> Self {
        Self {
            interface: None,
            frame_size: 2048,
            frame_count: 256,
            qdisc_bypass: false,
        }
    }
}

impl AfPacketTxBuilder {
    /// Set the network interface name (required).
    pub fn interface(mut self, name: &str) -> Self {
        self.interface = Some(name.to_string());
        self
    }

    /// TX frame size in bytes. Default: 2048.
    pub fn frame_size(mut self, bytes: usize) -> Self {
        self.frame_size = bytes;
        self
    }

    /// Number of TX frames. Default: 256.
    pub fn frame_count(mut self, n: usize) -> Self {
        self.frame_count = n;
        self
    }

    /// Bypass qdisc layer for lower TX latency. Default: false.
    pub fn qdisc_bypass(mut self, enable: bool) -> Self {
        self.qdisc_bypass = enable;
        self
    }

    /// Validate and create the [`AfPacketTx`].
    pub fn build(self) -> Result<AfPacketTx, Error> {
        let interface = self
            .interface
            .ok_or_else(|| Error::Config("interface is required".into()))?;

        crate::afpacket::validate_frame_size(self.frame_size)?;

        if self.frame_count == 0 {
            return Err(Error::Config("frame_count must be > 0".into()));
        }

        // Compute block_size: smallest power-of-2 >= PAGE_SIZE and >= frame_size.
        // Each "block" holds 1+ frames. The kernel requires block_size to be a
        // power of 2 and a multiple of PAGE_SIZE.
        let page_size = 4096usize;
        let block_size = self.frame_size.max(page_size).next_power_of_two();

        let frames_per_block = block_size / self.frame_size;
        let block_count = self.frame_count.div_ceil(frames_per_block);
        let actual_frame_count = block_count * frames_per_block;

        let mut req: ffi::tpacket_req3 = unsafe { std::mem::zeroed() };
        req.tp_block_size = block_size as u32;
        req.tp_block_nr = block_count as u32;
        req.tp_frame_size = self.frame_size as u32;
        req.tp_frame_nr = actual_frame_count as u32;

        // Create socket, set version, set TX ring, mmap, bind
        let fd = socket::create_packet_socket()?;
        socket::set_packet_version(fd.as_fd())?;
        socket::set_tx_ring(fd.as_fd(), &req)?;

        let ring_size = block_size * block_count;
        let ring = MmapRing::new(fd.as_fd(), ring_size, block_size, block_count)?;

        let ifindex = socket::resolve_interface(&interface)?;
        socket::bind_to_interface(fd.as_fd(), ifindex)?;

        if self.qdisc_bypass {
            // PACKET_QDISC_BYPASS sets a function pointer on the packet_sock
            // (kernel chooses packet_direct_xmit vs dev_queue_xmit). It has no
            // ordering dependency on bind() — netsniff-ng sets it earlier, but
            // the kernel handler in net/packet/af_packet.c does not care.
            let val: libc::c_int = 1;
            crate::sockopt::raw_setsockopt(
                fd.as_fd(),
                ffi::SOL_PACKET,
                ffi::PACKET_QDISC_BYPASS,
                &val,
                "PACKET_QDISC_BYPASS",
            )?;
        }

        let data_offset = ffi::tpacket_align(std::mem::size_of::<libc::tpacket_hdr>());

        Ok(AfPacketTx {
            ring,
            fd,
            current_frame: 0,
            frame_count: actual_frame_count,
            frame_size: self.frame_size,
            data_offset,
            pending: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_missing_interface() {
        let err = AfPacketTxBuilder::default().build().unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_bad_frame_size() {
        let err = AfPacketTxBuilder::default()
            .interface("lo")
            .frame_size(100) // not multiple of 16
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_zero_frame_count() {
        let err = AfPacketTxBuilder::default()
            .interface("lo")
            .frame_count(0)
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_defaults() {
        let b = AfPacketTxBuilder::default();
        assert_eq!(b.frame_size, 2048);
        assert_eq!(b.frame_count, 256);
        assert!(!b.qdisc_bypass);
    }

    /// frame_capacity should equal frame_size minus the tpacket_hdr alignment.
    /// Verified arithmetically since we can't construct a real AfPacketTx
    /// without a privileged socket.
    #[test]
    fn frame_capacity_arithmetic() {
        let hdr_aligned = ffi::tpacket_align(std::mem::size_of::<libc::tpacket_hdr>());
        // For default 2048 frame_size, capacity = 2048 - aligned(sizeof(tpacket_hdr))
        // tpacket_hdr is small (about 32 B on 64-bit), so capacity should be > 1500.
        let capacity = 2048 - hdr_aligned;
        assert!(capacity > 1500);
        assert!(capacity < 2048);
    }
}
