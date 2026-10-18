//! AF_PACKET TX path (`TPACKET_V2` frame ring).
//!
//! The TX ring is frame-based on every TPACKET version (V3's block layout is
//! RX-only), so the TX socket is set to `TPACKET_V2`: each frame starts with a
//! `tpacket2_hdr` (`u32 tp_status` at offset 0) and is walked by index with
//! `frame_size` stride. The kernel reads the packet from the fixed offset
//! `TPACKET2_HDRLEN - sizeof(sockaddr_ll)` = `TPACKET_ALIGN(sizeof(tpacket2_hdr))`
//! (`tpacket_parse_header()` in `net/packet/af_packet.c`).
//!
//! The socket's `PACKET_VERSION` and the header type written here must agree:
//! the kernel locates `tp_status` / `tp_len` by version, so a mismatch leaves
//! every frame looking `TP_STATUS_AVAILABLE` and nothing is sent (#187).

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::afpacket::ring::{MmapRing, RingGeometry};
use crate::afpacket::{ffi, socket};
use crate::error::Error;

/// The TX frame header: the socket is set to `TPACKET_V2`.
type TxFrameHdr = libc::tpacket2_hdr;

/// Offset of the packet data inside a TX frame. Without
/// `PACKET_TX_HAS_OFF` the kernel reads the packet from
/// `TPACKET2_HDRLEN - sizeof(sockaddr_ll)`, i.e. the aligned header size.
const TX_DATA_OFFSET: usize = ffi::tpacket_align(std::mem::size_of::<TxFrameHdr>());

// ── TxSlot ─────────────────────────────────────────────────────────────────

/// A mutable frame in the TX ring.
///
/// Calling [`send()`](TxSlot::send) marks the frame for transmission.
/// Dropping without calling `send()` discards the frame and returns it
/// to the available pool (the next [`Injector::allocate`] hands out the
/// same slot).
pub struct TxSlot<'a> {
    frame_ptr: NonNull<u8>,
    data_offset: usize,
    max_len: usize,
    len: usize,
    sent: bool,
    /// The slot's index in the ring.
    index: usize,
    /// Its status before it was handed out, restored if it isn't sent.
    prev_status: u32,
    queue: &'a mut TxQueue,
}

/// Where the injector and the kernel are in the TX ring.
///
/// The kernel sends frames strictly in ring order: each kick starts at its
/// TX position (`tx_ring.head`, 0 when the ring is set up) and takes every
/// `TP_STATUS_SEND_REQUEST` frame from there, moving one slot on per frame
/// it hands to the device (or drops, with `PACKET_LOSS`); it stops on the
/// first frame it can't take — still `SEND_REQUEST` (send buffer full,
/// device dropped it) or refused and left `WRONG_FORMAT` — or that isn't
/// queued. So the injector fills slots in the same order (`cursor`), and
/// the queued frames are always the `pending` slots from `head` (from
/// `head + 1` while `head_rejected`): after a kick, walking from `head`
/// over the slots that are no longer `SEND_REQUEST` finds what the kick
/// took in O(frames taken), without scanning the ring.
#[derive(Debug, Clone, Copy)]
struct TxQueue {
    /// Frames queued (`SEND_REQUEST`) that no kick has taken.
    pending: u32,
    /// The next slot [`Injector::allocate`] hands out.
    cursor: usize,
    /// The kernel's TX position.
    head: usize,
    /// The frame at `head` was refused and left `WRONG_FORMAT` (no
    /// `PACKET_LOSS`): the kernel waits on it until it is queued again.
    head_rejected: bool,
    frame_count: usize,
}

impl TxQueue {
    fn next(&self, index: usize) -> usize {
        if index + 1 == self.frame_count {
            0
        } else {
            index + 1
        }
    }

    /// The invariant every mutation keeps (debug builds): the next slot to
    /// fill is right after the queued frames — which start at `head`, or
    /// at `head + 1` behind a refused frame.
    fn check(&self) {
        debug_assert_eq!(
            self.cursor,
            (self.head + self.pending as usize + usize::from(self.head_rejected))
                % self.frame_count,
            "TX ring bookkeeping out of step: {self:?}"
        );
    }
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
    /// the frame capacity is known at [`Injector::allocate`] time, so
    /// exceeding it is a programming error (like indexing past a `Vec`).
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
    /// [`flush()`](Injector::flush) to trigger
    /// kernel transmission of all queued frames.
    pub fn send(mut self) {
        // Write tp_len, tp_snaplen, tp_mac into the tpacket2_hdr at frame start
        let hdr = self.frame_ptr.as_ptr().cast::<TxFrameHdr>();
        // SAFETY: frame_ptr points to a valid tpacket2_hdr in the mmap region.
        unsafe {
            (*hdr).tp_len = self.len as u32;
            (*hdr).tp_snaplen = self.len as u32;
            (*hdr).tp_mac = self.data_offset as u16;
            (*hdr).tp_net = self.data_offset as u16;
        }

        // Atomic store: TP_STATUS_SEND_REQUEST with Release ordering
        // ensures all data writes are visible before kernel reads the frame.
        let status_ptr = hdr.cast::<AtomicU32>();
        // SAFETY: tp_status is the u32 at offset 0 of tpacket2_hdr, naturally aligned.
        unsafe { &*status_ptr }.store(ffi::TP_STATUS_SEND_REQUEST, Ordering::Release);

        self.sent = true;
        self.queue.pending += 1;
        if self.queue.head_rejected && self.index == self.queue.head {
            // The refused frame's slot is queued again: the kernel's next
            // kick starts with it. `allocate` reaches that slot only once
            // every other slot is queued, so the ring is full now, and the
            // next slot to fill is this one again (once the kernel frees
            // it) — not the one after it.
            self.queue.head_rejected = false;
            self.queue.cursor = self.index;
        }
        self.queue.check();
    }
}

impl Drop for TxSlot<'_> {
    fn drop(&mut self) {
        if !self.sent {
            // Discard: the slot goes back as it was — AVAILABLE, or the
            // refused frame the kernel waits on — and is the next one
            // handed out, so the queued frames stay in ring order.
            let status_ptr = self.frame_ptr.as_ptr().cast::<AtomicU32>();
            // SAFETY: frame_ptr points to a valid tpacket2_hdr, tp_status at offset 0.
            unsafe { &*status_ptr }.store(self.prev_status, Ordering::Release);
            self.queue.cursor = self.index;
            self.queue.check();
        }
    }
}

// ── Injector ───────────────────────────────────────────────────────────────

/// How often [`Injector::refresh_link_if_stale`] re-reads the MTU.
const LINK_REFRESH: std::time::Duration = std::time::Duration::from_secs(1);
/// The least time between two re-reads for frames that don't fit.
const LINK_RECHECK: std::time::Duration = std::time::Duration::from_millis(50);

/// The egress device's length limit, as tpacket_snd() applies it.
#[derive(Debug, Clone, Copy)]
struct LinkLimit {
    ifindex: i32,
    mtu: usize,
    /// An Ethernet device whose header length is known (14): not another
    /// link type, not a VLAN sub-interface.
    checked: bool,
    read_at: std::time::Instant,
}

impl LinkLimit {
    fn fits(&self, frame: &[u8]) -> bool {
        const ETH_HLEN: usize = 14;
        const VLAN_HLEN: usize = 4;
        let len = frame.len();
        len <= self.mtu + ETH_HLEN
            || (len <= self.mtu + ETH_HLEN + VLAN_HLEN && frame.get(12..14) == Some(&[0x81, 0x00]))
    }
}

/// What a non-blocking kick did ([`Injector::kick`]).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Kick {
    /// Frames the kernel took: handed to the device, or dropped as
    /// refused.
    pub(crate) taken: usize,
    /// The device (or its qdisc) dropped the frame at the kernel's TX
    /// position (`ENOBUFS`: no carrier, a queue at its limit). The kernel
    /// put it back as queued and tries it again on the next kick — but it
    /// freed its skb, which wakes writability waiters: a wait for
    /// writability after such a kick returns at once, so the next kick
    /// must wait for time instead.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) device_dropped: bool,
}

/// AF_PACKET packet injector (`TPACKET_V2` TX frame ring).
///
/// Implements [`PacketSink`](crate::traits::PacketSink) and [`AsFd`].
/// Use [`Injector::open`] for the common case or [`Injector::builder`]
/// for full configuration.
///
/// # Examples
///
/// ```no_run
/// let mut tx = netring::Injector::open("lo")?;
/// if let Some(mut slot) = tx.allocate(64) {
///     slot.data_mut()[0..6].copy_from_slice(&[0xff; 6]);
///     slot.set_len(64);
///     slot.send();
/// }
/// tx.flush()?;
/// # Ok::<(), netring::Error>(())
/// ```
///
/// # Qdiscs that let go of frames early
///
/// The kernel sends ring frames without copying their data: the packet
/// keeps pointing at the frame's slot until the device is done with it,
/// and only then hands the slot back. A qdisc that **orphans** packets
/// when it queues them — `netem` with a delay, jitter or rate
/// (`skb_orphan_partial()` in its enqueue) — hands the slot back at once
/// while the packet still waits in the qdisc: the next frame queued in
/// that slot overwrites one not sent yet. Don't inject through such a
/// qdisc (shape on the receiving side, or use
/// [`qdisc_bypass`](InjectorBuilder::qdisc_bypass)); a plain socket
/// `send` copies the data and is not affected.
///
/// # Drop semantics
///
/// `Drop` performs a best-effort [`flush()`](Self::flush) to push any pending
/// frames to the kernel before unmapping the ring. Errors from this final
/// flush are logged at `warn` level via `tracing` but cannot be returned —
/// call [`flush()`](Self::flush) explicitly before dropping if you need to
/// observe transmission failures.
pub struct Injector {
    // Drop order: ring (munmap) before fd (close).
    ring: MmapRing,
    fd: OwnedFd,
    frame_count: usize,
    frame_size: usize,
    /// Frames per ring block: the kernel never lets a frame cross a block,
    /// so with a `frame_size` that does not divide the block the tail of
    /// each block is unused.
    frames_per_block: usize,
    data_offset: usize,
    queue: TxQueue,
    /// What the egress device takes ([`Self::fits_device`]).
    link: LinkLimit,
    /// Slot status reads (tests: a kick must not scan the ring).
    #[cfg(test)]
    status_reads: std::cell::Cell<u64>,
}

impl std::fmt::Debug for Injector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Injector")
            .field("frame_count", &self.frame_count)
            .field("frame_size", &self.frame_size)
            .field("pending", &self.queue.pending)
            .finish()
    }
}

impl Injector {
    /// Open an injector on `interface` with default settings.
    ///
    /// Equivalent to `Injector::builder().interface(interface).build()`.
    pub fn open(interface: &str) -> Result<Self, Error> {
        Self::builder().interface(interface).build()
    }

    /// Start building a configured injector.
    pub fn builder() -> InjectorBuilder {
        InjectorBuilder::default()
    }

    /// Frame `index`, where the kernel looks for it: frame
    /// `index % frames_per_block` of block `index / frames_per_block`
    /// (packet_lookup_frame()), not `index * frame_size`.
    fn frame_ptr(&self, index: usize) -> NonNull<u8> {
        let block = self.ring.block_ptr(index / self.frames_per_block);
        let offset = (index % self.frames_per_block) * self.frame_size;
        let ptr = block.as_ptr().cast::<u8>().map_addr(|a| a + offset);
        // SAFETY: block_ptr is in the ring and `offset + frame_size` is at
        // most `frames_per_block * frame_size <= block_size`.
        unsafe { NonNull::new_unchecked(ptr) }
    }

    fn read_frame_status(&self, index: usize) -> u32 {
        #[cfg(test)]
        self.status_reads.set(self.status_reads.get() + 1);
        let ptr = self.frame_ptr(index).as_ptr().cast::<AtomicU32>();
        // SAFETY: points to tp_status at the start of a tpacket2_hdr.
        unsafe { &*ptr }.load(Ordering::Acquire)
    }

    /// Maximum payload bytes that fit in a single TX frame.
    ///
    /// Equal to `frame_size - data_offset` where `data_offset` is the
    /// `tpacket_align(sizeof(tpacket2_hdr))` (32-byte) reservation at the
    /// start of each frame.
    #[inline]
    pub fn frame_capacity(&self) -> usize {
        self.frame_size - self.data_offset
    }

    /// Total number of frames in the TX ring.
    #[inline]
    pub fn frame_count(&self) -> usize {
        self.frame_count
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
    /// Only with [`drop_rejected(false)`](InjectorBuilder::drop_rejected):
    /// the kick that met the refused frame (longer than the device takes,
    /// a malformed header) failed, and its slot stays `WRONG_FORMAT` until
    /// [`allocate`](Self::allocate) hands it out again. With the default
    /// `drop_rejected(true)` the kernel drops refused frames and this is
    /// always 0 — nothing counts them; compare frame lengths with
    /// [`max_frame_len`](Self::max_frame_len) before sending to know.
    /// O(frame_count); avoid in hot paths.
    pub fn rejected_slots(&self) -> usize {
        (0..self.frame_count)
            .filter(|&i| self.read_frame_status(i) == ffi::TP_STATUS_WRONG_FORMAT)
            .count()
    }

    /// The longest frame the kernel lets this socket send on the device, as
    /// tpacket_snd() checks it, with the MTU read now: `mtu + 14` on an
    /// Ethernet device — a frame whose outermost EtherType is 802.1Q
    /// (`0x8100`) may be 4 bytes longer; an 802.1ad (`0x88a8`) tag gets no
    /// allowance. `None` where the link-header length isn't known here
    /// (other link types, VLAN sub-interfaces): the kernel decides.
    /// Longer frames are refused: dropped silently by default, see
    /// [`InjectorBuilder::drop_rejected`]. New in 0.32.0.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the device's MTU can't be read (it was removed).
    pub fn max_frame_len(&self) -> Result<Option<usize>, Error> {
        const ETH_HLEN: usize = 14;
        if !self.link.checked {
            return Ok(None);
        }
        let fd = self.fd.as_fd();
        let name = socket::interface_name(fd, self.link.ifindex)?;
        Ok(Some(socket::interface_mtu(fd, &name)? as usize + ETH_HLEN))
    }

    /// Whether the kernel lets this socket send `frame` on the device —
    /// tpacket_snd()'s limit: `dev->mtu + dev->hard_header_len`, plus
    /// `VLAN_HLEN` for an outer 802.1Q tag on an Ethernet device
    /// (packet_extra_vlan_len_allowed()). Checked only where that length
    /// is known — an Ethernet device (14-byte header) that isn't a VLAN
    /// sub-interface (which may take 4 more); elsewhere `true`, and the
    /// kernel decides. The MTU is re-read when a frame doesn't fit (not
    /// more than every 50 ms) and by [`Self::refresh_link_if_stale`].
    pub(crate) fn fits_device(&mut self, frame: &[u8]) -> bool {
        if !self.link.checked || self.link.fits(frame) {
            return true;
        }
        // It may have grown since it was read.
        if self.link.read_at.elapsed() >= LINK_RECHECK {
            self.refresh_mtu();
            return self.link.fits(frame);
        }
        false
    }

    /// Re-read the device's MTU if the last read is a second old — the
    /// bridge does this on each drain, so a lowered MTU is noticed.
    pub(crate) fn refresh_link_if_stale(&mut self) {
        if self.link.checked && self.link.read_at.elapsed() >= LINK_REFRESH {
            self.refresh_mtu();
        }
    }

    /// Re-read the MTU, by ifindex (the device may have been renamed).
    fn refresh_mtu(&mut self) {
        self.link.read_at = std::time::Instant::now();
        let fd = self.fd.as_fd();
        match socket::interface_name(fd, self.link.ifindex)
            .and_then(|name| socket::interface_mtu(fd, &name))
        {
            Ok(mtu) => self.link.mtu = mtu as usize,
            Err(e) => tracing::debug!(error = %e, "TX: could not re-read the device MTU"),
        }
    }

    /// Number of frames queued with [`TxSlot::send`] that no kick has handed
    /// to the kernel yet (`TP_STATUS_SEND_REQUEST`): what the next
    /// [`flush`](Self::flush) / [`flush_nonblocking`](Self::flush_nonblocking)
    /// will try to hand over. O(1). New in 0.32.0.
    pub fn queued_count(&self) -> usize {
        self.queue.pending as usize
    }

    /// After a kick: move [`TxQueue::head`] over the frames the kernel took
    /// — handed to the device (`SENDING`, or already `AVAILABLE` again) or
    /// dropped (`PACKET_LOSS`) — up to the first it left `SEND_REQUEST` or
    /// refused (`WRONG_FORMAT`). Returns how many it took. O(taken): the
    /// kernel moves a slot out of `SEND_REQUEST` only inside our own kicks
    /// (`tpacket_snd()` runs from `sendto()`), in ring order.
    fn advance_head(&mut self) -> usize {
        let mut taken = 0;
        while self.queue.pending > 0 && !self.queue.head_rejected {
            let status = self.read_frame_status(self.queue.head);
            if status & ffi::TP_STATUS_SEND_REQUEST != 0 {
                break;
            }
            self.queue.pending -= 1;
            if status & ffi::TP_STATUS_WRONG_FORMAT != 0 {
                // Refused, not dropped: the kernel stays on it.
                self.queue.head_rejected = true;
                break;
            }
            self.queue.head = self.queue.next(self.queue.head);
            taken += 1;
        }
        self.queue.check();
        taken
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

    /// 0.25 W3: read the next **egress timestamp** from the socket's error
    /// queue (non-blocking). Requires the injector to have been built with
    /// [`InjectorBuilder::tx_timestamps(true)`](InjectorBuilder::tx_timestamps).
    ///
    /// Returns `None` when no timestamp is currently queued (call again after
    /// the kernel has transmitted — i.e. after [`flush`](Self::flush) /
    /// `wait_drained`). The value is the hardware TX timestamp when the NIC
    /// populates one, else the software timestamp (which works on `lo`).
    pub fn read_tx_timestamp(&self) -> Option<crate::Timestamp> {
        use std::os::fd::AsRawFd;

        // Error-queue messages with OPT_TSONLY carry no payload; a zero-length
        // iov is fine. The control buffer holds the SCM_TIMESTAMPING cmsg.
        let mut ctrl = [0u8; 256];
        let mut iov = libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = ctrl.len() as _;

        // SAFETY: `msg` is fully initialised; recvmsg writes only into `ctrl`
        // and (for OPT_TSONLY, nothing into) the zero-length `iov`.
        let n = unsafe {
            libc::recvmsg(
                self.fd.as_raw_fd(),
                &mut msg,
                libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            return None; // EAGAIN (queue empty) or timestamping not enabled
        }

        // Walk the control messages for SOL_SOCKET / SCM_TIMESTAMPING, whose
        // data is `struct scm_timestamping { struct timespec ts[3]; }`:
        // ts[0] = software, ts[1] = deprecated, ts[2] = raw hardware.
        // SAFETY: cmsg pointers come from the kernel-filled `msg`; we read a
        // POD `[timespec; 3]` unaligned from the cmsg data.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                let c = &*cmsg;
                if c.cmsg_level == libc::SOL_SOCKET && c.cmsg_type == libc::SCM_TIMESTAMPING {
                    let data = libc::CMSG_DATA(cmsg) as *const [libc::timespec; 3];
                    let ts = std::ptr::read_unaligned(data);
                    let hw = ts[2];
                    let sw = ts[0];
                    let pick = if hw.tv_sec != 0 || hw.tv_nsec != 0 {
                        hw
                    } else {
                        sw
                    };
                    if pick.tv_sec != 0 || pick.tv_nsec != 0 {
                        return Some(crate::Timestamp::new(
                            pick.tv_sec as u32,
                            pick.tv_nsec as u32,
                        ));
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        None
    }

    /// Block until [`pending_count`](Self::pending_count) reaches zero or
    /// `timeout` elapses.
    ///
    /// Useful before [`Drop`](Self::drop): the destructor's best-effort
    /// flush returns immediately after `sendto` succeeds, so frames may
    /// still be in flight when the ring is unmapped. Calling
    /// `wait_drained(...)` first ensures the kernel has finished.
    ///
    /// Checks [`pending_count`](Self::pending_count) every millisecond,
    /// sleeping in between. `poll(2)` can't wait for completions here: a
    /// TX-ring packet socket reports `POLLOUT` whenever its write memory is
    /// below half `SO_SNDBUF` (datagram_poll()), whatever the ring holds,
    /// and `POLLERR` while TX timestamps sit unread in its error queue — so
    /// a poll returns at once, and waiting on it burnt a core (#226).
    ///
    /// A frame queued but never kicked ([`flush`](Self::flush)) never
    /// drains: the wait then times out.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] with `ErrorKind::TimedOut` if the timeout elapses
    ///   with frames still pending.
    pub fn wait_drained(&mut self, timeout: std::time::Duration) -> Result<(), Error> {
        use std::time::Instant;
        /// How often a pending frame is looked at.
        const SLICE: std::time::Duration = std::time::Duration::from_millis(1);
        let deadline = Instant::now() + timeout;
        loop {
            if self.pending_count() == 0 {
                return Ok(());
            }
            let remaining = match deadline.checked_duration_since(Instant::now()) {
                Some(r) if !r.is_zero() => r,
                _ => {
                    return Err(Error::Io(std::io::Error::from(
                        std::io::ErrorKind::TimedOut,
                    )));
                }
            };
            std::thread::sleep(remaining.min(SLICE));
        }
    }

    /// Allocate a TX frame for a packet of up to `len` bytes.
    ///
    /// Slots are handed out strictly in ring order — the order the kernel
    /// sends them in. Returns `None` if the packet is too large for the
    /// frame, or if the next slot is still queued
    /// (`TP_STATUS_SEND_REQUEST`) or in flight (`TP_STATUS_SENDING`): the
    /// ring is full up to it. Kick ([`flush`](Self::flush)) and wait for
    /// the device to complete frames
    /// ([`pending_count`](Self::pending_count)). Before 0.32 it skipped to
    /// any free slot further on, which the kernel then didn't send until
    /// the skipped one was queued again.
    ///
    /// A slot the kernel refused (`TP_STATUS_WRONG_FORMAT`, with
    /// [`drop_rejected(false)`](InjectorBuilder::drop_rejected)) is reset
    /// and handed out: the kernel's TX position waits on it.
    ///
    /// O(1).
    pub fn allocate(&mut self, len: usize) -> Option<TxSlot<'_>> {
        if len > self.frame_size - self.data_offset {
            return None; // frame can't hold this packet
        }
        // Strictly in ring order: the kernel sends from its TX position
        // onwards and stops at the first slot that isn't queued, so a frame
        // queued past a slot that is still in flight would wait for that
        // slot to be queued again (see `TxQueue`).
        let index = self.queue.cursor;
        let status = self.read_frame_status(index);
        if status & (ffi::TP_STATUS_SEND_REQUEST | ffi::TP_STATUS_SENDING) != 0 {
            return None;
        }
        if status & ffi::TP_STATUS_WRONG_FORMAT != 0 {
            // The kernel refused this frame (`drop_rejected(false)`) and
            // its TX position stays on the slot: the frames queued after
            // it leave only once this slot is queued again, so it is the
            // one to fill.
            tracing::warn!(
                "AF_PACKET TX: the kernel rejected a frame (WRONG_FORMAT) — reusing its slot"
            );
            self.reset_slot(index);
        }
        self.queue.cursor = self.queue.next(index);
        Some(TxSlot {
            frame_ptr: self.frame_ptr(index),
            data_offset: self.data_offset,
            max_len: self.frame_size - self.data_offset,
            len: 0,
            sent: false,
            index,
            prev_status: status,
            queue: &mut self.queue,
        })
    }

    fn reset_slot(&self, idx: usize) {
        let ptr = self.frame_ptr(idx).as_ptr().cast::<AtomicU32>();
        // SAFETY: ptr points to the tp_status u32 at the start of a
        // tpacket2_hdr in the mmap region; AtomicU32 has the same layout.
        unsafe { &*ptr }.store(ffi::TP_STATUS_AVAILABLE, Ordering::Release);
    }

    /// Kick the kernel to transmit all frames queued via [`TxSlot::send()`],
    /// and **wait** until the device has completed every frame it handed
    /// over: a blocking `sendto` on a TX ring (tpacket_snd(), `need_wait`)
    /// returns once no frame is in flight — on a device that holds frames
    /// (a stalled queue, a qdisc that delays or holds them) that may take
    /// long, or forever. [`flush_nonblocking`](Self::flush_nonblocking) kicks
    /// without waiting; the async [`AsyncInjector`](crate::AsyncInjector)
    /// only uses that one (#228).
    ///
    /// Returns the number of frames that were *queued* (had
    /// `TP_STATUS_SEND_REQUEST` set) when this call started. **This is not
    /// necessarily the number of frames transmitted**: the kernel drops a
    /// frame it refuses (longer than the device takes, a malformed header)
    /// without a trace under the default
    /// [`drop_rejected(true)`](InjectorBuilder::drop_rejected) — check
    /// lengths against [`max_frame_len`](Self::max_frame_len) — or, with
    /// `drop_rejected(false)`, stops there with the error and leaves the
    /// frame `TP_STATUS_WRONG_FORMAT` ([`rejected_slots`](Self::rejected_slots)).
    /// A kick cut short leaves frames queued ([`queued_count`](Self::queued_count))
    /// for the next one.
    ///
    /// EINTR is handled internally; transient `EAGAIN` and `ENOBUFS` (the
    /// device dropped the frame being sent; it stays queued) are reported
    /// as success: the next kick tries again.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the underlying `sendto` syscall fails with
    /// a non-transient error.
    pub fn flush(&mut self) -> Result<usize, Error> {
        if self.queue.pending == 0 {
            return Ok(0);
        }
        let count = self.queue.pending as usize;
        let res = crate::syscall::sendto_kick_eintr_safe(self.fd.as_raw_fd(), 0);
        // Whatever the kick did, the ring says how far it got: a kick the
        // kernel cut short (an error, a full send buffer) leaves frames in
        // SEND_REQUEST, and the next flush must kick them.
        self.advance_head();
        res.map_err(Error::Io)?;
        Ok(count)
    }

    /// Kick the kernel to transmit all frames queued via [`TxSlot::send()`]
    /// **without waiting** for them (`MSG_DONTWAIT`): returns once the
    /// kernel has handed them to the device (`TP_STATUS_SENDING`). Their
    /// slots come back as the device completes them — watch
    /// [`pending_count`](Self::pending_count) or wait with
    /// [`wait_drained`](Self::wait_drained). New in 0.32.0 (#228).
    ///
    /// The kernel stops early when the socket's send buffer fills — with
    /// `EAGAIN` before the first frame, or after handing over some (it
    /// then reports success) — and the rest stay queued
    /// ([`queued_count`](Self::queued_count)); the next flush kicks them.
    ///
    /// Returns the number of frames **this kick handed to the kernel** —
    /// `0` when it could hand over none (send buffer full; wait for the
    /// device to complete frames before kicking again).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the underlying `sendto` syscall fails with
    /// a non-transient error.
    pub fn flush_nonblocking(&mut self) -> Result<usize, Error> {
        self.kick().map(|k| k.taken)
    }

    /// [`flush_nonblocking`](Self::flush_nonblocking), saying whether the
    /// device dropped the frame at the kernel's TX position (`ENOBUFS`).
    pub(crate) fn kick(&mut self) -> Result<Kick, Error> {
        if self.queue.pending == 0 {
            return Ok(Kick::default());
        }
        let res = crate::syscall::sendto_kick_status(self.fd.as_raw_fd(), libc::MSG_DONTWAIT);
        // From the ring, not from the return value: tpacket_snd() reports
        // a kick the send buffer cut short as a success (#228 review).
        let taken = self.advance_head();
        let status = res.map_err(Error::Io)?;
        Ok(Kick {
            taken,
            device_dropped: status == crate::syscall::KickStatus::NoBufs,
        })
    }
}

impl AsFd for Injector {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Injector {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

impl crate::traits::PacketSink for Injector {
    fn allocate(&mut self, len: usize) -> Option<TxSlot<'_>> {
        Injector::allocate(self, len)
    }

    fn flush(&mut self) -> Result<usize, Error> {
        Injector::flush(self)
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        // Best-effort, non-blocking kick before unmapping (#228): a blocking
        // one would wait for the device to complete every frame, possibly
        // forever. Frames in flight keep their own page references. Errors
        // are logged at warn level rather than discarded silently — an
        // explicit `flush()` before drop remains the only way to observe
        // transmission failures (Drop can't return Result).
        if let Err(e) = self.flush_nonblocking() {
            tracing::warn!(error = %e, "Injector::drop final flush failed");
        }
    }
}

// SAFETY: Injector owns its fd and ring exclusively.
unsafe impl Send for Injector {}

// ── Builder ────────────────────────────────────────────────────────────────

/// Builder for [`Injector`].
#[must_use]
pub struct InjectorBuilder {
    interface: Option<String>,
    frame_size: usize,
    frame_count: usize,
    qdisc_bypass: bool,
    tx_timestamps: bool,
    drop_rejected: bool,
}

impl Default for InjectorBuilder {
    fn default() -> Self {
        Self {
            interface: None,
            frame_size: 2048,
            frame_count: 256,
            qdisc_bypass: false,
            tx_timestamps: false,
            drop_rejected: true,
        }
    }
}

impl InjectorBuilder {
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

    /// What a kick does with a frame the kernel refuses to send — longer
    /// than the device accepts (`mtu + 14`, `+ 4` only for an outer 802.1Q
    /// tag), or with a malformed header. Default: `true`.
    ///
    /// - `true` — the kernel **drops** it (`PACKET_LOSS`): its slot becomes
    ///   available again and the kick goes on with the next frame. Nothing
    ///   reports the drop; compare lengths with
    ///   [`Injector::max_frame_len`] before sending if you need to know.
    /// - `false` — the kick **stops** at it with the error (`EMSGSIZE`, …)
    ///   and leaves its slot `TP_STATUS_WRONG_FORMAT`
    ///   ([`Injector::rejected_slots`]). The kernel's TX position stays on
    ///   that slot — what 0.31 did — so the frames queued after it are
    ///   **held**: kicks hand over nothing ([`flush`](Injector::flush)
    ///   keeps returning `Ok`, [`wait_drained`](Injector::wait_drained)
    ///   times out) until the slot is filled again, and
    ///   [`allocate`](Injector::allocate) hands it out only when its turn
    ///   in the ring comes — once `frame_count - 1` frames wait behind it,
    ///   the held ones included. The frame that refills it
    ///   then leaves **first**, ahead of the frames that waited behind
    ///   the refused one: they are reordered.
    ///
    /// New in 0.32.0.
    pub fn drop_rejected(mut self, enable: bool) -> Self {
        self.drop_rejected = enable;
        self
    }

    /// 0.25 W3: request **egress timestamps** (`SO_TIMESTAMPING`) for sent
    /// frames. Default: false.
    ///
    /// Enables software *and* (where the NIC supports it) hardware TX
    /// timestamps. After a frame is transmitted the kernel queues its timestamp
    /// on the socket's error queue; read it with
    /// [`Injector::read_tx_timestamp`] (or
    /// [`AsyncInjector::read_tx_timestamp`](crate::AsyncInjector::read_tx_timestamp)).
    /// Enabling is best-effort: if the kernel rejects the option (very old
    /// kernel) the build still succeeds without timestamps. Software TX
    /// timestamps work on `lo`; hardware timestamps need a capable NIC.
    pub fn tx_timestamps(mut self, enable: bool) -> Self {
        self.tx_timestamps = enable;
        self
    }

    /// Validate and create the [`Injector`].
    pub fn build(self) -> Result<Injector, Error> {
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
        let block_size = self
            .frame_size
            .max(page_size)
            .checked_next_power_of_two()
            .ok_or_else(|| Error::Config(format!("frame_size {} is too large", self.frame_size)))?;

        let frames_per_block = block_size / self.frame_size;
        let block_count = self.frame_count.div_ceil(frames_per_block);
        let geometry = RingGeometry::new(block_size, block_count, self.frame_size)?;

        let mut req: ffi::tpacket_req3 = unsafe { std::mem::zeroed() };
        req.tp_block_size = geometry.block_size;
        req.tp_block_nr = geometry.block_nr;
        req.tp_frame_size = geometry.frame_size;
        req.tp_frame_nr = geometry.frame_nr;

        // Create socket, set version, set TX ring, mmap, bind. Protocol 0
        // throughout: the injector never reads, and a socket bound to
        // ETH_P_ALL without an RX ring gets a copy of every packet on the
        // interface queued (packet_rcv()) until its rcvbuf fills. TX does
        // not need it — tpacket_snd() sends on the bound device and
        // packet_parse_headers() takes skb->protocol from the frame.
        let fd = socket::create_packet_socket_proto(0)?;
        socket::set_packet_version(fd.as_fd(), ffi::TPACKET_V2_INT)?;
        if self.drop_rejected {
            // Before the ring: the kernel refuses PACKET_LOSS once one is
            // set up (EBUSY).
            let on: libc::c_int = 1;
            crate::sockopt::raw_setsockopt(
                fd.as_fd(),
                ffi::SOL_PACKET,
                libc::PACKET_LOSS,
                &on,
                "PACKET_LOSS",
            )?;
        }
        // V2 reads only the leading `tpacket_req` part of the request.
        socket::set_tx_ring(fd.as_fd(), &req)?;

        let ring = MmapRing::new(fd.as_fd(), geometry.size, block_size, block_count)?;

        let ifindex = socket::resolve_interface(&interface)?;
        socket::bind_to_interface_proto(fd.as_fd(), ifindex, 0)?;
        let mtu = socket::interface_mtu(fd.as_fd(), &interface)? as usize;
        // A VLAN sub-interface may count its tag in the header length; its
        // limit is the kernel's to apply.
        let vlan_dev = std::path::Path::new("/proc/net/vlan")
            .join(&interface)
            .exists();
        let ether = socket::interface_link_type(fd.as_fd(), &interface)
            .is_ok_and(|t| t == libc::ARPHRD_ETHER);
        let link = LinkLimit {
            ifindex,
            mtu,
            checked: ether && !vlan_dev,
            read_at: std::time::Instant::now(),
        };

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

        if self.tx_timestamps {
            // SOF_TIMESTAMPING_TX_SOFTWARE/HARDWARE generate the egress
            // timestamps; *_SOFTWARE/RAW_HARDWARE report them; OPT_TSONLY makes
            // the error-queue message carry just the timestamp (no payload),
            // and OPT_ID tags each so the caller can correlate. Best-effort —
            // a rejection (e.g. ancient kernel) is logged, not fatal.
            let flags: u32 = libc::SOF_TIMESTAMPING_TX_SOFTWARE
                | libc::SOF_TIMESTAMPING_TX_HARDWARE
                | libc::SOF_TIMESTAMPING_SOFTWARE
                | libc::SOF_TIMESTAMPING_RAW_HARDWARE
                | libc::SOF_TIMESTAMPING_OPT_TSONLY
                | libc::SOF_TIMESTAMPING_OPT_ID;
            if let Err(e) = crate::sockopt::raw_setsockopt(
                fd.as_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPING,
                &flags,
                "SO_TIMESTAMPING",
            ) {
                tracing::warn!(error = %e, "TX timestamping not enabled (SO_TIMESTAMPING rejected)");
            }
        }

        let data_offset = TX_DATA_OFFSET;

        Ok(Injector {
            ring,
            fd,
            frame_count: geometry.frame_nr as usize,
            frame_size: self.frame_size,
            frames_per_block,
            data_offset,
            queue: TxQueue {
                pending: 0,
                cursor: 0,
                head: 0,
                head_rejected: false,
                frame_count: geometry.frame_nr as usize,
            },
            link,
            #[cfg(test)]
            status_reads: std::cell::Cell::new(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_missing_interface() {
        let err = InjectorBuilder::default().build().unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_bad_frame_size() {
        let err = InjectorBuilder::default()
            .interface("lo")
            .frame_size(100) // not multiple of 16
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn builder_rejects_zero_frame_count() {
        let err = InjectorBuilder::default()
            .interface("lo")
            .frame_count(0)
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    /// A frame count whose ring size overflows `usize` (or whose block /
    /// frame counts do not fit the kernel's `u32` fields) is a config error,
    /// caught before the socket exists.
    #[test]
    fn builder_rejects_ring_geometry_overflow() {
        let err = InjectorBuilder::default()
            .interface("lo")
            .frame_count((1 << 53) + 2)
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)), "{err:?}");
    }

    #[test]
    fn builder_defaults() {
        let b = InjectorBuilder::default();
        assert_eq!(b.frame_size, 2048);
        assert_eq!(b.frame_count, 256);
        assert!(!b.qdisc_bypass);
        assert!(b.drop_rejected);
    }

    /// Review r3: every non-blocking kick scanned the whole ring twice
    /// (what was queued before and after), so `send_stream` on a 16 384-frame
    /// ring ran at 2 250 frames/s. A kick now reads the slots it took, from
    /// the kernel's TX position. Needs `CAP_NET_RAW` (skips without).
    #[test]
    fn a_kick_reads_only_the_slots_it_took() {
        let mut tx = match InjectorBuilder::default()
            .interface("lo")
            .frame_count(4096)
            .build()
        {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("skip (needs CAP_NET_RAW): {e}");
                return;
            }
        };
        let mut frame = [0u8; 64];
        frame[..6].copy_from_slice(&[0xff; 6]);
        frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        let queue = |tx: &mut Injector| {
            if tx.allocate(frame.len()).is_none() {
                tx.wait_drained(std::time::Duration::from_secs(2)).unwrap();
            }
            let mut slot = tx.allocate(frame.len()).expect("a drained ring has room");
            slot.data_mut()[..frame.len()].copy_from_slice(&frame);
            slot.set_len(frame.len());
            slot.send();
        };
        // One frame per kick, around the ring three times.
        let kicks = 3 * 4096;
        tx.status_reads.set(0);
        let mut taken = 0;
        for _ in 0..kicks {
            queue(&mut tx);
            taken += tx.flush_nonblocking().unwrap();
        }
        let reads = tx.status_reads.get();
        assert_eq!(taken, kicks, "lo takes every frame");
        assert!(
            reads <= 4 * kicks as u64,
            "{reads} slot reads for {kicks} one-frame kicks"
        );
        // A batch: 100 frames, one kick.
        tx.status_reads.set(0);
        for _ in 0..100 {
            queue(&mut tx);
        }
        assert_eq!(tx.queued_count(), 100);
        assert_eq!(tx.flush_nonblocking().unwrap(), 100);
        assert!(
            tx.status_reads.get() <= 4 * 100,
            "{}",
            tx.status_reads.get()
        );
        assert_eq!(tx.queued_count(), 0);
    }

    /// A slot handed out but not sent is the next one handed out: the
    /// frames queued stay in ring order, and the kernel sends them all.
    #[test]
    fn a_dropped_slot_is_handed_out_again() {
        let mut tx = match InjectorBuilder::default()
            .interface("lo")
            .frame_count(8)
            .build()
        {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("skip (needs CAP_NET_RAW): {e}");
                return;
            }
        };
        let frame = [0xffu8; 64];
        let send = |tx: &mut Injector| {
            let mut slot = tx.allocate(64).expect("free slot");
            slot.data_mut()[..64].copy_from_slice(&frame);
            slot.set_len(64);
            slot.send();
        };
        send(&mut tx);
        drop(tx.allocate(64).expect("free slot"));
        send(&mut tx);
        send(&mut tx);
        assert_eq!(tx.queued_count(), 3);
        assert_eq!(tx.flush_nonblocking().unwrap(), 3, "no hole stops the kick");
        assert_eq!(tx.queued_count(), 0);
        tx.wait_drained(std::time::Duration::from_secs(2)).unwrap();
    }

    /// `ip …`; `false` when it fails (no privilege).
    fn ip(args: &[&str]) -> bool {
        std::process::Command::new("ip")
            .args(args)
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Review r3: the egress check applied the Ethernet header length and
    /// the 802.1Q allowance to every device type; the kernel allows `mtu +
    /// hard_header_len` (24 on a GRE device with a remote), +4 for 802.1Q
    /// only on Ethernet. Non-Ethernet devices are the kernel's to check.
    /// Needs `CAP_NET_ADMIN` + `CAP_NET_RAW` (skips without).
    #[test]
    fn the_egress_check_follows_the_device_type() {
        let _ = ip(&["link", "delete", "nrtxgre0"]);
        if !ip(&[
            "link", "add", "nrtxgre0", "type", "gre", "remote", "10.9.9.2", "local", "10.9.9.1",
        ]) || !ip(&["link", "set", "nrtxgre0", "up"])
        {
            eprintln!("skip: cannot create a GRE device (needs CAP_NET_ADMIN, ip_gre)");
            return;
        }
        let gre = InjectorBuilder::default().interface("nrtxgre0").build();
        let _ = ip(&["link", "add", "nrtxeth0", "type", "dummy"]);
        let _ = ip(&["link", "set", "nrtxeth0", "mtu", "1500", "up"]);
        let eth = InjectorBuilder::default().interface("nrtxeth0").build();
        let _ = ip(&["link", "delete", "nrtxgre0"]);
        let (mut gre, mut eth) = match (gre, eth) {
            (Ok(g), Ok(e)) => (g, e),
            (g, e) => {
                let _ = ip(&["link", "delete", "nrtxeth0"]);
                eprintln!("skip (needs CAP_NET_RAW): {:?} {:?}", g.err(), e.err());
                return;
            }
        };
        // GRE (MTU 1476, a 24-byte link header): a full-size frame is 1500.
        assert!(gre.fits_device(&vec![0u8; 1476 + 24]));
        assert_eq!(gre.max_frame_len().unwrap(), None, "the kernel's to say");
        assert_eq!(eth.max_frame_len().unwrap(), Some(1514));
        // Ethernet: 1514, or 1518 with an outer 802.1Q tag; not 802.1ad.
        let tagged = |tpid: u16, len: usize| {
            let mut f = vec![0u8; len];
            f[12..14].copy_from_slice(&tpid.to_be_bytes());
            f
        };
        assert!(eth.fits_device(&vec![0u8; 1514]));
        assert!(!eth.fits_device(&vec![0u8; 1515]));
        assert!(eth.fits_device(&tagged(0x8100, 1518)));
        assert!(!eth.fits_device(&tagged(0x88a8, 1518)));
        let _ = ip(&["link", "delete", "nrtxeth0"]);
    }

    /// frame_capacity should equal frame_size minus the tpacket2_hdr alignment.
    #[test]
    fn frame_capacity_arithmetic() {
        let capacity = 2048 - TX_DATA_OFFSET;
        assert_eq!(capacity, 2016);
    }

    /// The header layout the TX code writes must be the kernel's V2 layout:
    /// `tp_status` (the word `read_frame_status` / `send` access atomically)
    /// at offset 0 and `tp_len` right after it.
    #[test]
    fn tx_header_is_tpacket_v2() {
        assert_eq!(std::mem::offset_of!(TxFrameHdr, tp_status), 0);
        assert_eq!(std::mem::offset_of!(TxFrameHdr, tp_len), 4);
        assert_eq!(std::mem::size_of::<TxFrameHdr>(), 32);
        assert_eq!(ffi::TPACKET_V2_INT, 1);
    }
}
