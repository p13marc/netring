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
    pub fn data_mut(&mut self) -> &mut [u8] {
        let ptr = self.frame_ptr.as_ptr().map_addr(|a| a + self.data_offset);
        // SAFETY: frame is user-owned, ptr is within mmap region, max_len is valid.
        unsafe { std::slice::from_raw_parts_mut(ptr, self.max_len) }
    }

    /// Set the actual packet length to send.
    ///
    /// # Panics
    ///
    /// Panics if `len > max_len`.
    pub fn set_len(&mut self, len: usize) {
        assert!(
            len <= self.max_len,
            "packet length {len} exceeds frame capacity {}",
            self.max_len
        );
        self.len = len;
    }

    /// Mark this frame for transmission and release the slot.
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

    /// Allocate a TX frame. Returns `None` if the ring is full.
    pub fn allocate(&mut self, len: usize) -> Option<TxSlot<'_>> {
        if len > self.frame_size - self.data_offset {
            return None; // frame can't hold this packet
        }

        let status = self.read_frame_status(self.current_frame);
        if status != ffi::TP_STATUS_AVAILABLE {
            return None; // ring full at this position
        }

        let slot = TxSlot {
            frame_ptr: self.frame_ptr(self.current_frame),
            data_offset: self.data_offset,
            max_len: self.frame_size - self.data_offset,
            len: 0,
            sent: false,
            pending: &mut self.pending,
        };

        self.current_frame = (self.current_frame + 1) % self.frame_count;
        Some(slot)
    }

    /// Flush all pending frames to the wire.
    ///
    /// Calls `sendto(fd, NULL, 0, 0, NULL, 0)` to kick the kernel.
    /// Returns the number of frames that were pending.
    pub fn flush(&mut self) -> Result<usize, Error> {
        if self.pending == 0 {
            return Ok(0);
        }

        let ret = unsafe {
            // SAFETY: fd is valid. NULL buffer with 0 length is the standard
            // TPACKET TX kick mechanism.
            libc::sendto(
                self.fd.as_raw_fd(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null(),
                0,
            )
        };

        if ret == -1 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

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
        // Best-effort flush before unmapping.
        let _ = self.flush();
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

        let align = ffi::TPACKET_ALIGNMENT as usize;
        if self.frame_size % align != 0 {
            return Err(Error::Config(format!(
                "frame_size {} is not a multiple of TPACKET_ALIGNMENT ({})",
                self.frame_size, align
            )));
        }

        let hdrlen = ffi::TPACKET3_HDRLEN as usize;
        if self.frame_size < hdrlen {
            return Err(Error::Config(format!(
                "frame_size {} is less than TPACKET3_HDRLEN ({})",
                self.frame_size, hdrlen
            )));
        }

        if self.frame_count == 0 {
            return Err(Error::Config("frame_count must be > 0".into()));
        }

        // Compute block_size: smallest power-of-2 >= PAGE_SIZE that is a
        // multiple of frame_size, with at least 1 frame per block.
        let page_size = 4096usize;
        let mut block_size = page_size.max(self.frame_size);
        if !block_size.is_power_of_two() {
            block_size = block_size.next_power_of_two();
        }
        // Ensure block_size is a multiple of frame_size
        if block_size % self.frame_size != 0 {
            block_size = self.frame_size * (block_size / self.frame_size + 1);
            if !block_size.is_power_of_two() {
                block_size = block_size.next_power_of_two();
            }
        }

        let frames_per_block = block_size / self.frame_size;
        let block_count =
            (self.frame_count + frames_per_block - 1) / frames_per_block;
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
            let val: libc::c_int = 1;
            socket::raw_setsockopt(
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
}
