//! Mmap ring buffer management and block status helpers.

use std::num::NonZeroUsize;
use std::os::fd::AsFd;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

use nix::sys::mman::{MapFlags, ProtFlags};

use crate::afpacket::ffi;
use crate::error::Error;

// ── RingGeometry ───────────────────────────────────────────────────────────

/// Checked ring geometry: the `tpacket_req3` fields handed to
/// `PACKET_RX_RING` / `PACKET_TX_RING` and the mmap length that matches them.
///
/// The kernel takes `u32` block / frame counts and maps exactly
/// `tp_block_nr` blocks, so a count that wraps — on the `u32` cast or on the
/// `usize` size multiply — would leave the kernel with a smaller ring than
/// the one [`MmapRing`] walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RingGeometry {
    pub(crate) block_size: u32,
    pub(crate) block_nr: u32,
    pub(crate) frame_size: u32,
    pub(crate) frame_nr: u32,
    /// `block_size * block_nr` bytes: the length to mmap.
    pub(crate) size: usize,
}

impl RingGeometry {
    /// Geometry of `block_count` blocks of `block_size` bytes, each holding
    /// `block_size / frame_size` frames. Overflow is an [`Error::Config`].
    pub(crate) fn new(
        block_size: usize,
        block_count: usize,
        frame_size: usize,
    ) -> Result<Self, Error> {
        let overflow = || {
            Error::Config(format!(
                "ring of {block_count} blocks of {block_size} bytes \
                 ({frame_size}-byte frames) exceeds the kernel's ring limits"
            ))
        };
        let frames_per_block = block_size
            .checked_div(frame_size)
            .filter(|&n| n > 0)
            .ok_or_else(|| {
                Error::Config(format!(
                    "frame_size {frame_size} does not fit block_size {block_size}"
                ))
            })?;
        let frame_nr = frames_per_block
            .checked_mul(block_count)
            .ok_or_else(overflow)?;
        let size = block_size.checked_mul(block_count).ok_or_else(overflow)?;
        let to_u32 = |n: usize| u32::try_from(n).map_err(|_| overflow());
        Ok(Self {
            block_size: to_u32(block_size)?,
            block_nr: to_u32(block_count)?,
            frame_size: to_u32(frame_size)?,
            frame_nr: to_u32(frame_nr)?,
            size,
        })
    }
}

// ── MmapRing ───────────────────────────────────────────────────────────────

/// RAII wrapper for an mmap'd TPACKET ring buffer region.
///
/// Uses strict provenance (`ptr.map_addr()`) for all pointer arithmetic.
pub(crate) struct MmapRing {
    base: NonNull<u8>,
    size: usize,
    block_size: usize,
    block_count: usize,
}

impl MmapRing {
    /// Create a new ring by mmap'ing the given fd.
    ///
    /// Tries `MAP_SHARED | MAP_LOCKED | MAP_POPULATE`. If `MAP_LOCKED` fails
    /// with `EPERM`, retries without it and logs a warning.
    pub(crate) fn new(
        fd: impl AsFd,
        size: usize,
        block_size: usize,
        block_count: usize,
    ) -> Result<Self, Error> {
        // `block_ptr` trusts this: every block it hands out lies in the map.
        if block_size.checked_mul(block_count) != Some(size) {
            return Err(Error::Config(format!(
                "ring size {size} is not {block_count} blocks of {block_size} bytes"
            )));
        }

        let length =
            NonZeroUsize::new(size).ok_or_else(|| Error::Config("ring size is 0".into()))?;

        let prot = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE;
        let flags = MapFlags::MAP_SHARED | MapFlags::MAP_LOCKED | MapFlags::MAP_POPULATE;

        let result = unsafe {
            // SAFETY: fd is valid, length > 0, flags are standard mmap flags.
            nix::sys::mman::mmap(None, length, prot, flags, &fd, 0)
        };

        let ptr = match result {
            Ok(p) => p,
            Err(
                e @ (nix::errno::Errno::EPERM
                | nix::errno::Errno::ENOMEM
                | nix::errno::Errno::EAGAIN),
            ) => {
                // MAP_LOCKED has a few distinct failure modes; surface the
                // likely cause so users can pick the right remediation.
                let hint = match e {
                    nix::errno::Errno::EPERM => "missing CAP_IPC_LOCK",
                    nix::errno::Errno::ENOMEM => "RLIMIT_MEMLOCK exhausted or genuine OOM",
                    nix::errno::Errno::EAGAIN => "RLIMIT_MEMLOCK exhausted",
                    _ => unreachable!(),
                };
                tracing::warn!(
                    error = %e,
                    hint,
                    "mmap MAP_LOCKED failed; retrying without MAP_LOCKED"
                );
                let flags_no_lock = MapFlags::MAP_SHARED | MapFlags::MAP_POPULATE;
                unsafe { nix::sys::mman::mmap(None, length, prot, flags_no_lock, &fd, 0) }
                    .map_err(|e| Error::Mmap(e.into()))?
            }
            Err(e) => return Err(Error::Mmap(e.into())),
        };

        Ok(Self {
            base: ptr.cast(),
            size,
            block_size,
            block_count,
        })
    }

    /// Pointer to block at `index` using strict provenance.
    ///
    /// # Panics
    ///
    /// Panics if `index >= block_count`.
    #[inline]
    pub(crate) fn block_ptr(&self, index: usize) -> NonNull<ffi::tpacket_block_desc> {
        assert!(
            index < self.block_count,
            "block index {index} out of range (count: {})",
            self.block_count
        );
        let offset = index * self.block_size;
        let ptr = self.base.as_ptr().map_addr(|a| a + offset);
        // SAFETY: base is non-null; `new` checked `size == block_size *
        // block_count`, so the offset is within the mmap region.
        unsafe { NonNull::new_unchecked(ptr.cast::<ffi::tpacket_block_desc>()) }
    }

    /// Base pointer to the mmap region.
    pub(crate) fn base(&self) -> NonNull<u8> {
        self.base
    }

    /// Total size of the mmap region in bytes.
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    /// Number of blocks in the ring.
    pub(crate) fn block_count(&self) -> usize {
        self.block_count
    }
}

impl Drop for MmapRing {
    fn drop(&mut self) {
        // SAFETY: self.base was returned by mmap in new(), self.size matches.
        let _ = unsafe { nix::sys::mman::munmap(self.base.cast(), self.size) };
    }
}

// MmapRing owns its mmap region exclusively — safe to move across threads.
// SAFETY: The mmap region is not shared; exclusive access via &mut self.
unsafe impl Send for MmapRing {}

// ── Block status helpers ───────────────────────────────────────────────────

/// Read the `block_status` field of a block descriptor with `Acquire` ordering.
///
/// The `Acquire` fence ensures we see all packet data the kernel wrote
/// before setting `TP_STATUS_USER`.
///
/// # Safety
///
/// `bd` must point to a valid `tpacket_block_desc` within an mmap'd region.
#[inline]
pub(crate) unsafe fn read_block_status(bd: NonNull<ffi::tpacket_block_desc>) -> u32 {
    // SAFETY: caller guarantees bd is valid. We use addr_of! to avoid
    // creating a reference to the union, then cast to AtomicU32.
    let status_ptr =
        unsafe { core::ptr::addr_of!((*bd.as_ptr()).hdr.bh1.block_status) as *const AtomicU32 };
    // SAFETY: block_status is a naturally-aligned u32. AtomicU32 has the
    // same size and alignment.
    unsafe { &*status_ptr }.load(Ordering::Acquire)
}

/// Return a block to the kernel by writing `TP_STATUS_KERNEL` with `Release` ordering.
///
/// The `Release` ordering ensures all our reads of packet data are complete
/// before the kernel reclaims the block.
///
/// # Safety
///
/// `bd` must point to a valid `tpacket_block_desc` within an mmap'd region.
#[inline]
pub(crate) unsafe fn release_block(bd: NonNull<ffi::tpacket_block_desc>) {
    // SAFETY: same as read_block_status — valid pointer, aligned u32.
    let status_ptr =
        unsafe { core::ptr::addr_of!((*bd.as_ptr()).hdr.bh1.block_status) as *const AtomicU32 };
    // SAFETY: AtomicU32 reference is valid for the mmap region lifetime.
    unsafe { &*status_ptr }.store(ffi::TP_STATUS_KERNEL, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `block_ptr` trusts `size == block_size * block_count`; a mismatch
    /// must be refused before anything is mapped.
    #[test]
    fn new_rejects_size_mismatch() {
        let fd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/zero")
            .unwrap();
        let err = MmapRing::new(&fd, 4096, 4096, 2).err().expect("rejected");
        assert!(matches!(err, Error::Config(_)), "{err:?}");
        let err = MmapRing::new(&fd, 4096, 1 << 22, (1 << 42) + 1)
            .err()
            .expect("rejected");
        assert!(matches!(err, Error::Config(_)), "{err:?}");
    }

    #[test]
    fn geometry_of_the_default_rx_ring() {
        let g = RingGeometry::new(1 << 22, 64, 2048).unwrap();
        assert_eq!(
            g,
            RingGeometry {
                block_size: 1 << 22,
                block_nr: 64,
                frame_size: 2048,
                frame_nr: 2048 * 64,
                size: 64 << 22,
            }
        );
    }

    /// Counts that wrapped silently: the `usize` size multiply, the `u32`
    /// block / frame counts, and a block size beyond `u32`.
    #[test]
    fn geometry_rejects_overflow() {
        for (block_size, block_count, frame_size) in [
            (1 << 22, (1usize << 42) + 1, 2048), // size wraps to one block
            (1 << 12, 1usize << 32, 2048),       // block_nr wraps to 0
            (1 << 22, 1usize << 20, 256),        // frame_nr > u32::MAX
            (1usize << 32, 1, 2048),             // block_size > u32::MAX
        ] {
            let err = RingGeometry::new(block_size, block_count, frame_size).unwrap_err();
            assert!(matches!(err, Error::Config(_)), "{err:?}");
        }
        assert!(RingGeometry::new(4096, 1, 8192).is_err());
        assert!(RingGeometry::new(4096, 1, 0).is_err());
    }
}
