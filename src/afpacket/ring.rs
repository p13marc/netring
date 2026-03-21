//! Mmap ring buffer management and block status helpers.

use std::num::NonZeroUsize;
use std::os::fd::AsFd;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

use nix::sys::mman::{MapFlags, ProtFlags};

use crate::afpacket::ffi;
use crate::error::Error;

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
        debug_assert_eq!(size, block_size * block_count);

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
            Err(nix::errno::Errno::EPERM)
            | Err(nix::errno::Errno::ENOMEM)
            | Err(nix::errno::Errno::EAGAIN) => {
                // MAP_LOCKED may fail without CAP_IPC_LOCK or when RLIMIT_MEMLOCK
                // is exceeded (EAGAIN). Retry without it.
                log::warn!("mmap with MAP_LOCKED failed, retrying without (consider CAP_IPC_LOCK)");
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
    pub(crate) fn block_ptr(&self, index: usize) -> NonNull<ffi::tpacket_block_desc> {
        assert!(
            index < self.block_count,
            "block index {index} out of range (count: {})",
            self.block_count
        );
        let offset = index * self.block_size;
        let ptr = self.base.as_ptr().map_addr(|a| a + offset);
        // SAFETY: base is non-null, offset is within the mmap region.
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

    /// Size of each block in bytes.
    #[allow(dead_code)]
    pub(crate) fn block_size(&self) -> usize {
        self.block_size
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
pub(crate) unsafe fn release_block(bd: NonNull<ffi::tpacket_block_desc>) {
    // SAFETY: same as read_block_status — valid pointer, aligned u32.
    let status_ptr =
        unsafe { core::ptr::addr_of!((*bd.as_ptr()).hdr.bh1.block_status) as *const AtomicU32 };
    // SAFETY: AtomicU32 reference is valid for the mmap region lifetime.
    unsafe { &*status_ptr }.store(ffi::TP_STATUS_KERNEL, Ordering::Release);
}
