//! UMEM allocation and frame management for AF_XDP.
//!
//! UMEM is a contiguous memory region shared between userspace and the kernel.
//! Frames are allocated from a free list and recycled after use.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::ptr::NonNull;

use nix::sys::mman::{MapFlags, ProtFlags};

use crate::error::Error;

/// UMEM region: mmap'd anonymous memory with a frame-based free list allocator.
pub(crate) struct Umem {
    base: NonNull<u8>,
    size: usize,
    frame_size: usize,
    #[allow(dead_code)]
    frame_count: usize,
    free_list: VecDeque<u64>,
}

impl Umem {
    /// Allocate a new UMEM region with `frame_count` frames of `frame_size` bytes each.
    pub(crate) fn new(frame_size: usize, frame_count: usize) -> Result<Self, Error> {
        let size = frame_size
            .checked_mul(frame_count)
            .ok_or_else(|| Error::Config("umem size overflow".into()))?;

        let nz_size =
            NonZeroUsize::new(size).ok_or_else(|| Error::Config("umem size is 0".into()))?;

        // MAP_PRIVATE | MAP_ANONYMOUS — kernel pins pages via GUP regardless.
        // MAP_POPULATE to fault pages in up front.
        let base = unsafe {
            nix::sys::mman::mmap_anonymous(
                None,
                nz_size,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_POPULATE,
            )
            .map_err(|e| Error::Mmap(e.into()))?
        };

        // Initialize free list: [0, frame_size, 2*frame_size, ...]
        let free_list: VecDeque<u64> = (0..frame_count)
            .map(|i| (i * frame_size) as u64)
            .collect();

        Ok(Self {
            base: base.cast(),
            size,
            frame_size,
            frame_count,
            free_list,
        })
    }

    /// Allocate a frame, returning its byte offset within UMEM.
    #[inline]
    pub(crate) fn alloc_frame(&mut self) -> Option<u64> {
        self.free_list.pop_front()
    }

    /// Return a frame to the free list.
    #[inline]
    pub(crate) fn free_frame(&mut self, addr: u64) {
        self.free_list.push_back(addr);
    }

    /// Return multiple frames to the free list.
    #[inline]
    pub(crate) fn free_frames(&mut self, addrs: &[u64]) {
        self.free_list.extend(addrs);
    }

    /// Number of frames currently available for allocation.
    #[inline]
    pub(crate) fn available(&self) -> usize {
        self.free_list.len()
    }

    /// Frame size in bytes.
    #[inline]
    pub(crate) fn frame_size(&self) -> usize {
        self.frame_size
    }

    /// Read packet data from UMEM at the given byte offset.
    ///
    /// # Safety
    ///
    /// `addr + len` must be within the UMEM region.
    #[inline]
    pub(crate) unsafe fn data(&self, addr: u64, len: usize) -> &[u8] {
        let ptr = self.base.as_ptr().map_addr(|a| a + addr as usize);
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Get a mutable slice into UMEM at the given byte offset.
    ///
    /// # Safety
    ///
    /// `addr + len` must be within the UMEM region.
    #[inline]
    pub(crate) unsafe fn data_mut(&mut self, addr: u64, len: usize) -> &mut [u8] {
        let ptr = self.base.as_ptr().map_addr(|a| a + addr as usize);
        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }

    /// Build an `xdp_umem_reg` for kernel registration.
    pub(crate) fn as_reg(&self) -> libc::xdp_umem_reg {
        libc::xdp_umem_reg {
            addr: self.base.as_ptr() as u64,
            len: self.size as u64,
            chunk_size: self.frame_size as u32,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        }
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        let _ = unsafe { nix::sys::mman::munmap(self.base.cast(), self.size) };
    }
}

// SAFETY: The mmap region is not shared with other threads; access is mediated
// by the owning XdpSocket which holds &mut self for all operations.
unsafe impl Send for Umem {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_frames() {
        let umem = Umem::new(4096, 16).unwrap();
        assert_eq!(umem.available(), 16);
        assert_eq!(umem.frame_size(), 4096);
    }

    #[test]
    fn alloc_returns_sequential_offsets() {
        let mut umem = Umem::new(4096, 4).unwrap();
        assert_eq!(umem.alloc_frame(), Some(0));
        assert_eq!(umem.alloc_frame(), Some(4096));
        assert_eq!(umem.alloc_frame(), Some(8192));
        assert_eq!(umem.alloc_frame(), Some(12288));
    }

    #[test]
    fn exhaustion_returns_none() {
        let mut umem = Umem::new(4096, 2).unwrap();
        assert!(umem.alloc_frame().is_some());
        assert!(umem.alloc_frame().is_some());
        assert_eq!(umem.alloc_frame(), None);
    }

    #[test]
    fn free_recycles_fifo() {
        let mut umem = Umem::new(4096, 2).unwrap();
        let a = umem.alloc_frame().unwrap();
        let b = umem.alloc_frame().unwrap();
        assert_eq!(umem.alloc_frame(), None);

        umem.free_frame(a);
        umem.free_frame(b);
        assert_eq!(umem.available(), 2);
        // FIFO: returns a first
        assert_eq!(umem.alloc_frame(), Some(a));
        assert_eq!(umem.alloc_frame(), Some(b));
    }

    #[test]
    fn as_reg_correct() {
        let umem = Umem::new(4096, 16).unwrap();
        let reg = umem.as_reg();
        assert_eq!(reg.len, (4096 * 16) as u64);
        assert_eq!(reg.chunk_size, 4096);
        assert_eq!(reg.headroom, 0);
        assert_eq!(reg.flags, 0);
        assert_eq!(reg.tx_metadata_len, 0);
        assert_ne!(reg.addr, 0);
    }

    #[test]
    fn data_read_write() {
        let mut umem = Umem::new(4096, 2).unwrap();
        let addr = umem.alloc_frame().unwrap();

        // Write some data
        unsafe {
            let buf = umem.data_mut(addr, 4);
            buf.copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        }

        // Read it back
        let data = unsafe { umem.data(addr, 4) };
        assert_eq!(data, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn zero_size_rejected() {
        assert!(Umem::new(0, 16).is_err());
        assert!(Umem::new(4096, 0).is_err());
    }

    #[test]
    fn overflow_rejected() {
        // frame_size * frame_count would overflow usize
        let result = Umem::new(usize::MAX, 2);
        assert!(result.is_err());
    }
}
