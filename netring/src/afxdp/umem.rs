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
    headroom: u32,
    free_list: VecDeque<u64>,
}

/// 0.25 W4: UMEM placement options for AF_XDP zero-copy tuning.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UmemOptions {
    /// Back the UMEM with `MAP_HUGETLB` (default 2 MiB) hugepages to cut TLB
    /// misses on the per-frame DMA path. Falls back to regular pages (with a
    /// `warn`) if hugepages aren't reserved.
    pub(crate) hugepages: bool,
    /// Bind the UMEM's pages to this NUMA node (the NIC's node) via `mbind`,
    /// avoiding cross-node DMA + cache traffic. Best-effort.
    pub(crate) numa_node: Option<u32>,
    /// Per-frame headroom reserved ahead of the packet data, reported to the
    /// kernel via `xdp_umem_reg.headroom`. RX-metadata capture (issue #13) sets
    /// this to [`XdpRxMeta::LEN`](super::metadata::XdpRxMeta::LEN) so the XDP
    /// program's metadata struct fits before each frame; otherwise `0`.
    pub(crate) headroom: u32,
}

const HUGEPAGE_2MB: usize = 2 * 1024 * 1024;

impl Umem {
    /// Allocate a new UMEM region with `frame_count` frames of `frame_size`
    /// bytes each and default placement. Convenience over
    /// [`new_with_options`](Self::new_with_options); used by the test suite (the
    /// builder always goes through `new_with_options`).
    #[allow(dead_code)]
    pub(crate) fn new(frame_size: usize, frame_count: usize) -> Result<Self, Error> {
        Self::new_with_options(frame_size, frame_count, &UmemOptions::default())
    }

    /// 0.25 W4: allocate a UMEM with explicit hugepage / NUMA placement
    /// ([`UmemOptions`]). Both options are best-effort: hugepages fall back to
    /// regular pages with a `warn`, and NUMA binding logs a `warn` on failure.
    pub(crate) fn new_with_options(
        frame_size: usize,
        frame_count: usize,
        opts: &UmemOptions,
    ) -> Result<Self, Error> {
        let size = frame_size
            .checked_mul(frame_count)
            .ok_or_else(|| Error::Config("umem size overflow".into()))?;
        if size == 0 {
            return Err(Error::Config("umem size is 0".into()));
        }

        // Hugepage mappings must be a multiple of the hugepage size; round the
        // region up (the slack past `frame_count` frames is just unused tail).
        let alloc_size = if opts.hugepages {
            size.div_ceil(HUGEPAGE_2MB) * HUGEPAGE_2MB
        } else {
            size
        };
        let nz_size =
            NonZeroUsize::new(alloc_size).ok_or_else(|| Error::Config("umem size is 0".into()))?;

        // MAP_PRIVATE | MAP_ANONYMOUS — kernel pins pages via GUP regardless.
        // MAP_POPULATE faults pages in up front. MAP_HUGETLB (0.25 W4) backs the
        // region with hugepages; if that fails (none reserved) retry without it.
        // `mapped_len` tracks the ACTUAL mapping length so Drop's `munmap` never
        // exceeds it (a too-large munmap would unmap adjacent allocations →
        // memory corruption / SIGSEGV).
        let base_flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_POPULATE;
        let regular = |len: usize| -> Result<NonNull<libc::c_void>, Error> {
            let nz = NonZeroUsize::new(len).unwrap();
            // SAFETY: anonymous mmap, no aliasing of existing memory.
            unsafe {
                nix::sys::mman::mmap_anonymous(
                    None,
                    nz,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    base_flags,
                )
                .map_err(|e| Error::Mmap(e.into()))
            }
        };
        let (base, mapped_len) = if opts.hugepages {
            // SAFETY: anonymous mmap, no aliasing of existing memory.
            match unsafe {
                nix::sys::mman::mmap_anonymous(
                    None,
                    nz_size,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    base_flags | MapFlags::MAP_HUGETLB,
                )
            } {
                Ok(b) => (b, alloc_size),
                Err(e) => {
                    tracing::warn!(error = %e, "UMEM hugepage mmap failed (no hugepages reserved?); falling back to regular pages");
                    (regular(size)?, size)
                }
            }
        } else {
            (regular(size)?, size)
        };

        // 0.25 W4: best-effort NUMA binding of the just-mapped region.
        if let Some(node) = opts.numa_node {
            bind_numa(base.as_ptr() as usize, mapped_len, node);
        }

        // Initialize free list: [0, frame_size, 2*frame_size, ...]
        let free_list: VecDeque<u64> = (0..frame_count).map(|i| (i * frame_size) as u64).collect();

        Ok(Self {
            base: base.cast(),
            // The actual mapping length (munmap'd on Drop; reported to the
            // kernel via `as_reg`). On hugepage fallback this is `size`, not the
            // rounded-up `alloc_size`.
            size: mapped_len,
            frame_size,
            frame_count,
            headroom: opts.headroom,
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

    /// Read packet data from UMEM at the given byte offset, with bounds validation.
    ///
    /// Returns `None` if `addr + len` overflows, exceeds the UMEM region, or
    /// `len` exceeds the per-frame size. Use this on any descriptor read from
    /// the kernel (RX ring); the kernel won't normally produce out-of-bounds
    /// values, but defense in depth is cheap.
    #[inline]
    pub(crate) fn data_checked(&self, addr: u64, len: usize) -> Option<&[u8]> {
        if len > self.frame_size {
            return None;
        }
        let end = (addr as usize).checked_add(len)?;
        if end > self.size {
            return None;
        }
        let ptr = self.base.as_ptr().map_addr(|a| a + addr as usize);
        // SAFETY: bounds verified above; the mmap region is valid for
        // `self.size` bytes; `ptr..ptr+len` lies within it.
        Some(unsafe { std::slice::from_raw_parts(ptr, len) })
    }

    /// Read the `len` headroom bytes immediately preceding the frame at `addr`
    /// — where an XDP program writes RX metadata via `bpf_xdp_adjust_meta`
    /// (issue #13). Returns `None` if `addr < len` (no room ahead of the
    /// frame), which is the case whenever no headroom was reserved.
    #[cfg(feature = "af-xdp")]
    #[inline]
    pub(crate) fn data_before(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let start = (addr as usize).checked_sub(len)?;
        let ptr = self.base.as_ptr().map_addr(|a| a + start);
        // SAFETY: `start + len == addr` and `addr <= self.size` (descriptor came
        // from the kernel within our mapping), so `ptr..ptr+len` lies inside the
        // mmap region.
        Some(unsafe { std::slice::from_raw_parts(ptr, len) })
    }

    /// Mutable view into UMEM at the given byte offset, with bounds validation.
    ///
    /// Same constraints as [`data_checked`](Self::data_checked).
    #[inline]
    pub(crate) fn data_mut_checked(&mut self, addr: u64, len: usize) -> Option<&mut [u8]> {
        if len > self.frame_size {
            return None;
        }
        let end = (addr as usize).checked_add(len)?;
        if end > self.size {
            return None;
        }
        let ptr = self.base.as_ptr().map_addr(|a| a + addr as usize);
        // SAFETY: bounds verified; we have &mut self so no aliasing.
        Some(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
    }

    /// Build an `xdp_umem_reg` for kernel registration.
    pub(crate) fn as_reg(&self) -> libc::xdp_umem_reg {
        libc::xdp_umem_reg {
            addr: self.base.as_ptr() as u64,
            len: self.size as u64,
            chunk_size: self.frame_size as u32,
            headroom: self.headroom,
            flags: 0,
            tx_metadata_len: 0,
        }
    }
}

/// 0.25 W4: best-effort `mbind` of `[addr, addr+len)` to NUMA `node` with
/// `MPOL_BIND`. Logs a `warn` on failure (single-node host, no CAP_SYS_NICE
/// for strict binding, …) — never fatal.
fn bind_numa(addr: usize, len: usize, node: u32) {
    if node >= 64 {
        tracing::warn!(
            node,
            "NUMA node out of range for the 64-bit nodemask; skipping mbind"
        );
        return;
    }
    let nodemask: u64 = 1u64 << node;
    // `maxnode` is the number of bits in the mask; it must exceed the highest
    // node index we set (here always < 64).
    let maxnode: libc::c_ulong = 64;
    // SAFETY: `mbind` over our own freshly-mapped region; `nodemask` outlives
    // the call. A failure is reported, not acted on.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mbind,
            addr as *mut libc::c_void,
            len as libc::c_ulong,
            libc::MPOL_BIND as libc::c_int,
            &nodemask as *const u64,
            maxnode,
            0 as libc::c_uint,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        tracing::warn!(error = %e, node, "mbind(UMEM, MPOL_BIND) failed; UMEM not NUMA-bound");
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
    fn hugepage_request_falls_back_when_unavailable() {
        // 0.25 W4: requesting hugepages must never error — it either maps
        // hugepages (if reserved) or falls back to regular pages. The free list
        // still has exactly `frame_count` frames regardless of the rounding.
        let opts = UmemOptions {
            hugepages: true,
            numa_node: None,
            headroom: 0,
        };
        let umem = Umem::new_with_options(4096, 64, &opts).expect("hugepage UMEM or fallback");
        assert_eq!(umem.available(), 64);
        assert_eq!(umem.frame_size(), 4096);
    }

    #[test]
    fn numa_bind_is_best_effort() {
        // 0.25 W4: a NUMA bind request is best-effort — on a single-node host
        // (or under a sandbox) the mbind warns and the UMEM is still usable.
        let opts = UmemOptions {
            hugepages: false,
            numa_node: Some(0),
            headroom: 0,
        };
        let umem = Umem::new_with_options(4096, 16, &opts).expect("numa-bound UMEM or warn");
        assert_eq!(umem.available(), 16);
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

        let buf = umem.data_mut_checked(addr, 4).unwrap();
        buf.copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let data = umem.data_checked(addr, 4).unwrap();
        assert_eq!(data, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn data_checked_rejects_oversize_len() {
        let umem = Umem::new(4096, 4).unwrap();
        // Exactly frame_size — OK.
        assert!(umem.data_checked(0, 4096).is_some());
        // One byte past frame_size — rejected.
        assert!(umem.data_checked(0, 4097).is_none());
    }

    #[test]
    fn data_checked_rejects_past_umem_end() {
        let umem = Umem::new(4096, 4).unwrap(); // 16 KiB total
        // Reads ending exactly at UMEM end — OK.
        assert!(umem.data_checked(16384 - 200, 200).is_some());
        // Reads past end — rejected.
        assert!(umem.data_checked(16384 - 100, 200).is_none());
    }

    #[test]
    fn data_checked_rejects_overflow_addr() {
        let umem = Umem::new(4096, 4).unwrap();
        assert!(umem.data_checked(u64::MAX, 1).is_none());
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
