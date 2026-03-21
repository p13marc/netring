# Phase G.2: UMEM Allocation + Registration

## File: `src/afxdp/umem.rs`

### Umem struct

```rust
pub(crate) struct Umem {
    base: NonNull<u8>,
    size: usize,
    frame_size: usize,
    frame_count: usize,
    free_list: VecDeque<u64>,
}
```

### Construction

```rust
impl Umem {
    pub(crate) fn new(frame_size: usize, frame_count: usize) -> Result<Self, Error> {
        let size = frame_size * frame_count;

        // mmap anonymous region: MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE
        // MAP_PRIVATE is correct — kernel pins pages via GUP regardless
        // Use nix::sys::mman::mmap_anonymous(None, NonZeroUsize, PROT_READ|PROT_WRITE, flags)
        let base = unsafe {
            nix::sys::mman::mmap_anonymous(
                None,
                NonZeroUsize::new(size).ok_or(Error::Config("umem size is 0"))?,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_POPULATE,
            ).map_err(|e| Error::Mmap(e.into()))?
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
}
```

### Frame allocator

```rust
impl Umem {
    #[inline]
    pub(crate) fn alloc_frame(&mut self) -> Option<u64> {
        self.free_list.pop_front()
    }

    #[inline]
    pub(crate) fn free_frame(&mut self, addr: u64) {
        self.free_list.push_back(addr);
    }

    pub(crate) fn free_frames(&mut self, addrs: &[u64]) {
        self.free_list.extend(addrs);
    }

    #[inline]
    pub(crate) fn available(&self) -> usize {
        self.free_list.len()
    }

    /// Read packet data from UMEM at the given offset.
    /// SAFETY: addr + len must be within the UMEM region.
    #[inline]
    pub(crate) unsafe fn data(&self, addr: u64, len: usize) -> &[u8] {
        let ptr = self.base.as_ptr().map_addr(|a| a + addr as usize);
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Write into UMEM at the given offset.
    /// SAFETY: addr + len must be within the UMEM region.
    #[inline]
    pub(crate) unsafe fn data_mut(&mut self, addr: u64, len: usize) -> &mut [u8] {
        let ptr = self.base.as_ptr().map_addr(|a| a + addr as usize);
        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }

    /// Build xdp_umem_reg for kernel registration.
    pub(crate) fn as_reg(&self) -> libc::xdp_umem_reg {
        libc::xdp_umem_reg {
            addr: self.base.as_ptr() as u64,
            len: self.size as u64,
            chunk_size: self.frame_size as u32,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,  // kernel 6.11+, older kernels ignore
        }
    }
}
```

### Drop + Send

```rust
impl Drop for Umem {
    fn drop(&mut self) {
        let _ = unsafe { nix::sys::mman::munmap(self.base.cast(), self.size) };
    }
}

unsafe impl Send for Umem {}
```

### Tests

- `Umem::new(4096, 16)` → `available() == 16`
- `alloc_frame()` returns 0, 4096, 8192, ...
- Exhaustion: after 16 allocs, `alloc_frame()` returns None
- `free_frame(0)` then `alloc_frame()` returns 0 (FIFO recycling)
- `as_reg()` has correct addr/len/chunk_size
