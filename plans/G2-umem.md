# Phase G.2: UMEM Allocation + Registration

## Goal

Implement UMEM (User Memory) management: anonymous mmap allocation,
kernel registration, and a frame allocator (free list).

## File: `src/afxdp/umem.rs`

### Umem struct

```rust
pub(crate) struct Umem {
    /// Base pointer to the UMEM mmap region.
    base: NonNull<u8>,
    /// Total size of the UMEM region.
    size: usize,
    /// Size of each frame (chunk).
    frame_size: usize,
    /// Total number of frames.
    frame_count: usize,
    /// Free list of available frame addresses (UMEM offsets).
    free_list: VecDeque<u64>,
}
```

### Construction

```rust
impl Umem {
    pub(crate) fn new(frame_size: usize, frame_count: usize) -> Result<Self, Error> {
        let size = frame_size * frame_count;

        // 1. mmap anonymous region for packet data
        //    mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0)
        //    Use nix::sys::mman::mmap_anonymous()

        // 2. Initialize free list with all frame offsets
        //    [0, frame_size, 2*frame_size, ..., (frame_count-1)*frame_size]

        // 3. Return Umem { base, size, frame_size, frame_count, free_list }
    }
}
```

### Frame allocator

```rust
impl Umem {
    /// Allocate a frame from the free list. Returns UMEM offset.
    pub(crate) fn alloc_frame(&mut self) -> Option<u64> {
        self.free_list.pop_front()
    }

    /// Return a frame to the free list.
    pub(crate) fn free_frame(&mut self, addr: u64) {
        self.free_list.push_back(addr);
    }

    /// Return multiple frames.
    pub(crate) fn free_frames(&mut self, addrs: &[u64]) {
        self.free_list.extend(addrs);
    }

    /// Number of available frames.
    pub(crate) fn available(&self) -> usize {
        self.free_list.len()
    }

    /// Get a slice of packet data at the given UMEM offset.
    pub(crate) unsafe fn data(&self, addr: u64, len: usize) -> &[u8] {
        let ptr = self.base.as_ptr().map_addr(|a| a + addr as usize);
        std::slice::from_raw_parts(ptr, len)
    }

    /// Get a mutable slice for writing packet data.
    pub(crate) unsafe fn data_mut(&mut self, addr: u64, len: usize) -> &mut [u8] {
        let ptr = self.base.as_ptr().map_addr(|a| a + addr as usize);
        std::slice::from_raw_parts_mut(ptr, len)
    }

    /// Build the xdp_umem_reg for kernel registration.
    pub(crate) fn as_reg(&self) -> libc::xdp_umem_reg {
        xdp_umem_reg {
            addr: self.base.as_ptr() as u64,
            len: self.size as u64,
            chunk_size: self.frame_size as u32,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        }
    }
}
```

### Drop

```rust
impl Drop for Umem {
    fn drop(&mut self) {
        // munmap(self.base, self.size)
    }
}

unsafe impl Send for Umem {}
```

### Tests

- `Umem::new(4096, 16)` — 16 frames, verify `available() == 16`
- `alloc_frame()` returns sequential offsets `0, 4096, 8192, ...`
- `alloc_frame()` returns `None` when exhausted
- `free_frame()` + `alloc_frame()` round-trip
- Drop runs without error
