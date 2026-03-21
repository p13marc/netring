# Phase G.3: Ring mmap + Producer/Consumer Protocol

## Goal

Implement the 4 AF_XDP ring types (Fill, RX, TX, Completion) with mmap
and atomic producer/consumer protocol. This is the core of AF_XDP.

## Background

Each ring is mmap'd from the socket fd at a specific page offset. The kernel
populates `xdp_mmap_offsets` (via getsockopt) with byte offsets to the
producer index, consumer index, flags, and descriptor array within each
mmap region.

```
Ring mmap region:
  [offset.producer] → AtomicU32 (producer index)
  [offset.consumer] → AtomicU32 (consumer index)
  [offset.flags]    → u32 (XDP_RING_NEED_WAKEUP)
  [offset.desc]     → T[ring_size]  (descriptors)
```

Descriptor types:
- **Fill ring**: `u64` (UMEM addresses to fill)
- **Completion ring**: `u64` (UMEM addresses of completed TX)
- **RX ring**: `xdp_desc` (16 bytes: addr, len, options)
- **TX ring**: `xdp_desc` (16 bytes: addr, len, options)

## File: `src/afxdp/ring.rs`

### Ring struct (generic over descriptor type)

```rust
pub(crate) struct XdpRing<T: Copy> {
    /// Base pointer to the mmap'd ring region.
    base: NonNull<u8>,
    /// Total mmap size (for munmap).
    mmap_size: usize,
    /// Number of entries (must be power of 2).
    size: u32,
    /// Bitmask: size - 1.
    mask: u32,
    /// Pointer to producer index (AtomicU32).
    producer: *const AtomicU32,
    /// Pointer to consumer index (AtomicU32).
    consumer: *const AtomicU32,
    /// Pointer to flags (u32, contains XDP_RING_NEED_WAKEUP).
    flags: *const u32,
    /// Pointer to descriptor array start.
    descs: *mut T,
    /// Cached local index (avoids atomic reads on every operation).
    cached_prod: u32,
    cached_cons: u32,
}
```

### Construction from mmap offsets

```rust
impl<T: Copy> XdpRing<T> {
    pub(crate) unsafe fn mmap(
        fd: BorrowedFd<'_>,
        size: u32,
        offsets: &xdp_ring_offset,
        pgoff: u64,  // e.g., XDP_PGOFF_RX_RING
    ) -> Result<Self, Error> {
        // Calculate mmap size = offsets.desc + size * sizeof(T)
        let mmap_size = offsets.desc as usize + (size as usize) * std::mem::size_of::<T>();

        // mmap(NULL, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, fd, pgoff)
        let base = nix::sys::mman::mmap(...)?;

        // Compute pointers using strict provenance
        let producer = base.map_addr(|a| a + offsets.producer as usize) as *const AtomicU32;
        let consumer = base.map_addr(|a| a + offsets.consumer as usize) as *const AtomicU32;
        let flags = base.map_addr(|a| a + offsets.flags as usize) as *const u32;
        let descs = base.map_addr(|a| a + offsets.desc as usize) as *mut T;

        Ok(Self { base, mmap_size, size, mask: size - 1, producer, consumer, flags, descs,
                  cached_prod: 0, cached_cons: 0 })
    }
}

impl<T: Copy> Drop for XdpRing<T> {
    fn drop(&mut self) { /* munmap(self.base, self.mmap_size) */ }
}

unsafe impl<T: Copy + Send> Send for XdpRing<T> {}
```

### Producer protocol (Fill ring, TX ring — userspace writes)

```rust
impl<T: Copy> XdpRing<T> {
    /// Reserve `n` slots for writing. Returns the start index, or None if full.
    pub(crate) fn producer_reserve(&mut self, n: u32) -> Option<u32> {
        // Refresh cached consumer if space appears insufficient
        if self.cached_prod - self.cached_cons + n > self.size {
            self.cached_cons = unsafe { &*self.consumer }.load(Ordering::Acquire);
        }
        if self.cached_prod - self.cached_cons + n > self.size {
            return None; // truly full
        }
        let idx = self.cached_prod;
        self.cached_prod += n;
        Some(idx)
    }

    /// Write a descriptor at `idx`.
    pub(crate) unsafe fn write_desc(&mut self, idx: u32, val: T) {
        let slot = self.descs.add((idx & self.mask) as usize);
        slot.write(val);
    }

    /// Submit `n` previously reserved descriptors to the kernel.
    pub(crate) fn producer_submit(&self, n: u32) {
        // Release fence ensures descriptor writes are visible before producer advance
        unsafe { &*self.producer }.fetch_add(n, Ordering::Release);
    }

    /// Check if kernel needs a wakeup (XDP_RING_NEED_WAKEUP flag).
    pub(crate) fn needs_wakeup(&self) -> bool {
        let flags = unsafe { std::ptr::read_volatile(self.flags) };
        flags & XDP_RING_NEED_WAKEUP != 0
    }
}
```

### Consumer protocol (RX ring, Completion ring — userspace reads)

```rust
impl<T: Copy> XdpRing<T> {
    /// Peek up to `n` available descriptors. Returns count available.
    pub(crate) fn consumer_peek(&mut self, n: u32) -> u32 {
        let available = self.cached_prod - self.cached_cons;
        if available == 0 {
            self.cached_prod = unsafe { &*self.producer }.load(Ordering::Acquire);
        }
        let available = self.cached_prod - self.cached_cons;
        available.min(n)
    }

    /// Read a descriptor at `idx`.
    pub(crate) unsafe fn read_desc(&self, idx: u32) -> T {
        let slot = self.descs.add((idx & self.mask) as usize);
        slot.read()
    }

    /// Release `n` consumed descriptors back to the kernel.
    pub(crate) fn consumer_release(&mut self, n: u32) {
        self.cached_cons += n;
        unsafe { &*self.consumer }.fetch_add(n, Ordering::Release);
    }
}
```

### Type aliases

```rust
pub(crate) type FillRing = XdpRing<u64>;         // UMEM addresses
pub(crate) type CompletionRing = XdpRing<u64>;    // UMEM addresses
pub(crate) type RxRing = XdpRing<xdp_desc>;       // packet descriptors
pub(crate) type TxRing = XdpRing<xdp_desc>;       // packet descriptors
```

## Tests

- Ring construction from synthetic offsets (mock mmap with Vec<u8>)
- Producer: reserve → write → submit, verify producer index advances
- Consumer: peek → read → release, verify consumer index advances
- Full ring: reserve returns None
- Mask wrapping: verify indices wrap at ring_size
