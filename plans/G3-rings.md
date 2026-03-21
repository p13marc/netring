# Phase G.3: Ring mmap + Producer/Consumer Protocol

## Critical: Use `store`, NOT `fetch_add`

The kernel uses **plain `store` with Release ordering** for ring index updates.
Each ring has a single producer and single consumer — no contention on the same side.

```rust
// CORRECT — matches kernel smp_store_release():
producer_ptr.store(cached_prod + n, Ordering::Release);

// WRONG — unnecessary atomic RMW:
producer_ptr.fetch_add(n, Ordering::Release);
```

## File: `src/afxdp/ring.rs`

### Generic XdpRing

```rust
pub(crate) struct XdpRing<T: Copy> {
    base: NonNull<u8>,
    mmap_size: usize,
    size: u32,
    mask: u32,  // size - 1
    producer: *const AtomicU32,
    consumer: *const AtomicU32,
    flags: *const u32,
    descs: *mut T,
    cached_prod: u32,
    cached_cons: u32,
}
```

### Construction from mmap

```rust
impl<T: Copy> XdpRing<T> {
    pub(crate) unsafe fn mmap(
        fd: BorrowedFd<'_>,
        size: u32,
        offsets: &xdp_ring_offset,
        pgoff: u64,
    ) -> Result<Self, Error> {
        let desc_end = offsets.desc as usize + (size as usize) * std::mem::size_of::<T>();
        let mmap_size = desc_end;

        // Cast pgoff (u64/c_ulonglong) to off_t (i64) — safe on 64-bit
        let offset = pgoff as libc::off_t;

        let base = unsafe {
            nix::sys::mman::mmap(
                None,
                NonZeroUsize::new(mmap_size).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED | MapFlags::MAP_POPULATE,
                &fd,
                offset,
            ).map_err(|e| Error::Mmap(e.into()))?
        };

        let base_ptr = base.as_ptr().cast::<u8>();
        let producer = base_ptr.map_addr(|a| a + offsets.producer as usize).cast::<AtomicU32>();
        let consumer = base_ptr.map_addr(|a| a + offsets.consumer as usize).cast::<AtomicU32>();
        let flags = base_ptr.map_addr(|a| a + offsets.flags as usize).cast::<u32>();
        let descs = base_ptr.map_addr(|a| a + offsets.desc as usize).cast::<T>() as *mut T;

        Ok(Self {
            base: NonNull::new_unchecked(base_ptr),
            mmap_size,
            size,
            mask: size - 1,
            producer,
            consumer,
            flags,
            descs,
            cached_prod: 0,
            cached_cons: 0,
        })
    }
}
```

### Producer protocol (Fill ring, TX ring)

Userspace writes descriptors, kernel reads.

```rust
impl<T: Copy> XdpRing<T> {
    /// Reserve n slots. Returns start index, or None if ring is full.
    #[inline]
    pub(crate) fn producer_reserve(&mut self, n: u32) -> Option<u32> {
        if self.free_slots() < n {
            // Refresh cached consumer from kernel
            self.cached_cons = unsafe { &*self.consumer }.load(Ordering::Acquire);
        }
        if self.free_slots() < n {
            return None;
        }
        let idx = self.cached_prod;
        self.cached_prod += n;
        Some(idx)
    }

    #[inline]
    fn free_slots(&self) -> u32 {
        self.size - (self.cached_prod - self.cached_cons)
    }

    /// Write descriptor at index.
    #[inline]
    pub(crate) unsafe fn write_desc(&mut self, idx: u32, val: T) {
        unsafe { self.descs.add((idx & self.mask) as usize).write(val) };
    }

    /// Submit n reserved entries to kernel.
    /// Uses store(Release) — NOT fetch_add.
    #[inline]
    pub(crate) fn producer_submit(&self, n: u32) {
        unsafe { &*self.producer }.store(self.cached_prod, Ordering::Release);
        // Note: cached_prod was already advanced in reserve()
        // The store makes it visible to the kernel
    }

    /// Check if kernel needs a wakeup.
    #[inline]
    pub(crate) fn needs_wakeup(&self) -> bool {
        unsafe { std::ptr::read_volatile(self.flags) } & super::ffi::XDP_RING_NEED_WAKEUP != 0
    }
}
```

### Consumer protocol (RX ring, Completion ring)

Kernel writes descriptors, userspace reads.

```rust
impl<T: Copy> XdpRing<T> {
    /// Peek up to n available entries. Returns count available.
    #[inline]
    pub(crate) fn consumer_peek(&mut self, n: u32) -> u32 {
        let mut available = self.cached_prod.wrapping_sub(self.cached_cons);
        if available == 0 {
            self.cached_prod = unsafe { &*self.producer }.load(Ordering::Acquire);
            available = self.cached_prod.wrapping_sub(self.cached_cons);
        }
        available.min(n)
    }

    /// Read descriptor at index.
    #[inline]
    pub(crate) unsafe fn read_desc(&self, idx: u32) -> T {
        unsafe { self.descs.add((idx & self.mask) as usize).read() }
    }

    /// Release n consumed entries.
    /// Uses store(Release) — NOT fetch_add.
    #[inline]
    pub(crate) fn consumer_release(&mut self, n: u32) {
        self.cached_cons += n;
        unsafe { &*self.consumer }.store(self.cached_cons, Ordering::Release);
    }
}
```

### Drop + Send + type aliases

```rust
impl<T: Copy> Drop for XdpRing<T> {
    fn drop(&mut self) {
        let _ = unsafe { nix::sys::mman::munmap(self.base.cast(), self.mmap_size) };
    }
}

unsafe impl<T: Copy + Send> Send for XdpRing<T> {}

pub(crate) type FillRing = XdpRing<u64>;
pub(crate) type CompletionRing = XdpRing<u64>;
pub(crate) type RxRing = XdpRing<libc::xdp_desc>;
pub(crate) type TxRing = XdpRing<libc::xdp_desc>;
```

## Tests

Unit tests use a `Vec<u8>` as a mock mmap region to test the
producer/consumer logic without actual AF_XDP sockets:

- `producer_reserve(1)` returns Some, advances cached_prod
- `producer_reserve(n)` returns None when full (free_slots < n)
- `consumer_peek(n)` returns 0 when empty
- `consumer_peek(n)` returns available after simulated kernel write
- Index wrapping: verify `idx & mask` wraps at ring_size
- `producer_submit` does `store(Release)` (verify via consumer `load(Acquire)`)
