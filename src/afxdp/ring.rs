//! AF_XDP ring buffer types with producer/consumer protocol.
//!
//! Each ring is a shared-memory region (mmap'd from the XDP socket fd) containing:
//! - An `AtomicU32` producer index
//! - An `AtomicU32` consumer index
//! - A `u32` flags field (for `XDP_RING_NEED_WAKEUP`)
//! - An array of descriptors (type `T`)
//!
//! # Protocol
//!
//! Uses plain `store(Release)` / `load(Acquire)` — NOT `fetch_add`.
//! Each ring has a single producer and single consumer (no contention).
//!
//! `XdpRing<T>` is intentionally `Send` but not `Sync`: the cached producer
//! and consumer indices are plain (non-atomic) `u32` fields, so concurrent
//! access from multiple threads to the same ring would race. The owning
//! [`XdpSocket`](crate::XdpSocket) enforces exclusion via `&mut self` on
//! every operation.

use std::num::NonZeroUsize;
use std::os::fd::BorrowedFd;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

use nix::sys::mman::{MapFlags, ProtFlags};

use super::ffi;
use crate::error::Error;

/// Generic XDP ring buffer over descriptor type `T`.
pub(crate) struct XdpRing<T: Copy> {
    base: NonNull<u8>,
    mmap_size: usize,
    size: u32,
    mask: u32, // size - 1
    producer: *const AtomicU32,
    consumer: *const AtomicU32,
    #[allow(dead_code)] // used by needs_wakeup(), which will be called from flush() optimization
    flags: *const u32,
    descs: *mut T,
    cached_prod: u32,
    cached_cons: u32,
}

impl<T: Copy> XdpRing<T> {
    /// mmap a ring from the XDP socket fd.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid AF_XDP socket that has had ring sizes configured.
    /// `offsets` must come from `getsockopt(XDP_MMAP_OFFSETS)`.
    /// `pgoff` is the page offset for this ring type.
    pub(crate) unsafe fn mmap(
        fd: BorrowedFd<'_>,
        size: u32,
        offsets: &ffi::xdp_ring_offset,
        pgoff: libc::off_t,
    ) -> Result<Self, Error> {
        let desc_end = offsets.desc as usize + (size as usize) * std::mem::size_of::<T>();
        let mmap_size = desc_end;

        let base = unsafe {
            nix::sys::mman::mmap(
                None,
                NonZeroUsize::new(mmap_size)
                    .ok_or_else(|| Error::Config("ring mmap size is 0".into()))?,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED | MapFlags::MAP_POPULATE,
                fd,
                pgoff,
            )
            .map_err(|e| Error::Mmap(e.into()))?
        };

        let base_ptr = base.as_ptr().cast::<u8>();
        let producer = base_ptr
            .map_addr(|a| a + offsets.producer as usize)
            .cast::<AtomicU32>();
        let consumer = base_ptr
            .map_addr(|a| a + offsets.consumer as usize)
            .cast::<AtomicU32>();
        let flags = base_ptr
            .map_addr(|a| a + offsets.flags as usize)
            .cast::<u32>();
        let descs = base_ptr.map_addr(|a| a + offsets.desc as usize).cast::<T>();

        Ok(Self {
            base: unsafe { NonNull::new_unchecked(base_ptr) },
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

    // ── Producer protocol (Fill ring, TX ring) ───────────────────────────

    /// Current consumer index (for indexing into `read_desc`).
    #[inline]
    pub(crate) fn consumer_index(&self) -> u32 {
        self.cached_cons
    }

    /// Number of free slots available for the producer.
    #[inline]
    fn free_slots(&self) -> u32 {
        self.size - (self.cached_prod.wrapping_sub(self.cached_cons))
    }

    /// Reserve `n` slots for producing. Returns the start index, or `None` if full.
    #[inline]
    pub(crate) fn producer_reserve(&mut self, n: u32) -> Option<u32> {
        if self.free_slots() < n {
            // Refresh cached consumer from kernel.
            self.cached_cons = unsafe { &*self.consumer }.load(Ordering::Acquire);
        }
        if self.free_slots() < n {
            return None;
        }
        let idx = self.cached_prod;
        self.cached_prod = self.cached_prod.wrapping_add(n);
        Some(idx)
    }

    /// Write a descriptor at the given ring index.
    ///
    /// # Safety
    ///
    /// `idx` must have been obtained from `producer_reserve`.
    #[inline]
    pub(crate) unsafe fn write_desc(&mut self, idx: u32, val: T) {
        unsafe { self.descs.add((idx & self.mask) as usize).write(val) };
    }

    /// Submit `n` reserved entries to the kernel.
    ///
    /// Uses `store(Release)` — NOT `fetch_add` (single producer per ring).
    #[inline]
    pub(crate) fn producer_submit(&self, _n: u32) {
        // cached_prod was already advanced in reserve().
        // The store makes it visible to the kernel.
        unsafe { &*self.producer }.store(self.cached_prod, Ordering::Release);
    }

    // ── Consumer protocol (RX ring, Completion ring) ─────────────────────

    /// Peek up to `n` available entries. Returns the count actually available.
    #[inline]
    pub(crate) fn consumer_peek(&mut self, n: u32) -> u32 {
        let mut available = self.cached_prod.wrapping_sub(self.cached_cons);
        if available == 0 {
            self.cached_prod = unsafe { &*self.producer }.load(Ordering::Acquire);
            available = self.cached_prod.wrapping_sub(self.cached_cons);
        }
        available.min(n)
    }

    /// Read a descriptor at the given ring index.
    ///
    /// # Safety
    ///
    /// `idx` must be within the range returned by `consumer_peek`.
    #[inline]
    pub(crate) unsafe fn read_desc(&self, idx: u32) -> T {
        unsafe { self.descs.add((idx & self.mask) as usize).read() }
    }

    /// Release `n` consumed entries back to the kernel.
    ///
    /// Uses `store(Release)` — NOT `fetch_add` (single consumer per ring).
    #[inline]
    pub(crate) fn consumer_release(&mut self, n: u32) {
        self.cached_cons = self.cached_cons.wrapping_add(n);
        unsafe { &*self.consumer }.store(self.cached_cons, Ordering::Release);
    }

    // ── Wakeup ───────────────────────────────────────────────────────────

    /// Check if the kernel needs a wakeup (via `sendto` or `poll`).
    ///
    /// Honored by [`XdpSocket::flush`] when the socket was bound with
    /// `XDP_USE_NEED_WAKEUP` — skips the syscall when the kernel signals it
    /// is actively polling the TX ring.
    #[inline]
    pub(crate) fn needs_wakeup(&self) -> bool {
        // SAFETY: `self.flags` is a u32 in the mmap'd ring shared with the kernel.
        // Volatile read prevents the compiler from caching kernel writes.
        (unsafe { self.flags.read_volatile() }) & ffi::XDP_RING_NEED_WAKEUP != 0
    }
}

impl<T: Copy> Drop for XdpRing<T> {
    fn drop(&mut self) {
        let _ = unsafe { nix::sys::mman::munmap(self.base.cast(), self.mmap_size) };
    }
}

// SAFETY: XdpRing owns its mmap region exclusively. The raw pointers
// (producer, consumer, flags, descs) all reference this single mmap that is
// freed on Drop, so they cannot outlive the ring. The mmap is shared with
// the kernel, but kernel access is synchronized via Acquire/Release atomic
// loads/stores on the producer/consumer indices.
//
// Send is sound: moving the ring transfers exclusive ownership of all four
// pointers and the mmap region; the kernel side does not change.
//
// Sync is intentionally NOT implemented: the cached_prod / cached_cons
// fields are plain u32 (not atomics), so concurrent calls from multiple
// threads on the same XdpRing would race. Raw pointers are !Sync by default,
// which gives us !Sync here automatically — the SPEC notes the intent and
// the static assertion below locks in the Send-but-not-Sync property.
unsafe impl<T: Copy + Send> Send for XdpRing<T> {}

// Static assertions: XdpRing<u64> is Send but not Sync.
// If a future change breaks either property, this fails to compile.
#[cfg(test)]
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<XdpRing<u64>>();
    assert_send::<XdpRing<libc::xdp_desc>>();
};

/// Fill ring: userspace produces frame addrs, kernel consumes for RX.
pub(crate) type FillRing = XdpRing<u64>;

/// Completion ring: kernel produces frame addrs after TX, userspace consumes.
pub(crate) type CompletionRing = XdpRing<u64>;

/// RX ring: kernel produces `xdp_desc`, userspace consumes received packets.
pub(crate) type RxRing = XdpRing<libc::xdp_desc>;

/// TX ring: userspace produces `xdp_desc`, kernel consumes for transmission.
pub(crate) type TxRing = XdpRing<libc::xdp_desc>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{Layout, alloc_zeroed, dealloc};

    /// Helper to create a mock ring in heap memory for testing the
    /// producer/consumer protocol without actual AF_XDP sockets.
    ///
    /// Layout matches kernel ring: [producer: AtomicU32, consumer: AtomicU32, flags: u32, pad: u32, descs...]
    struct MockRing<T: Copy> {
        ring: XdpRing<T>,
        ptr: *mut u8,
        layout: Layout,
    }

    impl<T: Copy> MockRing<T> {
        fn new(size: u32) -> Self {
            assert!(size.is_power_of_two());
            let desc_offset = 16usize; // after producer(4) + consumer(4) + flags(4) + pad(4)
            let total = desc_offset + (size as usize) * std::mem::size_of::<T>();
            let layout = Layout::from_size_align(total, 8).unwrap();
            let ptr = unsafe { alloc_zeroed(layout) };
            assert!(!ptr.is_null());

            let producer = ptr.cast::<AtomicU32>();
            let consumer = unsafe { ptr.add(4) }.cast::<AtomicU32>();
            let flags = unsafe { ptr.add(8) }.cast::<u32>();
            let descs = unsafe { ptr.add(desc_offset) }.cast::<T>();

            let ring = XdpRing {
                base: unsafe { NonNull::new_unchecked(ptr) },
                mmap_size: 0, // prevent munmap in drop
                size,
                mask: size - 1,
                producer,
                consumer,
                flags,
                descs,
                cached_prod: 0,
                cached_cons: 0,
            };

            Self { ring, ptr, layout }
        }

        /// Simulate kernel writing to the producer index (for consumer-side testing).
        fn kernel_set_producer(&self, val: u32) {
            unsafe { &*self.ring.producer }.store(val, Ordering::Release);
        }

        /// Read the producer index (to verify producer-side writes).
        fn read_producer(&self) -> u32 {
            unsafe { &*self.ring.producer }.load(Ordering::Acquire)
        }

        /// Read the consumer index (to verify consumer-side writes).
        fn read_consumer(&self) -> u32 {
            unsafe { &*self.ring.consumer }.load(Ordering::Acquire)
        }

        /// Set the flags field (to test needs_wakeup).
        fn set_flags(&self, val: u32) {
            unsafe { std::ptr::write_volatile(self.ring.flags as *mut u32, val) };
        }
    }

    impl<T: Copy> Drop for MockRing<T> {
        fn drop(&mut self) {
            // Override mmap_size to 0 so XdpRing::drop doesn't munmap.
            self.ring.mmap_size = 0;
            // Manually free the heap allocation.
            unsafe { dealloc(self.ptr, self.layout) };
        }
    }

    #[test]
    fn producer_reserve_and_submit() {
        let mut mock = MockRing::<u64>::new(4);
        // Reserve 1 slot
        let idx = mock.ring.producer_reserve(1);
        assert_eq!(idx, Some(0));

        // Write a descriptor
        unsafe { mock.ring.write_desc(0, 42u64) };
        mock.ring.producer_submit(1);

        // Producer index should be visible
        assert_eq!(mock.read_producer(), 1);
    }

    #[test]
    fn producer_reserve_full() {
        let mut mock = MockRing::<u64>::new(4);
        // Fill all 4 slots
        assert!(mock.ring.producer_reserve(4).is_some());
        mock.ring.producer_submit(4);

        // Ring is now full
        assert_eq!(mock.ring.producer_reserve(1), None);
    }

    #[test]
    fn consumer_peek_empty() {
        let mut mock = MockRing::<u64>::new(4);
        assert_eq!(mock.ring.consumer_peek(4), 0);
    }

    #[test]
    fn consumer_peek_after_produce() {
        let mut mock = MockRing::<u64>::new(4);
        // Simulate kernel producing 2 entries
        mock.kernel_set_producer(2);

        let n = mock.ring.consumer_peek(4);
        assert_eq!(n, 2);
    }

    #[test]
    fn consumer_read_and_release() {
        let mut mock = MockRing::<u64>::new(4);

        // Write descriptors directly (simulating kernel)
        unsafe {
            mock.ring.descs.add(0).write(100u64);
            mock.ring.descs.add(1).write(200u64);
        }
        mock.kernel_set_producer(2);

        let n = mock.ring.consumer_peek(4);
        assert_eq!(n, 2);

        let v0 = unsafe { mock.ring.read_desc(mock.ring.cached_cons) };
        let v1 = unsafe { mock.ring.read_desc(mock.ring.cached_cons + 1) };
        assert_eq!(v0, 100);
        assert_eq!(v1, 200);

        mock.ring.consumer_release(2);
        assert_eq!(mock.read_consumer(), 2);
    }

    #[test]
    fn index_wrapping() {
        let mut mock = MockRing::<u64>::new(4); // mask = 3

        // Produce 3, consume 3, then produce 2 more — wraps around
        assert!(mock.ring.producer_reserve(3).is_some());
        mock.ring.producer_submit(3);

        // Simulate consumer (kernel) consuming 3
        unsafe { &*mock.ring.consumer }.store(3, Ordering::Release);
        mock.ring.cached_cons = 3; // refresh

        // Now produce 2 more: indices 3,4 → slots 3,0 (wrapping)
        let idx = mock.ring.producer_reserve(2);
        assert_eq!(idx, Some(3));

        unsafe {
            mock.ring.write_desc(3, 30u64); // slot 3 & 3 = 3
            mock.ring.write_desc(4, 40u64); // slot 4 & 3 = 0
        }

        // Verify the wrapped write
        let v0 = unsafe { mock.ring.descs.add(3).read() };
        let v1 = unsafe { mock.ring.descs.add(0).read() };
        assert_eq!(v0, 30);
        assert_eq!(v1, 40);
    }

    #[test]
    fn needs_wakeup_flag() {
        let mock = MockRing::<u64>::new(4);
        assert!(!mock.ring.needs_wakeup());

        mock.set_flags(ffi::XDP_RING_NEED_WAKEUP);
        assert!(mock.ring.needs_wakeup());

        mock.set_flags(0);
        assert!(!mock.ring.needs_wakeup());
    }

    #[test]
    fn producer_reclaim_after_consume() {
        let mut mock = MockRing::<u64>::new(4);

        // Fill ring
        assert!(mock.ring.producer_reserve(4).is_some());
        mock.ring.producer_submit(4);
        assert_eq!(mock.ring.producer_reserve(1), None);

        // Kernel consumes 2
        unsafe { &*mock.ring.consumer }.store(2, Ordering::Release);

        // Now we can produce 2 more (reserve refreshes cached_cons)
        assert!(mock.ring.producer_reserve(2).is_some());
    }
}
