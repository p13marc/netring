# Phase 3 — AF_XDP completeness

The AF_XDP backend currently misses the zero-copy story it advertises, doesn't
validate kernel-supplied descriptors, and is not callable through the same trait
abstraction as AF_PACKET. This phase closes those gaps.

Land in this internal order: #12 → #13 → #14 → #21 → #22 → #31 → #33 → #32.

---

## Fix #12 — `XdpSocket::recv` does not validate `xdp_desc`

### Problem

`src/afxdp/mod.rs:309-318`:
```rust
let desc: libc::xdp_desc = unsafe { self.rx.read_desc(base_idx + i) };
let data = unsafe { self.umem.data(desc.addr, desc.len as usize) };
```

`desc.addr` and `desc.len` are kernel-supplied but used unchecked. A malformed or
malicious value (in principle the kernel won't, but defense-in-depth) constructs an
out-of-bounds slice.

### Plan

**Files:** `src/afxdp/umem.rs`

1. Add a checked accessor on `Umem`:

   ```rust
   /// Read packet data from UMEM with bounds validation.
   ///
   /// Returns `None` if `addr + len` exceeds the UMEM region or if `len` exceeds
   /// `frame_size` (a per-frame upper bound).
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
       // SAFETY: bounds verified above.
       Some(unsafe { std::slice::from_raw_parts(ptr, len) })
   }
   ```

2. Same for `data_mut_checked` (TX path validation).

3. In `XdpSocket::recv` replace the unchecked call:

   ```rust
   for i in 0..n {
       let desc: libc::xdp_desc = unsafe { self.rx.read_desc(base_idx + i) };
       match self.umem.data_checked(desc.addr, desc.len as usize) {
           Some(data) => packets.push(OwnedPacket {
               data: data.to_vec(),
               timestamp: Timestamp::default(),
               original_len: desc.len as usize,
           }),
           None => {
               tracing::warn!(
                   addr = desc.addr, len = desc.len,
                   "AF_XDP: malformed RX descriptor; skipping"
               );
           }
       }
       self.umem.free_frame(desc.addr);
   }
   ```

4. Mark the old `data`/`data_mut` `pub(crate)` and add `#[deprecated(note = "...")]`
   only if other internal callers exist that justify it; otherwise just delete the
   unchecked variant after migrating the one call site.

### Tests

Unit on `Umem`:
```rust
#[test]
fn data_checked_rejects_out_of_bounds() {
    let umem = Umem::new(4096, 4).unwrap();  // 16 KiB
    assert!(umem.data_checked(0, 4096).is_some());
    assert!(umem.data_checked(0, 4097).is_none());           // > frame_size
    assert!(umem.data_checked(16384 - 100, 200).is_none());  // past umem end
    assert!(umem.data_checked(u64::MAX, 1).is_none());       // overflow
}
```

### Checklist
- [ ] `Umem::data_checked`
- [ ] `Umem::data_mut_checked`
- [ ] Use checked variant in `recv`
- [ ] Unit tests
- [ ] CHANGELOG entry under "Fixed"

---

## Fix #13 — Zero-copy AF_XDP receive path

### Problem

`recv()` always allocates `Vec<OwnedPacket>` and copies bytes out of UMEM. The
README and module docs advertise "kernel-bypass / zero-copy" but the only available
RX API copies. AF_PACKET has `PacketBatch<'_>` / `Packet<'_>` lifetime-borrowed views
— AF_XDP has nothing equivalent.

### Plan

**Files:** `src/afxdp/mod.rs`, `src/afxdp/ring.rs`, new `src/afxdp/batch.rs`

This is the largest single fix. The structure mirrors `PacketBatch`/`BatchIter`.

1. **New types** in `src/afxdp/batch.rs`:

   ```rust
   /// Zero-copy view of an AF_XDP RX batch.
   ///
   /// Holds a borrow on the owning [`XdpSocket`], its UMEM, and a slice of RX
   /// descriptors that have been peeked from the RX ring. Dropping the batch
   /// returns the descriptors to the kernel's view of the RX ring (via
   /// `consumer_release`) and recycles the underlying UMEM frames into the fill
   /// ring.
   pub struct XdpBatch<'a> {
       socket: &'a mut XdpSocket,  // exclusive borrow
       base_idx: u32,
       n: u32,
       _no_send_marker: PhantomData<*const ()>, // !Send while batch is live
   }

   /// Zero-copy view of one AF_XDP packet.
   pub struct XdpPacket<'a> {
       data: &'a [u8],
       len: u32,
       options: u32,
       addr: u64,
   }

   impl<'a> XdpPacket<'a> {
       pub fn data(&self) -> &'a [u8] { self.data }
       pub fn len(&self) -> usize { self.len as usize }
       pub fn options(&self) -> u32 { self.options }
       /// UMEM offset (for advanced users; opaque otherwise).
       pub fn umem_addr(&self) -> u64 { self.addr }
   }

   impl<'a> XdpBatch<'a> {
       pub fn len(&self) -> usize { self.n as usize }
       pub fn is_empty(&self) -> bool { self.n == 0 }

       pub fn iter(&self) -> XdpBatchIter<'_> {
           XdpBatchIter { batch: self, i: 0 }
       }
   }

   impl<'a, 'b> IntoIterator for &'b XdpBatch<'a> {
       type Item = XdpPacket<'b>;
       type IntoIter = XdpBatchIter<'b>;
       fn into_iter(self) -> XdpBatchIter<'b> { self.iter() }
   }

   pub struct XdpBatchIter<'a> { batch: &'a XdpBatch<'a>, i: u32 }

   impl<'a> Iterator for XdpBatchIter<'a> {
       type Item = XdpPacket<'a>;
       fn next(&mut self) -> Option<XdpPacket<'a>> {
           if self.i >= self.batch.n { return None; }
           let desc = unsafe { self.batch.socket.rx.read_desc(self.batch.base_idx + self.i) };
           self.i += 1;
           let data = self.batch.socket.umem.data_checked(desc.addr, desc.len as usize)?;
           Some(XdpPacket { data, len: desc.len, options: desc.options, addr: desc.addr })
       }
   }

   impl Drop for XdpBatch<'_> {
       fn drop(&mut self) {
           // Recycle UMEM frames before releasing RX descriptors.
           for i in 0..self.n {
               let desc = unsafe { self.socket.rx.read_desc(self.base_idx + i) };
               self.socket.umem.free_frame(desc.addr);
           }
           self.socket.rx.consumer_release(self.n);
           self.socket.refill();
       }
   }
   ```

2. New method on `XdpSocket`:

   ```rust
   /// Receive packets as a zero-copy batch.
   ///
   /// Returns up to 64 packets borrowed directly from UMEM. The batch holds
   /// `&mut self` and must be dropped before another `recv_batch`/`recv`/`send`
   /// call. Dropping returns frames to the kernel automatically.
   pub fn recv_batch(&mut self) -> Result<Option<XdpBatch<'_>>, Error> {
       self.recycle_completed();
       let n = self.rx.consumer_peek(64);
       if n == 0 { return Ok(None); }
       let base_idx = self.rx.consumer_index();
       Ok(Some(XdpBatch { socket: self, base_idx, n, _no_send_marker: PhantomData }))
   }
   ```

3. Keep the existing `recv()` (returns `Vec<OwnedPacket>`) for users who don't need
   zero-copy. Document the perf gap in the rustdoc.

4. Re-export `XdpBatch`, `XdpPacket`, `XdpBatchIter` from `lib.rs` (gated on
   `af-xdp`).

### Tests

Unit (mock `Umem` + ring):
- `recv_batch_returns_zero_copy_view` — set up a fake ring with one descriptor,
  iterate, assert `data()` returns the right bytes without copy (compare
  `data().as_ptr()` against the expected UMEM offset).

Integration (`tests/xdp.rs`):
- `xdp_recv_batch_zero_copy` — TX from one socket, RX batch from another, assert
  `pkt.data().as_ptr()` lies within the receiving socket's UMEM range.

### Migration

Non-breaking — adds new methods/types; `recv()` unchanged.

### Checklist
- [ ] `src/afxdp/batch.rs` with `XdpBatch`, `XdpPacket`, `XdpBatchIter`
- [ ] `XdpSocket::recv_batch`
- [ ] `Drop` impl that releases descriptors and refills
- [ ] Lifetime / Send marker (`!Send`) check via compile_fail doctest
- [ ] Re-export from `lib.rs`
- [ ] Unit test on mock ring
- [ ] Integration test (zero-copy assertion)
- [ ] Update README/AF_XDP docs
- [ ] CHANGELOG entry under "Added"

---

## Fix #14 — RX timestamps and decoded statistics

### Problem

`recv()` always returns `Timestamp::default()` (zero). Statistics are leaked as the
raw kernel struct `xdp_statistics` which has unstable field naming across kernels.

### Plan

**Files:** `src/afxdp/mod.rs`, `src/afxdp/ffi.rs`, new `src/afxdp/stats.rs`

1. Decode `xdp_statistics` into a stable wrapper:

   ```rust
   // src/afxdp/stats.rs
   #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
   pub struct XdpStats {
       /// RX: descriptors dropped because fill ring was empty.
       pub rx_dropped: u64,
       /// RX: invalid descriptors detected by kernel.
       pub rx_invalid_descs: u64,
       /// TX: invalid descriptors rejected by kernel.
       pub tx_invalid_descs: u64,
       /// RX: dropped due to no rx queue.
       pub rx_ring_full: u64,
       /// RX: dropped due to fill ring being empty (specific to newer kernels).
       pub rx_fill_ring_empty_descs: u64,
       /// TX: dropped due to TX ring being empty.
       pub tx_ring_empty_descs: u64,
   }

   impl From<libc::xdp_statistics> for XdpStats {
       fn from(s: libc::xdp_statistics) -> Self {
           Self {
               rx_dropped: s.rx_dropped,
               rx_invalid_descs: s.rx_invalid_descs,
               tx_invalid_descs: s.tx_invalid_descs,
               rx_ring_full: s.rx_ring_full,
               rx_fill_ring_empty_descs: s.rx_fill_ring_empty_descs,
               tx_ring_empty_descs: s.tx_ring_empty_descs,
           }
       }
   }
   ```

2. Change `XdpSocket::statistics` signature:
   ```rust
   pub fn statistics(&self) -> Result<XdpStats, Error> {
       socket::get_statistics(self.fd.as_fd()).map(XdpStats::from)
   }
   ```

3. **Timestamps** — kernel TX/RX metadata extensions (Linux 6.0+) provide per-packet
   timestamps via the `XDP_RX_METADATA` extension. Implementing this requires
   `BPF_PROG_TYPE_XDP` cooperation; full support is deferred. As an interim:

   - Document that `Timestamp::default()` means "not provided".
   - Add `XdpPacket::timestamp() -> Option<Timestamp>` that always returns `None`
     today, paving the way for future metadata support without an API break.
   - In `recv()`, change `OwnedPacket::timestamp` to `Timestamp::default()` (already
     true) but document the field as "Always zero on AF_XDP today; future kernels
     will populate via XDP RX metadata."

4. Re-export `XdpStats` from `lib.rs`.

### Tests

- Unit: `XdpStats::from(xdp_statistics{...})` round-trip.
- Integration: deliberately overflow a small fill ring, assert
  `statistics().rx_dropped > 0` after sending burst traffic.

### Migration

**Soft breaking**: `statistics` return type changes from `xdp_statistics` to
`XdpStats`. The crate is `0.2.x` and AF_XDP is feature-gated and labeled new in
0.2 — bump the public type but list under "Breaking changes (af-xdp feature)".

### Checklist
- [ ] `XdpStats` type
- [ ] `XdpSocket::statistics` returns `XdpStats`
- [ ] `XdpPacket::timestamp` placeholder method (returns `None`)
- [ ] Re-export from `lib.rs`
- [ ] Unit test
- [ ] Integration test (rx_dropped)
- [ ] CHANGELOG entry — list as breaking under "Changed (af-xdp)"

---

## Fix #21 — `XdpRing` cached-index API is brittle

### Problem

`src/afxdp/ring.rs:99-100`: `consumer_index()` returns `cached_cons`. Today the
single in-tree caller (`recv()` and the future `recv_batch()`) uses the result
correctly because `cached_cons` is the start of unread descriptors. But:

- The name suggests "the index returned by the most recent `consumer_peek`".
- A caller that does `peek(N=5)` then `read_desc(consumer_index() + 7)` reads stale
  data without warning.

### Plan

**Files:** `src/afxdp/ring.rs`

1. Replace the public surface of the ring with a token-based API:

   ```rust
   /// Token returned by `consumer_peek` carrying the start index and count.
   #[derive(Debug, Clone, Copy)]
   pub(crate) struct PeekToken { pub(crate) start: u32, pub(crate) n: u32 }

   /// Token returned by `producer_reserve`.
   #[derive(Debug, Clone, Copy)]
   pub(crate) struct ReserveToken { pub(crate) start: u32, pub(crate) n: u32 }

   impl<T: Copy> XdpRing<T> {
       pub(crate) fn consumer_peek(&mut self, max: u32) -> Option<PeekToken> { /* ... */ }
       pub(crate) fn read_at(&self, tok: PeekToken, offset: u32) -> T { /* asserts offset < tok.n */ }
       pub(crate) fn consumer_release(&mut self, tok: PeekToken) { /* uses tok.n */ }

       pub(crate) fn producer_reserve(&mut self, n: u32) -> Option<ReserveToken> { /* ... */ }
       pub(crate) fn write_at(&mut self, tok: ReserveToken, offset: u32, val: T) { /* asserts */ }
       pub(crate) fn producer_submit(&self, tok: ReserveToken) { /* ... */ }
   }
   ```

2. Remove `consumer_index()` from the public-ish API.

3. Migrate the call sites in `XdpSocket::recv`, `recv_batch`, `send`, `flush`,
   `recycle_completed`, `refill`. Each becomes:

   ```rust
   if let Some(tok) = self.rx.consumer_peek(64) {
       for i in 0..tok.n {
           let desc = self.rx.read_at(tok, i);
           ...
       }
       self.rx.consumer_release(tok);
   }
   ```

4. The token can live for a short scope only (no `'static` borrowing issues since
   the ring itself owns the descriptor slots).

### Tests

Update `src/afxdp/ring.rs` tests (the `MockRing` infrastructure) to use the new
token API. Add:

```rust
#[test]
#[should_panic]
fn read_past_token_panics() {
    let mut mock = MockRing::<u64>::new(4);
    mock.kernel_set_producer(2);
    let tok = mock.ring.consumer_peek(4).unwrap();
    let _ = mock.ring.read_at(tok, 5); // offset 5 > tok.n
}
```

### Migration

Internal API only (`pub(crate)`); no external impact.

### Checklist
- [ ] `PeekToken` / `ReserveToken` types
- [ ] Refactor `XdpRing` methods
- [ ] Migrate `XdpSocket` call sites
- [ ] Update mock-ring tests
- [ ] Add panic test for out-of-range
- [ ] CHANGELOG entry under "Changed (internal)"

---

## Fix #22 — `XdpRing` Send/Sync clarification

### Problem

`src/afxdp/ring.rs:193`: `unsafe impl<T: Copy + Send> Send for XdpRing<T>` is
present. Sync is not — correctly so, because the kernel concurrently mutates
producer/consumer counters and the cached-index pattern relies on exclusive
`&mut self` access. The current SAFETY comment is one line and unclear.

### Plan

**Files:** `src/afxdp/ring.rs`

Strengthen the comment:

```rust
// SAFETY: XdpRing owns its mmap region exclusively. The raw pointers
// (producer, consumer, flags, descs) all reference this single mmap that is
// freed on Drop. The mmap is shared with the kernel, but kernel access is
// synchronized via Acquire/Release atomic loads/stores on producer and
// consumer. User-side concurrent access from multiple threads to the same
// XdpRing is unsound (the cached_prod / cached_cons fields are not atomic) —
// `XdpRing` is intentionally NOT Sync, and the owning `XdpSocket` enforces
// exclusion via `&mut self` on every operation. Send is sound because moving
// the ring transfers exclusive ownership of all four pointers and the mmap.
unsafe impl<T: Copy + Send> Send for XdpRing<T> {}
```

Also add a compile-fail doctest at the module level to lock in `!Sync`:

```rust
/// ```compile_fail
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<netring::XdpSocket>();
/// ```
```

(Place under `#[cfg(feature = "af-xdp")]` in a hidden module.)

### Tests

Compile-fail doctest covers it.

### Checklist
- [ ] Expand SAFETY comment
- [ ] Compile-fail doctest for `!Sync`
- [ ] CHANGELOG entry only if reviewer requests

---

## Fix #31 — AF_XDP trait integration

### Problem

`src/afxdp/mod.rs:24-27` says: "This module provides a standalone API that does
**not** implement [`PacketSource`]." This means `Bridge`, `AsyncCapture`, and
`ChannelCapture` cannot use AF_XDP at all.

The reason cited (lifetime model differs) is real but solvable.

### Plan

**Files:** `src/traits.rs`, `src/afxdp/mod.rs`, `src/lib.rs`

Two-phase approach.

### Phase A: a unified async-capable batch trait

`PacketSource` returns `PacketBatch<'_>` which is AF_PACKET-specific. Define a more
abstract trait:

```rust
// src/traits.rs

/// Common operations for any packet source backend.
///
/// This is the unifying trait between AF_PACKET and AF_XDP. Backends expose their
/// native batch type via the associated `Batch<'a>` (a GAT).
pub trait PacketBackend: AsFd {
    type Batch<'a>: PacketBatchView where Self: 'a;
    type Packet<'a>: PacketView where Self: 'a;

    /// Non-blocking poll for the next batch.
    fn poll_batch(&mut self) -> Option<Self::Batch<'_>>;

    /// Block until a batch is available or `timeout` expires.
    fn poll_batch_blocking(&mut self, timeout: Duration) -> Result<Option<Self::Batch<'_>>, Error>;
}

/// What every batch type can do.
pub trait PacketBatchView {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool { self.len() == 0 }
    /// Iterate as `&dyn PacketView` to avoid GAT-in-trait-method complications.
    fn for_each(&self, f: &mut dyn FnMut(&dyn PacketView));
}

pub trait PacketView {
    fn data(&self) -> &[u8];
    fn timestamp(&self) -> Option<Timestamp> { None }
    fn original_len(&self) -> usize { self.data().len() }
}
```

Implement `PacketBackend` for `AfPacketRx` and `XdpSocket`. Keep `PacketSource` as
a compatibility alias (deprecated long-term):

```rust
/// Compatibility trait — prefer [`PacketBackend`].
#[deprecated(note = "Use PacketBackend for new code")]
pub trait PacketSource: AsFd { /* unchanged */ }
```

### Phase B: bridge & async adapters use `PacketBackend`

- `Bridge`: parameterize over `<RA, TA, RB, TB>` instead of hardcoding
  `AfPacketRx`/`AfPacketTx`. Currently bridge needs paired RX/TX; keep that
  constraint but allow `XdpSocket` (which provides both).
- `AsyncCapture`: parameterize over `S: PacketBackend`. Replace inner
  `next_batch()` with `poll_batch()`.
- `ChannelCapture`: parameterize over `S: PacketBackend + Send`.

This is a substantial refactor. Mark as **stretch** for phase 3 — punt to a
separate `0.3.0` planning cycle if it bloats the PR.

### Tests

- Compile checks via `tests/trait_compat.rs` — instantiate generic functions
  taking `PacketBackend` for both backends.
- Existing tests should continue to compile through the deprecated `PacketSource`
  trait.

### Migration

Soft breaking — adds new traits, deprecates `PacketSource` but keeps it. Bump to
`0.3.0` if shipping in same release as Phase 5.

### Checklist
- [ ] Define `PacketBackend`, `PacketBatchView`, `PacketView` traits
- [ ] Implement for `AfPacketRx`
- [ ] Implement for `XdpSocket`
- [ ] Mark `PacketSource` deprecated
- [ ] (Stretch) generic `Bridge`
- [ ] (Stretch) generic `AsyncCapture`
- [ ] (Stretch) generic `ChannelCapture`
- [ ] Trait-compat compile test
- [ ] CHANGELOG entry under "Added"

---

## Fix #32 — Shared UMEM / multi-queue AF_XDP

### Problem

The kernel's `XDP_SHARED_UMEM` model is the canonical way to do multi-queue
capture. `XdpSocketBuilder` has no equivalent of `shared_umem_fd` (currently set to
0 in `socket::bind_xdp`).

### Plan

**Files:** `src/afxdp/mod.rs`, `src/afxdp/socket.rs`, `src/afxdp/umem.rs`

1. Refactor `Umem` ownership to support sharing:

   ```rust
   pub struct Umem { /* private */ }

   pub struct SharedUmem(Arc<Mutex<Umem>>);

   impl Umem {
       pub fn new_shared(frame_size: usize, frame_count: usize) -> Result<SharedUmem, Error> { ... }
   }
   ```

   The free list becomes shared; consider replacing `VecDeque<u64>` with
   `crossbeam::queue::SegQueue<u64>` for lock-free MPMC.

2. New builder methods:

   ```rust
   impl XdpSocketBuilder {
       /// Share UMEM with another socket (for multi-queue / multi-thread setups).
       ///
       /// The first socket binds normally and registers the UMEM; subsequent
       /// sockets pass the first's fd via this method to share its UMEM region.
       pub fn shared_umem(mut self, primary_fd: SharedUmemHandle) -> Self {
           self.shared_umem = Some(primary_fd);
           self
       }
   }

   pub struct SharedUmemHandle { /* wraps Arc<Umem> + the primary socket's RawFd */ }
   ```

3. In `bind_xdp`, when `shared_umem` is set, pass the primary fd as
   `sxdp_shared_umem_fd` and `XDP_SHARED_UMEM` flag in `sxdp_flags`.

4. Document the semantics: shared-UMEM sockets must use distinct `(ifindex, queue_id)`
   pairs and have their own RX/TX rings, but the underlying frame pool is shared.

### Tests

Integration:
- `xdp_shared_umem_two_queues` — bind two sockets sharing one UMEM on `lo` queue 0
  and (if available) queue 1; assert no UMEM corruption when both RX simultaneously.

### Migration

Non-breaking — purely additive.

### Checklist
- [ ] `SharedUmem` / `SharedUmemHandle` types
- [ ] Refactor free-list for thread-safety
- [ ] `XdpSocketBuilder::shared_umem`
- [ ] `bind_xdp` flag handling
- [ ] Integration test
- [ ] Doc/example
- [ ] CHANGELOG entry under "Added"

---

## Fix #33 — Use `needs_wakeup` in `flush`

### Problem

`src/afxdp/mod.rs:387-389` always calls `sendto` on flush. Comment says "Could
check self.tx.needs_wakeup()". For high pps loads this is wasted work.

### Plan

**Files:** `src/afxdp/mod.rs`

```rust
pub fn flush(&self) -> Result<(), Error> {
    if !self.tx.needs_wakeup() {
        return Ok(()); // kernel is actively polling; no wakeup needed
    }
    // remainder unchanged
}
```

Also remove the `#[allow(dead_code)]` on `XdpRing::needs_wakeup`.

### Tests

Hard to assert directly — needs_wakeup is set by the kernel based on driver state.
Add a soak test that runs `flush` 1M times and asserts CPU time is ≤ X ms (skipped
on CI; perf regression sentinel).

### Checklist
- [ ] Conditional sendto in `flush`
- [ ] Remove `dead_code` on `needs_wakeup`
- [ ] (Optional) soak benchmark
- [ ] CHANGELOG entry under "Changed (perf)"
