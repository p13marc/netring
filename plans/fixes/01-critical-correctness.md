# Phase 1 — Critical correctness bugs

These are the four issues that break advertised behavior or admit unsoundness.
Land each as a separate PR; do them in this order.

---

## Fix #1 — AF_XDP TX-only mode is broken

### Problem

`src/afxdp/mod.rs:222-231` (`XdpSocketBuilder::build`) prefills the **entire** fill ring
from the UMEM free list:

```rust
let prefill = umem.available().min(ring_size as usize) as u32;  // == frame_count
... umem.alloc_frame() ...     // drains free_list completely
```

For default config (`frame_count = 4096`, power of two), all 4096 frames go into the
fill ring and `free_list.is_empty()`. On the TX path, `send()`:

1. Calls `recycle_completed()` — nothing to recycle on first call.
2. Calls `umem.alloc_frame()` → `None`.
3. Returns `Ok(false)` — every time.

Net effect: the `xdp_send` example, advertised as "TX-only without a BPF program",
silently sends zero packets.

### Plan

**Files:** `src/afxdp/mod.rs`

1. Introduce a mode enum in `src/afxdp/mod.rs`:

   ```rust
   /// Operating mode for an AF_XDP socket.
   ///
   /// Controls how UMEM frames are partitioned between the fill ring (RX) and the
   /// free list (available for TX allocation).
   #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
   pub enum XdpMode {
       /// Receive only. All frames pre-staged to the fill ring.
       Rx,
       /// Transmit only. No prefill — all frames stay in the free list.
       Tx,
       /// Bidirectional. Half the frames prefilled to fill ring, half kept in free list.
       #[default]
       RxTx,
   }
   ```

2. Add to `XdpSocketBuilder`:

   ```rust
   pub fn mode(mut self, mode: XdpMode) -> Self {
       self.mode = mode;
       self
   }
   ```

   Field defaults to `XdpMode::RxTx` to match today's intent.

3. Replace prefill block in `build()` with:

   ```rust
   let prefill = match self.mode {
       XdpMode::Tx => 0,
       XdpMode::Rx => umem.available().min(ring_size as usize),
       XdpMode::RxTx => (umem.available() / 2).min(ring_size as usize),
   } as u32;

   if prefill > 0 {
       if let Some(idx) = fill.producer_reserve(prefill) {
           let mut written = 0u32;
           for i in 0..prefill {
               match umem.alloc_frame() {
                   Some(addr) => { unsafe { fill.write_desc(idx + i, addr) }; written += 1; }
                   None => break,
               }
           }
           if written > 0 { fill.producer_submit(written); }
       }
   }
   ```

4. Document the `frame_count` sizing implication on `XdpSocketBuilder::frame_count`:
   for `RxTx`, configure `frame_count >= 2 * desired_inflight_per_direction`.

5. Re-export `XdpMode` from `src/lib.rs` alongside `XdpSocket` and `XdpSocketBuilder`.

### Tests

- **Unit** (in `src/afxdp/mod.rs`): builder accepts each mode; `validate()` unchanged.
  No socket creation needed — pure builder logic.

- **Integration** (`tests/xdp.rs`, gated `#![cfg(all(feature = "integration-tests", feature = "af-xdp"))]`):

  - `xdp_tx_only_sends`: bind on `lo`, queue 0, `XdpMode::Tx`, send 100 known broadcast
    frames, run a parallel `Capture` on `lo` that filters by a marker payload, assert
    ≥ 50 captured. Marks the bug fixed.
  - `xdp_rxtx_roundtrip`: same setup but `RxTx`; one socket sends, another captures.

  Both tests skip if `lo` does not support AF_XDP (some kernels/configs). Use a small
  helper `xdp_compatible_iface()` that tries `bind` and skips on `EOPNOTSUPP`.

### Migration

Non-breaking. Existing users get `RxTx` (their previous default); RX-only users see
half their UMEM unused — document the trade-off and recommend `XdpMode::Rx` for
RX-bound workloads.

### Checklist

- [ ] `XdpMode` enum + builder method
- [ ] Mode-aware prefill in `build()`
- [ ] Re-export from `lib.rs`
- [ ] Builder unit test
- [ ] Integration test `xdp_tx_only_sends`
- [ ] Integration test `xdp_rxtx_roundtrip`
- [ ] Update `xdp_send.rs` example to use `.mode(XdpMode::Tx)`
- [ ] CHANGELOG entry under "Fixed" — call out behavior change

---

## Fix #2 — `Bridge::run()` busy-loops at 100 % CPU

### Problem

`src/bridge.rs:101-109` calls `forward_direction` for both A→B and B→A, each using the
non-blocking `rx.next_batch()`. When both rings are empty, control loops back
immediately — CPU pinned at 100 %, no `poll`, no sleep.

### Plan

**Files:** `src/bridge.rs`

1. Add `poll_timeout: Duration` to `BridgeBuilder` and `Bridge` (default 100 ms).
   Builder method:

   ```rust
   pub fn poll_timeout(mut self, timeout: Duration) -> Self {
       self.poll_timeout = timeout;
       self
   }
   ```

2. Replace `run()` body with:

   ```rust
   pub fn run<F>(&mut self, mut filter: F) -> Result<(), Error>
   where
       F: FnMut(&Packet<'_>, BridgeDirection) -> BridgeAction,
   {
       loop {
           let [a_ready, b_ready] = self.poll_both(self.poll_timeout)?;
           if a_ready { self.drain_direction(&mut filter, BridgeDirection::AtoB)?; }
           if b_ready { self.drain_direction(&mut filter, BridgeDirection::BtoA)?; }
       }
   }
   ```

3. New helper `poll_both`:

   ```rust
   fn poll_both(&self, timeout: Duration) -> Result<[bool; 2], Error> {
       use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
       let mut pfds = [
           PollFd::new(self.rx_a.as_fd(), PollFlags::POLLIN),
           PollFd::new(self.rx_b.as_fd(), PollFlags::POLLIN),
       ];
       let pt = PollTimeout::try_from(timeout).unwrap_or(PollTimeout::MAX);
       loop {
           match poll(&mut pfds, pt) {
               Ok(_) => break,
               Err(nix::errno::Errno::EINTR) => continue,
               Err(e) => return Err(Error::Io(e.into())),
           }
       }
       Ok([
           pfds[0].revents().is_some_and(|r| r.contains(PollFlags::POLLIN)),
           pfds[1].revents().is_some_and(|r| r.contains(PollFlags::POLLIN)),
       ])
   }
   ```

4. Rename `forward_direction` to `drain_direction` and have it loop until
   `rx.next_batch()` returns `None`, draining everything queued for that direction
   in one wake-up:

   ```rust
   fn drain_direction<F>(...) -> Result<(), Error> { ... 
       while let Some(batch) = rx.next_batch() {
           for pkt in &batch {
               if filter(&pkt, direction) == BridgeAction::Forward {
                   match tx.allocate(pkt.len()) {
                       Some(mut slot) => {
                           slot.data_mut()[..pkt.len()].copy_from_slice(pkt.data());
                           slot.set_len(pkt.len());
                           slot.send();
                       }
                       None => {
                           tracing::debug!("TX ring saturated dropping pkt len={}", pkt.len());
                       }
                   }
               }
           }
           tx.flush()?;
       }
       Ok(())
   }
   ```

5. `run_iterations(n, …)` becomes:

   ```rust
   for _ in 0..n {
       let [a, b] = self.poll_both(self.poll_timeout)?;
       if a { self.drain_direction(&mut filter, BridgeDirection::AtoB)?; }
       if b { self.drain_direction(&mut filter, BridgeDirection::BtoA)?; }
   }
   ```

### Tests

- Integration (`tests/bridge.rs`, gated `integration-tests`, requires two veth ends —
  see `tests/helpers.rs` extension):
  - `bridge_idle_does_not_busy_loop`: build a bridge on a paired veth, call
    `run_iterations(50, ...)` with no traffic; measure thread CPU time via
    `getrusage(RUSAGE_THREAD)` before/after; assert < 50 ms of CPU consumed across
    50 × 100 ms iterations.
  - `bridge_forwards_known_payload`: send 10 UDP packets through the bridge,
    assert all 10 emerge on the far end with payload intact.

  veth helper:
  ```rust
  // tests/helpers.rs
  pub fn paired_veth(name_a: &str, name_b: &str) -> Result<(), io::Error> {
      // Creates veth pair via `ip link add A type veth peer B`,
      // brings both up. Returns the names; cleanup is the caller's
      // responsibility (or use a Drop wrapper).
  }
  ```

### Migration

Non-breaking. New `poll_timeout` setter has a sensible default.

### Checklist

- [ ] `poll_timeout` field on `BridgeBuilder`
- [ ] `poll_both` helper
- [ ] `drain_direction` rewrite
- [ ] EINTR handling
- [ ] veth test helper
- [ ] Idle CPU assertion test
- [ ] Forwarding correctness test
- [ ] CHANGELOG entry

---

## Fix #3 — `BatchIter` infinite-duplicate on `tp_next_offset == 0`

### Problem

`src/packet.rs:508-511`:

```rust
if hdr.tp_next_offset != 0 {
    self.current = self.current.map_addr(|a| a + hdr.tp_next_offset as usize);
}
self.remaining -= 1;
```

When `tp_next_offset == 0` (kernel marker for last packet), `current` is **not**
advanced. If `remaining > 1` (e.g., corrupted block, or — as the existing test admits
— a bad synthetic input), the iterator returns the same packet repeatedly. The unit
test `batch_iter_bounds_check_bad_remaining` documents this as "no crash" rather than
asserting correctness.

### Plan

**Files:** `src/packet.rs`

1. Replace the trailing block of `BatchIter::next` with:

   ```rust
   if hdr.tp_next_offset != 0 {
       self.current = self.current.map_addr(|a| a + hdr.tp_next_offset as usize);
       self.remaining -= 1;
   } else {
       // Kernel marker: this was the last packet in the block.
       self.remaining = 0;
   }
   ```

2. Update `size_hint` to reflect that `remaining` is an upper bound only — change to
   `(0, Some(r))` and **remove** `impl ExactSizeIterator`.

3. Rewrite `batch_iter_bounds_check_bad_remaining` to assert exactly one packet:

   ```rust
   #[test]
   fn batch_iter_terminates_on_last_packet_marker() {
       let block = build_synthetic_block(&[b"only one"], ffi::TP_STATUS_USER);
       let mut iter = iter_from_block(&block, 10);  // claim 10, only 1 exists
       let pkt = iter.next().unwrap();
       assert_eq!(pkt.data(), b"only one");
       assert!(iter.next().is_none(), "should terminate after last-packet marker");
   }
   ```

4. Audit callers of `ExactSizeIterator` for `BatchIter` — the only one is
   `Vec::with_capacity(batch.iter().len())`-style usage in `tokio_adapter::recv`.
   That call uses `.iter().map(...).collect()` which works without `ExactSizeIterator`
   but loses the capacity hint. Replace with `Vec::with_capacity(batch.len())` (the
   block-level count, which the kernel guarantees).

### Tests

Already covered by the rewritten unit test. Add one more for the well-formed
multi-packet case to ensure no regression on `remaining` decrement order.

### Migration

`ExactSizeIterator` removal is **technically breaking** if any downstream relies on it.
Mitigation: `PacketBatch::len()` returns the same `u32` (cast to `usize`), and any
consumer can use that. Add a CHANGELOG note. Given pre-1.0 status, not worth a major
bump.

### Checklist

- [ ] Patch `BatchIter::next`
- [ ] Update `size_hint`
- [ ] Remove `ExactSizeIterator` impl
- [ ] Rewrite the misleading test
- [ ] Add multi-packet positive test
- [ ] Update `tokio_adapter::recv` capacity hint
- [ ] CHANGELOG entry under "Fixed"

---

## Fix #4 — Unify `PacketIter` with `BatchIter`

### Problem

`src/capture.rs:357-388` (`PacketIter::next`) re-implements packet-walk logic with a
weaker bounds check than `BatchIter::next`:

| Iterator    | Bounds checked                                   |
|-------------|--------------------------------------------------|
| `BatchIter` | `tpacket_align(sizeof(tpacket3_hdr)) + sizeof(sockaddr_ll)` |
| `PacketIter`| `sizeof(tpacket3_hdr)` only                      |

`Packet::direction()`, `source_ll_addr()`, `ll_protocol()` (`packet.rs:222-251`) all
read from the `sockaddr_ll` placed at `tpacket_align(sizeof(tpacket3_hdr))`. A `Packet`
emitted by `PacketIter` therefore can read `sockaddr_ll` past the bounds-check
guarantee. In practice the kernel always reserves that region, but this is a real
soundness inconsistency relative to the SPEC's invariant #4.

It also duplicates code that must stay in sync with Fix #3.

### Plan

**Files:** `src/capture.rs`

1. Restructure `PacketIter` to delegate to `BatchIter`:

   ```rust
   pub struct PacketIter<'cap> {
       rx: *mut AfPacketRx,
       timeout: Duration,
       batch: Option<ManuallyDrop<PacketBatch<'static>>>,
       iter: Option<BatchIter<'static>>,
       last_error: Option<Error>,    // for Fix #17
       _marker: PhantomData<&'cap mut Capture>,
   }
   ```

2. `next()` body becomes:

   ```rust
   fn next(&mut self) -> Option<Packet<'cap>> {
       loop {
           if let Some(it) = self.iter.as_mut() {
               // SAFETY: 'static lifetime erasure — see PacketBatch transmute below.
               // The iterator's lifetime is tied to the same erased batch.
               match it.next() {
                   Some(pkt) => return Some(unsafe { std::mem::transmute(pkt) }),
                   None => {
                       self.iter = None;
                       if let Some(batch) = self.batch.take() {
                           let _ = ManuallyDrop::into_inner(batch);
                       }
                   }
               }
           }

           // SAFETY: rx is valid for 'cap; no batch is currently live.
           let rx = unsafe { &mut *self.rx };
           match rx.next_batch_blocking(self.timeout) {
               Ok(Some(batch)) => {
                   if batch.is_empty() {
                       drop(batch);
                       continue;
                   }
                   // SAFETY: same as before — the batch's logical lifetime is 'cap;
                   // we erase to 'static so we can store it in the iterator alongside
                   // the BatchIter that borrows from it. Both are dropped together
                   // (in next() above and in PacketIter::drop).
                   let erased: PacketBatch<'static> = unsafe { std::mem::transmute(batch) };
                   let iter: BatchIter<'static> = erased.iter();
                   self.batch = Some(ManuallyDrop::new(erased));
                   self.iter = Some(iter);
               }
               Ok(None) => continue,
               Err(e) => {
                   self.last_error = Some(e);
                   return None;
               }
           }
       }
   }
   ```

3. Add `pub fn take_error(&mut self) -> Option<Error>` (paired with Fix #17 — see
   phase 2).

4. Promote the `'static`-erasure soundness warning from a code comment to public
   rustdoc on `Capture::packets`:

   ```rust
   /// # Soundness note
   ///
   /// Each [`Packet`] borrows from the current ring block. **Do not collect packets
   /// across iterations** (e.g., `cap.packets().collect::<Vec<_>>()`) — the iterator
   /// returns a block to the kernel before yielding packets from the next block, and
   /// any retained `Packet<'_>` from a prior block becomes a dangling reference. Use
   /// [`Packet::to_owned()`] if you need to retain a packet beyond the next iteration.
   ```

5. Remove the now-unused `remaining`, `current_ptr`, `block_end` fields and the
   inline walk code.

### Tests

- Unit tests in `src/capture.rs`:
  - `packets_iterator_yields_all_in_block` — synthetic 3-packet block fed via the
    same `iter_from_block` helper (factor out so it's reusable from both modules).
  - `packets_iterator_calls_direction` — emits packets and calls `pkt.direction()`,
    asserts no out-of-bounds via Miri (`cargo miri test --features tokio,channel`).
- Integration: existing `loopback_capture` tests must pass unchanged.

### Migration

Non-breaking. The new `take_error()` method is additive.

### Checklist

- [ ] Restructure `PacketIter` fields
- [ ] Replace `next()` implementation
- [ ] Add `take_error()`
- [ ] Update `Drop`
- [ ] Promote soundness warning to rustdoc
- [ ] Factor `iter_from_block` test helper
- [ ] Synthetic-block unit test
- [ ] `direction()` Miri assertion
- [ ] Verify `loopback_capture` tests still pass
- [ ] CHANGELOG entry under "Fixed"
