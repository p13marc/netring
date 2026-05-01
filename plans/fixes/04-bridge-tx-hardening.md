# Phase 4 — Bridge & TX hardening

Improvements to `Bridge` flexibility, `AfPacketTx` cursor handling, and
`ChannelCapture` shutdown.

---

## Fix #15 — Bridge silently drops jumbo frames

### Problem

`src/bridge.rs:266-285`: bridge TX builders use `frame_size = fs` (from the chosen
`RingProfile`). Default is 2048. If `RingProfile::JumboFrames` is selected, the RX
side captures 64 KiB but the TX side stays at 2048. A 9000-byte received packet
calls `tx.allocate(9000)` → `None`, and the diagnostic log misclassifies the
failure ("TX ring full" — `bridge.rs:146`).

### Plan

**Files:** `src/bridge.rs`, `src/afpacket/tx.rs`

1. In `BridgeBuilder::build`, derive TX `frame_size` from RX:

   ```rust
   let (rx_block_size, rx_block_count, rx_frame_size, rx_timeout) = self.profile.params();
   // TX frames must accommodate the largest packet we might receive — match RX.
   let tx_frame_size = rx_frame_size;
   ```

2. (Bundled with #34) expose individual setters so users can override:

   ```rust
   pub fn tx_frame_size(mut self, bytes: usize) -> Self { self.tx_frame_size = Some(bytes); self }
   ```

3. Update the drop log in `bridge.rs:146` to distinguish cause:

   ```rust
   if let Some(mut slot) = tx.allocate(pkt.len()) {
       slot.data_mut()[..pkt.len()].copy_from_slice(pkt.data());
       slot.set_len(pkt.len());
       slot.send();
   } else if pkt.len() > tx.frame_capacity() {
       tracing::warn!(
           pkt_len = pkt.len(),
           tx_frame = tx.frame_capacity(),
           "Bridge: dropping packet — TX frame size too small"
       );
       self.stats_dropped_too_large += 1;
   } else {
       tracing::debug!(pkt_len = pkt.len(), "Bridge: dropping packet — TX ring full");
       self.stats_dropped_ring_full += 1;
   }
   ```

   This requires:
   - New public method on `AfPacketTx`:
     ```rust
     pub fn frame_capacity(&self) -> usize { self.frame_size - self.data_offset }
     ```
   - New fields on `Bridge` to track these counters; expose in `BridgeStats`.

4. Extend `BridgeStats`:

   ```rust
   pub struct BridgeStats {
       pub a_to_b: CaptureStats,
       pub b_to_a: CaptureStats,
       pub a_to_b_dropped_too_large: u64,
       pub a_to_b_dropped_ring_full: u64,
       pub b_to_a_dropped_too_large: u64,
       pub b_to_a_dropped_ring_full: u64,
   }
   ```

### Tests

Unit: `BridgeStats::default()` zeros; arithmetic.

Integration (`tests/bridge.rs`):
- `bridge_drops_oversize_increments_stat` — set up a paired veth bridge with
  `tx_frame_size(1024)`, send a 1500-byte packet, assert
  `bridge.stats().a_to_b_dropped_too_large == 1`.

### Checklist
- [ ] `AfPacketTx::frame_capacity`
- [ ] Bridge derives TX frame size from profile
- [ ] Drop classification + counters
- [ ] Extend `BridgeStats`
- [ ] Update Display impl
- [ ] Integration test
- [ ] CHANGELOG entry under "Fixed" (jumbo) and "Added" (drop stats)

---

## Fix #20 — TX cursor inefficiency + `WRONG_FORMAT` invisibility

### Problem

`src/afpacket/tx.rs:169`: `current_frame = (current_frame + 1) % frame_count` runs
on every `allocate()` even if the resulting `TxSlot` is dropped without `send()`.
The slot's status correctly reverts to AVAILABLE in `Drop`, but the cursor has
moved on, leaving the hole until the next wrap.

Additionally: if the kernel sets `TP_STATUS_WRONG_FORMAT` on a frame, `allocate()`
will see "not AVAILABLE" and return `None`. The user has no signal that this
happened — they just see "ring full" when really it's a rejected frame.

### Plan

**Files:** `src/afpacket/tx.rs`

1. Add a hint to `TxSlot::Drop` for cursor rewind:

   ```rust
   pub struct TxSlot<'a> {
       frame_ptr: NonNull<u8>,
       data_offset: usize,
       max_len: usize,
       len: usize,
       sent: bool,
       cursor_was_advanced_to: usize,  // the index *after* this slot's index
       cursor: &'a mut usize,           // pointer to AfPacketTx::current_frame
       pending: &'a mut u32,
   }

   impl Drop for TxSlot<'_> {
       fn drop(&mut self) {
           if !self.sent {
               // Reset frame status to AVAILABLE.
               let status_ptr = self.frame_ptr.as_ptr().cast::<AtomicU32>();
               unsafe { &*status_ptr }.store(ffi::TP_STATUS_AVAILABLE, Ordering::Release);

               // Rewind cursor IF it hasn't been advanced past us by another allocation.
               // (Allocation always increments by 1, so if cursor == cursor_was_advanced_to
               // this slot was the most recent one and we can reclaim it.)
               if *self.cursor == self.cursor_was_advanced_to {
                   // Move cursor back by 1, modulo frame_count.
                   // Need frame_count — pass it in or compute via cursor_was_advanced_to - 1.
                   // Easier: store the original index instead of "advanced to".
               }
           }
       }
   }
   ```

   Realistically the rewind logic gets fiddly with concurrent slot drops. Simpler:
   leave the hole, but make `allocate()` smarter by scanning forward up to
   `frame_count` slots looking for the next AVAILABLE one (with an upper bound to
   keep allocate O(1) on the happy path):

   ```rust
   pub fn allocate(&mut self, len: usize) -> Option<TxSlot<'_>> {
       if len > self.frame_size - self.data_offset { return None; }

       // Scan up to frame_count slots for the next AVAILABLE.
       let mut wrong_format_count = 0;
       for _ in 0..self.frame_count {
           let status = self.read_frame_status(self.current_frame);
           match status {
               ffi::TP_STATUS_AVAILABLE => {
                   let slot = TxSlot { /* ... */ };
                   self.current_frame = (self.current_frame + 1) % self.frame_count;
                   return Some(slot);
               }
               ffi::TP_STATUS_WRONG_FORMAT => {
                   wrong_format_count += 1;
                   // Reset rejected slot back to AVAILABLE so it's reusable.
                   self.reset_slot(self.current_frame);
                   self.current_frame = (self.current_frame + 1) % self.frame_count;
               }
               _ => break, // SEND_REQUEST or SENDING — wait, ring is full
           }
       }
       if wrong_format_count > 0 {
           tracing::warn!(count = wrong_format_count, "AF_PACKET TX: kernel rejected frames (WRONG_FORMAT) — check packet contents");
       }
       None
   }

   fn reset_slot(&self, idx: usize) {
       let ptr = self.frame_ptr(idx).as_ptr().cast::<AtomicU32>();
       unsafe { &*ptr }.store(ffi::TP_STATUS_AVAILABLE, Ordering::Release);
   }
   ```

2. This eats both bugs at once: dropped slots get reused on the next alloc-scan;
   wrong-format slots get logged and reset.

3. Pair with `AfPacketTx::rejected_slots()` from Fix #9 so users can query the
   cumulative count.

### Tests

- Unit: synthetic ring with all slots AVAILABLE, allocate `frame_count` times,
  assert all return `Some`.
- Unit: synthetic ring with one slot in `WRONG_FORMAT`, allocate, assert it gets
  reset and the alloc succeeds for the next slot.
- Integration: existing inject tests should still pass.

### Migration

Behavioral change: `allocate()` may now scan more than 1 slot. Worst-case O(N) but
typical O(1). Document.

### Checklist
- [ ] `allocate()` scan-forward implementation
- [ ] `reset_slot` helper
- [ ] Tracing for WRONG_FORMAT
- [ ] Unit tests for both new branches
- [ ] CHANGELOG entry under "Fixed"

---

## Fix #24 — `ChannelCapture` data loss on shutdown

### Problem

`src/async_adapters/channel.rs:56-72`: the worker thread checks `stop` only at the
top of the loop. `next_batch_blocking(100ms)` may already be waiting; shutdown is
delayed up to 100 ms. Packets in the channel after the user's last `recv()` are
dropped on `Drop` because the channel is dropped along with the receiver.

### Plan

**Files:** `src/async_adapters/channel.rs`

1. Use a smaller poll timeout in the worker (10 ms) so shutdown is more responsive:

   ```rust
   while !stop_clone.load(Ordering::Relaxed) {
       match rx.next_batch_blocking(Duration::from_millis(10)) {
           ...
       }
   }
   ```

2. Add explicit drain semantics:

   ```rust
   /// Stop the capture thread and drain remaining packets from the channel.
   ///
   /// Returns all packets buffered in the channel at the moment the capture
   /// thread exited. Use this instead of relying on `Drop` if you need to
   /// process trailing packets.
   pub fn stop_and_drain(mut self) -> Vec<OwnedPacket> {
       self.stop.store(true, Ordering::Relaxed);
       if let Some(handle) = self.handle.take() {
           let _ = handle.join();
       }
       let mut drained = Vec::new();
       while let Ok(pkt) = self.receiver.try_recv() {
           drained.push(pkt);
       }
       drained
   }
   ```

3. Document `Drop` clearly:

   ```rust
   /// # Drop semantics
   ///
   /// On drop, the capture thread is signaled to stop and joined. Any packets
   /// still buffered in the channel are discarded. Use [`stop_and_drain()`]
   /// instead if you need to process trailing packets.
   ```

### Tests

Unit (no-priv-needed via mock backend, or integration via `lo`):
- `stop_and_drain_returns_buffered` — capture some packets, sleep briefly,
  `stop_and_drain()`, assert the returned vec is non-empty when traffic was active.

### Checklist
- [ ] Reduce worker poll timeout to 10 ms
- [ ] `stop_and_drain` method
- [ ] Drop docstring
- [ ] Test with `lo` helper
- [ ] CHANGELOG entry under "Added"

---

## Fix #34 — `BridgeBuilder` ring-tuning expressiveness

### Problem

`BridgeBuilder` exposes only `profile`, `promiscuous`, `qdisc_bypass`. Users who
need:
- Asymmetric A/B profiles
- BPF filters per direction
- Different `block_timeout_ms` per direction
- TX qdisc settings without RX promiscuous
- Custom `frame_size` with non-default `block_count`

…must drop down to manual `AfPacketRx` + `AfPacketTx` plumbing.

### Plan

**Files:** `src/bridge.rs`

1. Replace the single `profile` with per-direction overrides:

   ```rust
   pub struct BridgeBuilder {
       interface_a: Option<String>,
       interface_b: Option<String>,
       // Default profile applied to both directions; individual setters override.
       profile: RingProfile,
       // Per-direction overrides, all Optional so None = inherit from profile
       a_block_size: Option<usize>,
       a_block_count: Option<usize>,
       a_frame_size: Option<usize>,
       a_block_timeout_ms: Option<u32>,
       a_bpf_filter: Option<Vec<BpfInsn>>,
       a_promiscuous: bool,
       b_block_size: Option<usize>,
       b_block_count: Option<usize>,
       b_frame_size: Option<usize>,
       b_block_timeout_ms: Option<u32>,
       b_bpf_filter: Option<Vec<BpfInsn>>,
       b_promiscuous: bool,
       // TX
       tx_a_frame_size: Option<usize>,
       tx_b_frame_size: Option<usize>,
       tx_a_frame_count: Option<usize>,
       tx_b_frame_count: Option<usize>,
       qdisc_bypass: bool,
       // Bridge-level
       poll_timeout: Duration,
   }
   ```

2. Builder methods follow the pattern `a_block_size`, `b_block_size`, …. Add a
   higher-level convenience:

   ```rust
   /// Apply the same per-direction config as if you set both sides independently.
   pub fn both_block_size(self, sz: usize) -> Self {
       self.a_block_size(sz).b_block_size(sz)
   }
   ```

3. In `build()`, resolve effective values:

   ```rust
   let (default_bs, default_bc, default_fs, default_to) = self.profile.params();
   let a_bs = self.a_block_size.unwrap_or(default_bs);
   // ... etc
   ```

4. Write the tests for #15 against the new API.

### Tests

- Unit: builder with asymmetric settings produces an `AfPacketRxBuilder` /
  `AfPacketTxBuilder` with the expected fields. Factor out the resolution into a
  pure function for testability.

### Migration

Non-breaking. Existing `profile`, `promiscuous`, `qdisc_bypass` setters remain.

### Checklist
- [ ] Field expansion on `BridgeBuilder`
- [ ] Per-direction setters
- [ ] `both_*` convenience setters
- [ ] Resolution logic in `build()`
- [ ] Builder unit tests
- [ ] CHANGELOG entry under "Added"

---

## Fix #35 — `Bridge::into_inner` for advanced use

### Problem

Once a `Bridge` is built, the user has no access to the underlying `AfPacketRx`
and `AfPacketTx` handles. Advanced use cases (custom forwarding logic, eBPF
attachment to one side only, partial shutdown) require this access.

### Plan

**Files:** `src/bridge.rs`

```rust
/// The four backend handles that make up a [`Bridge`].
pub struct BridgeHandles {
    pub rx_a: AfPacketRx,
    pub tx_b: AfPacketTx,
    pub rx_b: AfPacketRx,
    pub tx_a: AfPacketTx,
}

impl Bridge {
    /// Decompose into the four backend handles.
    ///
    /// Useful for attaching eBPF programs, taking custom forwarding paths, or
    /// shutting down one direction independently. After this call, the bridge
    /// no longer drives forwarding — the caller is responsible.
    pub fn into_inner(self) -> BridgeHandles {
        BridgeHandles {
            rx_a: self.rx_a, tx_b: self.tx_b, rx_b: self.rx_b, tx_a: self.tx_a,
        }
    }

    /// Borrow the underlying handles for inspection / fd extraction.
    pub fn handles(&self) -> (&AfPacketRx, &AfPacketTx, &AfPacketRx, &AfPacketTx) {
        (&self.rx_a, &self.tx_b, &self.rx_b, &self.tx_a)
    }
}
```

### Tests

Unit: build a `Bridge`, decompose, assert the handles have the right fds (compare
`as_fd()` consistency).

### Checklist
- [ ] `BridgeHandles` struct
- [ ] `Bridge::into_inner`
- [ ] `Bridge::handles`
- [ ] Unit test
- [ ] CHANGELOG entry under "Added"
