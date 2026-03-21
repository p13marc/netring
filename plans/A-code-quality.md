# Phase A: Code Quality Fixes

## 1. Add `#[inline]` to hot-path accessors

All small methods called per-packet in tight loops:

```
src/packet.rs:
  Packet::data()
  Packet::len()
  Packet::is_empty()
  Packet::original_len()
  Packet::timestamp()
  Packet::status()
  Packet::rxhash()
  Packet::vlan_tci()
  Packet::vlan_tpid()
  Packet::from_raw()
  PacketStatus::from_raw()
  PacketBatch::len()
  PacketBatch::is_empty()
  Timestamp::new()
  Timestamp::to_system_time()
  Timestamp::to_duration()
  BatchIter::next()

src/afpacket/ring.rs:
  read_block_status()
  release_block()
  MmapRing::block_ptr()

src/afpacket/ffi.rs:
  tpacket_align()
```

## 2. Safety comment on PacketIter transmute

Location: `src/capture.rs` — the `transmute` erasing `PacketBatch<'_>` to `PacketBatch<'static>`.

Add a detailed `// SAFETY:` comment explaining:
- The mmap region is valid for `'cap` (owned by Capture)
- The block is only released when we call `ManuallyDrop::into_inner`
- The PhantomData<&'cap mut Capture> tracks the borrow
- Collecting packets across block boundaries is documented as unsound
- This exists because LendingIterator is not stabilized

## 3. Fix TX block_size calculation

Location: `src/afpacket/tx.rs` `AfPacketTxBuilder::build()`

Current logic can overshoot 2x (e.g. frame_size=3000 → block_size=16384 instead of 4096).

Fix: compute the smallest power-of-2 that is >= PAGE_SIZE and >= frame_size:
```rust
let block_size = frame_size.next_power_of_two().max(page_size);
// Each "block" holds exactly 1 frame when block_size == frame_size rounded up
```

This is simpler and wastes less memory.

## 4. Extract frame_size validator

Both `AfPacketRxBuilder::build()` and `AfPacketTxBuilder::build()` validate:
- frame_size multiple of TPACKET_ALIGNMENT
- frame_size >= TPACKET3_HDRLEN

Extract into a shared helper:
```rust
// src/afpacket/mod.rs or a new src/afpacket/validate.rs
pub(crate) fn validate_frame_size(frame_size: usize) -> Result<(), Error>
```

## 5. Document TxSlot::set_len panic

The `assert!` in `set_len()` is an intentional API choice (like `Vec::index`).
Add a `# Panics` section (already exists) and add a note explaining WHY it panics
instead of returning Result: frame capacity is known at allocate time, so exceeding
it is a programming error, not a runtime condition.

## Verification

```bash
cargo clippy --all-targets --all-features -- --deny warnings
cargo test --features tokio,channel
```
