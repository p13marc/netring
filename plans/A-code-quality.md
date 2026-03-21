# Phase A: Code Quality Fixes

## 1. Add `#[inline]` to hot-path accessors

All small methods called per-packet in tight loops:

```
src/packet.rs:
  Packet::data(), len(), is_empty(), original_len(), timestamp()
  Packet::status(), rxhash(), vlan_tci(), vlan_tpid(), from_raw()
  PacketStatus::from_raw()
  PacketBatch::len(), is_empty()
  Timestamp::new(), to_system_time(), to_duration()
  BatchIter::next()

src/afpacket/ring.rs:
  read_block_status(), release_block(), MmapRing::block_ptr()

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
```

## 4. Extract frame_size validator

Both `AfPacketRxBuilder::build()` and `AfPacketTxBuilder::build()` validate:
- frame_size multiple of TPACKET_ALIGNMENT
- frame_size >= TPACKET3_HDRLEN

Extract into `src/afpacket/mod.rs`:
```rust
pub(crate) fn validate_frame_size(frame_size: usize) -> Result<(), Error>
```

## 5. Document TxSlot::set_len panic

The `assert!` in `set_len()` is intentional (like `Vec::index`).
Add a note to the `# Panics` section explaining why: frame capacity is
known at allocate time, so exceeding it is a programming error.

## 6. Migrate `log` → `tracing`

Replace `log = "0.4"` with `tracing = { version = "0.1", default-features = false, features = ["std"] }`.

The Rust ecosystem has converged on `tracing`. Benefits:
- Structured fields: `tracing::warn!(block_index = idx, expected = exp, "sequence gap")`
- Span context (interface name, fanout group) propagates automatically
- Zero-cost when no subscriber installed (same as `log`)
- Backward-compatible: `tracing` emits `log` records by default

Migration is trivial — only a handful of `log::warn!` calls in:
- `src/afpacket/ring.rs` (MAP_LOCKED fallback)
- `src/afpacket/rx.rs` (sequence gap detection)
- `src/capture.rs` (ENOMEM retry)
- `src/packet.rs` (BatchIter bounds violations)

Change each `log::warn!(...)` to `tracing::warn!(...)` with structured fields.

## 7. Add `etherparse` integration (feature: `parse`)

Add optional dependency:
```toml
[features]
parse = ["dep:etherparse"]

[dependencies]
etherparse = { version = "0.16", optional = true }
```

Add to `src/packet.rs`:
```rust
#[cfg(feature = "parse")]
impl<'a> Packet<'a> {
    /// Parse Ethernet/IP/TCP/UDP headers from packet data.
    ///
    /// Uses `etherparse::SlicedPacket` for zero-copy parsing directly
    /// from the mmap ring buffer.
    pub fn parse(&self) -> Result<etherparse::SlicedPacket<'a>, etherparse::err::packet::SliceError> {
        etherparse::SlicedPacket::from_ethernet(self.data)
    }
}

#[cfg(feature = "parse")]
impl OwnedPacket {
    /// Parse Ethernet/IP/TCP/UDP headers from owned packet data.
    pub fn parse(&self) -> Result<etherparse::SlicedPacket<'_>, etherparse::err::packet::SliceError> {
        etherparse::SlicedPacket::from_ethernet(&self.data)
    }
}
```

Keep `etherparse = "0.16"` in dev-dependencies for the `dpi.rs` example regardless.

## 8. Add `core_affinity` dev-dependency

```toml
[dev-dependencies]
core_affinity = "0.8"
```

Update `examples/fanout.rs` to pin threads to CPUs:
```rust
core_affinity::set_for_current(core_affinity::CoreId { id: i });
```

## Verification

```bash
cargo clippy --all-targets --all-features -- --deny warnings
cargo test --features tokio,channel,parse
cargo build --examples --features tokio,channel
```
