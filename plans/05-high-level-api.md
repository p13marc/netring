# Phase 5: High-Level API — Capture, CaptureBuilder, Flat Iterator

## Goal

Implement the ergonomic high-level API: `Capture::builder().interface("eth0").build()?`
with a flat `packets()` iterator that hides block management, plus ENOMEM retry logic.

## Prerequisites

Phases 1-4 complete.

## Files

### src/capture.rs (new)

**Capture:**
```rust
pub struct Capture {
    rx: AfPacketRx,
    timeout: Duration,
}
```

- `new(interface: &str) -> Result<Self>` — shorthand for builder().interface(name).build()
- `builder() -> CaptureBuilder`
- `packets(&mut self) -> impl Iterator<Item = Packet<'_>>` — flat blocking iterator
- `stats(&self) -> Result<CaptureStats>`
- `into_inner(self) -> AfPacketRx`
- `impl AsFd` — delegates to rx

**CaptureBuilder:**
- Fields with defaults matching spec: block_size (4 MiB), block_count (64), frame_size (2048), block_timeout_ms (60), poll_timeout (100ms), promiscuous (false), ignore_outgoing (false), etc.
- All consuming builder methods (`#[must_use]`)
- `build()`:
  1. **Validate**: block_size power-of-2 + PAGE_SIZE multiple, frame_size alignment, frame_size >= TPACKET3_HDRLEN
  2. **ENOMEM retry loop**: attempt AfPacketRxBuilder::build(). On ENOMEM, shrink block_count by 25%, retry. Stop at 25% of original. Log each retry.
  3. Return `Capture { rx, timeout: poll_timeout }`

## The Flat Iterator Challenge

### Problem

`Packet<'a>` borrows from `PacketBatch<'a>` which borrows from `&'a mut AfPacketRx`.
The flat iterator must own the current batch AND hold `&mut AfPacketRx` in the same struct.
This is self-referential — standard Rust cannot express it safely.

### Solution: Raw Pointer + Lazy Block Release

```rust
pub struct PacketIter<'cap> {
    rx: *mut AfPacketRx,
    timeout: Duration,
    batch: Option<ManuallyDrop<PacketBatch<'static>>>,  // lifetime-erased
    batch_remaining: u32,
    next_packet_ptr: *const u8,
    block_end: *const u8,
    _marker: PhantomData<&'cap mut Capture>,
}
```

**next() algorithm:**
1. If `batch_remaining > 0`: construct `Packet<'cap>` from `next_packet_ptr`, advance pointer, decrement remaining, return packet
2. If batch exhausted: drop batch (ManuallyDrop::drop → release_block), set to None
3. Loop: call `(*self.rx).next_batch_blocking(timeout)`. On Ok(Some(batch)), store with erased lifetime, init pointers. Go to step 1. On Ok(None), retry. On Err, return None.

**Safety argument:**
- Raw pointer derived from `&'cap mut Capture.rx`, valid for `'cap`
- Only dereferenced when `self.batch` is None (no outstanding borrows)
- `PhantomData<&'cap mut Capture>` tracks the borrow
- NOT Send or Sync (raw pointer)

**Practical safety:** Designed for `for pkt in cap.packets()` usage where each packet is consumed within the loop body before `next()` is called again. The block containing the previously yielded packet is released at the START of the next `next()` call. Documented that collecting packets across block boundaries is unsound.

**Drop for PacketIter:** drops any remaining batch.

### Alternative for Simple Use Cases

For users who want guaranteed safety, document using the low-level API:
```rust
while let Some(batch) = rx.next_batch_blocking(timeout)? {
    for pkt in &batch {
        // fully safe — batch lifetime is explicit
    }
}
```

### src/lib.rs (modify)

Add `pub mod capture;`, re-export `Capture`, `CaptureBuilder`

## Testing

**Unit tests:**
- Builder validation: all invalid config combos return Error::Config
- Builder defaults match spec values
- ENOMEM retry: mock construction that fails with ENOMEM, verify shrink progression

## Potential Challenges

1. **Streaming iterator**: Standard `Iterator` cannot express lending/streaming semantics. The unsafe approach with lifetime erasure is the pragmatic choice. Document the contract clearly.
2. **ENOMEM detection**: Must match `Error::Mmap(io_err)` where `io_err.raw_os_error() == Some(ENOMEM)`. May also need to handle the error from `setsockopt(PACKET_RX_RING)` which fails with ENOMEM before mmap.
3. **Poll timeout for PAGE_SIZE**: Use `nix::unistd::sysconf(SysconfVar::PAGE_SIZE)` or hardcode 4096 with runtime assert.
