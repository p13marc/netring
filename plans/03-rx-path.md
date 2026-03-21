# Phase 3: RX Path — AfPacketRx, PacketBatch, Packet, BatchIter

## Goal

Implement the complete receive path: the `PacketSource` trait, zero-copy `Packet<'a>`,
RAII `PacketBatch<'a>` with block return on drop, `BatchIter` with bounds-checked
pointer walking, and `AfPacketRx` with builder and poll algorithm.

## Prerequisites

Phases 1-2 complete.

## Lifetime Model

```
AfPacketRx (owns fd + ring)
    │
    │ next_batch(&'a mut self) → PacketBatch<'a>
    │   (&mut self held for 'a — only one batch at a time)
    │
    └── PacketBatch<'a> (NonNull<block>, &'a MmapRing)
            │
            │ iter(&self) → BatchIter<'a>
            │
            └── Packet<'a> (&'a [u8], &'a tpacket3_hdr)
                    │
                    └── to_owned() → OwnedPacket (escapes ring)
```

**Key**: `&mut self` on `next_batch` prevents calling it again until the batch is dropped.
`PacketBatch::Drop` writes `TP_STATUS_KERNEL` to return block to kernel.

## Files

### src/traits.rs (new)

```rust
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be used as a packet source",
    label = "does not implement `PacketSource`",
    note = "use `AfPacketRx` or implement this trait for your backend"
)]
pub trait PacketSource: AsFd {
    fn next_batch(&mut self) -> Option<PacketBatch<'_>>;
    fn next_batch_blocking(&mut self, timeout: Duration) -> Result<Option<PacketBatch<'_>>, Error>;
    fn stats(&self) -> Result<CaptureStats, Error>;
}
```

### src/packet.rs (extend — add Packet, PacketBatch, BatchIter)

**Packet<'a>:**
- Fields: `data: &'a [u8]`, `hdr: &'a tpacket3_hdr`
- Methods: `data()`, `timestamp()`, `len()`, `original_len()`, `status()`, `rxhash()`, `vlan_tci()`, `vlan_tpid()`, `to_owned()`, `is_empty()`
- Constructor: `pub(crate) unsafe fn new(...)` — not public

**PacketBatch<'a>:**
- Fields: `block: NonNull<tpacket_block_desc>`, `ring: &'a MmapRing`, cached header fields (`block_status`, `num_pkts`, `seq_num`, `ts_first`, `ts_last`, `offset_to_first_pkt`, `blk_len`)
- Methods: `len()`, `is_empty()`, `timed_out()`, `seq_num()`, `ts_first()`, `ts_last()`, `iter()`
- Constructor: `pub(crate) unsafe fn new(block, ring) -> Self` — reads and caches header fields
- `IntoIterator for &'a PacketBatch<'a>`: delegates to `iter()`
- `Drop`: calls `release_block(self.block)` — Release store of TP_STATUS_KERNEL

**BatchIter<'a>:**
- Fields: `current: *const u8`, `remaining: u32`, `block_end: *const u8`, `PhantomData<&'a ()>`
- `Iterator for BatchIter<'a>` with `type Item = Packet<'a>`
- `ExactSizeIterator` (size_hint from remaining)

**next() algorithm:**
1. If `remaining == 0`, return None
2. Bounds check: `current + size_of::<tpacket3_hdr>() <= block_end`
3. Cast `current` to `&'a tpacket3_hdr` (unsafe, TPACKET_ALIGNMENT guarantees alignment)
4. Compute `data_ptr = current.map_addr(|a| a + tp_mac as usize)`
5. Bounds check: `data_ptr + tp_snaplen <= block_end`
6. Construct `&'a [u8]` via `from_raw_parts`
7. Advance: if `tp_next_offset != 0`, `current = current.map_addr(|a| a + tp_next_offset)`
8. Decrement remaining
9. Return `Some(Packet { data, hdr })`

### src/afpacket/rx.rs (new)

**AfPacketRx:**
```rust
pub struct AfPacketRx {
    ring: MmapRing,       // dropped first (munmap)
    fd: OwnedFd,          // dropped second (close)
    current_block: usize,
    expected_seq: u64,
}
```

- `unsafe impl Send for AfPacketRx {}` — owns all resources exclusively
- `impl AsFd` — delegates to `self.fd`
- `pub fn builder() -> AfPacketRxBuilder`
- `pub unsafe fn ring_ptr(&self) -> *const u8`
- `pub fn ring_len(&self) -> usize`

**PacketSource impl:**
- `next_batch()`: read_block_status(Acquire), check TP_STATUS_USER, log sequence gaps, construct PacketBatch, advance cursor
- `next_batch_blocking(timeout)`: try next_batch, if None → nix::poll::poll with POLLIN, try again
- `stats()`: getsockopt(PACKET_STATISTICS) → CaptureStats

**AfPacketRxBuilder:**
- All fields with defaults (4 MiB blocks, 64 count, 2048 frame, 60ms timeout)
- Consuming builder methods: interface, block_size, block_count, frame_size, block_timeout_ms, promiscuous, ignore_outgoing, busy_poll_us, timestamp_source, fanout, fanout_flags, bpf_filter
- `build()`:
  1. Validate config (power-of-2, alignment, frame_nr calculation)
  2. create_packet_socket()
  3. set_packet_version()
  4. set_rx_ring(&tpacket_req3)
  5. MmapRing::new()
  6. bind_to_interface()
  7. Optional: promiscuous, ignore_outgoing, busy_poll, timestamp, fanout, bpf_filter
  8. Return AfPacketRx

### src/afpacket/mod.rs (modify)

Add `pub mod rx;`, re-export `AfPacketRx`, `AfPacketRxBuilder`

### src/lib.rs (modify)

Add `pub mod traits;`, re-export `PacketSource`, `Packet`, `PacketBatch`, `AfPacketRx`

## Testing

**Unit tests:**
- Synthetic block builder helper: `build_synthetic_block(packets)` → `Vec<u8>`
- BatchIter: single packet, multiple packets, empty block, bad tp_next_offset, bad tp_snaplen
- PacketStatus from_raw for each flag combination
- Packet::to_owned round-trip
- Batch timed_out flag, seq_num, timestamps

**Integration tests (CAP_NET_RAW):**
- Capture on loopback: send UDP, verify next_batch returns packets with correct data
- Block timeout: short timeout, 1 packet, verify timed_out()

## Potential Challenges

1. **Union access**: `tpacket_block_desc.hdr.bh1.block_status` traverses a union — requires `addr_of!` pattern
2. **Poll timeout conversion**: `Duration::as_millis() → u128`, clamp to `i32::MAX` for nix::poll
3. **Alignment assertion**: debug_assert packet headers are 16-byte aligned
4. **`offset_of!` for nested union fields**: use `addr_of!` on raw pointer instead
