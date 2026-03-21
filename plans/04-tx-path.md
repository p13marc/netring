# Phase 4: TX Path — AfPacketTx, TxSlot, PacketSink, Injector

## Goal

Implement the transmit path using TPACKET_V3 TX (which uses V1 frame-based semantics).

## Prerequisites

Phases 1-2 complete. Phase 3 not strictly required but traits.rs should exist.

## Key Difference: TX Uses V1 Frame-Based Semantics

Unlike RX (block-based), TX is a flat array of fixed-size frames:
- User walks frames by index with `frame_size` stride
- Each frame has a `tpacket_hdr` (V1-style) at its start
- Frame status flow: `TP_STATUS_AVAILABLE (0) → user writes → TP_STATUS_SEND_REQUEST (1) → kernel sends → TP_STATUS_AVAILABLE (0)`
- `sendto(fd, NULL, 0, 0, NULL, 0)` kicks kernel to process pending frames

## Files

### src/afpacket/ffi.rs (modify — add TX constants)

- `TP_STATUS_AVAILABLE: u32 = 0`
- `TP_STATUS_SEND_REQUEST: u32 = 1`
- `TP_STATUS_SENDING: u32 = 2` (transient kernel state)
- `TP_STATUS_WRONG_FORMAT: u32 = 4`
- V1 `tpacket_hdr` struct (re-export from libc or define if missing)

### src/traits.rs (modify — add PacketSink)

```rust
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be used as a packet sink",
    note = "use `AfPacketTx` or implement this trait"
)]
pub trait PacketSink: AsFd {
    fn allocate(&mut self, len: usize) -> Option<TxSlot<'_>>;
    fn flush(&mut self) -> Result<usize, Error>;
}
```

### src/afpacket/tx.rs (new)

**TxSlot<'a>:**
- Fields: `frame_ptr: NonNull<u8>`, `data_offset: usize`, `max_len: usize`, `len: usize`, `sent: bool`, `pending: &'a mut u32`
- `data_mut(&mut self) -> &mut [u8]` — mutable slice over packet data region
- `set_len(&mut self, len: usize)` — panics if len > max_len
- `send(mut self)` — writes tp_len/tp_snaplen/tp_mac to tpacket_hdr, stores TP_STATUS_SEND_REQUEST (Release), increments pending
- `Drop`: if !sent, writes TP_STATUS_AVAILABLE (Release) to reclaim frame

**AfPacketTx:**
```rust
pub struct AfPacketTx {
    ring: MmapRing,        // dropped first
    fd: OwnedFd,           // dropped second
    current_frame: usize,
    frame_count: usize,
    frame_size: usize,
    data_offset: usize,    // TPACKET_ALIGN(sizeof(tpacket_hdr))
    pending: u32,
}
```

- `unsafe impl Send` — owns all resources
- `impl AsFd` — delegates to fd
- `frame_ptr(index) -> NonNull<u8>` — strict provenance
- `read_frame_status(index) -> u32` — AtomicU32 Acquire load
- `Drop`: best-effort `flush()` before ring unmap

**PacketSink impl:**
- `allocate(len)`: check len fits, check frame status is AVAILABLE, construct TxSlot, advance cursor
- `flush()`: if pending > 0, `libc::sendto(fd, null, 0, 0, null, 0)`, reset pending, return count

**AfPacketTxBuilder:**
- Fields: interface, frame_size (default 2048), frame_count (default 256), qdisc_bypass
- `build()`:
  1. Validate config
  2. Compute tpacket_req3 (block_size = next power-of-2 >= PAGE_SIZE that divides frame_size)
  3. create_packet_socket()
  4. set_packet_version()
  5. set_tx_ring()
  6. MmapRing::new()
  7. bind_to_interface()
  8. Optional: qdisc_bypass
  9. Return AfPacketTx

### src/inject.rs (new)

**Injector** — thin wrapper around AfPacketTx:
- `builder() -> InjectorBuilder`
- `allocate(len) -> Option<TxSlot>` — delegates to tx
- `flush() -> Result<usize>` — delegates to tx
- `into_inner() -> AfPacketTx`
- `impl AsFd`

**InjectorBuilder:**
- Fields: interface, frame_size, frame_count, qdisc_bypass
- `build()`: constructs AfPacketTxBuilder internally, wraps in Injector

### src/afpacket/mod.rs (modify)

Add `pub mod tx;`

### src/lib.rs (modify)

Add `pub mod inject;`, re-export `PacketSink`, `TxSlot`, `Injector`, `AfPacketTx`

## Memory Ordering

| Operation | Ordering | Why |
|-----------|----------|-----|
| Read `tp_status` (check available) | Acquire | See kernel's status clear |
| Write packet data | Regular | Frame is user-owned |
| Write `TP_STATUS_SEND_REQUEST` | Release | Data visible before kernel reads |
| Write `TP_STATUS_AVAILABLE` (drop) | Release | Consistency |

## Testing

**Unit tests:**
- TxSlot drop without send reclaims frame
- Builder config validation

**Integration tests (CAP_NET_RAW):**
- Inject on loopback, capture with separate socket, verify frame content
- Allocate → send → flush cycle, verify flush returns correct count
