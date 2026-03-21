# Architecture

## Overview

```
┌─────────────────────────────────────────────────────┐
│                  User Application                    │
├──────────────────┬──────────────────────────────────┤
│  High-Level API  │  Low-Level API                    │
│  Capture         │  PacketSource / PacketSink traits │
│  Injector        │  PacketBatch (block access)       │
│  (iterators)     │  AfPacketRx / AfPacketTx          │
├──────────────────┴──────────────────────────────────┤
│  Async Adapters (feature-gated)                      │
│  AsyncCapture (tokio)  │  ChannelCapture (crossbeam) │
├──────────────────┬──────────────────────────────────┤
│  AF_PACKET Backend                                   │
│  socket.rs  ring.rs  fanout.rs  filter.rs  ffi.rs   │
├─────────────────────────────────────────────────────┤
│  nix 0.31 (mmap, poll)  +  libc (setsockopt, bind)  │
├─────────────────────────────────────────────────────┤
│  Linux Kernel (AF_PACKET / TPACKET_V3)               │
└─────────────────────────────────────────────────────┘
```

## Two API Levels

### High-Level: `Capture` / `Injector`

For most users. Builder-configured, flat iterators, RAII everywhere.

```rust
let mut cap = Capture::new("eth0")?;
for pkt in cap.packets().take(100) {
    println!("{} bytes", pkt.len());
}
```

- `Capture` wraps `AfPacketRx` + poll timeout
- `packets()` returns a flat iterator that manages block retirement
- ENOMEM retry: builder shrinks ring size on allocation failure
- `Injector` wraps `AfPacketTx` for frame injection

### Low-Level: `AfPacketRx` / `AfPacketTx`

For performance-critical code. Exposes block-level batching.

```rust
let mut rx = AfPacketRx::builder().interface("eth0").build()?;
while let Some(batch) = rx.next_batch_blocking(timeout)? {
    println!("seq={} pkts={}", batch.seq_num(), batch.len());
    for pkt in &batch {
        process(pkt.data());
    }
    // batch dropped → block returned to kernel
}
```

- Explicit block lifecycle via `PacketBatch` (RAII)
- Sequence gap detection
- Direct access to `AsFd` for epoll/eBPF

## Zero-Copy Lifetime Model

```
AfPacketRx (owns fd + mmap ring)
    │
    │ next_batch(&mut self) → PacketBatch<'_>
    │   (mutable borrow held — one batch at a time)
    │
    └── PacketBatch<'_> (borrows ring, RAII block release)
            │
            │ iter() → BatchIter<'_>
            │
            └── Packet<'_> (&[u8] into mmap region)
                    │
                    └── to_owned() → OwnedPacket (escapes ring)
```

**Key invariant:** `Packet<'a>` borrows from `PacketBatch<'a>` which borrows from
`&'a mut AfPacketRx`. The compiler enforces that packet references cannot outlive
the batch, and the batch cannot outlive the ring. When the batch drops, it writes
`TP_STATUS_KERNEL` to return the block to the kernel.

## Ring Buffer Memory Layout

```
mmap region (block_size × block_count bytes):
┌────────────────┬────────────────┬────────────────┬───┐
│    Block 0     │    Block 1     │    Block 2     │...│
└────────────────┴────────────────┴────────────────┘

Each block:
┌──────────────────────────────────────┐
│ tpacket_block_desc (48 bytes)        │
│   block_status, num_pkts, seq_num    │
├──────────────────────────────────────┤
│ tpacket3_hdr → packet data           │
│ tpacket3_hdr → packet data           │
│ ... (linked list via tp_next_offset) │
├──────────────────────────────────────┤
│ [unused space]                       │
└──────────────────────────────────────┘
```

Blocks cycle between kernel-owned (`TP_STATUS_KERNEL`) and user-owned (`TP_STATUS_USER`).
Memory ordering uses `Acquire` on read, `Release` on return.

## Struct Drop Ordering

Field declaration order matters — Rust drops fields top to bottom:

```rust
pub struct AfPacketRx {
    ring: MmapRing,      // dropped first → munmap
    fd: OwnedFd,         // dropped second → close(fd)
    ...
}
```

`munmap` must happen before `close(fd)` to avoid the kernel reclaiming ring memory
while we might still be referencing it during drop.

## Async Adapters

### tokio (`AsyncCapture`)

Wraps `AfPacketRx` in `tokio::io::unix::AsyncFd`. Uses `wait_readable()` +
`get_mut().next_batch()` pattern because `PacketBatch`'s lending lifetime is
incompatible with `AsyncFd`'s guard-based API.

### Channel (`ChannelCapture`)

Spawns a dedicated thread that calls `next_batch_blocking()` in a loop,
copies packets via `to_owned()`, and sends them over a bounded crossbeam channel.
Runtime-agnostic — works with any async runtime or synchronous code.

## TX Path

TPACKET_V3 TX uses **V1 frame-based semantics** (not block-based):
- Flat array of fixed-size frames
- Status: `AVAILABLE → SEND_REQUEST → kernel sends → AVAILABLE`
- `sendto(fd, NULL, 0, 0, NULL, 0)` triggers kernel transmission
- `TxSlot::send()` marks frame; `TxSlot::Drop` discards if not sent

## AF_XDP Backend (feature: `af-xdp`)

Uses direct AF_XDP syscalls (`socket`, `setsockopt`, `mmap`, `bind`) via `libc`.
Same pure Rust approach as AF_PACKET — no C library dependencies.

```
src/afxdp/
  ├── mod.rs      XdpSocket + XdpSocketBuilder (public API)
  ├── ffi.rs      libc re-exports (XDP constants/structs)
  ├── socket.rs   socket(AF_XDP), setsockopt, getsockopt, bind
  ├── umem.rs     UMEM mmap + frame allocator (free list)
  └── ring.rs     4 ring types: Fill, RX, TX, Completion
                  Producer/consumer protocol with AtomicU32
```

Ring model: 4 shared rings (Fill, RX, TX, Completion) over UMEM.
Producer/consumer protocol with `AtomicU32` (`Acquire`/`Release` ordering).
Uses `store(Release)`, not `fetch_add` — single producer/consumer per ring.

Requires: Linux 5.4+, XDP-capable NIC driver, external XDP BPF program for RX.
TX works without a BPF program.
