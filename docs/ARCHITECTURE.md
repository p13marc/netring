# Architecture

## Overview

```
┌─────────────────────────────────────────────────────┐
│                  User Application                    │
├─────────────────────────────────────────────────────┤
│  Public API                                          │
│  Capture / Injector  (AF_PACKET)                     │
│  XdpSocket            (AF_XDP, feature af-xdp)       │
│  Bridge               (paired AF_PACKET RX+TX)       │
│  AsyncCapture / AsyncInjector  (feature tokio)       │
│  PacketStream                  (feature tokio)       │
│  ChannelCapture                (feature channel)     │
├─────────────────────────────────────────────────────┤
│  Backend internals                                   │
│  src/afpacket/   socket, ring, fanout, filter, ffi   │
│  src/afxdp/      socket, ring, umem, batch, ffi      │
│  src/syscall.rs  EINTR-safe poll/sendto wrappers     │
├─────────────────────────────────────────────────────┤
│  nix 0.31 (mmap, poll)  +  libc (setsockopt, bind)   │
├─────────────────────────────────────────────────────┤
│  Linux Kernel  (TPACKET_V3, AF_XDP)                  │
└─────────────────────────────────────────────────────┘
```

## One type per role

netring used to have a "high-level vs low-level" split — `Capture` wrapped
`AfPacketRx`, `Injector` wrapped `AfPacketTx`. As of 0.4 those are merged.
Each role is one type:

```rust
let mut cap = Capture::open("eth0")?;       // simple
// or
let mut cap = Capture::builder()             // configured
    .interface("eth0")
    .promiscuous(true)
    .build()?;

for pkt in cap.packets().take(100) { /* zero-copy */ }
// or
while let Some(batch) = cap.next_batch_blocking(timeout)? { /* batches */ }
```

The same type exposes both the flat iterator (`packets()`) and the
batch-level access (`next_batch`, `next_batch_blocking`). Old user code
referencing `AfPacketRx` / `AfPacketTx` still compiles via deprecated type
aliases.

## Zero-copy lifetime model

```
Capture (owns fd + mmap ring)
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

**Key invariant:** `Packet<'a>` borrows from `PacketBatch<'a>` which borrows
from `&'a mut Capture`. The compiler enforces that packet references cannot
outlive the batch, and the batch cannot outlive the ring. When the batch
drops, it writes `TP_STATUS_KERNEL` to return the block to the kernel.

The flat iterator (`Capture::packets`) uses `'static`-lifetime erasure
internally to thread the batch through `Iterator::next()` (which can't
express a lifetime tied to its own state). `for` loop consumption is sound;
`.collect()` across blocks is not — see the rustdoc on `Capture::packets`
for the full soundness note.

## Ring buffer memory layout

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
│ tpacket3_hdr → sockaddr_ll → data    │
│ tpacket3_hdr → sockaddr_ll → data    │
│ ... (linked list via tp_next_offset) │
├──────────────────────────────────────┤
│ [unused space]                       │
└──────────────────────────────────────┘
```

Blocks cycle between kernel-owned (`TP_STATUS_KERNEL`) and user-owned
(`TP_STATUS_USER`). Memory ordering uses `Acquire` on read, `Release` on
return.

`BatchIter::next` bounds-checks both the `tpacket3_hdr` and the
`sockaddr_ll` that follows it before constructing each `Packet` (so
`pkt.direction()`, `pkt.source_ll_addr()` are sound).

## Struct drop ordering

Field declaration order matters — Rust drops fields top to bottom:

```rust
pub struct Capture {
    ring: MmapRing,   // dropped first → munmap
    fd: OwnedFd,      // dropped second → close(fd)
    ...
}
```

`munmap` must happen before `close(fd)` to avoid the kernel reclaiming
ring memory while we might still be referencing it during drop.

## Async adapters (feature: `tokio`)

### `AsyncCapture<S>` — generic over any `PacketSource + AsRawFd`

Wraps the source in `tokio::io::unix::AsyncFd`. Provides:

- `readable() → ReadableGuard` — recommended; clears tokio readiness only
  on `None` to eliminate the wait/read race window.
- `try_recv_batch().await` — single-call zero-copy.
- `recv().await → Vec<OwnedPacket>` — `Send` future, use with
  `tokio::spawn` and channel sinks.
- `into_stream() → PacketStream<S>` — `futures_core::Stream<Item = ...>`
  for combinator-style code.

`PacketBatch` is `!Send` (mmap ring is `!Sync` on the user side because
of cached cursor state). Choose between `try_recv_batch` (zero-copy,
`!Send`) and `recv` (owned, `Send`) based on whether the surrounding
future needs to cross task boundaries.

### `AsyncInjector` — TX with backpressure

`send(data).await` awaits `POLLOUT` when the ring is full instead of
returning `None`. Mirrors `AsyncCapture` for symmetry.

### `Bridge::run_async`

Uses `tokio::select!` over `AsyncFd::readable()` on both RX fds — no
`poll(2)` syscall, the tokio reactor drives the loop.

## Channel adapter (feature: `channel`)

`ChannelCapture` spawns a dedicated thread that calls
`next_batch_blocking()` in a loop, copies packets via `to_owned()`, and
sends them over a bounded crossbeam channel. Runtime-agnostic — works
with any async runtime or synchronous code.

## TX path

TPACKET_V3 TX uses V1 frame-based semantics (not block-based):

- Flat array of fixed-size frames
- Status flow: `AVAILABLE → SEND_REQUEST → kernel sends → AVAILABLE` (or
  `WRONG_FORMAT` on rejection)
- `sendto(fd, NULL, 0, ...)` triggers kernel transmission
- `TxSlot::send()` marks the frame; `TxSlot::Drop` discards if not sent
- `Injector::allocate` scans forward up to `frame_count` slots so dropped
  slots and `WRONG_FORMAT`-rejected slots get reused promptly

## AF_XDP backend (feature: `af-xdp`)

Direct AF_XDP syscalls (`socket`, `setsockopt`, `mmap`, `bind`) via `libc`.
Same pure-Rust approach as AF_PACKET — no C library dependencies.

```
src/afxdp/
  ├── mod.rs    XdpSocket + XdpSocketBuilder + XdpMode (public API)
  ├── batch.rs  XdpBatch / XdpPacket / XdpBatchIter (zero-copy view)
  ├── stats.rs  XdpStats (decoded xdp_statistics)
  ├── socket.rs socket(AF_XDP), setsockopt, getsockopt, bind
  ├── umem.rs   UMEM mmap + frame allocator (free list, bounds-checked)
  ├── ring.rs   4 ring types (Fill, RX, TX, Completion) + token API
  └── ffi.rs    libc re-exports (XDP constants/structs)
```

Ring model: 4 shared rings (Fill, RX, TX, Completion) over UMEM.
Producer/consumer protocol with `AtomicU32` (`Acquire`/`Release` ordering),
single producer / single consumer per ring (no `fetch_add`). Operations
use `PeekToken` / `ReserveToken` to make bounds checks runtime-explicit.

`XdpMode` controls UMEM partitioning between the fill ring (RX) and the
free list (TX): pick `Tx` for transmit-only workloads, `Rx` for
receive-only, or accept the default `RxTx` 50/50 split.

Requires: Linux 5.4+, XDP-capable NIC driver, external XDP BPF program
for RX (TX-only mode skips the BPF requirement entirely).

## EINTR-safe syscalls

`src/syscall.rs` wraps `nix::poll::poll` and `libc::sendto` with
EINTR-retry loops. Every blocking site in the crate routes through these
helpers, so users never see spurious `Error::Io` from a signal landing
mid-syscall.
