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

let mut pkts = cap.packets();
while let Some(pkt) = pkts.next_packet() { /* zero-copy */ }
// or
while let Some(batch) = cap.next_batch_blocking(timeout)? { /* batches */ }
```

The same type exposes both the lending iterator (`packets()`) and the
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

## Monitor (feature: `monitor`)

The declarative `Monitor::builder()` API layers on top of the
async types. It's a typed dispatcher fed by one or more
`AsyncCapture` instances, with broadcast subscribers for
streaming consumers and `PACKET_FANOUT`-based per-CPU sharding.

```
┌────────────────────────────────────────────────────────┐
│  User handlers (Fn / async Fn / detector! / pattern!)  │
├────────────────────────────────────────────────────────┤
│  Monitor                                               │
│  ├─ Dispatcher (TypeId-keyed slot table, ≤ 16 events)  │
│  ├─ Subscribers (broadcast<Item> per protocol)         │
│  ├─ Sink chain (Layer → Layer → AnomalySink)           │
│  └─ Ctx (state map + per-flow state + counters)        │
├────────────────────────────────────────────────────────┤
│  flowscope Driver<E> (Send + Sync since 0.13)          │
│  ├─ FlowTracker (5-tuple flows, TCP state)             │
│  └─ Per-protocol Parser (Http / Dns / Tls / ICMP / …)  │
├────────────────────────────────────────────────────────┤
│  AsyncCapture(s) — one per interface                   │
└────────────────────────────────────────────────────────┘
```

**Send Monitor (since 0.21).** The `Monitor` value itself is
`Send` — `ProtocolSlot: Send` supertrait + flowscope 0.13's
unconditional `Driver<E>: Send + Sync` make the dispatcher's
slot table `Send`. Plain `#[tokio::main]` (multi-thread)
works without ceremony. The *future* returned by
`run_for` / `run_until_signal` is still `!Send` because the
underlying `AsyncCapture<S>` borrows the `!Sync` mmap ring
across awaits — so the run-loop future must stay on the main
task. Use `tokio::select!` to multiplex with subscribers /
shutdown sources; ship anomalies to a spawned worker via
`ChannelSink` when work needs to cross task boundaries.

**`EventStream<M>` subscribers.**
`MonitorBuilder::with_broadcast::<P>()` enrols a
`tokio::sync::broadcast::Sender<P::Message>` on the protocol's
slot. `Monitor::subscribe::<P>()` returns
`EventStream<P::Message>` which implements
`futures_core::Stream + Unpin`. The dispatcher publishes to
both the sync handler chain AND the broadcast channel in the
same lifecycle step — subscribers can't drift relative to
handlers within one event.

**Per-CPU sharding via `ShardedRunner`.** Instead of one
`Monitor` over one `AsyncCapture`, `ShardedRunner::new(iface,
mode, group_id, n, build_shard)` spawns N monitors each bound
to the same `PACKET_FANOUT(group_id, mode)`. The kernel
work-steals between them per `FanoutMode::Cpu` /
`Hash` / `Lb` / `QM`. The `build_shard: Arc<dyn Fn(MonitorBuilder)
-> MonitorBuilder>` closure runs once per shard so each
dispatcher owns its own state map — no cross-shard locking.
Global aggregation is a 0.22 follow-up (`ShardedRunner::merge_state`);
today users pipe per-shard `OwnedAnomaly`s through a
`Tee + ChannelSink` to a single collator task.

**Graceful drain.** `MonitorBuilder::drain_timeout(d)` budgets
a final-events sweep after the shutdown signal: any in-flight
flow emits its `FlowEnded` (or `ParserClosed`) lifecycle event
before the runtime exits. Without `drain_timeout`, shutdown
returns as soon as the signal arrives.

**Pcap replay.** `MonitorBuilder::pcap_source(path)` swaps the
live AF_PACKET source for an `AsyncPcapSource`. `Monitor::replay()`
is the run-mode counterpart to `run_until_signal()`.
`pcap_speed_factor(f32)` paces via `tokio::time::sleep`.

**Zero-allocation hot path.** `Dispatcher::dispatch::<P>` is a
typed call: no `Box<dyn>` per event, no `HashMap` lookup.
`AnomalyWriter<'sink>` is stack-only (`ArrayVec` for
observations + metrics). The `benches/zero_alloc.rs` dhat
profiler asserts `Δ 0 bytes / 0 blocks` per 100k synthetic
dispatches.

## EINTR-safe syscalls

`src/syscall.rs` wraps `nix::poll::poll` and `libc::sendto` with
EINTR-retry loops. Every blocking site in the crate routes through these
helpers, so users never see spurious `Error::Io` from a signal landing
mid-syscall.
