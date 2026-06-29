# AF_XDP backend

netring's AF_XDP backend is a **pure-Rust implementation built directly on `libc`
syscalls**, mirroring the AF_PACKET backend. The core socket/ring/UMEM code needs
no `libxdp`, no `aya`, and no external XDP helper crate; the optional `xdp-loader`
feature adds a bundled XDP program (via `aya`) so RX works out of the box.

Both backends share the same `MmapRing` RAII, error types, `Send`/`!Sync`
invariants, and `OwnedPacket` / `Timestamp` types, so the two read as one
architecture.

## Feature flags

| Feature | Enables |
|---|---|
| `af-xdp` | The AF_XDP socket, rings, UMEM, batches, stats, and the `netring::xdp` module (queue discovery, multi-queue capture types). |
| `xdp-loader` | The built-in XDP program loader (`with_default_program()`, `XdpCapture`, `filter_program`) — pulls in `aya`. |

## Module layout

```
src/afxdp/
  ├── mod.rs       — XdpSocket, XdpSocketBuilder, XdpMode (public API)
  ├── socket.rs    — socket(AF_XDP), setsockopt, getsockopt, bind
  ├── umem.rs      — UMEM mmap + bounds-checked frame allocator (hugepages/NUMA)
  ├── ring.rs      — 4 rings (Fill, RX, TX, Completion) + token-based API
  ├── batch.rs     — XdpBatch, XdpPacket, XdpBatchIter (zero-copy view)
  ├── stats.rs     — XdpStats (decoded xdp_statistics)
  ├── metadata.rs  — RX metadata decode (see "Hardware metadata" below)
  ├── capture.rs   — XdpCapture: high-level multi-queue capture
  ├── rss.rs       — symmetric RSS / flow-coherent hashing
  ├── steer.rs     — NIC RX flow steering (ethtool ntuple rules)
  ├── ffi.rs       — libc re-exports (XDP constants/structs)
  └── loader/      — XDP program loader (xdp-loader feature)
        ├── mod.rs             — XdpProgram, XdpAttachment, XdpFlags
        ├── default_program.rs — built-in bpf_redirect_map loader
        └── program.rs         — RAII attach + register helpers (aya)
```

## Operating modes

`XdpSocketBuilder::mode(..)` controls how UMEM frames are split between RX (the
fill ring) and TX (the free list) at construction. The enum is `#[non_exhaustive]`.

| `XdpMode` | Behaviour |
|---|---|
| `Rx` | Receive only — all frames pre-staged to the fill ring; `send()` returns `Ok(false)`. |
| `Tx` | Transmit only — no prefill; every frame stays in the free list for `send()`. |
| `RxTx` *(default)* | Bidirectional — half the frames prefilled to RX, half retained for TX. |
| `Custom { prefill }` | Pre-stage exactly `prefill` frames (clamped to `min(frame_count, ring_size)`); the rest stay for TX. |

## Ring protocol

Each of the four rings (Fill, RX, TX, Completion) is a shared-memory region
between userspace and the kernel containing an `AtomicU32` producer index, an
`AtomicU32` consumer index, a flags `u32` (for `XDP_RING_NEED_WAKEUP`), and a
descriptor array.

Each ring has a **single producer and single consumer**, so the producer/consumer
protocol uses plain `store(Release)` / `load(Acquire)` — never `fetch_add`.

Internally the rings expose a token-based API (`PeekToken` / `ReserveToken`) so
callers can't read past their peeked range:

```rust
if let Some(tok) = ring.consumer_peek(64) {
    for i in 0..tok.n {
        let desc = ring.read_at(tok, i);  // panics if i >= tok.n
        // ...
    }
    ring.consumer_release(tok);
}
```

## Loading the XDP program

The kernel needs an XDP program on the NIC that calls
`bpf_redirect_map(&xskmap, queue_id, 0)` before AF_XDP can receive. Three paths:

- **TX-only** needs no program: `XdpSocketBuilder::default().mode(XdpMode::Tx)`.
- **Bundled program** (`xdp-loader`): `XdpSocketBuilder::default().with_default_program()`
  loads + attaches netring's vendored redirect-all program and registers the socket
  on its XSKMAP. The program detaches and the map fd closes on `Drop`. Default attach
  mode is `SKB_MODE` (works on every interface including `lo`); switch to `DRV_MODE`
  with `xdp_attach_flags(..)` on a native-driver NIC. If a program is already
  attached, `build()` errors and suggests `force_replace()`.
- **Your own program**: `with_program(XdpProgram)` for caller-loaded bytecode
  (compiled via `aya` / `libbpf-rs` / `clang -target bpf`), reusing netring's
  attach + register + RAII teardown.

The vendored `.o` files are regenerated with `clang` (BPF target) by the
maintainer only; users never need a BPF toolchain.

## Multi-queue capture

A single AF_XDP socket binds to one `(netdev, RX-queue)` pair. To capture an
entire multi-queue NIC, the `netring::xdp` module (feature `xdp-loader`) provides:

- `queue_count(iface)` — read the NIC's RX-queue count (`ETHTOOL_GCHANNELS`).
- `Queues` — `Single(n)` | `Range(0..4)` | `Auto` (every RSS/combined queue via
  `ETHTOOL_GCHANNELS`, falling back to queue 0 if detection fails — always safe).
- `XdpCapture` / `XdpCaptureBuilder` — one socket per RX queue sharing a single
  loaded program, drained through a unified round-robin `next_batch`.
- `interface_numa_node(iface)` — sysfs NUMA node, for pinning per-queue UMEM.

For async, `AsyncXdpCapture` (feature `tokio`) fronts `XdpCapture` with per-queue
`AsyncFd`s. Inside the Monitor, `MonitorBuilder::xdp_queues(Queues)` routes a
self-loading interface through the multi-queue backend, and `XdpShardedRunner`
runs one Monitor per RX queue (worker-per-core, busy-poll) — the AF_XDP analogue
of `ShardedRunner`. See [scaling.md](scaling.md) and [BACKENDS.md](BACKENDS.md).

## Flow coherence and steering

- **Symmetric RSS** (`netring::xdp::rss`) — `RssConfig` / `toeplitz` /
  `SYMMETRIC_RSS_KEY` make both directions of a bidirectional flow hash to the
  same RX queue, so a sharded capture keeps a connection on one worker.
- **NIC flow steering** (`netring::xdp::steer`, shipped in 0.28) — `FlowRule` /
  `RxSteer` / `SteerGuard` pin chosen flows to chosen queues via ethtool ntuple
  rules (`FlowRule::tcp().dst_port(443).to_queue(3)`; `SteerGuard` removes rules on
  drop). Capability is driver-dependent and needs `CAP_NET_ADMIN`; loopback
  degrades cleanly to `-EOPNOTSUPP`. Follow-ups (FLOW_RSS contexts, rule
  enumeration, `XdpCaptureBuilder::steer`) are tracked in
  [issue #15](https://github.com/p13marc/netring/issues/15).

## Hardware metadata

Kernel 6.3+ can hand AF_XDP consumers a hardware RX timestamp, RX hash, VLAN tag,
and checksum status via XDP-hints kfuncs. The **userspace contract shipped in
0.28**: `metadata.rs` defines the fixed 32-byte `XdpRxMeta` BPF↔userspace struct
(magic+version gate, per-field validity flags) and decodes it into
`flowscope::RxMetadata`; enable it opt-in with `XdpSocketBuilder::rx_metadata(true)`
(off by default, zero overhead), and the Monitor's AF_XDP arms prefer the hardware
timestamp automatically. The companion `redirect_meta.bpf.c` program ships as
source; compiling its `.o` and validating real timestamps on an ice/mlx5/gve NIC
is the remaining piece, tracked in
[issue #13](https://github.com/p13marc/netring/issues/13) (loopback/generic XDP
exercises only the software-timestamp degrade path). Other deferred upstream items
are tracked in [issue #117](https://github.com/p13marc/netring/issues/117).

## Performance

The userspace ring protocol is identical to the `libxdp`-backed ecosystem
(`xsk-rs`), which reports 10–24 Mpps with zero-copy (`DRV_MODE`) on modern NICs;
netring shares the same kernel-side semantics. End-to-end throughput depends on
NIC, driver mode, queue count, and CPU pinning — see [PERFORMANCE.md](PERFORMANCE.md)
for the measurement methodology and [TUNING_GUIDE.md](TUNING_GUIDE.md) for the
system tuning levers.

## Reference

- `xdp` 0.7.3 — <https://codeberg.org/ca1ne/xdp> (used by Google Quilkin)
- `xsk-rs` 0.8 — <https://crates.io/crates/xsk-rs> (wraps `libxdp`)
- Linux kernel docs — `Documentation/networking/af_xdp.rst`,
  [XDP RX metadata](https://docs.kernel.org/networking/xdp-rx-metadata.html)
