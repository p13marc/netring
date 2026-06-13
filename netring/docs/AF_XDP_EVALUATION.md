# AF_XDP backend — design retrospective

## What we shipped

netring's AF_XDP backend is a **pure-Rust implementation built directly on
`libc` syscalls**, mirroring the AF_PACKET backend's approach. No
`libxdp`, no `aya` runtime requirement, no external XDP helper crate.

The implementation lives in `src/afxdp/`:

```
src/afxdp/
  ├── mod.rs    — XdpSocket, XdpSocketBuilder, XdpMode (public API)
  ├── batch.rs  — XdpBatch, XdpPacket, XdpBatchIter (zero-copy view)
  ├── stats.rs  — XdpStats (decoded xdp_statistics)
  ├── socket.rs — socket(AF_XDP), setsockopt, getsockopt, bind
  ├── umem.rs   — UMEM mmap + bounds-checked frame allocator
  ├── ring.rs   — 4 rings (Fill, RX, TX, Completion) + token-based API
  └── ffi.rs    — libc re-exports (XDP constants/structs)
```

## Why our own implementation

Three approaches were on the table when AF_XDP support was scoped:

| Option | Result |
|--------|--------|
| Use `xdp` 0.7.3 crate | Considered. Production-tested at Google but pulls in another dependency stack. |
| Use `xsk-rs` 0.8 | Considered. Requires `libxdp` C library. |
| Pure-Rust on `libc` | Shipped. ~700 lines, no new transitive deps. |

The deciding factor was consistency with the AF_PACKET backend. Both now
share patterns for `MmapRing` RAII, error types, `Send`/`!Sync`
invariants, and the `OwnedPacket` / `Timestamp` types. A reviewer
understanding the AF_PACKET code can read the AF_XDP code without
context-switching between two architectures.

## Ring protocol

Each of the four rings (Fill, RX, TX, Completion) is a shared-memory
region between userspace and kernel containing:

- `AtomicU32` producer index
- `AtomicU32` consumer index
- A flags `u32` (for `XDP_RING_NEED_WAKEUP`)
- A descriptor array

Producer/consumer protocol uses plain `store(Release)` / `load(Acquire)`
— **never** `fetch_add`, because each ring has a single producer and a
single consumer.

Internally we expose a token-based API (`PeekToken` / `ReserveToken`)
so callers can't accidentally read past their peeked range:

```rust
if let Some(tok) = ring.consumer_peek(64) {
    for i in 0..tok.n {
        let desc = ring.read_at(tok, i);  // panics if i >= tok.n
        // ...
    }
    ring.consumer_release(tok);
}
```

## BPF program requirement

- **TX-only**: works without any BPF program. Use
  `XdpSocketBuilder::default().mode(XdpMode::Tx)`.
- **RX**: the kernel requires an XDP program attached to the NIC that
  calls `bpf_redirect_map(&xskmap, queue_id, 0)`. netring does not load
  it for you — bring `aya` (or `libbpf-rs`, or static eBPF bytecode via
  `bpf_loader`) and attach it via the socket's `AsFd`.

This split is intentional: bundling an aya runtime would add ~49
transitive dependencies that most users wouldn't exercise. Users who
want a turnkey RX setup can wrap netring + their preferred eBPF loader
in their own crate.

## Performance characteristics

The `xsk-rs` (`libxdp`-backed) ecosystem reports 10–24 Mpps on modern
NICs with zero-copy mode. netring's pure-Rust implementation has the
same kernel-side semantics — the only differences are at the userspace
ring-protocol level, which is identical. We have not benchmarked
end-to-end ourselves; that's tracked as future work.

## What's not yet wired

- **Shared UMEM** (`XDP_SHARED_UMEM`) for multi-queue capture across one
  UMEM region. The kernel supports it; netring doesn't surface it yet.
- **XDP RX metadata extension** (Linux 6.0+) — would let `XdpPacket`
  carry kernel timestamps, hash, vlan tags. `XdpPacket::timestamp()`
  currently returns `None` unconditionally; the API is forward-compatible.
- **TX metadata** (Linux 6.10+) — checksum offload, hardware timestamping
  request — also not surfaced.

These are tracked in `plans/upstream-tracking.md`.

## Reference

If you want to compare designs:

- `xdp` 0.7.3: https://codeberg.org/ca1ne/xdp — used by Google Quilkin.
- `xsk-rs` 0.8: https://crates.io/crates/xsk-rs — wraps `libxdp`.
- Linux kernel docs: `Documentation/networking/af_xdp.rst`.
