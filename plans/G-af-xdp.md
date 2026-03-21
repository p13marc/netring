# Phase G: AF_XDP Backend

## Goal

Add an AF_XDP (XDP sockets) backend behind an `af-xdp` feature flag, implementing
the same `PacketSource` / `PacketSink` traits. AF_XDP provides true kernel-bypass
packet I/O with 10–24 Mpps throughput (vs 1–5 for AF_PACKET).

## Depends on

Phase A (code quality) — clean trait abstractions.

## Background

AF_XDP uses four ring buffers shared between kernel and userspace:
- **FILL ring**: userspace posts empty buffer descriptors for kernel to fill
- **COMPLETION ring**: kernel returns buffer descriptors after TX
- **RX ring**: kernel posts received packet descriptors
- **TX ring**: userspace posts packet descriptors for transmission

All rings operate over a shared UMEM (User Memory) region. Packets are
referenced by offset+length descriptors, not copied.

### Requirements

- Linux 5.4+ (AF_XDP stable)
- NIC driver with XDP support for zero-copy mode (Intel ice/i40e/ixgbe, Mellanox mlx5)
- An XDP program attached to the NIC (mandatory — redirects packets to the socket)
- `CAP_NET_RAW` + `CAP_BPF` (or `CAP_SYS_ADMIN`)

### Comparison

| Aspect | AF_PACKET (current) | AF_XDP (this phase) |
|--------|-------------------|-------------------|
| Performance | 1–5 Mpps | 10–24 Mpps |
| Zero-copy | mmap (kernel copies to ring) | True (NIC DMA to UMEM) |
| Complexity | Moderate | High (eBPF + UMEM) |
| Driver support | All NICs | Requires XDP driver |
| TX | V1 frame-based | Full bidirectional |

## Feature flag

```toml
[features]
af-xdp = ["dep:xsk-rs"]

[dependencies]
xsk-rs = { version = "0.8", optional = true }
```

Use `xsk-rs` (the established Rust AF_XDP crate) as the low-level layer.
netring provides the `PacketSource`/`PacketSink` trait implementations on top.

## Module structure

```
src/afxdp/
  ├── mod.rs          — feature-gated module
  ├── rx.rs           — XdpRx: PacketSource impl
  ├── tx.rs           — XdpTx: PacketSink impl
  └── umem.rs         — UMEM management, buffer pool
```

## 1. XdpRx — PacketSource implementation

```rust
/// AF_XDP receive handle.
///
/// Implements [`PacketSource`]. Provides zero-copy packet access via
/// shared UMEM memory.
#[cfg(feature = "af-xdp")]
pub struct XdpRx {
    socket: xsk_rs::Socket,
    rx_ring: xsk_rs::RxQueue,
    fill_ring: xsk_rs::FillQueue,
    umem: Arc<Umem>,
    // PacketBatch adapter state
}
```

### Key design challenge: PacketBatch compatibility

`PacketSource::next_batch()` returns `PacketBatch<'_>` which currently assumes
TPACKET_V3 block layout (tpacket_block_desc → tpacket3_hdr linked list).

For AF_XDP, the "batch" is a set of descriptors from the RX ring pointing into
UMEM. Two options:

**Option A: Abstract PacketBatch over backends**
Make `PacketBatch` an enum:
```rust
pub enum PacketBatch<'a> {
    AfPacket(AfPacketBatch<'a>),
    Xdp(XdpBatch<'a>),
}
```
Pro: single type. Con: every `match` on every packet access, enum overhead.

**Option B: Separate batch types, generic trait**
Keep `PacketBatch` for AF_PACKET. Add `XdpBatch` for AF_XDP. Make `PacketSource`
generic over the batch type:
```rust
pub trait PacketSource: AsFd {
    type Batch<'a>: IntoIterator<Item = Packet<'a>> where Self: 'a;
    fn next_batch(&mut self) -> Option<Self::Batch<'_>>;
}
```
Pro: zero overhead. Con: changes the public trait (breaking change for v0.2).

**Option C: XdpRx returns owned packets only**
`XdpRx` doesn't implement `PacketSource`. Instead it has its own API that returns
`Vec<OwnedPacket>` or a custom iterator. Users choose the backend explicitly.

**Recommendation: Option B** for v0.4 (breaking change acceptable). For v0.2,
start with Option C as a preview behind the feature flag. Migrate to Option B
when GATs on traits are better established.

## 2. XdpTx — PacketSink implementation

```rust
#[cfg(feature = "af-xdp")]
pub struct XdpTx {
    socket: xsk_rs::Socket,
    tx_ring: xsk_rs::TxQueue,
    comp_ring: xsk_rs::CompQueue,
    umem: Arc<Umem>,
}
```

Same trait compatibility challenge. Start with standalone API.

## 3. Umem management

```rust
/// Shared UMEM region for AF_XDP sockets.
#[cfg(feature = "af-xdp")]
pub struct Umem {
    area: xsk_rs::MmapArea,
    frame_size: usize,
    frame_count: usize,
    // Free list for buffer recycling
    free: crossbeam_queue::ArrayQueue<u64>, // frame offsets
}
```

The UMEM is pre-allocated and divided into fixed-size frames. RX fills frames,
userspace processes them, then returns frames to the FILL ring. TX borrows
frames from the free list, fills them, submits to TX ring, and reclaims via
COMPLETION ring.

## 4. XdpBuilder

```rust
#[cfg(feature = "af-xdp")]
pub struct XdpBuilder {
    interface: Option<String>,
    queue_id: u32,              // NIC queue to bind to
    frame_size: usize,          // default: 4096
    frame_count: usize,         // default: 4096
    zero_copy: bool,            // default: true (falls back to copy mode)
    xdp_program: Option<RawFd>, // user provides the XDP program fd
}
```

The user must provide an XDP program (e.g., via `aya`) that redirects packets
to the XSK socket. netring does NOT load XDP programs — that's the user's
responsibility (keeps us independent of `aya`).

## 5. Example

```rust
// examples/xdp_capture.rs
use netring::afxdp::XdpBuilder;

let (mut rx, _tx) = XdpBuilder::new()
    .interface("eth0")
    .queue_id(0)
    .build()?;

loop {
    let packets = rx.recv()?; // Vec<OwnedPacket> for now
    for pkt in &packets {
        println!("{} bytes", pkt.data.len());
    }
}
```

## 6. Testing

- Unit: builder validation
- Integration (needs XDP-capable NIC + eBPF program): manual only
- CI: build-test only (`cargo build --features af-xdp`), no runtime test

## Phasing

1. First: add `xsk-rs` dependency behind feature flag, create module structure
2. Second: implement `XdpRx` with `recv() -> Vec<OwnedPacket>` (Option C)
3. Third: implement `XdpTx` with `send(&[u8])` API
4. Fourth: implement UMEM buffer pool for efficient recycling
5. Future: migrate to GAT-based `PacketSource` (Option B) when ready for v0.4

## Documentation

- `docs/AF_XDP.md` — setup guide (NIC requirements, XDP program, capabilities)
- Update `docs/ARCHITECTURE.md` with AF_XDP backend diagram
- Update README with AF_XDP feature flag
