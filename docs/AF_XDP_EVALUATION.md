# AF_XDP Implementation Evaluation

## Summary

AF_XDP (XDP sockets) is a Linux socket family (AF_XDP = 44) that provides
kernel-bypass packet I/O with 10–24 Mpps throughput. The entire userspace
side can be implemented with **just `libc` syscalls** — no C library needed.

This document evaluates three approaches for netring's AF_XDP backend.

## Approach Comparison

| Approach | Lines | Deps | Control | Risk |
|----------|-------|------|---------|------|
| **A. Use `xdp` 0.7.3** | ~50 (wrapper) | 0 transitive | Low | Low — proven in Google Quilkin |
| **B. Own impl with `libc`** | ~1100 | `libc` (existing) | Full | Medium — ring atomics are subtle |
| **C. Own impl with `aya` for BPF** | ~1200 | `aya` 0.13 (~49 transitive) | Full | Medium — aya is large dep |

## Approach A: Use `xdp` 0.7.3 Crate

The `xdp` crate (https://codeberg.org/ca1ne/xdp) is a **zero-dependency** pure
Rust AF_XDP implementation. It defines its own libc bindings inline (no `libc`
crate), provides UMEM management, all 4 rings, TX checksum offload, and NIC
capability querying.

**Pros:**
- Zero dependencies (not even `libc`)
- Used in production by Google Quilkin
- Actively maintained, MSRV 1.85
- 6,451 lines covering the full AF_XDP surface
- Apache-2.0 / MIT license (compatible with netring)

**Cons:**
- No BPF program loading (need separate `aya` or raw bpf syscalls)
- No async integration
- We'd depend on an external crate's internal design decisions
- Our own `libc` re-exports would overlap with their inline bindings

**Integration pattern:**
```rust
// netring wraps xdp crate's types behind our API
pub struct XdpSocket {
    inner: xdp::Socket,
    umem: xdp::Umem,
}
```

## Approach B: Own Implementation with `libc`

AF_XDP is a standard socket family. The userspace side is:

1. `socket(AF_XDP, SOCK_RAW, 0)`
2. `setsockopt(SOL_XDP, XDP_UMEM_REG, &xdp_umem_reg)` — register UMEM
3. `setsockopt(SOL_XDP, XDP_RX_RING/TX_RING/FILL_RING/COMPLETION_RING, &size)` — configure rings
4. `getsockopt(SOL_XDP, XDP_MMAP_OFFSETS, &offsets)` — get ring layout
5. `mmap()` — map UMEM and each ring
6. `bind(&sockaddr_xdp)` — bind to interface + queue
7. Producer/consumer ring protocol with AtomicU32 (Acquire/Release)

**All constants and structs are in `libc` 0.2.183:**
- `AF_XDP` (44), `SOL_XDP` (283)
- `xdp_umem_reg`, `xdp_mmap_offsets`, `xdp_ring_offset`, `xdp_desc`, `sockaddr_xdp`
- `XDP_RX_RING` (2), `XDP_TX_RING` (3), `XDP_UMEM_REG` (4), `XDP_UMEM_FILL_RING` (5), `XDP_UMEM_COMPLETION_RING` (6)
- `XDP_PGOFF_RX_RING`, `XDP_PGOFF_TX_RING`, `XDP_UMEM_PGOFF_FILL_RING`, `XDP_UMEM_PGOFF_COMPLETION_RING`
- `XDP_COPY`, `XDP_ZEROCOPY`, `XDP_USE_NEED_WAKEUP`

**This mirrors exactly how we built AF_PACKET** — `libc` for structs/constants, `nix` for mmap/poll, raw `libc` for setsockopt.

### Estimated Components

| Component | Lines | Description |
|-----------|-------|-------------|
| FFI constants | ~20 | Re-export from `libc` (same pattern as `afpacket/ffi.rs`) |
| Socket setup | ~80 | socket + setsockopt + getsockopt + bind |
| UMEM | ~100 | mmap anonymous region + registration + frame allocator |
| Rings (×4) | ~200 | mmap + producer/consumer protocol with AtomicU32 |
| MmapRing RAII | ~40 | mmap wrapper with Drop (reuse existing `MmapRing` pattern) |
| XdpSocket API | ~150 | recv/send/flush public methods |
| Builder | ~80 | XdpSocketBuilder with validation |
| Error handling | ~30 | Map to existing Error enum |
| **Total** | **~700** | |

**Pros:**
- Consistent with our AF_PACKET approach (same patterns, same libc/nix)
- Full control over atomics, memory layout, error handling
- No new dependencies
- Can integrate directly with our existing `MmapRing`, `OwnedPacket`, `Timestamp`
- Can share `validate_frame_size()` and other helpers

**Cons:**
- Ring producer/consumer protocol must be correct (subtle atomics)
- Need to handle `XDP_USE_NEED_WAKEUP` flag properly
- ~700 lines of new code to write and test
- No BPF loading (same as xdp crate — users bring aya)

### Ring Protocol Detail

Each ring has a producer and consumer index (AtomicU32) and a descriptor array:

```
Producer ring (Fill, TX — userspace writes):
  1. Check space: cached_prod - cached_cons < ring_size
  2. Write descriptors at ring[prod_idx & mask]
  3. fence(Release); producer.store(new_prod, Release)

Consumer ring (RX, Completion — userspace reads):
  1. Check available: producer.load(Acquire) - cached_cons > 0
  2. Read descriptors at ring[cons_idx & mask]
  3. consumer.store(new_cons, Release)
```

This is the same Acquire/Release pattern we use for TPACKET_V3 block status.

## Approach C: Own Impl + aya for BPF

Same as B, but add `aya` as an optional dependency to provide a turnkey
"load XDP program + create XSKMAP + attach" helper.

**aya integration (~100 lines):**
```rust
#[cfg(feature = "aya")]
pub fn setup_xdp_redirect(
    interface: &str,
    queue_id: u32,
    socket_fd: RawFd,
) -> Result<(), Error> {
    // 1. Load embedded XDP program (simple bpf_redirect_map)
    // 2. Create XSKMAP
    // 3. Attach XDP program to interface
    // 4. Register socket_fd in XSKMAP at queue_id
}
```

**Pros:** Turnkey RX support — user doesn't need to write eBPF
**Cons:** `aya` adds ~49 transitive dependencies

## BPF Program Requirement

AF_XDP **TX works without BPF**. For **RX**, the kernel requires an XDP
program attached to the NIC that calls `bpf_redirect_map(&xskmap, queue_id, 0)`.

Options for netring users:
1. **External aya**: User loads their own XDP program (current pattern via `AsFd`)
2. **Embedded BPF bytecode**: netring ships a pre-compiled redirect program
3. **Optional aya helper**: Behind `aya` feature flag

Recommendation: Option 1 (external) for v0.4, option 3 (aya helper) for v0.5.

## Kernel Structs (all in libc 0.2.183)

```rust
#[repr(C)]
struct xdp_umem_reg {       // 32 bytes
    addr: u64,              // UMEM base pointer
    len: u64,               // UMEM total size
    chunk_size: u32,        // frame size (2048-4096)
    headroom: u32,          // per-frame headroom
    flags: u32,             // XDP_UMEM_UNALIGNED_CHUNK_FLAG etc
    tx_metadata_len: u32,   // kernel 6.11+
}

#[repr(C)]
struct sockaddr_xdp {       // 16 bytes
    sxdp_family: u16,       // AF_XDP (44)
    sxdp_flags: u16,        // XDP_COPY, XDP_ZEROCOPY, XDP_USE_NEED_WAKEUP
    sxdp_ifindex: u32,      // interface index
    sxdp_queue_id: u32,     // NIC queue
    sxdp_shared_umem_fd: u32, // for UMEM sharing
}

#[repr(C)]
struct xdp_desc {           // 16 bytes
    addr: u64,              // UMEM offset
    len: u32,               // packet length
    options: u32,           // XDP_PKT_CONTD, XDP_TX_METADATA
}

#[repr(C)]
struct xdp_mmap_offsets {   // 128 bytes
    rx: xdp_ring_offset,
    tx: xdp_ring_offset,
    fr: xdp_ring_offset,    // fill ring
    cr: xdp_ring_offset,    // completion ring
}

#[repr(C)]
struct xdp_ring_offset {    // 32 bytes
    producer: u64,          // offset to AtomicU32 producer index
    consumer: u64,          // offset to AtomicU32 consumer index
    desc: u64,              // offset to descriptor array
    flags: u64,             // offset to flags (NEED_WAKEUP)
}
```

## Recommendation

**Build our own (Approach B)** for these reasons:

1. **Consistency**: Same libc/nix pattern as AF_PACKET — reviewers understand one codebase
2. **Zero new deps**: We already have libc and nix
3. **Full control**: Integrate with our MmapRing, OwnedPacket, error types
4. **~700 lines**: Manageable scope, all patterns proven in our AF_PACKET code
5. **Ring atomics**: Same Acquire/Release as our TPACKET_V3 block status code
6. **Reference**: Use `xdp` 0.7.3 source as a reference for correctness

The `xdp` crate is excellent but adds an external dependency where we can do it
ourselves with existing tools. If we later find our implementation has correctness
issues, we can always swap in `xdp` 0.7.3 as a drop-in.

**BPF**: Users bring their own via `aya` + `AsFd` (existing pattern). Consider
an optional `aya` helper in a future version.

## Implementation Plan

```
src/afxdp/
  ├── mod.rs          # Public API, feature gate
  ├── ffi.rs          # Re-export libc XDP constants/structs
  ├── socket.rs       # Socket create, setsockopt, bind
  ├── umem.rs         # UMEM mmap + frame allocator
  ├── ring.rs         # Ring mmap + producer/consumer protocol
  └── xdp_socket.rs   # XdpSocket + XdpSocketBuilder
```

Estimated: ~700 lines, ~2 days of implementation, ~20 new tests.
