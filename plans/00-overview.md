# AF_XDP Implementation Plan — v0.4

## Goal

Replace the AF_XDP stub with a full pure Rust implementation using `libc`
syscalls (same approach as AF_PACKET). No new dependencies.

## Phases

| Phase | Name | Effort | Depends On |
|-------|------|--------|-----------|
| G.1 | FFI constants + socket setup | Small | — |
| G.2 | UMEM allocation + registration | Small | G.1 |
| G.3 | Ring mmap + producer/consumer protocol | Medium | G.1, G.2 |
| G.4 | XdpSocket API (recv/send/flush) | Medium | G.1–G.3 |
| G.5 | Tests, example, docs | Small | G.4 |

## Architecture

```
src/afxdp/
  ├── mod.rs          # Public API, XdpSocket + XdpSocketBuilder
  ├── ffi.rs          # Re-export libc XDP constants/structs
  ├── socket.rs       # socket(AF_XDP), setsockopt, getsockopt, bind
  ├── umem.rs         # UMEM mmap + frame allocator (free list)
  └── ring.rs         # 4 ring types: Fill, RX, TX, Completion
                      # Producer/consumer protocol with AtomicU32
```

## Verified Technical Details (libc 0.2.183)

Critical findings from kernel source verification:

| Detail | Correct Value | Common Mistake |
|--------|---------------|---------------|
| `xdp_mmap_offsets` fill field | `.fr` (not `.fill`) | Many docs say `.fill` |
| Ring protocol | `store(cached + n, Release)` | NOT `fetch_add` — single producer/consumer per ring |
| TX wakeup | `sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0)` | `MSG_DONTWAIT` is **mandatory** (kernel returns EOPNOTSUPP without it) |
| Bind flags for auto-negotiate | Pass `0` (no flags) | NOT `XDP_ZEROCOPY` — kernel auto-tries zero-copy, falls back to copy |
| UMEM allocation | `MAP_PRIVATE \| MAP_ANONYMOUS` | Not MAP_SHARED |
| `XDP_USE_NEED_WAKEUP` | Flag on `bind()` in `sxdp_flags` | Not a setsockopt |
| mmap page offsets | Cast `u64` to `off_t` (i64) — safe on 64-bit | 32-bit overflow (AF_XDP is 64-bit only) |
| `AF_XDP` type | `c_int` (i32), cast to `u16` for `sxdp_family` | Direct assignment without cast |
| `xdp_umem_reg` | 6 fields including `tx_metadata_len` | Older kernels accept 4-field version automatically |
| Ring sizes | Independent (fill ≠ rx allowed) | Some docs say they must match |

## Key Design Decisions

1. **Pure Rust**: `libc` for structs/constants, `nix` for mmap/poll — same as AF_PACKET
2. **Standalone API**: `XdpSocket` does NOT implement `PacketSource` (different ring model)
3. **No BPF loading**: Users bring `aya` + `AsFd` for RX program (existing pattern)
4. **TX works without BPF**: No XDP program needed for send-only use cases
5. **Bind with flags=0**: Let kernel auto-negotiate zero-copy vs copy mode
6. **Copy-based recv**: Returns `Vec<OwnedPacket>` — true zero-copy deferred to future GAT redesign

## Reference

- Kernel source: `net/xdp/xsk.c`, `include/net/xdp_sock_drv.h`, `include/uapi/linux/if_xdp.h`
- `xdp` crate 0.7.3 source (https://codeberg.org/ca1ne/xdp) as correctness reference
- `docs/AF_XDP_EVALUATION.md` for full syscall interface details
