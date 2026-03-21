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

## Key Design Decisions

1. **Pure Rust**: `libc` for structs/constants, `nix` for mmap/poll — same as AF_PACKET
2. **Standalone API**: `XdpSocket` does NOT implement `PacketSource` (different ring model)
3. **No BPF loading**: Users bring `aya` + `AsFd` for RX program (existing pattern)
4. **TX works without BPF**: No XDP program needed for send-only use cases
5. **Copy-based recv**: Returns `Vec<OwnedPacket>` — true zero-copy deferred to future GAT redesign

## Reference

- Kernel docs: `Documentation/networking/af_xdp.rst`
- `xdp` crate 0.7.3 source (https://codeberg.org/ca1ne/xdp) as correctness reference
- `docs/AF_XDP_EVALUATION.md` for full syscall interface details
