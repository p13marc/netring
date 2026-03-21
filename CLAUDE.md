# CLAUDE.md

## Project Overview

netring is a pure Rust library for zero-copy packet capture and injection on Linux,
built on AF_PACKET with TPACKET_V3 (block-based mmap ring buffers).

- Edition 2024, MSRV 1.85, Linux only
- Two API levels: high-level `Capture` (iterator) and low-level `AfPacketRx` (batch)
- Zero-copy via mmap with lifetime-enforced safety

## Key Files

- `SPEC.md` — Complete specification (the source of truth)
- `plans/` — 8 phased implementation plans (00-overview through 07-tests-docs)
- `src/lib.rs` — Placeholder (implementation not started)

## Build & Test

```bash
cargo build
cargo test
cargo test --features integration-tests           # needs CAP_NET_RAW
cargo test --features "integration-tests,tokio"    # + async tests
cargo test --features "integration-tests,channel"  # + channel tests
cargo clippy -- --deny warnings
```

## Architecture

- `nix` 0.31 for standard syscalls (mmap, poll, bind)
- Raw `libc` for TPACKET-specific setsockopt
- `libc` 0.2.183 exports all TPACKET_V3 structs — `ffi.rs` re-exports, does NOT redefine
- Strict provenance (`ptr.map_addr()`) for all mmap pointer math
- `OwnedFd` / `BorrowedFd` / `AsFd` — no raw fd in public API
- `thiserror` 2.x, `bitflags` 2.x, `log` 0.4

## Implementation Status

Not yet started. Follow the phases in `plans/` directory:
1. FFI & Foundations
2. Socket & MmapRing
3. RX Path (PacketSource, Packet, PacketBatch, AfPacketRx)
4. TX Path (PacketSink, TxSlot, AfPacketTx, Injector)
5. High-Level API (Capture, CaptureBuilder)
6. Async & Channel adapters
7. Tests, benchmarks, examples, docs

## Design Constraints

- Drop ordering: `ring: MmapRing` before `fd: OwnedFd` in struct fields
- `LendingIterator` not stabilized — flat iterator uses unsafe raw pointer
- `gen` blocks not stabilized — `nightly` feature reserved for future
- TX uses V1 frame-based semantics (not V3 blocks)
- `tpacket_bd_ts.ts_usec` in libc — read as nanoseconds for TPACKET_V3
