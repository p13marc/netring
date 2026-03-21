# CLAUDE.md

## Project Overview

netring is a pure Rust library for zero-copy packet capture and injection on Linux,
built on AF_PACKET with TPACKET_V3 (block-based mmap ring buffers).

- Edition 2024, MSRV 1.85, Linux only
- Two API levels: high-level `Capture`/`Injector` and low-level `AfPacketRx`/`AfPacketTx`
- Zero-copy via mmap with lifetime-enforced safety
- Async adapters: tokio (`AsyncCapture`) and channel (`ChannelCapture`)

## Implementation Status

**Complete.** All 7 phases implemented:
1. FFI foundations (libc re-exports, config, error, value types)
2. Socket setup, MmapRing, BPF filter, fanout
3. RX path (PacketSource, Packet, PacketBatch, BatchIter, AfPacketRx)
4. TX path (PacketSink, TxSlot, AfPacketTx, Injector)
5. High-level API (Capture, CaptureBuilder, flat iterator, ENOMEM retry)
6. Async adapters (tokio AsyncFd, crossbeam channel)
7. Tests, benchmarks, examples, documentation

68 tests pass. Zero warnings. Zero doc warnings.

## Build & Test

```bash
cargo build                                              # build
cargo test                                               # unit tests (no privileges)
cargo test --features integration-tests                  # + integration (needs CAP_NET_RAW)
cargo test --features "integration-tests,tokio,channel"  # + async/channel tests
cargo bench --no-run                                     # verify benchmarks compile
cargo doc --all-features --no-deps                       # build docs
```

## Key Files

- `SPEC.md` — Complete specification (source of truth for design)
- `plans/` — 8 phased implementation plans (completed)
- `docs/` — Architecture, API overview, tuning guide, troubleshooting
- `src/capture.rs` — High-level Capture + CaptureBuilder
- `src/inject.rs` — High-level Injector
- `src/traits.rs` — PacketSource, PacketSink, AsyncPacketSource traits
- `src/packet.rs` — Packet, PacketBatch, BatchIter, Timestamp, PacketStatus
- `src/afpacket/rx.rs` — AfPacketRx + builder
- `src/afpacket/tx.rs` — AfPacketTx + builder
- `src/afpacket/ring.rs` — MmapRing (NonNull, strict provenance, AtomicU32)
- `src/afpacket/socket.rs` — All setsockopt wrappers
- `src/afpacket/ffi.rs` — libc re-exports + supplemental constants
- `src/async_adapters/` — tokio and channel adapters

## Architecture

- `nix` 0.31 for standard syscalls (mmap, poll, if_nametoindex)
- Raw `libc` for TPACKET-specific setsockopt and sendto(NULL) for TX
- `libc` 0.2.183 exports all TPACKET_V3 structs — `ffi.rs` re-exports only
- Strict provenance (`ptr.map_addr()`) for all mmap pointer math
- `OwnedFd` / `BorrowedFd` / `AsFd` — no raw fd in public API
- Drop ordering: `ring: MmapRing` before `fd: OwnedFd` in struct fields

## Design Constraints

- `LendingIterator` not stabilized — flat `packets()` iterator uses unsafe (raw pointer + lifetime erasure)
- `gen` blocks not stabilized — `nightly` feature reserved for future
- TX uses V1 frame-based semantics (not V3 blocks)
- `tpacket_bd_ts.ts_usec` in libc — read as nanoseconds for TPACKET_V3
- `AsyncCapture` uses `wait_readable()` + `get_mut().next_batch()` pattern due to borrow-checker limitations with `AsyncFd` + lending returns
