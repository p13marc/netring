# CLAUDE.md

## Project Overview

netring is a pure Rust library for zero-copy packet capture and injection on Linux,
built on AF_PACKET with TPACKET_V3 (block-based mmap ring buffers).

- Edition 2024, MSRV 1.85, Linux only
- Two API levels: high-level `Capture`/`Injector` and low-level `AfPacketRx`/`AfPacketTx`
- Zero-copy via mmap with lifetime-enforced safety
- Async adapters: tokio (`AsyncCapture`) and channel (`ChannelCapture`)

## Implementation Status

**Complete.** All 7 phases implemented. 71 tests, 10 examples, zero warnings.

## Build & Test

```bash
# Unit tests (no privileges)
cargo test

# Full tests (need CAP_NET_RAW — use justfile)
just setcap          # sudo once — grants capabilities on all binaries
just test            # runs all tests without sudo
just test-unit       # unit tests only
just test-one <name> # run specific test

# Examples
just capture eth0    # basic capture
just dpi eth0        # deep packet inspection
just stats eth0      # live statistics

# Lint
just ci              # clippy + unit tests + docs + bench compile
just ci-full         # setcap + full test suite
```

## Key Files

- `SPEC.md` — Complete specification (source of truth for design)
- `docs/` — Architecture, API overview, tuning guide, troubleshooting
- `src/capture.rs` — High-level Capture + CaptureBuilder
- `src/inject.rs` — High-level Injector
- `src/traits.rs` — PacketSource, PacketSink, AsyncPacketSource traits
- `src/packet.rs` — Packet, PacketBatch, BatchIter, Timestamp, PacketStatus
- `src/afpacket/rx.rs` — AfPacketRx + builder
- `src/afpacket/tx.rs` — AfPacketTx + builder (V1 frame-based TX)
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

- `LendingIterator` not stabilized — flat `packets()` iterator uses unsafe (raw pointer + lifetime erasure via transmute)
- `gen` blocks not stabilized — `nightly` feature reserved for future
- TX uses V1 frame-based semantics (not V3 blocks)
- `tpacket_bd_ts.ts_usec` in libc — read as nanoseconds for TPACKET_V3
- `AsyncCapture` uses `wait_readable()` + `get_mut().next_batch()` for zero-copy, or `recv()` for owned packets, due to borrow-checker limitations with AsyncFd + lending returns
- `MAP_LOCKED` fallback: catches EPERM, ENOMEM, and EAGAIN, retries without MAP_LOCKED
- Integration tests must use deadline-based loops with `next_batch_blocking()`, NOT `packets()` (which blocks forever on timeout)
