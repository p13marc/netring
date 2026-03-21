# Implementation Plan Overview

## Phases

| Phase | Name | Depends On | Key Deliverables |
|-------|------|-----------|-----------------|
| 1 | FFI & Foundations | — | Cargo.toml, error.rs, ffi.rs (re-export libc + layout tests), config.rs, stats.rs, packet.rs (value types) |
| 2 | Socket & MmapRing | 1 | socket.rs, ring.rs (NonNull + strict provenance), filter.rs, fanout.rs |
| 3 | RX Path | 1, 2 | traits.rs (PacketSource), Packet, PacketBatch (RAII), BatchIter, AfPacketRx + builder |
| 4 | TX Path | 1, 2 | PacketSink trait, AfPacketTx (V1 frame-based), TxSlot, Injector |
| 5 | High-Level API | 1–4 | Capture, CaptureBuilder, flat packet iterator (unsafe), ENOMEM retry |
| 6 | Async & Channel | 1–5 | AsyncCapture (tokio AsyncFd), ChannelCapture (crossbeam), AsyncPacketSource (native async fn) |
| 7 | Tests & Docs | 1–6 | FFI layout tests, synthetic BatchIter, integration tests, divan+criterion, examples, README |

## Phase Dependencies

```
Phase 1 ──→ Phase 2 ──→ Phase 3 ──→ Phase 5 ──→ Phase 6 ──→ Phase 7
                    └──→ Phase 4 ──┘
```

## File Creation Order

```
Phase 1:
  Cargo.toml (modify)
  src/lib.rs (replace)
  src/error.rs
  src/afpacket/mod.rs
  src/afpacket/ffi.rs          ← re-export from libc, NOT redefine
  src/config.rs
  src/stats.rs
  src/packet.rs (value types only: Timestamp, PacketStatus, OwnedPacket)

Phase 2:
  src/afpacket/socket.rs       ← nix for socket(), libc for setsockopt(SOL_PACKET)
  src/afpacket/ring.rs         ← MmapRing with NonNull<u8>, nix::mmap(F: AsFd)
  src/afpacket/filter.rs
  src/afpacket/fanout.rs

Phase 3:
  src/traits.rs                ← PacketSource + #[diagnostic::on_unimplemented]
  src/packet.rs (complete)     ← Packet<'a>, PacketBatch<'a>, BatchIter<'a>
  src/afpacket/rx.rs           ← AfPacketRx, AfPacketRxBuilder, PacketSource impl

Phase 4:
  src/afpacket/ffi.rs (add TX status constants)
  src/traits.rs (add PacketSink)
  src/afpacket/tx.rs           ← AfPacketTx (V1 frames), TxSlot
  src/inject.rs                ← Injector + InjectorBuilder

Phase 5:
  src/capture.rs               ← Capture, CaptureBuilder, PacketIter (raw pointer + unsafe)

Phase 6:
  src/async/mod.rs             ← pub mod r#async; (raw identifier)
  src/async/tokio.rs           ← AsyncCapture<S: PacketSource>, native async fn in trait
  src/async/channel.rs         ← ChannelCapture, background thread + crossbeam

Phase 7:
  tests/helpers/mod.rs
  tests/*.rs (integration, gated on feature "integration-tests")
  benches/poll_throughput.rs (divan)
  benches/e2e_capture.rs (criterion)
  examples/{capture,fanout,inject,async_capture}.rs
  README.md
```

## Key Architectural Constraints

1. **Lifetime chain**: `Packet<'a>` → `PacketBatch<'a>` → `&'a mut AfPacketRx` — compiler-enforced single-batch-at-a-time
2. **Drop ordering**: `ring: MmapRing` before `fd: OwnedFd` in struct fields — munmap before close
3. **Strict provenance**: `ptr.map_addr()` for all mmap pointer math (stable since 1.84), never `ptr as usize`
4. **I/O safety**: `OwnedFd` / `BorrowedFd` / `AsFd` on all public handles — no raw fd in public API
5. **Edition 2024**: explicit `unsafe {}` blocks inside `unsafe fn` bodies
6. **`nix` 0.31 for standard syscalls** (mmap, munmap, poll, if_nametoindex), **raw `libc` for TPACKET-specific setsockopt** and `sendto(NULL)` for TX flush
7. **`libc` exports all TPACKET_V3 structs** — ffi.rs re-exports, does NOT redefine them
8. **`AsFd` on every public handle** — enables eBPF attachment via `aya` without raw fds
9. **`LendingIterator` not stabilized** — flat iterator in Phase 5 uses raw pointer + unsafe
10. **`gen` blocks not stabilized** — `nightly` feature flag reserved, no implementation in initial release

## Verified Dependency Versions (March 2026)

| Crate | Version | Notes |
|-------|---------|-------|
| `libc` | 0.2.183 | Exports all TPACKET_V3 types; `tpacket_bd_ts.ts_usec` (read as nsec for V3) |
| `nix` | 0.31.2 | `mmap` returns `NonNull<c_void>`, takes `F: AsFd`; `MAP_POPULATE` available |
| `thiserror` | 2.x | `#[source]` attributes |
| `bitflags` | 2.x | Derive macros on `FanoutFlags` |
| `log` | 0.4 | Sequence gap warnings, ENOMEM retries |
| `tokio` | 1.50 | `AsyncFd::with_interest` for async adapter |
| `crossbeam-channel` | 0.5 | Bounded channel for thread adapter |
| `divan` | 0.1 | Microbenchmarks |
| `criterion` | 0.5 | E2E benchmarks |
