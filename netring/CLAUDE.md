# CLAUDE.md

## Project Overview

netring is a pure Rust library for zero-copy packet capture and injection on Linux,
built on AF_PACKET with TPACKET_V3 (block-based mmap ring buffers) and AF_XDP.

- Edition 2024, MSRV 1.85, Linux only
- Two API levels: high-level `Capture`/`Injector` and low-level `AfPacketRx`/`AfPacketTx`
- AF_XDP backend via `XdpSocket` (feature: `af-xdp`) for kernel-bypass packet I/O
- Optional self-contained AF_XDP via `xdp-loader` feature (loads + attaches a redirect-all
  XDP program, no external `aya`/`libxdp`/`bpftool` dance)
- Zero-copy via mmap with lifetime-enforced safety
- Async adapters: tokio (`AsyncCapture`) and channel (`ChannelCapture`)
- Flow & session tracking lives in the separate
  [`flowscope`](https://github.com/p13marc/flowscope) crate; netring's
  `flow` feature pulls it in and adds tokio Stream adapters
  (`flow_stream`, `session_stream`, `datagram_stream`,
  `dedup_stream`, `flow_broadcast`).

## Implementation Status

**Active.** netring 0.7.0 published; 0.8.0 prepared (this branch).
~140 tests, ~12 examples, zero warnings.

### Recent additions (0.8.0)

- **Plan 11**: `SO_PREFER_BUSY_POLL` + `SO_BUSY_POLL_BUDGET` builder
  methods on AF_PACKET and AF_XDP (kernel ≥ 5.11). Closes the AF_XDP↔
  DPDK latency gap on payload-touching workloads.
- **Plan 12 phase 1+2**: built-in XDP redirect-all program loader via
  optional `aya`. `XdpSocketBuilder::with_default_program()` is a
  full AF_XDP recipe in one call. `XdpProgram::from_aya(...)` lets
  users wrap their own compiled programs and reuse netring's
  attach + register + RAII teardown.
- **Plan 50.6**: `FlowStream::broadcast(buffer)` →
  `FlowBroadcast<K>` for multi-subscriber flow events with
  per-subscriber `Lagged` semantics (tokio `broadcast` channel under
  the hood).
- **Workspace split**: flow tracking (formerly `netring-flow{,-http,
  -tls,-dns,-pcap}`) extracted to a separate `flowscope` crate. No
  user-facing API broke; `netring::flow::*` re-exports still work.

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

# Plan 11 example: AF_XDP with busy-poll trio
just async-xdp-busy eth0 30   # 30s capture, busy-poll-tuned

# Plan 12 example: AF_XDP self-loaded (no external XDP loader)
just async-xdp-self lo 10     # 10s capture on lo, SKB mode

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
- `src/dedup.rs` — Loopback dedup primitive (plan 10)
- `src/error.rs` — Error enum (now includes `Loader` for `xdp-loader` feature)
- `src/afpacket/rx.rs` — AfPacketRx + builder (busy-poll trio added in 0.8)
- `src/afpacket/tx.rs` — AfPacketTx + builder (V1 frame-based TX)
- `src/afpacket/ring.rs` — MmapRing (NonNull, strict provenance, AtomicU32)
- `src/afpacket/socket.rs` — All setsockopt wrappers (incl. busy-poll trio)
- `src/afpacket/ffi.rs` — libc re-exports + supplemental constants
- `src/afpacket/fanout.rs` — `PACKET_FANOUT` plumbing (Hash/CPU/QM/EBPF/LB)
- `src/afxdp/mod.rs` — XdpSocket + XdpSocketBuilder (AF_XDP public API)
- `src/afxdp/ffi.rs` — libc re-exports for XDP constants/structs
- `src/afxdp/socket.rs` — AF_XDP socket/setsockopt/bind wrappers
- `src/afxdp/umem.rs` — UMEM mmap + frame allocator
- `src/afxdp/ring.rs` — 4 XDP ring types (Fill, RX, TX, Completion)
- `src/afxdp/loader/` — XDP program loader (plan 12, `xdp-loader` feature)
  - `mod.rs` — public `XdpProgram` / `XdpAttachment` / `XdpFlags`
  - `default_program.rs` — built-in `bpf_redirect_map` loader
  - `program.rs` — RAII attach + register helpers (uses `aya`)
  - `programs/redirect_all.bpf.{c,o}` — vendored compiled bytecode
- `src/async_adapters/` — tokio and channel adapters
  - `flow_stream.rs` — `AsyncCapture::flow_stream(extractor)` core
  - `session_stream.rs` — `.session_stream(parser)` (plan 31)
  - `datagram_stream.rs` — `.datagram_stream(parser)` (plan 31)
  - `flow_broadcast.rs` — `.broadcast(buffer)` multi-subscriber (plan 50.6)
  - `conversation.rs` — `Conversation<K>` aggregate
  - `dedup_stream.rs` — loopback dedup async wrapper
  - `async_reassembler.rs` — async TCP reassembly hook

## Architecture

- `nix` 0.31 for standard syscalls (mmap, poll, if_nametoindex)
- Raw `libc` for TPACKET-specific setsockopt and sendto(NULL) for TX
- `libc` 0.2.183 exports all TPACKET_V3 structs and busy-poll constants —
  `ffi.rs` re-exports only
- Strict provenance (`ptr.map_addr()`) for all mmap pointer math
- `OwnedFd` / `BorrowedFd` / `AsFd` — no raw fd in public API
- Drop ordering: `ring: MmapRing` before `fd: OwnedFd` in struct fields
- XDP loader (when `xdp-loader` enabled): `_xdp_attachment: Option<XdpAttachment>`
  in `XdpSocket` drops before the rings + fd, so the program detaches from
  the interface before AF_XDP shuts down
- `flowscope` is a non-optional dep with `default-features = false` (just
  `bitflags` + `thiserror`); `Timestamp` and `PacketView` are unconditionally
  re-exported from it. The `parse` / `flow` features add flowscope's heavier
  modules (extractors, tracker, reassembler, session)

## Design Constraints

- `LendingIterator` not stabilized — flat `packets()` iterator uses unsafe (raw pointer + lifetime erasure via transmute)
- `gen` blocks not stabilized — `nightly` feature reserved for future
- TX uses V1 frame-based semantics (not V3 blocks)
- `tpacket_bd_ts.ts_usec` in libc — read as nanoseconds for TPACKET_V3
- `AsyncCapture` uses `wait_readable()` + `get_mut().next_batch()` for zero-copy, or `recv()` for owned packets, due to borrow-checker limitations with AsyncFd + lending returns
- `MAP_LOCKED` fallback: catches EPERM, ENOMEM, and EAGAIN, retries without MAP_LOCKED
- Integration tests must use deadline-based loops with `next_batch_blocking()`, NOT `packets()` (which blocks forever on timeout)
- `xdp-loader` ships a vendored 1 KB ELF (`redirect_all.bpf.o`); regenerating
  needs `clang` but only the maintainer touches it
- AF_XDP `with_default_program()` defaults to `SKB_MODE` so it works on
  `lo` and unprivileged interfaces; users on real NICs should switch to
  `DRV_MODE` for native-driver AF_XDP

## Pre-publish checklist

For the next `cargo publish` of netring:

1. Ensure `flowscope` is published to crates.io at the version netring
   needs (currently `0.1`).
2. Swap netring's git dep on `flowscope` for a version dep:
   `flowscope = "0.1"` (default features false; same feature
   selectors as today).
3. Bump `netring/Cargo.toml` `version` if more changes have landed
   beyond what's in this CHANGELOG.
4. `cargo publish -p netring --dry-run` to verify the package
   contents.
5. `cargo publish -p netring`.
