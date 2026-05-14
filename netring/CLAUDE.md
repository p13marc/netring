# CLAUDE.md

## Project Overview

netring is a pure Rust library for zero-copy packet capture and injection on Linux,
built on AF_PACKET with TPACKET_V3 (block-based mmap ring buffers) and AF_XDP.

- Edition 2024, MSRV 1.95, Linux only
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

**Active.** netring 0.13.0 published; 0.13.1 prepared (this branch).
~225 tests, ~37 examples, zero warnings.

### Recent additions (0.13.1)

Patch release — no API changes, no new features.

- **MSRV raised to 1.95** (was 1.85 in 0.13.0). Reason: the
  flow-tracker / pcap-tap / multi-streams hot paths already used
  `if let X && let Y` let-chains (stabilized in 1.88), and the
  Rust 1.95 clippy promoted `clippy::manual_is_multiple_of` and
  refined `clippy::collapsible_if` to fire through let-chain
  bindings. Bumping MSRV to 1.95 lets the codebase track current
  stable idioms directly.
- **Code-quality**: 8 `n % m == 0` → `n.is_multiple_of(m)`
  conversions across `afpacket/`, `config/`, and 5 examples;
  4 nested-`if let` blocks collapsed to let-chains. Clippy clean
  under `-D warnings` for default + `tokio,channel` +
  `--all-features` matrices.
- **CI**: pinned matrix `rust: [stable, "1.95"]`. Test fixture
  for `bpf_filter_lifecycle` now uses `#[tokio::test]` so
  `AsyncCapture::open_with_filter` sees the runtime it needs.
- **New example**: `async_stats_monitor.rs` — async sibling of
  `stats_monitor.rs`. Demonstrates `StreamCapture::capture_stats()`
  /`capture_cumulative_stats()` polling on a live `FlowStream`
  without disrupting the consumer. Builds on plan 20.

### Recent additions (0.13.0)

Four consolidated plans (20-23) closing all 7 items from des-rs's
2026-05-14 feedback round.

- **Plan 20**: Sealed `StreamCapture` trait gives `FlowStream`,
  `SessionStream`, `DatagramStream`, `DedupStream` a uniform
  `capture()` accessor with default-methoded `capture_stats()` /
  `capture_cumulative_stats()`. Plus `with_pcap_tap(writer)` +
  `TapErrorPolicy { Continue, DropTap, FailStream }` builders on
  each stream type — records each packet to `CaptureWriter` before
  the flow tracker processes it; tap survives session/datagram/
  with_async_reassembler conversions.
- **Plan 21**: New `PacketSetFilter` trait (implemented for
  `Capture`, not for `XdpSocket`). `Capture::set_filter` +
  `AsyncCapture::set_filter` for atomic in-kernel BPF swap.
  `AsyncCapture::open_with_filter(iface, filter)` one-call
  constructor. Composes with plan 20 via
  `stream.capture().set_filter(&new_filter)`.
- **Plan 22**: `AsyncMultiCapture` with five constructors
  (multi-interface, fanout-group workers, heterogeneous). Three
  `Multi*Stream` types yielding `TaggedEvent { source_idx, event }`
  via custom round-robin select (no `futures-util` dep). Per-source
  and aggregate `capture_stats`. New `docs/scaling.md` with
  `FanoutMode` decision matrix and 7 anti-patterns.
- **Plan 23**: `AsyncPcapSource` reads PCAP/PCAPNG via mpsc channel
  fed by `spawn_blocking` task. Format auto-detect; optional
  packet-timestamp pacing; loop-at-eof. `PcapFlowStream` bridges to
  flowscope `FlowTracker`. Live + offline pipelines unify via
  generic `Stream<Item = FlowEvent<K>>` consumer.

### Recent additions (0.12.0)

- **Plan 19**: flowscope 0.3 bump. New builder knobs on `FlowStream`
  / `SessionStream` / `DatagramStream`: `with_idle_timeout_fn(F)`
  (per-key idle timeout override), `with_monotonic_timestamps(bool)`
  (strictly non-decreasing timestamp clamp), `snapshot_flow_stats()`
  (live `(K, FlowStats)` iterator with reassembler high-watermark
  diagnostics). **Breaking**: `SessionEvent::Anomaly` is now
  forwarded as a typed event (previously `tracing::warn!`-and-drop);
  `EndReason::ParseError` is new (treated like `Rst` internally);
  `SessionParser::Message` / `DatagramParser::Message` require
  `Debug` (upstream). `flow_stream(...).session_stream(...)` and
  `.datagram_stream(...)` now move the tracker (preserving
  `idle_timeout_fn` + hot-cache + in-flight flows) instead of
  rebuilding it.

### Recent additions (0.11.0)

- **Plan 18**: Typed `BpfFilter::builder()` — a fluent in-tree
  compiler from a small match vocabulary (`tcp`, `udp`, `vlan`,
  `host`, `net`, `port`, `negate`, `or`) to classic BPF bytecode.
  No external tools (no `tcpdump -dd`), no native deps (no libpcap,
  libbpf, clang), no `unsafe`, no panics. `BpfFilter::matches`
  software interpreter for offline validation. `BpfFilter::new`
  becomes fallible (`Result<_, BuildError>`); `CaptureBuilder::bpf_filter`
  takes a `BpfFilter` directly. See `examples/bpf_filter.rs`.
- **Plan 12 phase 2**: `XdpSocketBuilder::with_program(XdpProgram)`
  for caller-loaded XDP programs (compiled via `aya-bpf` /
  `bpf-linker` / `clang -target bpf`). Same orchestration as
  `with_default_program()` (register socket on map → attach program
  → RAII detach on drop) but pointing at user-supplied bytecode.
  Mutually exclusive with `with_default_program()`. See
  `examples/async_xdp_custom_program.rs`.

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
- `src/config/` — Config types module
  - `bpf.rs` — `BpfFilter` + `BpfInsn` + `BuildError`
  - `bpf_builder.rs` — Typed `BpfFilterBuilder` + `MatchFrag` IR
  - `bpf_compile.rs` — Symbolic-IR cBPF compiler (plan 18)
  - `bpf_interp.rs` — Software cBPF interpreter (`BpfFilter::matches`)
  - `ipnet.rs` — Zero-dep `IpNet` (addr + prefix)
  - `mod.rs` — `FanoutMode` / `FanoutFlags` / `TimestampSource` / `RingProfile`
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
  - `stream_capture.rs` — sealed `StreamCapture` trait (plan 20)
  - `multi_capture.rs` — `AsyncMultiCapture` + constructors (plan 22)
  - `multi_streams.rs` — `MultiFlowStream`/`MultiSessionStream`/
    `MultiDatagramStream` + `TaggedEvent` (plan 22)
- `src/pcap_tap.rs` — `PcapTap` + `TapErrorPolicy` (plan 20; `pcap + tokio`)
- `src/pcap_source.rs` — `AsyncPcapSource` + `AsyncPcapConfig` +
  `PcapFormat` (plan 23; `pcap + tokio`)
- `src/pcap_flow.rs` — `PcapFlowStream` bridge to flowscope
  (plan 23; `pcap + tokio + flow`)
- `docs/scaling.md` — fanout decision matrix + anti-patterns (plan 22)

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
   needs (currently `0.3`).
2. Verify `netring/Cargo.toml`'s `flowscope` version dep matches
   (default features false; same feature selectors as today).
3. Bump `netring/Cargo.toml` `version` if more changes have landed
   beyond what's in this CHANGELOG.
4. `cargo publish -p netring --dry-run` to verify the package
   contents.
5. `cargo publish -p netring`.

**Known operator gotcha**: on at least one dev machine
`~/.cargo/credentials.toml` is an empty root-owned directory (likely
a misconfigured Docker volume mount). `cargo publish` fails with
"Is a directory". Workarounds: `export CARGO_REGISTRY_TOKEN=<token>`
or `sudo rmdir ~/.cargo/credentials.toml && cargo login`.
