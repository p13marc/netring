# Upstream + future-work tracking

Things waiting on rustc / kernel features, or deliberately deferred. Re-check
at each minor release and update the "Last checked" line.

---

## `gen` blocks (Iterator generator syntax)

- **RFC**: https://rust-lang.github.io/rfcs/3513-gen-blocks.html
- **Tracking issue**: rust-lang/rust #117078
- **Action when stable**: implement `Capture::packets_gen` per SPEC §6.3.
- **Cargo.toml** reserves the `nightly` feature for this.
- **Last checked**: 2026-06-03 — still nightly only.

## `LendingIterator` / GAT iteration in `Iterator`

- **Status**: not on track for stabilization.
- **Workaround in netring**: `PacketBatch<'a>` + `BatchIter<'a>` pair plus
  the `'static`-erasure trick in `Packets` (`src/afpacket/rx.rs`) and
  `AsyncCapture::try_recv_batch` (`src/async_adapters/tokio_adapter.rs`).
  When Polonius lands these workarounds simplify; until then they stay.
- **Last checked**: 2026-06-03.

## Polonius (NLL successor)

- **Tracking issue**: rust-lang/rust #43234
- **Affects**: `ReadableGuard::next_batch` and `AsyncCapture::try_recv_batch`
  use a raw-pointer split because stable's NLL can't see that the Some-arm
  borrow doesn't outlive the None-arm `clear_ready`. Polonius would handle
  the split natively; remove the unsafe blocks once it's stable on the MSRV.
- **Last checked**: 2026-06-03 — `-Znext-solver` previews but no
  stabilization ETA.

## XDP RX metadata extensions

- **Kernel**: 6.0+ via `BPF_PROG_TYPE_XDP` with `xdp_metadata_ops`.
- **Action**: implement `XdpPacket::timestamp()` (currently always returns
  `None`) and populate `OwnedPacket` metadata fields for AF_XDP origin.
  Both are documented as "not yet wired" and are forward-compatible.
- **Tracking**: kernel commit set around v6.0; userland integration still
  evolving (libxdp/aya have partial support).
- **Last checked**: 2026-06-03.

## High-level `SharedUmem` helper

- **Status**: low-level primitive shipped in 0.5.0
  (`XdpSocketBuilder::shared_umem(primary)` — sets `XDP_SHARED_UMEM` and
  passes the primary fd as `sxdp_shared_umem_fd`). Each socket still has
  its own private free-list; users must partition the UMEM range manually.
- **Action**: design and ship a higher-level helper that automates frame
  partitioning across primary + N secondaries, optionally with a shared
  allocator (Mutex-protected or partition-based). Wait for actual user
  code that demands it before settling the threading-model trade-offs.
- **Last checked**: 2026-06-03.

## Unified `PacketBackend` trait

- **Status**: deferred. AF_PACKET `Packet` exposes metadata
  (`direction`, `vlan_tci`, `rxhash`, `status`) that AF_XDP doesn't,
  so a unified trait would force `Option`-wrapped accessors and lose
  ergonomics. Most users pick one backend and stay there.
- **Action**: revisit when there's user code that demands cross-backend
  generic handling.
- **Known consumers waiting on this**: simple-nms (AF_PACKET in
  v1/v2, AF_XDP in v3+); their ARP analyzer reads `vlan_tci` and
  `direction`. See doc 10 §N2.3 in the simple-nms repo for context.
- **Last checked**: 2026-06-03.

## flowscope `serde` feature (G5)

- **Status**: queued in
  [`flowscope-0.8-feedback-2026-06-03.md`](./flowscope-0.8-feedback-2026-06-03.md)
  G5; not yet shipped.
- **Action when shipped**: netring picks up the bump as part of the
  next flowscope-lockstep release (see
  [`netring-0.18-roadmap-2026-06-03.md`](./netring-0.18-roadmap-2026-06-03.md)
  O3 + O4). Unblocks `with_message_tap` (O3) and serde-derive on
  `Anomaly<K>` / `AnomalyContext` / `Severity` (O4).
- **Last checked**: 2026-06-03 — flowscope 0.8 not released.

## flowscope correlate primitives (F6 / G8)

- **Status**: netring shipped its own `netring::correlate` module with
  `KeyIndexed` and `TimeBucketedCounter`. flowscope side still open; if /
  when flowscope ships an equivalent, netring re-exports.
- **Action when shipped**: tag the netring types with a deprecation note
  pointing at `flowscope::correlate::*`; remove on a major.
- **Last checked**: 2026-06-03 — netring keeps its own copy for now.

## CI hardening (post-0.5)

- **Miri** — add `cargo +nightly miri test --features tokio,channel` to
  catch UB in the unsafe-heavy modules (`packet.rs::BatchIter`,
  `afxdp::ring`, `async_adapters::tokio_adapter`).
- **cargo-public-api** — pin the public API once 0.5 is stable, surface
  diffs on PRs.
- **Last checked**: 2026-06-03 — neither blocking, both nice-to-have.

## Anomaly path benchmarks (post-0.16)

- **Status**: untracked. The `ProtocolMonitor` + `AnomalyMonitor` path
  shipped without perf characterization. Open questions: per-event cost,
  rule-count scaling, sweep tick cost, `Vec::take` realloc impact.
- **Action**: tracked as O6 in
  [`netring-0.18-roadmap-2026-06-03.md`](./netring-0.18-roadmap-2026-06-03.md).
- **Last checked**: 2026-06-03 — not yet measured.

## Review cadence

Each minor release: re-check the "Last checked" lines and update or remove
obsolete entries. When an item ships, port the implementation note into the
release CHANGELOG and remove its entry here.
