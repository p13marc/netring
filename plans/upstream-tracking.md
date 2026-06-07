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

- **Status**: ✅ shipped in flowscope 0.8 (plan 83) — opt-in
  `Serialize` + `Deserialize` derives on every public event /
  message / accessor type, with locked snake_case wire
  vocabulary.
- **Action**: ✅ adopted in netring 0.17 (`c1ec36b`).
  `netring/serde` Cargo feature derives `Serialize` (not
  `Deserialize` — `&'static str` fields can't roundtrip) on
  `Anomaly<K>` / `AnomalyContext` / `Severity` and ships
  `Anomaly::to_json_value()`. See CHANGELOG.md 0.17.0.
- **Last checked**: 2026-06-07.

## flowscope correlate primitives (F6 / G8)

- **Status**: ✅ shipped — `flowscope::correlate` module with
  `TimeBucketedCounter` + `KeyIndexed` + `SequencePattern`
  (flowscope 0.9) plus `TimeBucketedSet` + `BurstDetector` +
  `TopK` + `Ewma` extensions (flowscope 0.10).
- **Action**: partially adopted in netring 0.17 (`96f8d78`):
  `netring::correlate` re-exports the new extensions
  (`BurstDetector` / `BurstHit` / `Ewma` / `SequencePattern` /
  `KeylessSequencePattern` / `TimeBucketedSet` / `TopK`)
  alongside netring's own `KeyIndexed` + `TimeBucketedCounter`
  (kept because flowscope's `KeyIndexed` lacks `drain_expired`).
  Extensions further adopted in
  [`netring-0.18-unified-driver-refactor-2026-06-07.md`](./netring-0.18-unified-driver-refactor-2026-06-07.md)
  D2–D5 (port_scan, syn_flood_burst, top_n_flows, ewma_rate).
- **Last checked**: 2026-06-07.

## flowscope unified `Driver<E, M>` + `Event<K, M>`

- **Status**: ✅ shipped in flowscope 0.10 (plan 116) — collapses
  the 0.9-era 6-driver / 4-event surface into one. Closes
  netring's long-deferred N5 + N6 in one strike.
- **Action**: tracked in
  [`netring-0.18-unified-driver-refactor-2026-06-07.md`](./netring-0.18-unified-driver-refactor-2026-06-07.md)
  — ProtocolMonitor adopts the unified Driver; ~1300 LoC
  deleted from netring's `async_adapters/session_stream.rs` +
  `datagram_stream.rs`.
- **Last checked**: 2026-06-07.

## flowscope `emit` + `aggregate` + `detect` modules

- **Status**: ✅ shipped in flowscope 0.10. `emit` =
  CSV/NDJSON/Zeek writers (plan 101). `aggregate` = Histogram +
  Percentile (plan 102 sub-B). `detect` = shannon_entropy,
  ngram_distribution, is_base64ish, is_hex_string, etc. (plan
  102 sub-C). `detect::signatures` = magic-byte recognizers
  (plan 113 sub-A).
- **Action**: tracked in
  [`netring-0.18-unified-driver-refactor-2026-06-07.md`](./netring-0.18-unified-driver-refactor-2026-06-07.md)
  D1 (DNS tunnel via shannon_entropy), D7 (Zeek conn.log writer).
- **Last checked**: 2026-06-07.

## flowscope MSRV bump (1.85 → 1.88)

- **Status**: ✅ shipped in flowscope 0.9 (plan 99) — let-chains
  at expression position. AFIT + async closures + trait
  upcasting also available within the new MSRV.
- **Action**: ✅ verified during netring 0.17 lockstep bump
  (`151901e`). netring's MSRV 1.95 satisfies flowscope's 1.88
  without change.
- **Last checked**: 2026-06-07.

## CI hardening (post-0.5)

- **Miri** — add `cargo +nightly miri test --features tokio,channel` to
  catch UB in the unsafe-heavy modules (`packet.rs::BatchIter`,
  `afxdp::ring`, `async_adapters::tokio_adapter`).
- **cargo-public-api** — pin the public API once 0.5 is stable, surface
  diffs on PRs.
- **Last checked**: 2026-06-03 — neither blocking, both nice-to-have.

## Anomaly path benchmarks (post-0.16)

- **Status**: ✅ shipped 2026-06-03 (commit `fb9bdc0`,
  `benches/anomaly.rs`). 8 criterion benches / 13 input
  parameterizations. Baseline numbers pinned in the bench file's
  module rustdoc. Re-run after each refactor:
  `cargo bench --bench anomaly --features ... -- --save-baseline X`.
- **Last checked**: 2026-06-07.

## Review cadence

Each minor release: re-check the "Last checked" lines and update or remove
obsolete entries. When an item ships, port the implementation note into the
release CHANGELOG and remove its entry here.
