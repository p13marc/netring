# Plan 11 — Benchmarks + perf baseline

## Summary

Land `criterion` benchmark binaries that measure the hot paths of the
flow stack — extractor, tracker, reassembler — and publish baseline
numbers in the workspace README. Without numbers, the Tier 4 perf
work has nothing to optimize against.

## Status

Not started.

## Prerequisites

- Plans 00–04 complete (the flow stack is the thing being measured).

## Out of scope

- Optimization. This plan only **measures**; Plan 41 acts on the
  results.
- AF_PACKET / AF_XDP capture-side benchmarks. Those already exist in
  `netring/benches/throughput.rs`. We're benchmarking the flow stack.

---

## Goals

1. **Reproducible numbers** for: extractor parse rate, tracker
   `track()` cost at various flow counts, reassembler `segment()`
   cost, full-stack flow-stream throughput against a synthetic
   load.
2. **Comparable baseline** that future PRs can regression-check.
3. **Public README numbers** so users have something to cite.

---

## Files

### NEW

```
netring-flow/benches/
├── extractor.rs       # FiveTuple, IpPair, MacPair, encap variants
├── tracker.rs         # FlowTracker::track at 10k / 100k / 1M flows
└── reassembler.rs     # BufferedReassembler.segment + FlowDriver

netring/benches/
└── flow_stream.rs     # End-to-end synthetic capture → flow events
```

Pre-existing `netring/benches/throughput.rs` keeps its current
focus on capture I/O.

### Test data

`netring-flow/benches/data/`:
- `single_tcp.bin` — synthetic IPv4-TCP frame (built in code, no
  on-disk fixture needed)
- Other synthetic frames are constructed in-bench from
  `extract::parse::test_frames::*` helpers.

---

## Concrete bench targets

### `extractor.rs`

```rust
fn bench_five_tuple_ipv4_tcp(c: &mut Criterion) { ... }
fn bench_five_tuple_ipv6_tcp(c: &mut Criterion) { ... }
fn bench_strip_vlan_then_ipv4_tcp(c: &mut Criterion) { ... }
fn bench_strip_mpls_then_ipv4_tcp(c: &mut Criterion) { ... }
fn bench_inner_vxlan_then_ipv4_tcp(c: &mut Criterion) { ... }
fn bench_inner_gtp_u_then_ipv4_tcp(c: &mut Criterion) { ... }
fn bench_ip_pair(c: &mut Criterion) { ... }
fn bench_mac_pair(c: &mut Criterion) { ... }
```

Each benchmark constructs a frame once, then loops `extractor.extract(view)`.

Target: report ns/iter for each extractor at typical packet sizes
(74-byte SYN, 1500-byte data).

### `tracker.rs`

```rust
fn bench_track_steady_state_10k(c: &mut Criterion) { ... }
fn bench_track_steady_state_100k(c: &mut Criterion) { ... }
fn bench_track_steady_state_1M(c: &mut Criterion) { ... }
fn bench_track_new_flow(c: &mut Criterion) { ... }
fn bench_sweep_idle_5pct(c: &mut Criterion) { ... }
fn bench_lru_evict(c: &mut Criterion) { ... }
```

Steady-state benches pre-fill the tracker with N distinct flows,
then loop `tracker.track(view)` against a randomly-selected
existing flow.

`new_flow` measures the fresh-flow path (allocation + LRU push).

`sweep` measures the cost of walking the table when 5% of flows are
expired.

### `reassembler.rs`

```rust
fn bench_buffered_in_order(c: &mut Criterion) { ... }
fn bench_buffered_take(c: &mut Criterion) { ... }
fn bench_flow_driver_steady_state(c: &mut Criterion) { ... }
```

`flow_driver_steady_state` exercises the full sync stack:
tracker.track + per-segment reassembler dispatch.

### `flow_stream.rs` (in `netring`)

End-to-end bench: synthesize a stream of frames in memory, feed
through `FlowStream`, time per-event consumption.

```rust
fn bench_flow_stream_no_reassembler(c: &mut Criterion) { ... }
fn bench_flow_stream_async_reassembler_channel(c: &mut Criterion) { ... }
```

The async ones use a `current_thread` runtime and `std::hint::black_box`
on consumed events.

---

## Cargo.toml changes

### `netring-flow/Cargo.toml`

```toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "extractor"
harness = false

[[bench]]
name = "tracker"
harness = false

[[bench]]
name = "reassembler"
harness = false
```

### `netring/Cargo.toml`

```toml
[[bench]]
name = "flow_stream"
harness = false
required-features = ["tokio", "flow"]
```

---

## Implementation steps

1. **Add `criterion` dev-dep to `netring-flow`.** Already in workspace
   deps; just inherit.
2. **Write `extractor.rs` bench.** Use `extract::parse::test_frames`
   helpers (made `pub(crate)` in plan 02; promote to `pub` for
   benches by switching to a `pub fn make_frames()` helper or
   re-exposing under `cfg(feature = "bench-helpers")`).
3. **Write `tracker.rs` bench.**
   - Pre-fill helper builds N distinct flows by varying src port:
     `for i in 0..N { ipv4_tcp(..., 1024+i, 80, ...) }`.
4. **Write `reassembler.rs` bench.**
5. **Write `flow_stream.rs` bench in `netring`.** Mocks an `AsyncCapture`
   alternative — actually, `AsyncCapture` requires AF_PACKET. Use a
   different shape: directly drive `FlowTracker` from a tokio task
   over a synthetic `Vec<PacketView>` source. Bench the tracker+stream
   combination, not the capture I/O.
6. **Run benchmarks**: `just bench-flow` (new recipe) generates
   numbers + HTML report under `target/criterion/`.
7. **Document baseline.** Capture the steady-state numbers in
   `docs/PERFORMANCE.md` (new) — include CPU model, OS, Rust
   version, and the criterion summary lines.
8. **Add a README "Performance" section** with the headline number
   (e.g. "1M flow lookups/sec on a single 5GHz core").

---

## Justfile recipes

```
bench-flow:
    cargo bench -p netring-flow

bench-flow-stream:
    cargo bench -p netring --bench flow_stream --features tokio,flow
```

---

## Tests

Benches don't need test coverage themselves, but acceptance includes:

- `cargo bench -p netring-flow --no-run` succeeds.
- `cargo bench -p netring --bench flow_stream --features tokio,flow --no-run`
  succeeds.

---

## Acceptance criteria

- [ ] All four bench files compile (`cargo bench --no-run` clean).
- [ ] Running `just bench-flow` generates a criterion HTML report.
- [ ] Numbers exist in `docs/PERFORMANCE.md` with hardware/version
      context.
- [ ] README has a Performance section linking to PERFORMANCE.md.
- [ ] CI runs `cargo bench --no-run` to catch bench-compile breakage
      (already does for `netring`'s throughput bench; extend to
      flow benches).

---

## Risks

1. **`test_frames` is `pub(crate)`.** Need to expose to benches.
   Cleanest: gate behind a `bench-helpers` feature on `netring-flow`
   that re-exports the test_frames module under `pub mod`. Don't
   make it default — keep it dev-only.
2. **Bench numbers are flaky on shared CI.** GitHub Actions runners
   have noisy neighbors. Solution: run benches locally, document
   the hardware, and treat CI bench-compile-only as a smoke check.
3. **End-to-end async bench needs a synthetic capture source.** A
   `MockCapture` that implements `PacketSource + AsRawFd` would let
   us drive `AsyncCapture` from a `Vec<bytes>`. Skip in v1 — bench
   only the post-capture path.
4. **Baseline numbers will look bad before Plan 41.** That's the
   point — we need a starting line for optimization.

---

## Effort

- LOC: ~600 (~150 per bench file).
- Time: 1 day.

---

## What this unlocks

- Plan 41 (perf foundations) has a concrete optimization target.
- Future PRs can include `cargo bench` diffs to prove they didn't
  regress hot paths.
- Public README numbers strengthen the "high-performance" claim.
