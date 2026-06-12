# netring 0.22 roadmap

## 1. Summary

Four classes of work for the next cycle:

1. **Legacy API deletion.** The 0.19 trio
   (`ProtocolMonitor`, `ProtocolMonitorBuilder`, `AnomalyMonitor`,
   `AnomalyRule`, `FlowAnomalyRule`) are `#[deprecated(since =
   "0.21.0")]` and slated for removal in 0.22.0. Mechanical
   delete, plus a cleanup pass on internal demo code that still
   uses them.
2. **Phase C deferrals.** The 0.21 `ShardedRunner` shipped with
   the merge worker + `LayerSpec` documented as deferrals. 0.22
   ships them properly.
3. **Phase G follow-up.** netring's local `KeyIndexed` waits on
   flowscope adding `drain_expired(now) -> impl Iterator<Item =
   (K, V)>` upstream. Either re-export when that lands, or
   formally adopt the netring version as the canonical
   implementation and write it back into flowscope.
4. **0.21 sweep follow-ups.** Items surfaced by the
   `0.21-doc-sweep-issues.md` retrospective: tiny API polish
   (`MinSeverity::info()`), the deferred `multi_thread_default`
   example reframed honestly as a Send-caveat demo, a research
   item on whether `Monitor::run_for`'s future can be made
   `Send`, and CI hygiene for clippy doc lints. None are
   blockers; bundled here so they don't drift.

## 2. Status

Open. No commits yet on a `0.22-dev` branch.

## 3. Prerequisites

- 0.21.0 cut + tagged.
- flowscope 0.14 (or later) shipping the `drain_expired` /
  `into_iter_expired` method for `KeyIndexed`. Track via
  flowscope's plans/ directory.

## 4. Items

### 0.22-D — Legacy delete (the "D" stands for "delete")

Files to remove or trim outright:

- `netring/src/protocol/monitor.rs` — delete
- `netring/src/anomaly/monitor.rs` — delete
- `netring/src/anomaly/rule.rs` — keep `Anomaly`,
  `AnomalyContext`, `Severity` value types (they're still used
  by the new sinks); delete the `AnomalyRule` trait
- `netring/src/anomaly/builtin.rs` — delete (`FlowAnomalyRule`)
- 11 examples under `netring/examples/anomaly/` that still use
  the legacy API — delete or rewrite against
  `Monitor::builder()` + `detector!` / `pattern_detector!`
- 3 tests (`tests/anomaly_monitor_smoke.rs`,
  `tests/anomaly_new_detectors.rs`, `tests/anomaly_pcap_replay.rs`)
  — delete; the equivalent coverage is in the new test files
- `netring/benches/anomaly.rs` — delete; the dhat bench in
  `benches/zero_alloc.rs` is the canonical perf gate now
- Re-export sites in `src/lib.rs`, `src/anomaly/mod.rs`,
  `src/protocol/mod.rs` — delete the deprecated names
- All the `#![allow(deprecated)]` shields shipped in
  `netring 0.21 H.3` — delete (no longer needed)

LoC delta: roughly **-3500** (the legacy API surface + its
demo code is substantial).

CHANGELOG entry: under `## 0.22.0`, lead with the deletion.

### 0.22-C.5 — Cross-shard state merging

The 0.21 `ShardedRunner` documented its lack of merge as:

> users wanting global aggregation today route per-shard
> anomalies through a `Tee + ChannelSink` to a single collator
> task, or use a sharded metrics backend.

0.22 ships the merge worker that the original Phase C plan
called for. Sketch:

```rust
impl ShardedRunner {
    pub fn merge_state<T, F>(self, period: Duration, merge: F) -> Self
    where T: Default + Send + 'static,
          F: Fn(&mut T, T) + Send + Sync + 'static;

    pub fn state_auto_merge<T>(self, period: Duration) -> Self
    where T: AddAssign + Default + Send + 'static;
}
```

The runner spawns one more OS thread (the merge worker) that
periodically (`period` cadence) probes each shard via an
`mpsc::UnboundedSender<ShardSnapshot>` to ask for a `mem::take`
of its `T` slot, then folds into a `primary_state: StateMap`.

Implementation outline:

- `MonitorShard` (renamed from the closure-built `Monitor`)
  gains a `mpsc::Receiver<MergeRequest>` it polls in the run
  loop's `tokio::select!`.
- Run-loop branch for the merge request: `let value =
  mem::take(state_map.get_or_init_mut::<T>()); reply.send(value)?;`
- Worker thread on `tokio::time::interval`: send `(MergeRequest,
  reply)` to each shard, await all replies, fold into primary.

Plus a `BuildError::FanoutWithoutMerge { type_name }` variant
that fires when a state type is registered via
`MonitorBuilder::state::<T>()` but no merge closure was
declared (and `T` doesn't impl `AddAssign`).

### 0.22-C.6 — `LayerSpec` trait

Layers like `MinSeverity::warning()` are `Clone`-able. Layers
like `DedupeAnomalies::within(...)` carry a per-shard dedup
table and shouldn't be cloned. The plan called for:

```rust
pub trait LayerSpec: Send + Sync + 'static {
    fn instantiate(&self) -> Box<dyn Layer>;
}

impl<L: Layer + Clone + Send + Sync + 'static> LayerSpec for L {
    fn instantiate(&self) -> Box<dyn Layer> { Box::new(self.clone()) }
}
```

`ShardedRunner::layer<L: LayerSpec>(layer)` would replace the
need to write `Tee::factory(|| ...)` for every secondary sink.

### 0.22-G — Re-export `KeyIndexed` from flowscope

When flowscope ships `KeyIndexed::drain_expired(now) -> impl
Iterator<Item = (K, V)>` (or an equivalent), netring drops its
local copy and re-exports. The Phase G partial deferral note
documented the specific signature gap.

Until then, leave `netring::correlate::KeyIndexed` local.

### 0.22-quality — `multi_thread_default.rs` Send-caveat demo

The 0.21 Phase H plan called for a dedicated
`examples/monitor/multi_thread_default.rs` showing the Send
sweep payoff explicitly. The retrospective in
`0.21-doc-sweep-issues.md` revised the framing: `Monitor: Send`
is real (`tests/monitor_send.rs` asserts it) but the *future*
returned by `Monitor::run_for` / `run_until_signal` stays
`!Send` because the run loop borrows the `!Sync` mmap ring
across awaits.

The example should therefore demonstrate *both* halves:
- Plain `#[tokio::main]` works — no `flavor = "current_thread"`
  ceremony needed (the Send-value payoff).
- `tokio::spawn(monitor.run_for(...))` does NOT compile —
  the example calls it out with a `compile_fail` doctest block
  or a commented-out variant, then shows the working pattern
  (`tokio::select!` to multiplex the run loop with shutdown
  sources / subscribers, plus `ChannelSink` for cross-task
  anomaly delivery).

~50 LoC, three blocks: (1) the no-ceremony case, (2) the
`!Send` foot-gun, (3) the `tokio::select!` + `ChannelSink`
recovery. Higher priority than the original 0.21 H.5 spec
because it documents a real surprise users will otherwise hit.

### 0.22-quality — `MinSeverity::info()` constant

One-line API addition: `pub const fn MinSeverity::info() -> Self`
aliasing `Self::at_least(Severity::Info)`. The
`warning()` / `error()` constructors already exist; `info()`
was omitted because Info-floor is a no-op for the common case,
but the asymmetric surface is a foot-gun (caught in the
0.21 sweep — see `0.21-doc-sweep-issues.md` §2a). Add it +
update the rustdoc note on `at_least` to point at all three.

### 0.22-S — Send-future investigation (research)

`tests/monitor_send.rs` asserts `Monitor: Send`,
`MonitorBuilder: Send`, `ShardedRunner: Send`,
`EventStream<M>: Send`. The retrospective flagged that the
future returned by `Monitor::run_for(d).await` is **not**
`Send`, because `AsyncCapture<S>` borrows the `!Sync` mmap
ring across awaits. This means `tokio::spawn(monitor.run_for(d))`
fails to compile — a surprise relative to the "Send Monitor"
headline.

Investigation scope:
- Identify whether `dispatch_lifecycle` / `next_batch` /
  `try_recv_batch` can be reshaped so the run-loop future
  doesn't borrow the `!Sync` ring across await points.
- Likely options:
  1. **Owned-batch run path** — switch the live capture path
     to `AsyncCapture::recv()` (`Vec<OwnedPacket>`, `Send`)
     instead of the borrowed `try_recv_batch()`. Costs one
     copy per packet per batch — measure against the
     `benches/zero_alloc.rs` dhat regression gate.
  2. **`tokio::task::spawn_local` adapter** — ship a
     `Monitor::spawn_local()` helper that wraps the run loop
     in a `LocalSet`, documenting the constraint explicitly
     instead of trying to lift it.
  3. **Status quo + better docs** — accept the constraint as
     structural, sharpen the `MIGRATING_0.20_TO_0.21.md` /
     `ASYNC_GUIDE.md` story (commit `761b6d4` already started
     this), and ship the H.5 demo above to make the pattern
     concrete.

Output: a written recommendation in
`plans/netring-0.22-send-future-decision.md` before any
implementation. Likely lands as option 3 (the perf trade-off
in option 1 is real) plus the H.5 example, but the analysis
is worth doing.

### 0.22-quality — clippy doc-lint CI gate

clippy 1.95's `doc_lazy_continuation` lint fires on rustdoc
that re-exports README.md (via `#![doc = include_str!("../README.md")]`
or similar). Bug fixed in commit `761b6d4`, but the lint will
trip again as the README evolves and the existing CI matrix
doesn't surface it before merge. Add a `cargo clippy -p
netring --features monitor-quickstart --all-targets -- -D
warnings` row that builds the rustdoc, not just the binary,
so README-driven doc lints surface in PR review instead of
post-merge.

### 0.22-docs — `MIGRATING_0.20_TO_0.21.md` Send caveat

Not strictly 0.22 (could land in the 0.21 release-gates
sweep), but listed here in case 0.21.0 ships before this
note lands. The migration guide tells users to drop
`flavor = "current_thread"` without the asterisk that the
run-loop future is still `!Send`. Add a paragraph mirroring
the README + ASYNC_GUIDE edits from commit `761b6d4`. ~10
lines.

## 5. Non-goals

- AF_XDP per-CPU mode. AF_PACKET fanout is the supported path;
  AF_XDP shows up later if a consumer asks.
- Cross-shard correlation. Each shard stays independent; the
  merge worker only aggregates state via user-supplied closures,
  it doesn't enable cross-shard event lookup.
- Multi-interface + sharding combination. The
  closure-builder pattern actively forbids this by virtue of
  taking `iface: impl Into<String>` (singular).

## 6. Open questions

- Should `merge_state::<T>` default to `AddAssign` auto-merge
  when `T: AddAssign + Default + Send + 'static`? Saves the
  explicit `state_auto_merge` setter. Trade-off: ambiguity if
  the user wants a different merge for an `AddAssign` type.
- `LayerSpec` could be implemented for `Fn() -> Box<dyn Layer>`
  the same way `Tee::factory` works. Two construction shapes
  on the same trait, mirrors the `Tee::into` / `Tee::factory`
  split.
- 0.22-S: is the per-packet copy cost of an owned-batch run
  path acceptable? `benches/zero_alloc.rs` currently asserts
  Δ 0 bytes / 0 blocks on dispatch — switching from borrowed
  batches to `Vec<OwnedPacket>` breaks that invariant. The
  research item should quantify the regression before any
  code change.

## 7. Provenance

- 0.21 Phase C plan, §C.5 + §C.6 (deferred at ship time,
  documented in `netring/src/monitor/shard.rs` lines 12–16).
- 0.21 Phase G plan, partial-ship deferral (re-export
  `KeyIndexed` once flowscope adds `drain_expired`).
- 0.21 Phase H plan, §H.5 (multi_thread_default example).
- 0.21 deprecation notes on the legacy 0.19 API surface.
- `0.21-doc-sweep-issues.md` retrospective (recommendations
  §2a, §4, §5, plus the framing revision for H.5).

## 8. Effort

- 0.22-D (legacy delete): ~1 day. Mechanical.
- 0.22-C.5 (merge worker): ~3 days. The deferred bulk of
  Phase C from 0.21.
- 0.22-C.6 (LayerSpec): ~1 day. Glue + tests.
- 0.22-G: blocked on flowscope; ~30 min once the upstream
  change lands.
- 0.22-quality `multi_thread_default` example: ~2 hours
  (3 blocks + `compile_fail` doctest).
- 0.22-quality `MinSeverity::info()`: ~15 minutes (one const
  + rustdoc cross-link).
- 0.22-S Send-future investigation: ~1 day analysis + write-up.
  Implementation effort depends on which option lands.
- 0.22-quality clippy doc-lint CI row: ~30 min.
- 0.22-docs migration guide Send caveat: ~30 min (may land in
  0.21 release gates instead).

Total: still about a week of focused work plus flowscope-side
coordination. The new items are mostly polish; only 0.22-S
could grow if option 1 (owned-batch run path) is chosen.
