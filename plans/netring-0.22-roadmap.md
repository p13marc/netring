# netring 0.22 roadmap

## 1. Summary

Three classes of work for the next cycle:

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

### 0.22-quality — `Phase H.5 multi_thread_default.rs example`

The 0.21 Phase H plan called for a dedicated
`examples/monitor/multi_thread_default.rs` showing the Send
sweep payoff explicitly. The 0.21 sweep dropped
`flavor = "current_thread"` from every monitor example, so
this is essentially "any monitor example already demonstrates
the multi-thread default" — but a brief, focused example
(maybe 30 LoC) that emphasizes the `#[tokio::main]` no-ceremony
pattern still has value. Carry it as a low-priority polish
item.

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

## 7. Provenance

- 0.21 Phase C plan, §C.5 + §C.6 (deferred at ship time,
  documented in `netring/src/monitor/shard.rs` lines 12–16).
- 0.21 Phase G plan, partial-ship deferral (re-export
  `KeyIndexed` once flowscope adds `drain_expired`).
- 0.21 Phase H plan, §H.5 (multi_thread_default example).
- 0.21 deprecation notes on the legacy 0.19 API surface.

## 8. Effort

- 0.22-D (legacy delete): ~1 day. Mechanical.
- 0.22-C.5 (merge worker): ~3 days. The deferred bulk of
  Phase C from 0.21.
- 0.22-C.6 (LayerSpec): ~1 day. Glue + tests.
- 0.22-G: blocked on flowscope; ~30 min once the upstream
  change lands.
- 0.22-H.5 example: ~1 hour.

Total: about a week of focused work plus flowscope-side
coordination.
