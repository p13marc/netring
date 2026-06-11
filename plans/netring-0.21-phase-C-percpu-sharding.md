# netring 0.21 Phase C — Per-CPU sharding

## 1. Summary

Implement `MonitorBuilder::fanout_per_cpu(iface, mode)` so netring scales past the ~2 Mpps single-CPU ceiling. Each shard runs its own `Dispatcher`, `StateMap`, `CounterRegistry`, and `Sink` on a dedicated OS thread with its own `current_thread` tokio runtime. A periodic merge worker folds per-shard state into a primary.

The phase depends on Phase A.1 (the `Arc<dyn Fn>` handler-storage swap) to make handlers cloneable across shards. The architecture itself is unchanged from the original 0.20 Phase F plan — that plan deferred F.3 to 0.21 specifically to resolve this handler-cloning question.

## 2. Status

Not started. The longest phase in 0.21 (~5 days). Depends on Phase A.1.

## 3. Prerequisites

- Phase A.1 — `BoxedHandler = Arc<dyn Fn + Send + Sync>` storage swap. Without this, building N per-shard dispatchers requires either a `Fn + Clone` bound on user handlers or handler-factory closures (both API churn).
- Phase B.4 — `Tee::factory(|| sink)` for per-shard secondary sinks.
- flowscope 0.13.0 — `Driver<E>: Send + Sync` makes the per-shard thread spawn clean. Without this, each shard would need `LocalSet` glue. Shipped upstream.

## 4. Out of scope

- AF_XDP per-CPU mode. AF_PACKET via `PACKET_FANOUT_CPU` only. AF_XDP arrives in 0.22+ via a separate plan if a consumer asks.
- Cross-shard correlation. Each shard is independent; the merge worker only aggregates state via user-supplied closures.
- Multi-interface + sharding. `fanout_per_cpu(iface, …)` takes one interface; combining with `.interfaces([…])` is a `BuildError`.

## 5. Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/monitor/dispatcher.rs` | `Dispatcher::clone_for_shard(&self) -> Self` (added in Phase A.1) |
| Modify | `src/monitor/mod.rs` | `MonitorBuilder::fanout_per_cpu` / `.merge_state::<T>` / `.merge_interval` / `.sink_factory` |
| New | `src/monitor/shard.rs` | `ShardedMonitor` + `MonitorShard` + merge worker + per-shard run loop |
| Modify | `src/monitor/run.rs` | Branch on `(SingleShard | Sharded)` at top of `run_loop` |
| Modify | `src/error.rs` | `BuildError::FanoutWithoutMerge { type_name }`, `BuildError::FanoutWithMultiInterface` |
| New | `tests/shard_2cpu.rs` | 2-shard end-to-end on `lo` with a known synthetic flow, assert per-shard counters merge correctly |
| New | `tests/shard_merge_addassign.rs` | `T: AddAssign + Default` auto-merge path |
| New | `tests/shard_merge_missing.rs` | Sharded + `state::<T>()` without `merge_state` → `BuildError::FanoutWithoutMerge` |

LoC estimates: ~750 LoC new (~400 LoC shard plumbing, ~200 LoC merge worker, ~150 LoC tests).

## 6. API

### C.1 — `Dispatcher::clone_for_shard` (already in Phase A.1)

```rust
impl Dispatcher {
    pub(crate) fn clone_for_shard(&self) -> Self {
        Self {
            slot_by_type: self.slot_by_type.clone(),
            slots: self.slots.iter().map(|v| {
                v.iter().map(|s| HandlerSlot { handler: Arc::clone(&s.handler) }).collect()
            }).collect::<Vec<_>>().into_boxed_slice(),
            async_slots: /* same shape */,
        }
    }
}
```

Refcount-bump per slot. O(handler-count) — practically free.

### C.2 — Counter spec + protocol spec separation

`MonitorBuilder::counter::<K>(window, bucket)` today constructs the `TimeBucketedCounter<K>` immediately. For sharded build, the builder records the `(window, bucket)` tuple and constructs N counters at shard-build time.

```rust
struct CounterSpec {
    type_id: TypeId,
    window: Duration,
    bucket: Duration,
    factory: Box<dyn Fn() -> Box<dyn AnyCounter> + Send + Sync>,
}
```

Same for protocols: `MonitorBuilder::protocol::<P>()` records `TypeId::of::<P>()` + `P::dispatch()`. `P::register(&mut driver_builder)` moves to build-time, per shard.

### C.3 — `MonitorShard` + sink factory

```rust
// src/monitor/shard.rs
pub(crate) struct MonitorShard {
    cpu: usize,
    dispatcher: Dispatcher,
    state_map: StateMap,
    counters: CounterRegistry,
    sink: Box<dyn AnomalySink>,
    protocol_slots: Vec<Box<dyn ProtocolSlot>>,
    tick_handlers: Vec<TickRegistration>,
    iface: String,
    fanout_mode: FanoutMode,
}

impl MonitorBuilder {
    pub fn sink_factory<S, F>(mut self, factory: F) -> Self
    where S: AnomalySink + 'static, F: Fn() -> S + Send + Sync + 'static {
        self.sink_factory = Some(Box::new(move || Box::new(factory()) as Box<dyn AnomalySink>));
        self
    }
}
```

### C.4 — `fanout_per_cpu` + `ShardedMonitor` + per-shard run loop

```rust
pub use flowscope::FanoutMode;  // re-export (Hash | Cpu | QM | EBPF | LB)

impl MonitorBuilder {
    pub fn fanout_per_cpu(mut self, iface: impl Into<String>, mode: FanoutMode) -> Self {
        self.fanout = Some(FanoutConfig { interface: iface.into(), mode });
        self
    }
}

/// Public `Monitor` type is opaque — internal enum dispatch hides
/// whether the user opted for single-shard or sharded operation.
/// Methods (`run_for`, `run_until_signal`, `run_until`, `replay`,
/// `subscribe`) work identically against both variants.
pub struct Monitor {
    inner: MonitorInner,
}

// Private — user code never spells this.
enum MonitorInner {
    SingleShard(SingleShardMonitor),
    Sharded(ShardedMonitor),
}

struct ShardedMonitor {
    shards: Vec<MonitorShard>,
    merge_closures: HashMap<TypeId, MergeClosure>,
    merge_interval: Duration,
    primary_state: StateMap,
}
```

Run loop spawns N OS threads via `std::thread::spawn`. Each shard's thread builds a `tokio::runtime::Builder::new_current_thread().build()?` runtime and drives its own packet stream.

Public `Monitor::shard_count() -> usize` exposes the runtime count (`1` for single-shard, `N` for sharded). Lets users instrument without breaking the opaque-type discipline.

### C.5 — `merge_state` + auto-merge + merge worker

```rust
impl MonitorBuilder {
    pub fn merge_state<T, F>(mut self, merge: F) -> Self
    where T: Default + Send + 'static, F: Fn(&mut T, T) + Send + Sync + 'static
    { … }

    /// Convenience for `T: AddAssign + Default`.
    pub fn state_auto_merge<T>(self) -> Self
    where T: AddAssign + Default + Send + 'static
    {
        self.merge_state::<T, _>(|acc, b| *acc += b)
    }

    pub fn merge_interval(mut self, period: Duration) -> Self {
        self.merge_interval = Some(period);
        self
    }
}
```

Merge worker shape (runs in its own thread):
1. `tokio::time::sleep(merge_interval).await`.
2. For each shard, send a snapshot request via `mpsc::UnboundedSender<ShardSnapshot>`.
3. Each shard responds with `mem::take`-d state slots.
4. Worker folds via the registered merge closures.
5. Optionally re-broadcast back to shards (not in 0.21 — folds into primary only).

### C.6 — `LayerSpec` trait + `Tee::factory`

```rust
pub trait LayerSpec: Send + Sync + 'static {
    fn instantiate(&self) -> Box<dyn Layer>;
}

impl<L: Layer + Clone + Send + Sync + 'static> LayerSpec for L {
    fn instantiate(&self) -> Box<dyn Layer> { Box::new(self.clone()) }
}
```

`Tee::factory(|| StdoutSink::default())` (added in Phase B.4) covers the non-Clone secondary case.

## 7. Implementation steps

1. **C.1** lands in Phase A.1.
2. **C.2** — refactor `MonitorBuilder` to record counter / protocol specs instead of constructing immediately. Single-shard `build()` path delegates to per-shard logic with N=1.
3. **C.3** — write `MonitorShard` + `sink_factory`.
4. **C.4** — write `fanout_per_cpu` + `ShardedMonitor` + per-shard thread spawn. Each shard opens its AF_PACKET ring with `FanoutMode::Cpu`.
5. **C.5** — merge worker spawn + closure registry + `BuildError::FanoutWithoutMerge` if a state type is registered without a merge closure (and isn't `AddAssign`).
6. **C.6** — `LayerSpec` trait + per-shard layer instantiation.

## 8. Tests

- `tests/shard_2cpu.rs` — opens `lo` with `fanout_per_cpu("lo", FanoutMode::Cpu)`, 2 shards. Registers `state::<Counters>().state_auto_merge::<Counters>()`. Synthetic traffic drives `Arc<AtomicU64>` counters; merge worker runs once; final state is the sum.
- `tests/shard_merge_addassign.rs` — `T: AddAssign` is auto-registered as merge; no explicit `merge_state` needed.
- `tests/shard_merge_missing.rs` — `state::<NonAddT>()` without `merge_state` returns `BuildError::FanoutWithoutMerge { type_name: "NonAddT" }`.
- `tests/shard_layer_per_shard.rs` — `.layer(DedupeAnomalies::within(60s))` applied per shard (each shard has its own dedup window, not a global one).

Root-gated where `AsyncCapture::open` is needed.

## 9. Acceptance criteria

- 2-shard test on `lo` passes.
- Per-shard handler counts (sum across shards) equals the original synthetic traffic count.
- `fanout_per_cpu` + `interface("lo")` returns `BuildError::FanoutWithMultiInterface`.
- Zero-alloc bench still passes when sharding is configured (each shard's hot path is unchanged from single-shard).

## 10. Risks

- **R1 — flowscope `SlotHandle` Send semantics across shards.** Each shard owns its own `Driver<E>` + its own slot handles. Handles never cross shards. Verified safe (`SlotHandle: Send + Sync` since flowscope 0.13.0).
- **R2 — `current_thread` runtime per OS thread.** Each shard thread runs `tokio::runtime::Builder::new_current_thread()`. The runtime is per-shard — shards don't share tokio infrastructure.
- **R3 — Merge worker contention.** `mpsc::UnboundedSender` from shards → worker is the only cross-thread path. `unbounded` is justified because merge is on a fixed cadence (one snapshot per interval per shard).
- **R4 — Merge-on-shutdown.** If the run loop exits between merge ticks, in-flight per-shard state is lost. Mitigation: final merge during shutdown drain (Phase D.2 graceful drain).
- **R5 — `flowscope::SlotHandle::clone` is competitive consumption (MPMC).** If two shards' slot handles somehow share an `Arc`, messages get split. Each shard's handles are built from scratch; verify no sharing. Documented invariant.

## 11. Effort

- LoC delta: +750 (shard plumbing ~400, merge worker ~200, tests ~150).
- Time estimate: **~5 days**.

## 12. Provenance

- 0.20 Phase F splits into F.1 (multi-interface, shipped), F.2 (tick handlers, shipped), F.3 (this plan).
- F.3 was deferred from 0.20 specifically to resolve the handler-cloning question. The `Arc<dyn Fn>` analysis (originally in `netring-0.20-phase-F3-handler-cloning-analysis.md`, deleted) found the storage swap is one-line and zero-API-impact. That swap moved to Phase A.1; this phase is the actual sharded-monitor implementation.
- Suricata's `workers` runmode is the architectural prior art: one detect thread per CPU, signatures (handlers) shared read-only via `DetectEngineCtx*`. The `Arc<dyn Fn>` shape maps to this exactly.
