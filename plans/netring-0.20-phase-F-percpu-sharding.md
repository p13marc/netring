# netring 0.20 — Phase F: Per-CPU sharding + state merging

**Effort:** 3–4 days
**Predecessor:** [`Phase E`](./netring-0.20-phase-E-macro-prelude.md) — macro + prelude + multi-iface
**Successor:** [`Phase G`](./netring-0.20-phase-G-migration-release.md) — migration + docs + release

## 1. Goal

Make netring scale past single-CPU saturation (~2 Mpps on commodity hardware). After this phase:

- `MonitorBuilder::fanout_per_cpu(iface, mode)` opens N AF_PACKET rings (one per CPU) via `PACKET_FANOUT_CPU`.
- Each shard runs its own `Dispatcher`, `StateMap`, `CounterRegistry`, `Sink`.
- No cross-CPU `Arc<Mutex>` traffic during steady-state dispatch.
- `MonitorBuilder::merge_state::<T>(|a, b| ...)` registers per-type merge closures.
- A periodic merge loop (configurable interval) folds per-CPU state into a primary instance and re-publishes.
- Tick handlers fire after merge boundaries so they see merged state.

The goal is *linear scaling to 32+ cores* on a typical high-PPS workload — Suricata-style architecture.

## 2. Scope

### In
- `MonitorBuilder::fanout_per_cpu(iface, FanoutMode)` builder method.
- `MonitorBuilder::merge_state::<T>(merge_fn)` per-type merge registration.
- `MonitorBuilder::merge_interval(Duration)` to set the merge cadence.
- `ShardedMonitor` internal type holding `Vec<MonitorShard>`.
- Per-shard run loop on `tokio::task::spawn_local` or per-thread runtime.
- Periodic merge worker — merges all shards' state into the primary shard, then re-broadcasts (or accumulates).
- Tick scheduling integrated with the merge cycle.
- Tests covering: 2-shard merge, 4-shard merge, default-AddAssign auto-merge, merge-missing build error.

### Out
- Migration recipes / docs — Phase G.
- AF_XDP per-CPU mode — out of scope for 0.20; documented as a future addition.

## 3. Dependencies

- Phase E merged: multi-interface, prelude, detector!.
- `AsyncMultiCapture` from netring 0.13 — supports `FanoutMode::Cpu` already.
- No new external dependencies.

## 4. Module layout

```
src/
├── monitor/
│   ├── shard.rs                  A  — ShardedMonitor + MonitorShard + merge worker
│   ├── mod.rs                    M  — MonitorBuilder::fanout_per_cpu + merge_state + merge_interval
│   └── run.rs                    M  — branch on (single-shard | sharded) run mode
│
├── error.rs                      M  — BuildError::FanoutWithoutMerge
│
tests/
├── shard_2cpu.rs                 A  — 2-shard monitor + merge correctness
├── shard_merge_missing.rs        A  — sharded + State<T> without merge_state fails build
└── shard_addassign_auto.rs       A  — T: AddAssign auto-merges without user-provided merge
```

**LoC estimates:** ~700 LoC new (~400 LoC shard plumbing, ~200 LoC merge worker, ~100 LoC tests).

## 5. Detailed deliverables

### 5.1 `FanoutMode` + builder method

netring already re-exports `flowscope::FanoutMode` (Hash/Cpu/QM/EBPF/LB). For per-CPU sharding we pin to `Cpu` initially; future revisions could allow `Hash` for flow-pinned shards.

```rust
impl MonitorBuilder {
    /// Open N AF_PACKET rings (one per CPU) via PACKET_FANOUT_CPU.
    /// Each shard runs its own Dispatcher + StateMap + Sink in a
    /// dedicated current_thread runtime.
    ///
    /// Mutually exclusive with `interfaces(...)` / `interface(...)`.
    /// Use `.fanout_per_cpu` OR `.interfaces`, not both.
    pub fn fanout_per_cpu(
        mut self,
        iface: impl Into<String>,
        mode: crate::FanoutMode,
    ) -> Self {
        self.fanout = Some(FanoutConfig {
            interface: iface.into(),
            mode,
        });
        self
    }

    /// Register a merge closure for state of type T. Required when
    /// `fanout_per_cpu` is used with `state::<T>()` unless T
    /// implements `AddAssign` (then auto-merge via `+=`).
    pub fn merge_state<T, F>(mut self, merge: F) -> Self
    where T: Default + Send + 'static,
          F: Fn(&mut T, T) + Send + Sync + 'static
    {
        self.merge_closures.insert(
            TypeId::of::<T>(),
            Box::new(move |a: &mut Box<dyn Any + Send>, b: Box<dyn Any + Send>| {
                let a = a.downcast_mut::<T>().expect("merge invariant: T matches");
                let b = *b.downcast::<T>().expect("merge invariant: T matches");
                merge(a, b);
            }),
        );
        self
    }

    /// Set the per-CPU merge cadence. Defaults to 5 seconds.
    pub fn merge_interval(mut self, period: Duration) -> Self {
        self.merge_interval = Some(period);
        self
    }
}

#[derive(Debug, Clone)]
struct FanoutConfig {
    interface: String,
    mode: crate::FanoutMode,
}

type MergeClosure = Box<
    dyn Fn(&mut Box<dyn Any + Send>, Box<dyn Any + Send>) + Send + Sync,
>;
```

### 5.2 `MonitorShard` + `ShardedMonitor`

```rust
//! Per-CPU sharded monitor.

use std::any::{Any, TypeId};
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;
use tokio::sync::mpsc;

use crate::ctx::{Ctx, CounterRegistry, SourceIdx, StateMap};
use crate::error::Result;
use crate::monitor::dispatcher::Dispatcher;
use crate::monitor::registry::ProtocolSlot;

/// A single per-CPU shard.
pub(crate) struct MonitorShard {
    pub cpu: usize,
    pub dispatcher: Dispatcher,
    pub protocol_slots: Vec<Box<dyn ProtocolSlot>>,
    pub state_map: StateMap,
    pub counters: CounterRegistry,
    pub sink: Box<dyn crate::anomaly::sink::AnomalySink>,
}

/// The sharded monitor wraps N shards + the merge worker.
pub(crate) struct ShardedMonitor {
    pub shards: Vec<MonitorShard>,
    pub merge_closures: FxHashMap<TypeId, MergeClosure>,
    pub merge_interval: Duration,
    pub fanout: FanoutConfig,
}

impl ShardedMonitor {
    /// Spawn one task per shard + one merge task. Each shard task
    /// runs a current_thread runtime; the merge task runs on the
    /// caller's tokio runtime.
    pub async fn run_loop(self, stop: StopCondition) -> Result<()> {
        let n_shards = self.shards.len();
        let mut shard_handles = Vec::with_capacity(n_shards);

        // Inter-shard channel: each shard sends its `(TypeId,
        // Box<dyn Any>)` state snapshots to the merge worker
        // on each merge tick.
        let (snap_tx, mut snap_rx) =
            mpsc::unbounded_channel::<ShardSnapshot>();

        for shard in self.shards.into_iter() {
            let snap_tx = snap_tx.clone();
            let merge_interval = self.merge_interval;
            let fanout = self.fanout.clone();
            let handle = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("failed to build shard runtime");
                rt.block_on(run_one_shard(shard, snap_tx, merge_interval, fanout));
            });
            shard_handles.push(handle);
        }

        drop(snap_tx);

        // Merge worker — receives snapshots, folds via merge closures.
        let merge_closures = self.merge_closures;
        let merge_handle = tokio::spawn(async move {
            let mut accumulated: FxHashMap<TypeId, Box<dyn Any + Send>>
                = FxHashMap::default();
            while let Some(snap) = snap_rx.recv().await {
                for (type_id, value) in snap.into_iter() {
                    if let Some(merge) = merge_closures.get(&type_id) {
                        if let Some(existing) = accumulated.get_mut(&type_id) {
                            merge(existing, value);
                        } else {
                            accumulated.insert(type_id, value);
                        }
                    }
                }
            }
            // accumulated now contains merged state; emit via a
            // user-facing channel or log.
        });

        // Wait for all shards.
        for h in shard_handles {
            let _ = h.join();
        }
        let _ = merge_handle.await;
        Ok(())
    }
}

type ShardSnapshot = Vec<(TypeId, Box<dyn Any + Send>)>;

async fn run_one_shard(
    mut shard: MonitorShard,
    snap_tx: mpsc::UnboundedSender<ShardSnapshot>,
    merge_interval: Duration,
    fanout: FanoutConfig,
) {
    // Open the AF_PACKET ring for THIS CPU.
    let cap = crate::AsyncCapture::open_with_fanout(
        &fanout.interface,
        fanout.mode,
        Some(shard.cpu),
    )
    .expect("open per-cpu ring");
    let mut packet_stream = cap.into_stream();

    let mut merge_timer = tokio::time::interval(merge_interval);

    loop {
        tokio::select! {
            biased;
            packet = packet_stream.next() => {
                let Some(Ok(packet)) = packet else { break };
                let view = flowscope::PacketView::new(&packet.data, packet.timestamp);
                // ... track_into + dispatch (Phase E run loop) ...
                let _ = view;
            }
            _ = merge_timer.tick() => {
                // Snapshot per-TypeId state. The clone protocol
                // depends on T implementing Clone. For non-Clone
                // T (rare), we'd need a snapshot trait.
                let snap = shard.state_map.snapshot_for_merge();
                let _ = snap_tx.send(snap);
            }
        }
    }
}
```

### 5.3 `StateMap::snapshot_for_merge`

For merge to work, each `T` in the StateMap needs to be cloneable into a `Box<dyn Any + Send>`. Two options:

**Option A — require `T: Clone` for sharded state.**
Add a `T: Clone` bound to `merge_state::<T>(...)` and document that sharded monitors can only state-merge `Clone` types.

**Option B — Snapshot via swap with `Default::default()`.**
Replace `&mut T` with `std::mem::take(state)` (which leaves `T::default()` in place). The taken `T` ships to the merge worker. This is zero-copy and doesn't require `Clone`.

Recommendation: **Option B.** Aligns with "state is per-CPU, drained on tick" pattern. Document that handlers between ticks see freshly-zeroed state after each merge boundary.

```rust
impl StateMap {
    /// Snapshot all registered states by `mem::take`'ing them.
    /// After this call each state slot is reset to T::default().
    pub fn snapshot_for_merge(&mut self) -> ShardSnapshot {
        let mut out = Vec::with_capacity(self.by_type.len());
        for (type_id, slot) in self.by_type.iter_mut() {
            // We need a per-type "take into Box<dyn Any>". The
            // registration path records a snapshot function alongside
            // each slot — see SnapshotRegistry below.
            // ...
        }
        out
    }
}
```

A `SnapshotRegistry` stores a `fn snapshot(&mut Box<dyn Any>) -> Box<dyn Any>` per registered type, populated by `MonitorBuilder::merge_state` or auto-derived for `T: AddAssign + Default + Clone`.

### 5.4 Auto-merge for `T: AddAssign + Default`

```rust
impl MonitorBuilder {
    /// Auto-merge: convenience for state types that just sum.
    /// Requires `T: AddAssign + Default + Send + 'static`.
    pub fn state_auto_merge<T>(self) -> Self
    where T: Default + Send + std::ops::AddAssign + 'static
    {
        self.merge_state::<T, _>(|a, b| *a += b)
    }
}
```

Common counters (`u64`, `(u64, u64)`, custom structs with `#[derive(Default)]` + a manual `AddAssign` impl) hit this path.

### 5.5 Build-time validation

```rust
impl MonitorBuilder {
    pub fn build(self) -> Result<Monitor, BuildError> {
        // ... existing validation ...

        if self.fanout.is_some() {
            // Validate each registered State<T> has a corresponding
            // merge closure (or auto-merge if T: AddAssign).
            for (type_id, _) in self.state_map.by_type.iter() {
                if !self.merge_closures.contains_key(type_id) {
                    return Err(BuildError::FanoutWithoutMerge {
                        type_name: /* lookup via a separate type_name registry */,
                    });
                }
            }

            // Build the sharded monitor instead of the single Monitor.
            return Ok(Monitor::Sharded(ShardedMonitor::build(self)?));
        }

        // ... existing single-shard build ...
    }
}
```

`Monitor` becomes an enum:

```rust
pub enum Monitor {
    Single(SingleMonitor),
    Sharded(ShardedMonitor),
}

impl Monitor {
    pub async fn run_for(self, d: Duration) -> Result<()> {
        match self {
            Monitor::Single(m) => m.run_until(Instant::now() + d).await,
            Monitor::Sharded(m) => m.run_for(d).await,
        }
    }
    // ... same for run_until / run_until_signal / shutdown ...
}
```

### 5.6 Tick handler scheduling on sharded path

The single-shard tick path schedules a `tokio::time::interval` alongside the packet stream. The sharded path is the same per shard — each shard runs its own tick timer. After a merge boundary, the merge worker can optionally fire a "merged tick" handler that sees the merged state.

For Phase F simplicity: per-shard ticks fire independently; "global" ticks are deferred to a future revision. Document this.

## 6. Tests

`tests/shard_2cpu.rs`:

```rust
//! Verify 2 shards run + their counter state merges correctly.
//! Uses a synthetic event source — no real capture.

#[derive(Default, Clone)]
struct PerShardCount { n: u64 }

impl std::ops::AddAssign for PerShardCount {
    fn add_assign(&mut self, other: Self) { self.n += other.n; }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_shard_merge_via_add_assign() {
    // Build a sharded monitor with 2 CPUs (forced).
    // ... use a #[cfg(test)] override on shard count ...
    // Drive 100 events per shard.
    // Tick the merge worker.
    // Assert the accumulated state == 200.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_shard_merge_via_custom_closure() {
    #[derive(Default)] struct NotAddAssign { items: Vec<u32> }
    // Build with .merge_state::<NotAddAssign>(|a, b| a.items.extend(b.items)).
    // Drive distinct events to each shard.
    // Assert merged result has all items.
}
```

`tests/shard_merge_missing.rs`:

```rust
#[test]
fn fanout_with_state_without_merge_fails_build() {
    #[derive(Default)] struct NotAddAssign;

    let r = Monitor::builder()
        .fanout_per_cpu("eth0", FanoutMode::Cpu)
        .state::<NotAddAssign>()
        // ... no .merge_state ...
        .build();
    assert!(matches!(r, Err(BuildError::FanoutWithoutMerge { .. })));
}
```

`tests/shard_addassign_auto.rs`:

```rust
#[derive(Default, Clone)]
struct Sums { http: u64, dns: u64 }

impl std::ops::AddAssign for Sums {
    fn add_assign(&mut self, o: Self) { self.http += o.http; self.dns += o.dns; }
}

#[tokio::test(flavor = "multi_thread")]
async fn add_assign_auto_merges_without_explicit_call() {
    // Build with .state_auto_merge::<Sums>() (or just .state::<Sums>()
    // if we infer AddAssign automatically — see Risk #5).
    // Drive events to multiple shards.
    // Assert summed state.
}
```

## 7. Acceptance criteria

- [ ] `cargo build --features monitor` clean.
- [ ] `cargo nextest run` — 370+ tests pass.
- [ ] `cargo +stable clippy --all-targets -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
- [ ] dhat bench still passes (≤512 B / 100k events) — sharded mode runs per-CPU, so the bench needs to be updated to run in single-shard mode and stay zero-alloc there. Sharded mode itself does allocate (one Box per merge snapshot); document this is acceptable as it happens once per merge_interval, not per event.
- [ ] `tests/shard_2cpu.rs` + `tests/shard_merge_missing.rs` + `tests/shard_addassign_auto.rs` pass.
- [ ] A 2-shard monitor on `lo` runs without error (manual smoke test in CI under capabilities).
- [ ] `BuildError::FanoutWithoutMerge` triggers when state is registered but no merge function provided (and `T` doesn't auto-impl `AddAssign`).

## 8. Risks + mitigations

1. **Spawning per-thread runtimes is heavy.**
   Each shard creates a `tokio::runtime::Builder::new_current_thread()` runtime. ~1-2ms per shard at startup. For typical 4–16 shards this is ~16-32ms, acceptable. Document.

2. **`mem::take` snapshot semantics may surprise users.**
   Between merge boundaries, per-shard state accumulates. After a merge, each shard's state is reset to `Default::default()`. Handlers between ticks read freshly-zeroed state. This is fine for counters (the merge worker sums them) but surprising for "session caches." Document loudly. For sticky state, point users at `Arc<Mutex<T>>` outside the State extractor (slow path, opt-in).

3. **Merge worker is single-threaded.**
   It receives snapshots from N shards via unbounded mpsc. If shards produce snapshots faster than the worker can fold them, the queue grows. Mitigation: cap `mpsc` to bounded channel; emit a `WARN` log on overflow.

4. **`FanoutWithoutMerge` error needs `type_name`.**
   `TypeId` doesn't expose a name. Stash `type_name::<T>()` in a parallel `FxHashMap<TypeId, &'static str>` populated by `.state::<T>()`.

5. **Auto-detecting `T: AddAssign` requires specialization.**
   Rust doesn't have specialization on stable. Two options:
   - **Explicit**: user calls `.state_auto_merge::<T>()` instead of `.state::<T>()` to get AddAssign-based merge.
   - **Procedural**: use a macro that picks. Discouraged; adds magic.
   Recommendation: explicit `.state_auto_merge::<T>()`. Document clearly.

6. **Capture-level scheduling: which shard handles which CPU?**
   `PACKET_FANOUT_CPU` routes packets to the ring whose index matches `cpu_id % n_rings`. Shards must be CPU-pinned (`std::thread::spawn` + `core_affinity::set_for_current(...)`) to match. Use `core_affinity` crate (already in dev-deps from `proptest`'s transitive).

7. **Multi-interface + sharding interaction.**
   Out of scope for Phase F. Document that `.interfaces([...])` and `.fanout_per_cpu(...)` are mutually exclusive in 0.20. A future revision could combine them (each iface gets its own per-CPU fanout group).

## 9. Estimated effort + commit shape

**Total: 3–4 working days.** ~700 LoC new code + ~250 LoC tests.

**Commits (3):**

- `netring 0.20 (F.1): ShardedMonitor + MonitorShard + per-CPU AF_PACKET binding` — ~400 LoC.
- `netring 0.20 (F.2): merge_state + state_auto_merge + merge worker + build-time validation` — ~300 LoC.
- `netring 0.20 (F.3): per-shard tick scheduling + 3 integration tests` — ~150 LoC + tests.

## 10. Cross-phase notes

- **Phase G** migration guide adds a "scaling beyond 2 Mpps" subsection covering `.fanout_per_cpu(...)` + `.merge_state(...)`.
- **Phase G** updates `docs/scaling.md` with the new builder method.
- **Phase G** adds `examples/scaling/percpu_monitor.rs` — a representative 4-CPU example.
- The dhat bench (Phase C) stays single-shard. A separate `bench-sharded` could measure throughput at line rate, but that's out of scope for 0.20.

Ready to execute once Phase E is merged.
