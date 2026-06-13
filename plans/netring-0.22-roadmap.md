# netring 0.22 roadmap

## 1. Summary

flowscope **0.14.0** shipped on 2026-06-13 with every item from
the netring 0.22-flowscope-0.14 wishlist (plans 160-168) **plus**
five polish plans (170-174) the maintainer added on the way out.
The 0.22 cycle is now larger and more cohesive than the original
"legacy delete + small polish" scope: there's a real
flowscope-absorption phase to ship.

Five classes of work for the cycle, in dependency order:

1. **Phase A — flowscope 0.14 absorption.** Bump dep,
   re-export `KeyIndexed`, ship the `bandwidth_by_app()`
   primitive on top of `RollingRate<K, V>` + `LabelTable`,
   ship `IcmpError` typed event + `on_icmp_error` sugar on
   top of `FlowTracker::lookup_inner` + `DestUnreachableKind`
   + `MtuSignalKind`, refresh `net_diagnostic` as the
   demonstration (~80 LoC shrinkage). Headline of the cycle.
2. **Phase B — legacy 0.19 API deletion.** Mechanical
   `#[deprecated(since = "0.21.0")]` follow-through.
3. **Phase C — sharding completion.** The 0.21 `ShardedRunner`
   deferrals: `merge_state` worker + `LayerSpec` trait.
4. **Phase D — Send-future investigation.** Research +
   decision: can `Monitor::run_for`'s future be made `Send`,
   or do we double down on the documented workaround?
5. **Phase E — polish.** `MinSeverity::info()` constructor,
   the H.5 Send-caveat example, clippy doc-lint CI gate,
   migration-guide caveat, optional sugar (TcpRst typed
   event, `Tick` payload elision).

Total: ~2 weeks focused work. Phase A is the headline; the
rest can ship in parallel.

## 2. Status

Open. No commits yet on a `0.22-dev` branch. Wishlist file
`0.22-flowscope-0.14-wishlist.md` retired (every plan shipped
in flowscope 0.14 — see flowscope's CHANGELOG).

## 3. Prerequisites

- ✅ netring 0.21.0 cut + tagged + published (commit `32879eb`,
  tag `0.21.0`, crates.io `0.21.0`).
- ✅ flowscope 0.14.0 on crates.io (released 2026-06-13).
  Every wishlist item shipped — see `flowscope/CHANGELOG.md`
  "0.14.0" entry. Round-trip latency from "wishlist sent" to
  "shipped + on crates.io" was ~30 hours.

No remaining external blockers.

## 4. Phase A — flowscope 0.14 absorption (headline)

The big one. flowscope 0.14 ships the primitives that collapse
the highest-LoC hand-rolled patterns from the 0.21 cycle. The
`net_diagnostic.rs` example shrinks from **306 LoC** to roughly
**80 LoC** without losing functionality. Every netring user
hitting bandwidth-by-app, ICMP-to-flow correlation, or
custom-port labelling stands to benefit.

### 0.22-A.1 — Bump `flowscope` dep `0.13.0` → `0.14.0`

Mechanical version bump in `netring/Cargo.toml`. flowscope
0.14 has one breaking change (`LabelTable::override_count`
renamed to `len`) but netring never used `override_count`, so
the bump is a no-op for netring's own code paths. Compile +
clippy + nextest must stay green under the new dep.

### 0.22-A.2 — Re-export `KeyIndexed` from flowscope

Was 0.22-G in the prior roadmap; flowscope 0.14 plan 160
shipped `KeyIndexed::drain_expired(now) -> Vec<(K, V)>` +
`drain_expired_into(now, buf) -> usize`. netring drops its
local `netring/src/correlate.rs::KeyIndexed` and does:

```rust
// netring::correlate
pub use flowscope::correlate::KeyIndexed;
```

Carry the `_into` allocation-friendly variant through as well.
Migration recipe in `docs/MIGRATING_0.21_TO_0.22.md`.

LoC delta: ~-300 (the netring local copy + its tests).

### 0.22-A.3 — Ship `bandwidth_by_app()` primitive

The headline ergonomics win. Builds on flowscope 0.14's
`RollingRate<K, V>` + `LabelTable` + `FiveTupleKey::app_label()`.

```rust
// netring::monitor::MonitorBuilder
impl MonitorBuilder {
    /// Register a per-app rolling rate of bytes/sec keyed by
    /// `FiveTupleKey::app_label()` ("http", "https", "dns",
    /// site-custom labels). Pairs with `.report(period, |snap| { … })`
    /// or polled directly via `ctx.bandwidth().snapshot(now)`.
    ///
    /// Internally wires `FlowPacket<Tcp>` + `FlowPacket<Udp>`
    /// handlers that record `evt.len` into a
    /// `RollingRate<&'static str, u64>` state slot. The wire
    /// is hidden from the user.
    pub fn bandwidth_by_app(self) -> Self;
    pub fn bandwidth_by_app_with_table(self, table: LabelTable) -> Self;
}

impl<'a> Ctx<'a> {
    /// Snapshot accessor for the current monitor's bandwidth
    /// state, if `.bandwidth_by_app()` was registered. Returns
    /// `None` if the builder didn't register the primitive.
    pub fn bandwidth(&self) -> Option<&RollingRate<&'static str, u64>>;
}
```

Refreshes the 0.22 design input's N6 from "proposal" to
"shipped concrete API". The user-facing recipe collapses
~80 LoC of `net_diagnostic` to:

```rust
Monitor::builder()
    .interface(iface)
    .all_l4()                                  // 0.22-E.x umbrella
    .bandwidth_by_app()
    .report(Duration::from_secs(5), |bw| {
        for (label, bps) in bw.top_k(10, Instant::now().into()) {
            println!("{label}: {bps:.0} B/s");
        }
    })
    .sink(StdoutSink::default())
    .run_until_signal().await?;
```

`report()` helper is netring 0.22-E.x (see Phase E).

### 0.22-A.4 — Adopt `LabelTable` for custom-port labelling

`MonitorBuilder::label_table(table)` setter that threads a
flowscope `LabelTable` through downstream handlers via the
`Ctx`. Site deployments register internal services
(gRPC on 8765, custom telemetry on 9101) without forking
flowscope's well-known table.

```rust
impl MonitorBuilder {
    /// Use a custom `LabelTable` for `app_label_with` lookups
    /// inside this monitor. Defaults to flowscope's built-in
    /// table when unset.
    pub fn label_table(self, table: LabelTable) -> Self;
}

impl<'a> Ctx<'a> {
    /// Borrow the active label table. Always returns something
    /// — the default is flowscope's built-in.
    pub fn label_table(&self) -> &LabelTable;
}
```

When 0.22-A.3 is set + 0.22-A.4 is set, the bandwidth primitive
internally uses the custom table.

### 0.22-A.5 — `IcmpError` typed event + ICMP-to-flow join

Builds on flowscope 0.14 plan 161 (`FlowTracker::lookup_inner`
+ `stats_for_inner`) + plan 162 (`DestUnreachableKind`) + plan
170 (`MtuSignalKind`).

```rust
// netring::protocol::event_typed
pub struct IcmpError {
    pub family: IcmpFamily,                  // V4 | V6
    pub kind: IcmpErrorKind,                 // unified across types
    pub correlated_flow: Option<FlowKey>,    // join from lookup_inner
    pub stats: Option<FlowStats>,            // from stats_for_inner
    pub ts: Timestamp,
}

#[non_exhaustive]
pub enum IcmpErrorKind {
    DestUnreachable(DestUnreachableKind),    // host/port/network/admin/…
    TimeExceeded,
    ParameterProblem,
    MtuSignal(MtuSignalKind),                // v4 frag-needed / v6 packet-too-big
}

impl Event for IcmpError { type Payload = IcmpError; }
```

Internal dispatch arm: when `Icmp` is registered and the
parsed `IcmpType::is_error()` returns true, the dispatcher
synthesises an `IcmpError` event, queries the FlowTracker via
`lookup_inner`, and fires the typed event. Users handle one
event shape regardless of v4/v6 — the 30-line classifier
collapses to one match.

### 0.22-A.6 — `MonitorBuilder::on_icmp_error(handler)` sugar

Implicit `Icmp` protocol registration + typed handler:

```rust
.on_icmp_error(|err: &IcmpError, ctx: &mut Ctx<'_>| {
    if let Some(flow) = err.correlated_flow {
        ctx.sink_mut()
            .begin("FlowKilledByIcmp", Severity::Warning, ctx.ts)
            .with("flow", &format!("{flow:?}"))
            .with("kind", err.kind.as_str())
            .emit();
    }
    Ok(())
})
```

Direct mapping from the 0.22 design input's N8. Two lines of
ceremony replace the 50-LoC `on_ctx::<Icmp>` classifier in
`net_diagnostic`.

### 0.22-A.7 — Refresh `net_diagnostic` as the demonstration

The example shrinks ~80 LoC. Three concrete changes:

1. `classify_unreachable` (30 LoC) → `err.kind.as_str()` (1 LoC).
2. Hand-rolled `AppBandwidth` HashMap + tick reporter (~50 LoC)
   → `.bandwidth_by_app()` + `.report()` (~10 LoC).
3. Per-L4 `FlowPacket<Tcp>` + `FlowPacket<Udp>` handlers (10
   LoC) → bundled into `bandwidth_by_app()` (0 LoC).

End shape: ~80 LoC total. CHANGELOG entry for 0.22.0 leads
with the before/after as the cycle's headline.

### 0.22-A.8 — Sync the netring prelude with flowscope 0.14

flowscope 0.14 plan 167 expanded its prelude with
`TimeBucketedCounter`, `TimeBucketedSet`, `KeyIndexed`,
`BurstDetector`, `Ewma`, `TopK`, `RollingRate`, `FlowStateMap`,
`IcmpType`, `IcmpMessage`, `IcmpInner`, `LabelTable`. netring's
prelude needs the corresponding additions plus its own gaps
flagged in the 0.21 retrospective:

- Add `FlowPacket`, `FlowTick`, `ParserClosed` (the
  retrospective §1.1).
- Add `RollingRate`, `LabelTable`, `DestUnreachableKind`,
  `MtuSignalKind`, `IcmpError`, `IcmpErrorKind`.
- Re-add flowscope's prelude additions through netring's
  prelude.

Net: ~12 new names land in `netring::prelude::*`.

### 0.22-A.9 — Adopt `FlowStats` throughput helpers

flowscope 0.14 plan 173 added `FlowStats::throughput_bps()`,
`throughput_pps()`, `throughput_bps_for(side)`,
`throughput_pps_for(side)`. Plus plan 168 added `bytes_for`,
`pkts_for`, `mean_pkt_size_for`, `direction_skew()`. Sweep
the shipped netring examples to use them where appropriate
(both for correctness — safe-divide built in — and for
discoverability via example).

Sites to update:
- `examples/anomaly/lateral_movement.rs`
- `examples/anomaly/icmp_explained_drop.rs` (will be
  deprecated by `net_diagnostic`'s refresh, but the netring-
  side delete happens in Phase B, not here)
- The refreshed `net_diagnostic` uses `throughput_bps_for`
  + `direction_skew` to flag one-sided flows

### 0.22-A.10 — Discoverability page

Mirror flowscope's `docs/discoverability.md` on the netring
side: one page listing every shipped primitive grouped by
use case ("monitor lifecycle handlers" / "per-flow state" /
"rolling rates" / "ICMP triage" / "anomaly emission"). Adds
no API surface; pure docs.

## 5. Phase B — Legacy 0.19 API deletion

Unchanged from the prior roadmap, repeated here for
self-containedness.

Files to remove or trim outright:

- `netring/src/protocol/monitor.rs` — delete
- `netring/src/anomaly/monitor.rs` — delete
- `netring/src/anomaly/rule.rs` — keep `Anomaly`,
  `AnomalyContext`, `Severity` value types (still used by the
  new sinks); delete the `AnomalyRule` trait
- `netring/src/anomaly/builtin.rs` — delete (`FlowAnomalyRule`)
- 11 examples under `netring/examples/anomaly/` that still use
  the legacy API — delete or rewrite against
  `Monitor::builder()` + `detector!` / `pattern_detector!`
- 3 tests (`tests/anomaly_monitor_smoke.rs`,
  `tests/anomaly_new_detectors.rs`, `tests/anomaly_pcap_replay.rs`)
  — delete; coverage is in the new test files
- `netring/benches/anomaly.rs` — delete; `benches/zero_alloc.rs`
  is the canonical perf gate now
- Re-export sites in `src/lib.rs`, `src/anomaly/mod.rs`,
  `src/protocol/mod.rs` — delete the deprecated names
- All the `#![allow(deprecated)]` shields shipped in
  `netring 0.21 H.3` — delete

LoC delta: roughly **-3500**. CHANGELOG entry under `## 0.22.0`
leads with the deletion right after Phase A's bandwidth
ergonomics win.

## 6. Phase C — Sharding completion

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
periodically probes each shard via an
`mpsc::UnboundedSender<MergeRequest>` to ask for a `mem::take`
of its `T` slot, then folds into a `primary_state: StateMap`.

`BuildError::FanoutWithoutMerge { type_name }` variant fires
when a state type is registered via `MonitorBuilder::state::<T>()`
but no merge closure was declared (and `T` doesn't impl `AddAssign`).

**flowscope-side opportunity:** `RollingRate<K, V>` would
benefit from a `merge_into(&mut self, other: Self)` method so
that `bandwidth_by_app()` in a `ShardedRunner` context can
auto-merge per-shard rates into a global view via
`state_auto_merge`. Add to the 0.15 wishlist if 0.22-A.3 +
0.22-C.5 ship together.

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

`ShardedRunner::layer<L: LayerSpec>(layer)` replaces the
`Tee::factory(|| ...)` recipe for every secondary sink.

## 7. Phase D — Send-future investigation

Carried from prior roadmap unchanged.

`tests/monitor_send.rs` asserts `Monitor: Send`,
`MonitorBuilder: Send`, `ShardedRunner: Send`,
`EventStream<M>: Send`. The 0.21 retrospective flagged that the
future returned by `Monitor::run_for(d).await` is **not**
`Send`, because `AsyncCapture<S>` borrows the `!Sync` mmap
ring across awaits.

Investigation scope (write up before any code):
- Can `dispatch_lifecycle` / `next_batch` / `try_recv_batch`
  be reshaped so the run-loop future doesn't borrow the
  `!Sync` ring across await points?
- Options:
  1. **Owned-batch run path** — switch the live capture path
     to `AsyncCapture::recv()` (`Vec<OwnedPacket>`, `Send`).
     Costs one copy per packet — measure against
     `benches/zero_alloc.rs`. The dhat invariant breaks.
  2. **`tokio::task::spawn_local` adapter** — ship a
     `Monitor::spawn_local()` helper that wraps the run loop
     in a `LocalSet`, documenting the constraint explicitly.
  3. **Status quo + sharper docs** — accept the constraint
     as structural, point users at the `tokio::select!` +
     `ChannelSink` pattern.

Output: `plans/netring-0.22-send-future-decision.md` before
any implementation. Likely lands as option 3 plus 0.22-E.x's
multi_thread_default demo, but the analysis is worth doing.

## 8. Phase E — Polish

### 0.22-E.1 — `multi_thread_default.rs` Send-caveat demo

The 0.21 Phase H plan called for a dedicated
`examples/monitor/multi_thread_default.rs`. The retrospective
in `0.21-doc-sweep-issues.md` revised the framing: `Monitor:
Send` is real but the *future* returned by `Monitor::run_for`
stays `!Send`.

The example demonstrates *both* halves:
- Plain `#[tokio::main]` works — no `flavor = "current_thread"`
  ceremony needed (the Send-value payoff).
- `tokio::spawn(monitor.run_for(...))` does NOT compile —
  the example calls it out with a `compile_fail` doctest
  block or commented-out variant, then shows the working
  pattern (`tokio::select!` + `ChannelSink`).

~50 LoC, three blocks.

### 0.22-E.2 — `MinSeverity::info()` constant

One-line API addition: `pub const fn MinSeverity::info() -> Self`
aliasing `Self::at_least(Severity::Info)`. Removes a foot-gun
caught in the 0.21 sweep (`0.21-doc-sweep-issues.md` §2a).

### 0.22-E.3 — `report()` helper

The 0.22 design input's N7. A higher-level helper that bundles
tick + snapshot:

```rust
pub fn report<F>(self, period: Duration, f: F) -> Self
where F: Fn(ReportSnapshot<'_>) + Send + 'static
```

`ReportSnapshot<'_>` exposes typed accessors for the registered
primitives (`snap.bandwidth()`, `snap.counter::<K>()`,
`snap.state::<T>()`). Solves the "three state slots → ugly tick
handler" pain.

Pairs with 0.22-A.3 — `bandwidth_by_app() + report()` is the
ergonomic shape for the headline example.

### 0.22-E.4 — `TcpRst` typed event

The 0.22 design input's N3.

```rust
pub struct TcpRst {
    pub key: FlowKey,
    pub stats: FlowStats,
    pub ts: Timestamp,
    pub zero_payload: bool,
}
```

Synthesised from `FlowEnded<Tcp>` when `reason ==
EndReason::Rst`. Plus the matching
`MonitorBuilder::on_tcp_reset(handler)` sugar. No flowscope
dep — purely netring-internal.

### 0.22-E.5 — `Tick` payload elision

Currently `.tick(period, |_tick: &Tick, ctx| { … })` forces
users to destructure the rarely-used Tick payload. Add a
`Handler<NoEvent>`-style marker so `.tick(period, |ctx| { … })`
works.

### 0.22-E.6 — `all_l4()` / `all_l7()` umbrellas

```rust
.all_l4()  // == .protocol::<Tcp>().protocol::<Udp>().protocol::<Icmp>()
.all_l7()  // adds Http + Dns + Tls + TlsHandshake (feature-gated)
```

Removes the "I registered Tcp + Udp but forgot Icmp" foot-gun
that almost made `net_diagnostic` miss ICMP entirely.

### 0.22-E.7 — Clippy doc-lint CI gate

clippy 1.95's `doc_lazy_continuation` lint fires on rustdoc
that re-exports README.md. Bug fixed in commit `761b6d4`, but
the lint will trip again as the README evolves and the
existing CI matrix doesn't surface it before merge. Add a
rustdoc-building clippy row.

The 0.21 release sequence also caught broken intra-doc links
in commit `32879eb` via local `RUSTDOCFLAGS="-D warnings"`.
The CI's `Documentation` job already does this; the gap is
that the local dev workflow doesn't. Document the local
incantation in `netring/CLAUDE.md`'s pre-publish checklist.

### 0.22-E.8 — `MIGRATING_0.20_TO_0.21.md` Send caveat

May land in a `0.21.x` patch or in 0.22 if it slipped. The
migration guide says "drop `flavor = "current_thread"`"
without the asterisk about the !Send run-loop future. Add
the paragraph mirroring the README + ASYNC_GUIDE edits from
commit `761b6d4`.

## 9. Discretionary 0.22 narrative items (R-class)

The 0.22 design input proposed bigger redesigns (R1-R6). With
Phase A already large, picking one of these would sharpen the
0.22 narrative. None are required.

- **R1: Split `Protocol` → `FlowProtocol` + `MessageProtocol`.**
  Fixes the §1.12 architectural confusion. Migration cost low
  (the public `Protocol` trait stays; the new traits are
  markers). Pairs naturally with Phase A.5's `IcmpError` event
  — ICMP is the canonical `MessageProtocol`.
- **R2: Drop `FlowPacket<P>` parameterization.** With
  `bandwidth_by_app()` shipping in Phase A.3, the parametric
  per-packet event becomes mostly vestigial. Replace with one
  unparameterized `FlowPacket { key, side, len, tcp, ts }`.
- **R3: First-class `ReportSink` model.** Generalizes E.3's
  `report()` helper. Could be the cycle's narrative if E.3
  alone feels too small.
- **R6: eBPF integration.** Out of scope for 0.22; needs a
  dedicated cycle. Mentioned in the design input for
  completeness — the `xdp-loader` is there but the eBPF-
  backed bandwidth pattern is a separate research line.

My recommendation: ship Phase A + B + C + E without picking
an R-item. The 0.22 cycle already has a clear headline
("absorb flowscope 0.14, ship `bandwidth_by_app()` + ICMP
correlation + custom labels"). Adding R1/R2/R3 dilutes the
narrative; defer to 0.23.

## 10. Non-goals

- AF_XDP per-CPU mode. AF_PACKET fanout is the supported path.
- Cross-shard correlation. Each shard stays independent; the
  merge worker aggregates state via user-supplied closures
  but doesn't enable cross-shard event lookup.
- Multi-interface + sharding combination. The closure-builder
  pattern actively forbids this by virtue of taking `iface:
  impl Into<String>` (singular).
- ReportSink (R3) — discretionary; see §9.
- eBPF-backed bandwidth — discretionary; see §9.

## 11. Open questions

- **Should `merge_state::<T>` default to `AddAssign`
  auto-merge?** Saves the explicit `state_auto_merge` setter.
  Trade-off: ambiguity if the user wants a different merge
  for an `AddAssign` type.
- **`LayerSpec` for `Fn() -> Box<dyn Layer>`?** Two
  construction shapes on the same trait, mirroring the
  `Tee::into` / `Tee::factory` split.
- **0.22-D Send-future**: is the per-packet copy cost of an
  owned-batch run path acceptable? `benches/zero_alloc.rs`
  currently asserts Δ 0 bytes / 0 blocks on dispatch —
  switching from borrowed batches to `Vec<OwnedPacket>`
  breaks that invariant. The research item should quantify
  the regression before any code change.
- **0.22-A.3 `bandwidth_by_app()` and Sharding.** Does the
  primitive compose with `ShardedRunner`? Each shard owns
  its own `RollingRate` state slot; merging requires either
  flowscope shipping `RollingRate::merge_into` (add to 0.15
  flowscope wishlist) or netring's `merge_state` closure
  handling the merge inline.
- **0.22-A.5 IcmpError lookup synchronization.** The
  dispatcher synthesises `IcmpError` events post-parse; the
  FlowTracker lookup is read-only. Does the lookup happen
  on the same task as the FlowTracker's mutating ops? Likely
  yes (the run loop owns both) but verify before shipping.

## 12. Provenance

- 0.21 Phase C plan, §C.5 + §C.6 (deferred at ship time,
  documented in `netring/src/monitor/shard.rs` lines 12-16).
- 0.21 Phase H plan, §H.5 (multi_thread_default example).
- 0.21 deprecation notes on the legacy 0.19 API surface.
- `0.21-doc-sweep-issues.md` retrospective (§2a `MinSeverity::info`,
  §4 doc lints, §5 framing revision for H.5, §1 Send-future).
- `0.22-design-input-from-net-diagnostic.md` (N1-N10 + R1-R6;
  Phase A items derive from N2/N4/N6/N7/N8).
- `0.22-flowscope-0.14-wishlist.md` (retired — every plan
  shipped in flowscope 0.14 on 2026-06-13).
- flowscope 0.14 CHANGELOG (the surface Phase A absorbs).

## 13. Effort

| Item | Effort | Depends on |
|---|---|---|
| 0.22-A.1 dep bump | ~30 min | — |
| 0.22-A.2 KeyIndexed re-export | ~half day | A.1 |
| 0.22-A.3 `bandwidth_by_app()` | ~2 days | A.1, E.3 (`report()`) |
| 0.22-A.4 `label_table()` | ~half day | A.1 |
| 0.22-A.5 `IcmpError` event | ~1 day | A.1 |
| 0.22-A.6 `on_icmp_error()` sugar | ~half day | A.5 |
| 0.22-A.7 `net_diagnostic` refresh | ~half day | A.3, A.5, A.6 |
| 0.22-A.8 prelude sync | ~1 hour | A.1 |
| 0.22-A.9 throughput helpers in examples | ~1 hour | A.1 |
| 0.22-A.10 discoverability page | ~half day | A.8 |
| 0.22-B legacy delete | ~1 day | — |
| 0.22-C.5 merge worker | ~3 days | — |
| 0.22-C.6 LayerSpec | ~1 day | — |
| 0.22-D Send-future investigation | ~1 day | — |
| 0.22-E.1 multi_thread_default | ~2 hours | — |
| 0.22-E.2 `MinSeverity::info` | ~15 min | — |
| 0.22-E.3 `report()` helper | ~1 day | — |
| 0.22-E.4 `TcpRst` event | ~half day | — |
| 0.22-E.5 Tick payload elision | ~half day | — |
| 0.22-E.6 `all_l4()` / `all_l7()` | ~1 hour | — |
| 0.22-E.7 clippy doc-lint CI gate | ~30 min | — |
| 0.22-E.8 migration guide caveat | ~30 min | — |

**Critical path:** A.1 → A.5 → A.6 → A.7 (~2 days). Most
items are parallelisable.

**Total:** **~2 weeks** of focused work. Phase A is ~1 week,
B + C + D + E roughly another week.

## 14. Cycle close

When 0.22 ships:

- Tag `0.22.0` (no `v` prefix).
- Delete `plans/netring-0.22-roadmap.md` per the "delete on
  ship" convention.
- Delete `0.22-flowscope-0.14-wishlist.md` (already eligible
  — every plan shipped on the flowscope side).
- Update `netring/CLAUDE.md` Implementation Status.
- `cargo publish` (per explicit user approval).
- Open the 0.23 cycle by either picking an R-item (R1 / R2 /
  R3 from the 0.22 design input) or driving a new
  flowscope wishlist round.

Next wishlist round to flowscope: track `RollingRate::merge_into`
+ a per-flow `FlowStateMap` for ICMP correlation cache + any
discoverability gaps surfaced while writing Phase A.
