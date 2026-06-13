# netring 0.22 — consolidated implementation plan

## Implementation status (on `0.22-dev`)

| Phase / item | Status |
|---|---|
| §1 Foundations (flowscope 0.14, Ctx infra, R1 roles, R2 flat FlowPacket) | ✅ shipped |
| §2 flowscope absorption (KeyIndexed, bandwidth/`on_bandwidth`, `IcmpError`/`on_icmp_error`, `TcpRst`, `all_l4`/`all_l7`, prelude, net_diagnostic, discoverability) | ✅ shipped |
| §3 report model (R3: `Report`/`ReportSink`/`report`/`report_to`) | ✅ shipped |
| §4 legacy 0.19 API deletion (−5378 LoC) | ✅ shipped |
| §5.2 `LayerSpec` per-shard layers | ✅ shipped |
| §7 polish (MinSeverity const, `tick_ctx`, migration guide, Send-future decision, multi_thread demo, CI gate) | ✅ shipped |
| **§5.1 cross-shard `merge_state` worker** | ⏳ **remaining** — heaviest item; cross-thread merge worker + run-loop `select!` branch + `BuildError::FanoutWithoutMerge`. Design in §5.1 below. Deferred for a focused session (concurrency-sensitive). |
| **§6 eBPF bandwidth backend** | ⏳ **remaining** — R4 backend seam + R6 spike-gated XDP path. High risk; needs perf measurement on real hardware. Design in §6 below. |

Side effect: shipped **flowscope 0.14.1** (ICMP datagram-routing fix —
`datagram_broadcast(IcmpParser)` had never delivered ICMP messages;
netring patches to the local checkout until 0.14.1 is published).

Every shipped commit holds the cross-phase invariants: `clippy
--all-features --all-targets -D warnings` clean, 326 lib + integration
tests + doctests pass, dhat **Δ 0 / 0**.

---

**Single authoritative plan for the 0.22 cycle.** Supersedes the prior
`netring-0.22-roadmap.md` + the per-phase splinter files (all deleted).
Grounded against the netring 0.21.0 tree and the shipped flowscope 0.14.0 API
(`/var/home/mpardo/git/flowscope`).

**0.22 is a large, deliberately-infrequent breaking release.** Rather than a
string of weekly polish drops, the cycle reshapes the type model so the next
several cycles build on a cleaner foundation: it absorbs flowscope 0.14, splits
the protocol abstraction into typed roles (`FlowProtocol`/`MessageProtocol`),
de-parameterises the per-packet event, adds a first-class **report** output
stream alongside anomalies, completes sharding, removes the legacy 0.19 surface,
and lands an (optionally kernel-accelerated) bandwidth path. No `#[deprecated]`
windows — we break cleanly and ship one migration guide.

Design north stars, in priority order:

1. **Strongly typed.** The type system encodes real invariants: `on::<Tcp>` and
   `FlowStarted<Http>` become *compile errors*, not runtime no-ops. Reuse
   flowscope enums; never re-declare them.
2. **High-level by default, low-level on demand.** The headline path is a
   one-liner (`on_bandwidth`, `on_icmp_error`, `report_to`); the primitive
   underneath stays reachable.
3. **No performance regression.** The dhat steady-state invariant
   (**Δ 0 bytes / Δ 0 blocks** per 100k synthetic dispatches,
   `benches/zero_alloc.rs`) holds on every per-packet path. Allocation is
   confined to periodic (tick/report) paths. The eBPF phase *raises* the ceiling.
4. **Idiomatic.** Fluent builder (`-> Self`), object-safe traits where the
   dispatcher needs them, the existing `Ctx<'a>` stack-borrow model (never heap).

---

## Breaking-change summary (one place; expanded recipes in the migration guide)

| Break | Migration |
|---|---|
| Legacy `ProtocolMonitor`/`AnomalyMonitor`/`AnomalyRule`/`FlowAnomalyRule` removed | Use `Monitor::builder()` + `detector!`/`pattern_detector!`. |
| `Protocol` split into `FlowProtocol` + `MessageProtocol` roles | `on::<Tcp>`→`on::<FlowStarted<Tcp>>` (Tcp has no message); `FlowStarted<Http>`/`<Dns>`/`<Tls>` no longer exist (HTTP rides a TCP flow → use `FlowStarted<Tcp>`). |
| `FlowPacket<P>` → flat `FlowPacket { proto, … }` | `on::<FlowPacket<Tcp>>(\|e\|…)` → `on::<FlowPacket>(\|e\| match e.proto {…})`. |
| `Layer: Send + Sync` (added `Sync`); `Tee::factory` removed | Per-shard layers go through `ShardedRunner::layer(spec)` / `LayerSpec`. |
| `KeyIndexed` now `flow`-gated; re-exports flowscope's | Path unchanged under `flow`; the `_into` allocation-free variant is new. |
| flowscope dep floor `0.13`→`0.14` | `LabelTable::override_count`→`len` (netring never used it). |
| `report()` closure returns `Result<()>` | Tail `Ok(())`. |
| New report output stream (`Report`/`ReportSink`) | Additive; opt-in. |

---

## 0. Ground-truth corrections (verified against source)

1. **`RollingRate` keys on `flowscope::Timestamp`, not `Instant`.** The
   roadmap's `top_k(10, Instant::now().into())` does not compile
   (`rolling_rate.rs:106-307`). The high-level `BandwidthReport` captures the
   tick `Timestamp` internally (§3.4); raw `Timestamp` never appears at the
   headline.
2. **`Ctx` has no typed event re-inject** (only `emit(kind,sev)`,
   `ctx/mod.rs:251`). Synthetic events (`IcmpError`, `TcpRst`) are produced in
   the run loop / a dedicated slot, not by re-dispatching handlers.
3. **`Driver::tracker()` exists** (`flowscope/src/driver/typed.rs:402`) +
   `FlowTracker::{lookup_inner,stats_for_inner}` (`tracker.rs:915,932`) — the
   run loop borrows `&driver.tracker()` into `Ctx` (no conflict with the
   `&mut state_map/sink/counters` distinct locals) for the ICMP→flow join.
4. **ICMP is flow-tracked *and* message-bearing.** flowscope's tracker emits
   `FlowStarted/Ended/Packet/Tick` for `L4Proto::Icmp` (5-tuple keyed) *and* the
   `IcmpParser` emits `IcmpMessage`. So `Icmp` is **both** a `FlowProtocol` and
   a `MessageProtocol` (§2); `Tcp`/`Udp` are flow-only (`Message = ()`);
   `Http`/`Dns`/`Tls` are message-only (their flow is the underlying TCP/UDP).

---

## 1. Foundations — type model + Ctx (everything else builds on this)

Land these first, in order. They are the load-bearing redesigns.

### 1.1 flowscope dep bump `0.13` → `0.14`

`netring/Cargo.toml`: `flowscope = { version = "0.14", default-features = false }`.
`git grep override_count netring/` is empty → no code-path change. Full matrix
compile + clippy `-D warnings` + nextest green before proceeding. First commit.

### 1.2 `Ctx<'a>` — typed state read, label table, tracker borrow

`src/ctx/mod.rs` — add two borrowed fields (plain references; zero runtime cost):

```rust
pub struct Ctx<'a> {
    // … existing …
    pub(crate) label_table: &'a flowscope::well_known::LabelTable,   // §2.2
    #[cfg(feature = "icmp")]
    pub(crate) tracker: Option<&'a flowscope::FlowTracker<flowscope::extract::FiveTuple, ()>>, // §2.5
}
```

`Monitor` always owns a `label_table: LabelTable` (default `LabelTable::new()`,
inheriting built-ins). New accessors:

```rust
impl<'a> Ctx<'a> {
    /// Immutable, non-creating read of a global state slot. Sibling to state_mut.
    pub fn state<T: 'static>(&self) -> Option<&T> { self.state_map.get::<T>() }
    /// Active label table (always present).
    pub fn label_table(&self) -> &flowscope::well_known::LabelTable { self.label_table }
    #[cfg(feature = "icmp")]
    pub fn lookup_icmp_flow(&self, inner: &flowscope::icmp::IcmpInner)
        -> Option<(FlowKey, flowscope::FlowStats)> { self.tracker?.stats_for_inner(inner) }
}
```

Back with `StateMap::get::<T>()` + `CounterRegistry::get::<K>()` (new,
non-panicking). Thread `label_table` (+ `tracker`) at the ~6 run-loop `Ctx`
sites (post-construction, mirroring `ctx.monitor_name = …`): live slot loop
(`run.rs:201`), `dispatch_one!` macro (`:799`), `fire_tick` (`:538`),
`drain_phase` (`:410`). A module `static DEFAULT_LABEL_TABLE: LazyLock<LabelTable>`
serves the `#[doc(hidden)]` test/bench `Ctx::new`. Test: `tests/ctx_threading.rs`.

### 1.3 R1 — split `Protocol` into typed roles

`src/protocol/mod.rs`. Two marker subtraits encode the role; the dispatch
machinery is unchanged, but the **`Event` impls gain role bounds** so invalid
handler registrations fail to compile.

```rust
/// A protocol whose flows the tracker follows end-to-end: emits
/// `FlowStarted`/`FlowEstablished`/`FlowEnded`/`FlowTick` and participates in
/// the flat `FlowPacket` stream. Keyed by 5-tuple.
pub trait FlowProtocol: Protocol {}

/// A protocol that delivers discrete parsed messages (`on::<Self>` fires
/// `Self::Message`). Has no flow lifecycle of its own.
pub trait MessageProtocol: Protocol {}
```

Role assignments (a protocol may be both):

| Marker | FlowProtocol | MessageProtocol | `Message` |
|---|:--:|:--:|---|
| `Tcp` | ✅ | — | `()` |
| `Udp` | ✅ | — | `()` |
| `Icmp` | ✅ | ✅ | `IcmpMessage` |
| `Http`/`Dns`/`Tls`/`TlsHandshake` | — | ✅ | `…Message` |

**Bound the events** (`src/protocol/event_typed.rs`):

```rust
// was: impl<P: Protocol> Event for P
impl<P: MessageProtocol> Event for P { type Payload = P::Message;
    fn protocol_marker() -> Option<TypeId> { Some(TypeId::of::<P>()) }
    fn protocol_name() -> &'static str { P::NAME } }

// was: impl<P: Protocol> Event for FlowStarted<P>  (and Ended/Established/Tick)
impl<P: FlowProtocol> Event for FlowStarted<P>   { type Payload = FlowStarted<P>; }
impl<P: FlowProtocol> Event for FlowEnded<P>     { type Payload = FlowEnded<P>; }
impl<P: FlowProtocol> Event for FlowEstablished<P>{ type Payload = FlowEstablished<P>; }
impl<P: FlowProtocol> Event for FlowTick<P>      { type Payload = FlowTick<P>; }
```

Result, enforced at compile time:
- `on::<Tcp>(…)` → **error** (`Tcp: !MessageProtocol`; it dispatched `()` before).
- `on::<FlowStarted<Http>>(…)` → **error** (`Http: !FlowProtocol`; never fired).
- `on::<FlowStarted<Tcp>>`, `on::<Http>`, `on::<Icmp>`, `on::<FlowStarted<Icmp>>`
  all valid — matching what actually fires.

Tighten the broadcast surface too: `with_broadcast<P: MessageProtocol>` /
`subscribe<P: MessageProtocol>` (only message protocols have a meaningful
per-message broadcast). `ParserClosed<P>` stays unbounded (`P: Protocol`) — it
fires for both parser and L4 closes (`event_typed.rs:343`).

Keep `.protocol::<P>()` as the universal registrar (it already routes
lifecycle-only `Err` vs parser slot, `mod.rs:495`). The type-level win is in the
handler bounds, not the registration call; the §2.7 `all_l4`/`all_l7` umbrellas
remain the ergonomic entry. `§1.12` architectural confusion resolved: ICMP's dual
role is now explicit in the trait impls + documented on the markers.

Test: `tests/protocol_roles.rs` — a `compile_fail` doctest for `on::<Tcp>` and
`on::<FlowStarted<Http>>`; positive assertions for the valid combinations.

### 1.4 R2 — de-parameterise `FlowPacket`

Per-packet dispatch always branches on `evt.proto` anyway; the `<P>` is
vestigial and forces the bandwidth recorder into two near-identical handlers.
Replace with one flat type (`src/protocol/event_typed.rs`):

```rust
#[non_exhaustive] #[derive(Debug, Clone)]
pub struct FlowPacket {
    pub proto: L4Proto,
    pub key: FlowKey,
    pub side: FlowSide,
    pub len: usize,
    pub tcp: Option<TcpInfo>,
    pub ts: Timestamp,
}
impl Event for FlowPacket { type Payload = FlowPacket; }   // no protocol_marker — fires for any tracked flow
```

Run loop: the `FsEvent::FlowPacket` arm (`run.rs:711`) collapses from a 3-way
`match key.proto` to a single
`dispatch::<FlowPacket>(&FlowPacket { proto: key.proto, key, side, len, tcp, ts })`
(sync + async). `FlowPacket<P>`, its `PhantomData`, and the per-proto arms are
deleted. This **subsumes** the design's `AnyFlowPacket` (N2) — there is no other
shape. `FlowTick<P>` stays parameterised (low-frequency, lifecycle-adjacent,
`P: FlowProtocol`): the rule is *high-frequency data-plane events go flat with a
`proto` field; control-plane lifecycle events stay typed*.

Migration: `on::<FlowPacket<Tcp>>(|e| …)` → `on::<FlowPacket>(|e| match e.proto { L4Proto::Tcp => …, … })`.
Update `examples/monitor/net_diagnostic.rs` (handled by §2.9), `tests/typed_flow_packet_event.rs`,
`benches/zero_alloc.rs` (synthetic `FlowPacket` construction). Test:
`tests/flow_packet_flat.rs`.

---

## 2. Phase — flowscope 0.14 absorption (headline)

Built on the §1 type model. `examples/monitor/net_diagnostic.rs`: 306 → ~60 LoC.

### 2.1 ~~Re-export `KeyIndexed`; delete the netring copy~~ — REVISED: keep it

**Finding during impl:** flowscope 0.14's `KeyIndexed` and netring's local one
diverged into *different data structures*. flowscope's is an **LRU cache**
(`get(&mut self, …)` bumps recency, `new(ttl, capacity)`); netring's is a
**TTL map** (`get(&self, …)`, single-arg `new(ttl)`) with `iter_fresh` /
`contains_fresh` / `get_with_ts` that flowscope lacks. A re-export would force
`&mut` reads, drop those helpers, and break every correlation detector. So the
netring copy **stays**; we added `drain_expired_into` (the one flowscope-only
method) for parity. Filed on the 0.15 wishlist: reconcile upstream. Net: no
deletion, +1 method + a unit test for `drain_expired_into`.

### 2.2 `label_table()` custom-port labelling

```rust
/// Custom LabelTable for app/protocol lookups in this monitor (default = built-in).
pub fn label_table(mut self, table: flowscope::well_known::LabelTable) -> Self { self.label_table = Some(table); self }
```
`MonitorBuilder.label_table: Option<LabelTable>` → moved into `Monitor.label_table`
at build. Read via `Ctx::label_table()` (§1.2). Helpers (flowscope 0.14):
`LabelTable::new()`/`standalone()`/`.set(proto,port,label)`/`.extend([...])`.
Re-export at `netring::well_known::LabelTable` + prelude. Test: `tests/label_table.rs`.

### 2.3 Bandwidth-by-app — one recorder (post-R2), strongly-typed view

**Primitive** (`src/monitor/bandwidth.rs`, `#[cfg(feature="flow")]`): a private
`BandwidthState(RollingRate<&'static str, u64>)` newtype (TypeId can't clash with
a user `RollingRate`). Window/bucket default 10s/1s (bytes/sec); a
`bandwidth_windowed(window, bucket)` variant removes the hard-coded foot-gun.
Registration declares `Tcp`+`Udp`, `state_init`s the slot, and installs **one**
recorder (R2 collapsed the two):

```rust
self.on_ctx::<FlowPacket>(|evt, ctx| {
    let label = evt.key.app_label_with(ctx.label_table()); // &'static str, total
    ctx.state_mut::<BandwidthState>().0.record(label, evt.len as u64, ctx.ts);
    Ok(())
})
```
`record` is zero-alloc on bucket/key reuse → per-packet path stays Δ0.

**Typed view** — no `RollingRate`/`Timestamp`/`Option` leakage:
```rust
pub struct BandwidthReport<'a> { rate: &'a RollingRate<&'static str, u64>, now: Timestamp }
impl BandwidthReport<'_> {
    pub fn top(&self, n: usize) -> Vec<(&'static str, f64)> { self.rate.top_k(n, self.now) }
    pub fn rate(&self, app: &str) -> f64 { … }
    pub fn total(&self) -> f64 { self.rate.snapshot(self.now).map(|(_, r)| r).sum() }
    pub fn app_count(&self) -> usize { self.rate.len(self.now) }
    /// Owned snapshot for a ReportSink (§4): top-N entries by rate.
    pub fn to_snapshot(&self, n: usize) -> BandwidthSnapshot { … }   // impls Report + Serialize
}
```
`Ctx::bandwidth(&self) -> Option<BandwidthReport<'_>>` (uses `self.ts`).

**High-level fused reporter** (auto-registers everything; non-`Option` closure):
```rust
pub fn on_bandwidth<F>(self, period: Duration, f: F) -> Self
where F: Fn(&BandwidthReport<'_>) -> Result<()> + Send + Sync + 'static;
```
Headline recipe (compiles; no `Timestamp` in sight):
```rust
Monitor::builder().interface(iface)
    .on_icmp_error(|err, ctx| { … })
    .on_bandwidth(Duration::from_secs(5), |bw| {
        for (app, bps) in bw.top(10) { println!("{app}: {bps:>10.0} B/s"); } Ok(())
    })
    .sink(StdoutSink::default()).run_until_signal().await?;
```
Sharded slot is per-shard; global view needs §5.1 `state_auto_merge` + flowscope
`RollingRate::merge_into` (0.15 wishlist) — document, don't block. The
bandwidth backend is **pluggable** (§6 swaps in an XDP backend behind this same
API). Test: `tests/bandwidth_by_app.rs` + a dhat per-packet Δ0 assertion.

### 2.4 `IcmpError` typed event (reuse flowscope enums)

```rust
pub use flowscope::icmp::IcmpFamily;                 // V4 | V6 — reuse
#[non_exhaustive] #[derive(Debug, Clone)]
pub struct IcmpError {
    pub family: IcmpFamily,
    pub kind: IcmpErrorKind,
    pub correlated_flow: Option<FlowKey>,            // from_inner_canonical (no tracker)
    pub stats: Option<flowscope::FlowStats>,         // stats_for_inner (tracker)
    pub ts: Timestamp,
}
#[non_exhaustive] #[derive(Debug, Clone)]
pub enum IcmpErrorKind {
    DestUnreachable(flowscope::icmp::DestUnreachableKind), TimeExceeded,
    ParameterProblem, MtuSignal(flowscope::icmp::MtuSignalKind),
}
impl IcmpErrorKind { pub fn as_str(&self) -> &'static str { … } }  // delegates to flowscope as_str
impl Event for IcmpError { type Payload = IcmpError; }
```
Classifier from flowscope 0.14: `is_error()` (:589), `mtu_signal()` (:609),
`dest_unreachable_kind()` (:604), `error_inner()` (:594), `short_kind()` (:599
— confirm exact slugs before wiring `TimeExceeded`/`ParameterProblem`).

### 2.5 ICMP synthesis + `on_icmp_error` sugar

> **Impl note (blocker found + fixed):** `datagram_broadcast(IcmpParser)`
> never actually delivered ICMP messages — flowscope's datagram driver
> extracted only UDP payloads (`extract_udp_payload` matched
> `TransportSlice::Udp` only), so the ICMP parser was never fed and the
> driver-level ICMP path was untested. Fixed in **flowscope 0.14.1**
> (handle `Icmpv4`/`Icmpv6`, regression test
> `tests/icmp_datagram_routing.rs`); netring bumps its floor to `0.14.1`
> and patches `[patch.crates-io] flowscope = { path = "../flowscope" }`
> until 0.14.1 is published. Routing is via a new `Protocol::make_slot`
> hook (default `TypedProtocolSlot`; `Icmp` overrides → `IcmpSlot`).

`Icmp` is drained by one dedicated `IcmpSlot` (replaces the generic
`TypedProtocolSlot::<Icmp>` whenever `Icmp` is declared) that always forwards the
raw `IcmpMessage` *and* synthesises `IcmpError` (no flag; `dispatch` no-ops
without a handler, so the only error-path cost is building the struct):

```rust
for m in self.scratch.drain(..) {
    ctx.flow = Some(m.key); ctx.ts = m.ts;
    d.dispatch::<IcmpMessage>(&m.message, ctx)?;                    // raw on::<Icmp>
    if let Some(kind) = classify(&m.message) {
        let inner = m.message.error_inner().map(|(_, i)| i);
        let err = IcmpError { family: m.message.family, kind,
            correlated_flow: inner.and_then(FiveTupleKey::from_inner_canonical),
            stats: inner.and_then(|i| ctx.lookup_icmp_flow(i).map(|(_, s)| s)), ts: m.ts };
        d.dispatch::<IcmpError>(&err, ctx)?;                        // typed on_icmp_error
    }
}
```
`from_inner_canonical` needs no tracker (join survives eviction; stats then
`None`). Lookup runs after `driver.track_into` on the same task → read-consistent
(roadmap open question resolved). Sugar:
```rust
pub fn on_icmp_error<H, M>(self, h: H) -> Self where H: Handler<IcmpError, M>, M: 'static
{ self.protocol::<Icmp>().on_handler::<IcmpError, _, _>(h) }
```
Sync-only for 0.22 (async ICMP triage is niche; documented).
Test: `tests/icmp_error_event.rs` (v4 DestUnreachable + v6 PacketTooBig→MtuSignal).

### 2.6 `TcpRst` typed event + `on_tcp_reset`

```rust
#[non_exhaustive] #[derive(Debug, Clone)]
pub struct TcpRst { pub key: FlowKey, pub stats: flowscope::FlowStats, pub ts: Timestamp, pub zero_payload: bool }
impl Event for TcpRst { type Payload = TcpRst; }
```
Synthesised in `dispatch_lifecycle`'s `FsEvent::FlowEnded` arm (`run.rs:660`)
when `l4 == Tcp && reason == Rst` (struct built only on real RSTs; dispatch
no-ops without a handler). `pub fn on_tcp_reset<H,M>(…)` sugar. Test:
`tests/tcp_rst_event.rs`.

### 2.7 `all_l4()` / `all_l7()` umbrellas

`all_l4()` = `Tcp + Udp + Icmp` (Icmp behind its feature); `all_l7()` =
feature-gated `Http + Dns + Tls + TlsHandshake`. Removes the "forgot Icmp"
foot-gun. Test: `declared_protocols` populated.

### 2.8 Prelude + discoverability

`src/prelude.rs` adds (flow/icmp-gated): `FlowPacket` (flat), `FlowTick`,
`ParserClosed`, `FlowProtocol`, `MessageProtocol`, `IcmpError`, `IcmpErrorKind`,
`IcmpFamily`, `TcpRst`, `BandwidthReport`, `BandwidthSnapshot`, `Report`,
`ReportSink`, `RollingRate`, `LabelTable`, `DestUnreachableKind`,
`MtuSignalKind`, `TimeBucketedSet`, `BurstDetector`, `Ewma`, `TopK`; `KeyIndexed`
moves under `flow`. New `netring::well_known` module. `netring/docs/discoverability.md`
— one-page tour grouped by use case (pure docs).

### 2.9 `net_diagnostic` refresh + throughput sweep

Rewrite to ~60 LoC: `classify_unreachable`→`on_icmp_error`; `AppBandwidth`+tick+
two `FlowPacket` handlers→`on_bandwidth`; `FlowEnded<Tcp>` RST arm→`on_tcp_reset`.
Use `FlowStats::throughput_bps_for(side)` + `direction_skew()` (flowscope 0.14,
safe-divide) to flag one-sided flows. Sweep `examples/anomaly/lateral_movement.rs`
for hand-rolled byte math.

---

## 3. Phase — report model (R3) + correlate toolkit (R5)

A first-class third output stream (periodic structured snapshots) beside
`AnomalySink` (event-driven) and `EventStream<P>` (broadcast). Today reports
squat on `Tick` + `println!`.

### 3.1 The `Report` / `ReportSink` traits (`src/report/mod.rs`, new)

```rust
/// A periodic structured snapshot a monitor emits.
pub trait Report: Send + 'static { const NAME: &'static str; }

/// Consumes reports of type `R`. Object-safe per `R`.
pub trait ReportSink<R: Report>: Send + 'static {
    fn record(&mut self, report: &R);
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
```
Shipped sinks (the minimal cut the design called for):
- `StdoutReportSink` — `R: std::fmt::Debug` (or a `Report::write_human`).
- `JsonReportSink` (`feature = "serde"`) — `R: Serialize`, one JSON line per cadence.
- `MetricsReportSink` (`feature = "metrics"`) — `R: ReportMetrics` (a small
  `fn record_to(&self, recorder)` the user/derive provides) → Prometheus gauges.
`PrometheusReportSink`/`InfluxReportSink` are downstream/3rd-party — the trait is
the extension point.

### 3.2 Builder surface

```rust
/// Ship a typed report to a sink every `period`. `build` constructs `R` from a
/// snapshot of monitor state; the framework drives cadence + flush.
pub fn report_to<R, B, S>(self, period: Duration, build: B, sink: S) -> Self
where R: Report, B: Fn(ReportSnapshot<'_>) -> R + Send + Sync + 'static, S: ReportSink<R> + 'static;

/// Closure form for ad-hoc reporting (println / custom). Returns Result for parity.
pub fn report<F>(self, period: Duration, f: F) -> Self
where F: Fn(ReportSnapshot<'_>) -> Result<()> + Send + Sync + 'static;
```
`ReportSnapshot<'a>` wraps the tick `&mut Ctx` + `now: Timestamp`, exposing
typed accessors over the registered primitives (solves the §1.7 "N state slots →
ugly tick handler" pain — reports want *all* slots, sequentially):
```rust
impl<'a> ReportSnapshot<'a> {
    pub fn now(&self) -> Timestamp;
    #[cfg(feature="flow")] pub fn bandwidth(&self) -> Option<BandwidthReport<'_>>;
    pub fn state<T: 'static>(&self) -> Option<&T>;
    pub fn counter<K>(&self) -> Option<&TimeBucketedCounter<K>> where K: Hash+Eq+Clone+'static;
    pub fn emit(&mut self, kind: &'static str, sev: Severity) -> AnomalyWriter<'_>;
}
```

### 3.3 Run-loop integration (zero Mutex on the sink)

`Monitor` gains `report_streams: Vec<ReportRegistration>` parallel to
`tick_handlers`. Each holds `(period, type-erased build_fn, type-erased sink)`
behind a small `dyn ReportStream { fn fire(&mut self, ctx: &mut Ctx, now) }`
giving the run loop `&mut` access to the sink on the cadence tick — no interior
mutability, no per-report alloc beyond what `build` does. Reports fire on the
same `tokio::time::Interval` machinery as ticks (`run.rs:526` `fire_tick`
neighbourhood), with a `flush()` on drain. `on_bandwidth` (§2.3) and `report`
(closure) are sugar over this. `Report::NAME` stamps sink labels/log targets.

### 3.4 `BandwidthSnapshot` as the reference `Report`

The owned counterpart to `BandwidthReport<'_>`:
```rust
#[cfg_attr(feature="serde", derive(serde::Serialize))]
pub struct BandwidthSnapshot { pub ts_unix_nanos: u64, pub apps: Vec<BandwidthEntry> }
pub struct BandwidthEntry { pub app: &'static str, pub bytes_per_sec: f64 }
impl Report for BandwidthSnapshot { const NAME: &'static str = "bandwidth"; }
```
`report_to(5s, |snap| snap.bandwidth().unwrap().to_snapshot(10), JsonReportSink::new())`
ships bandwidth as newline JSON (Suricata `stats.log` / Zeek `conn.log` shape).
Example: `examples/monitor/bandwidth_report.rs`. Tests: `tests/report_*`.

### 3.5 R5 — unified `correlate::` toolkit

Per the no-tokio-in-lib-crate rule, computational primitives live in flowscope;
netring 0.22 unifies the **surface**: `netring::correlate` re-exports the full
set (`TimeBucketedCounter`, `RollingRate`, `TopK`, `TimeBucketedSet`,
`BurstDetector`, `Ewma`, `KeyIndexed`, `FlowStateMap`) with a module-doc
"choosing a primitive" table (rate vs snapshot vs cache vs decay). The one
**new** primitive the design wants — `Bucketed<K,V>` / `Histogram<K,V>`
(snapshot-by-key: top-N sources/paths/domains) — is a **flowscope 0.15 wishlist**
item (filed now), surfaced through netring when it lands. No netring-local
compute primitive is added (keeps the no-tokio invariant + avoids a second
maintenance home).

---

## 4. Phase — delete the legacy 0.19 API (~−3500 LoC)

After §2.9 (new `net_diagnostic` is the proven replacement). Inventory first:
`git grep -n 'ProtocolMonitor\|AnomalyMonitor\|AnomalyRule\|FlowAnomalyRule'`
+ `git grep allow(deprecated)`.

| Target | Action |
|---|---|
| `src/protocol/monitor.rs`, `src/anomaly/{monitor,builtin}.rs` | delete |
| `src/anomaly/rule.rs` | trim — keep `Anomaly`/`AnomalyContext`/`Severity`; delete `AnomalyRule`; delete `Anomaly<K>` too if grep proves it dead post-trim |
| `src/{lib,anomaly/mod,protocol/mod}.rs` | drop deleted re-exports + `mod` lines + every `allow(deprecated)` shield |
| `examples/anomaly/*` (12) | per-file `grep -l` legacy types → delete if duplicated under `examples/monitor/`, else rewrite on `Monitor::builder()`; **prune `[[example]]` entries** + README |
| `tests/anomaly_{monitor_smoke,new_detectors,pcap_replay}.rs` | delete (port any unique assertion to `tests/monitor_*` first) |
| `benches/anomaly.rs` + `[[bench]]` | delete (`zero_alloc`/`throughput` remain) |
| docs | strip legacy mentions; banner on `migration-0.19-to-0.20.md` |

Verify: `cargo build -p netring --all-features --all-targets` (every example/bench
path resolves) + clippy `-D warnings` (shields gone) + empty legacy grep.

---

## 5. Phase — sharding completion

Independent of §1–4. Heaviest single item.

### 5.1 Cross-shard state merging — ⏳ REMAINING (design sharpened post-impl)

Each shard runs an independent `Monitor` on its own OS thread + a
**`current_thread` tokio runtime** (`shard.rs:191`); they share only the fanout
group + an `Arc<AtomicBool>` stop flag. A merge worker periodically folds each
shard's copy of a state type `T` into a single primary.

**Concurrency shape (corrected for the actual threading model).** The shards
are async (tokio); the merge worker is a **plain OS thread with no runtime**.
So the two channels must differ:

- **Request** (worker → shard): `tokio::sync::mpsc::UnboundedSender/Receiver`.
  The worker calls the non-async `UnboundedSender::send` (works without a
  runtime); the shard polls `merge_rx.recv().await` in its run-loop `select!`.
- **Reply** (shard → worker): `std::sync::mpsc` — the worker has no runtime, so
  it **blocks** on `Receiver::recv_timeout(...)` (a tokio `oneshot::blocking_recv`
  would also work, but `std::mpsc::recv_timeout` is the clean bounded wait).

```rust
// src/monitor/merge.rs
pub(crate) struct MergeRequest {
    type_id: TypeId,
    reply: std::sync::mpsc::Sender<Option<Box<dyn Any + Send>>>,
}
```

- `Monitor` gains `merge_rx: Option<tokio::sync::mpsc::UnboundedReceiver<MergeRequest>>`
  (default `None`; `ShardedRunner::run_inner` injects one per shard after
  `build(cpu)?`, via a new `Monitor::set_merge_rx`). The run-loop `select!` gains
  a branch **gated `if merge_rx.is_some()`** (zero cost for non-merge monitors,
  exactly like the existing tick-interval branch):
  ```rust
  Some(req) = recv_merge(&mut merge_rx), if merge_rx.is_some() => {
      let taken = state_map.take_dyn(req.type_id); // remove the slot (Box<dyn Any+Send>)
      let _ = req.reply.send(taken);               // shard re-creates T::default lazily
  }
  ```
  `StateMap::take_dyn(TypeId) -> Option<Box<dyn Any + Send>>` removes the slot.
  **take-and-reset is the right additive semantic**: each interval folds the
  delta accumulated since the last take; the shard's next `state_mut::<T>()`
  lazily re-creates `T::default()`.

- Worker = one OS thread (a tiny `current_thread` runtime is *not* needed since
  it only `send`s + blocking-`recv`s). It holds the per-shard `Sender`s + a
  `HashMap<TypeId, MergeSpec>`. Each `MergeSpec` is type-erased:
  ```rust
  struct MergeSpec {
      period: Duration,
      next_fire: Instant,
      primary: Box<dyn Any + Send>,                                  // Box<T>, init T::default()
      fold:    Box<dyn FnMut(&mut (dyn Any), Box<dyn Any + Send>) + Send>, // downcasts both to T
      observe: Option<Box<dyn Fn(&(dyn Any)) + Send>>,               // from on_merge
  }
  ```
  Loop: park until the soonest `next_fire`; for each due spec, send a
  `MergeRequest` to every shard, collect replies (`recv_timeout`, **so a stalled
  shard can't wedge the worker**), `fold` each non-`None` reply into `primary`,
  then call `observe(primary)`. Exit when the stop flag flips.

- `ShardedRunner` API (one builder addition each):
  ```rust
  pub fn merge_state<T,F>(self, period: Duration, merge: F) -> Self
    where T: Default+Send+'static, F: Fn(&mut T, T)+Send+Sync+'static;
  pub fn state_auto_merge<T>(self, period: Duration) -> Self
    where T: AddAssign+Default+Send+'static;        // fold = `*p += t`
  pub fn on_merge<T,G>(self, observe: G) -> Self     // attaches to the T spec by TypeId
    where T: Send+'static, G: Fn(&T)+Send+Sync+'static;
  ```

**Open tension — `FanoutWithoutMerge` is probably wrong as a hard error.**
The prior plan said: error when a state type is registered under fanout but has
no merge. But **per-shard-local state is legitimate** (a scratch buffer, a
per-shard rate the user reads via a per-shard sink). Erroring on *any* unmerged
state is too aggressive and there's no way to distinguish "forgot to merge" from
"intentionally local". **Decision: drop the hard error.** Either (a) no check at
all — `merge_state` is explicit opt-in, or (b) a `log::debug!` listing unmerged
fanout state types as a hint. Recommend (a) for 0.22; revisit if users actually
trip on it. (This also removes the need for `Monitor::declared_state_types()`.)

**Shutdown semantics.** Take-and-reset means the final sub-interval of state is
lost on shutdown unless the worker does one last merge after the stop flag.
Recommend a single best-effort final pass (send one more round, short timeout)
and document it. Don't block shutdown on it.

flowscope follow-up (don't block): `RollingRate::merge_into` so sharded
`bandwidth_by_app` (a `RollingRate` slot) can `state_auto_merge` into a global
view → 0.15 wishlist. **Test:** `tests/sharded_merge.rs` — two shards each
increment a `Counter(u64)`; `state_auto_merge` 50ms period; `on_merge` observes
the cross-shard sum within a few periods. **Risk: medium-high** — the run-loop
`select!` branch has real blast radius (it's on the live capture path), so keep
it strictly gated; and the worker↔shard shutdown ordering needs the timeout
bounds above. Best done in a focused session, not the tail of a marathon.

### 5.2 `LayerSpec` per-shard layers — ✅ SHIPPED (with deviations)

Shipped `d3530bd`. Two corrections vs the original sketch, both verified
necessary during impl:

1. **`Layer` is NOT made `Sync`.** Adding `Sync` to `Layer` breaks `Tee` — it
   holds a `Box<dyn AnomalySink>`, and `AnomalySink: Send` (not `Sync`), so
   `Tee` is `!Sync` and couldn't impl a `Sync` `Layer`. Instead `Sync` lives
   only on `LayerSpec` (which *is* shared across shard threads); `Layer` stays
   `Send + 'static`. Less breaking, and `Tee` keeps working.
2. **`Tee::factory` kept; the `Fn` blanket → a `LayerFactory` newtype.** Two
   blanket impls (`impl<L: Layer+Clone+Sync>` and `impl<F: Fn()->Box<dyn Layer>>`)
   **collide under coherence** (Rust can't prove no type is both). So the factory
   path is an explicit `pub struct LayerFactory<F>(pub F)` with its own impl.
   `Tee::factory` is unchanged (still used by examples/tests).

Also: the per-layer "hand-impl" audit was **unnecessary**. Each layer's mutable
state (`DedupeAnomalies` table, `Sample` RNG, `RateLimit` buckets) lives in the
per-`wrap()` `*Layered` sink, **not** the config struct — so the blanket
`Clone` impl is correct (each shard's `wrap()` mints fresh state).
`MinSeverity`/`DedupeAnomalies`/`RateLimitAnomalies`/`Sample` just got
`#[derive(Clone)]`; `Sample` documents that cloned configs share the seed (use
`LayerFactory(|| …)` with a varied seed for independent per-shard sampling).
`ShardedRunner::layer<L: LayerSpec>(spec)` + `Monitor::wrap_sink` apply specs
outermost. Test: `tests/layer_spec.rs`.

---

## 6. Phase — eBPF acceleration of bandwidth (R4 + R6), spike-gated — ⏳ REMAINING

The design's R4/R6: move per-packet byte accounting off the Rust hot path into
the kernel, behind the **same** `on_bandwidth` API. This is the established
**Cilium/Hubble shape** — eBPF programs account bytes into per-CPU BPF maps in a
single hash lookup; per-CPU maps "eliminate global lock contention and scale
linearly with core count" (Cilium's `acc_map` keys an accounting map per
hook/flow). High risk (kernel/driver portability), so it's **spike-gated**: the
one place in this plan that measures before committing.

> **Research grounding** (June 2026): aya — the Rust eBPF lib netring already
> uses for `xdp-loader` — provides userspace `HashMap`, `PerCpuHashMap`,
> `PerCpuArray`. A `PerCpuHashMap` read returns a `PerCpuValues` (a slice with
> one value per CPU); **userspace sums the slice** to get the total for a key.
> Per-CPU maps need **no atomics in the kernel** — each CPU writes its own slot,
> so the XDP `+= len` is a plain add. Maps an XDP program defines are reachable
> from userspace via `Ebpf::map` / `take_map` after load. Sources at the end of
> this section.

### 6.1 Backend abstraction (the R4 seam)

```rust
// src/monitor/bandwidth.rs
#[non_exhaustive]
pub enum BandwidthBackend {
    /// Per-packet accounting in the Rust dispatcher (default; portable; Δ0 alloc).
    Userland,
    /// Kernel-side per-CPU-hash accounting read on the report cadence.
    /// Requires `xdp-loader` + a recent kernel. (See §6.2.)
    #[cfg(feature = "xdp-loader")]
    Xdp,
}
impl MonitorBuilder {
    pub fn bandwidth_backend(self, b: BandwidthBackend) -> Self; // default Userland
}
```
`Userland` is the shipped §2.3 path. `BandwidthReport` reads from whichever
backend — the user-facing API + typed view are identical, only the producer
changes. **Note:** a one-variant enum is hollow on its own, so §6.1 ships
*with* §6.2 (gated), not before it — if the spike defers `Xdp`, the seam lands
as `#[non_exhaustive] enum { Userland }` so adding `Xdp` later isn't breaking.

### 6.2 XDP backend (R6) — spike → implement → gate

**Kernel side.** netring already vendors a redirect-all XDP program
(`src/afxdp/loader/programs/redirect_all.bpf.{c,o}`) loaded via aya. Extend it
(or add a sibling program) to maintain a flow-keyed accounting map *before* the
redirect:

```c
struct flow_key { __u8 proto; __u8 _pad[3]; __be32 saddr, daddr; __be16 sport, dport; }; // #[repr(C)] mirror in Rust
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
         __type(key, struct flow_key); __type(value, __u64);
         __uint(max_entries, 1<<16); } acc_map SEC(".maps");

SEC("xdp") int account(struct xdp_md *ctx) {
    struct flow_key k; __u64 len; /* parse 5-tuple + frame len */
    __u64 *b = bpf_map_lookup_elem(&acc_map, &k);
    if (b) *b += len;                       // per-CPU: no atomic needed
    else   bpf_map_update_elem(&acc_map, &k, &len, BPF_ANY);
    return /* redirect as today */;
}
```

**Userland side (aya).** On the report cadence, read `acc_map` as a
`PerCpuHashMap<_, FlowKey, u64>`: iterate keys, sum each key's `PerCpuValues`,
map `FlowKey → app_label` via the `LabelTable` (userland), aggregate per app →
feed the existing `BandwidthReport` / `RollingRate`. The diff-since-last-read
gives the interval bytes (or use a `BPF_MAP_TYPE_LRU_PERCPU_HASH` so stale flows
self-evict). The per-packet path is now **zero** Rust work — the dhat Δ0
invariant is trivially held because there's no Rust per-packet code at all.

**Key-ABI ownership (open question, resolved direction).** The `flow_key` C
struct + its Rust `#[repr(C)]` mirror are an ABI. flowscope owns the flow/key
model (`FiveTupleKey`), so the canonical place for the BPF program + key layout
is **flowscope** (0.15 wishlist: ship the program + a versioned map ABI);
netring loads + reads it. For the 0.22 spike, prototype the key netring-side to
get numbers, then move it to flowscope if it ships.

**Spike methodology + gate (time-boxed, ~1 week).**
1. Prototype the program + the aya read loop; wire it behind `BandwidthBackend::Xdp`.
2. Measure on a **real multi-Gbps NIC** (not `lo`): packet-drop rate + CPU vs
   the `Userland` recorder under load. `SKB_MODE` works on `lo`/unprivileged but
   has no perf benefit; the win is `DRV_MODE` on a native-driver NIC.
3. **Gate:** ship `Xdp` only if the delta is material *and* the portability cost
   (kernel version, driver `DRV` vs `SKB`, the verifier accepting the program) is
   acceptable. Otherwise: keep the seam (`enum { Userland }`), document `Xdp` as
   deferred-to-0.23 with the recorded numbers. Either outcome is a clean ship.

**Stretch (explicitly 0.23, not 0.22):** kernel-side TCP-RST (`SOCK_OPS`) +
ICMP correlation maps. Recorded so the eBPF story is coherent; out of scope here.

`docs/EBPF_BANDWIDTH.md` documents the backend, the kernel/driver requirements,
the key ABI, and the spike results. Risk: **high** (kernel/portability + a real
NIC needed to measure); fully gated, never blocks the rest of 0.22.

Sources: [Cilium BPF & XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
(the `acc_map` per-CPU accounting example); [aya `maps` docs](https://docs.rs/aya/latest/aya/maps/index.html)
(`PerCpuHashMap` / `PerCpuValues`, `Ebpf::map`/`take_map`).

---

## 7. Phase — Send-future decision + polish — ✅ SHIPPED

Shipped across `6ea3d09` + `dc60f5f`. The Send-future investigation found a
**different** root cause than §7.1 assumed (the async-dispatch `*const ()` +
boxed handler future, not only the mmap ring — see
`plans/netring-0.22-send-future-decision.md`). Two-marker `tick_ctx` chosen over
overloading `.tick` (the `PayloadOnly`/`CtxOnly` arity-1 ambiguity the §7.4
sub-section predicted). MinSeverity const family, migration guide, and the
multi_thread demo all landed; the CI doc-lint gate was already present
(`clippy --all-features -D warnings` + `cargo doc` `RUSTDOCFLAGS=-D warnings`).
The per-sub-section design below is preserved for the record.

### 7.1 Send-future investigation → decision doc (research, no feature code)

`plans/netring-0.22-send-future-decision.md` before any code: (a) capture the
exact `!Send` holder + await point from rustc (`tokio::spawn(monitor.run_for)`);
trace whether it's the `MmapRing` (`!Sync`) or a flowscope `Rc` handle — the fix
differs. (b) Three options with measured cost: *owned-batch* (`recv() ->
Vec<OwnedPacket>`, `Send` but **breaks dhat Δ0** — bench the per-packet alloc +
throughput; opt-in only if pursued), *`spawn_local`/`LocalSet`* (weigh against
0.21's ceremony-removal win), *status quo + docs* (`ChannelSink`/`subscribe` are
already `Send`). (c) Evidence-backed recommendation; if it picks owned-batch/
spawn_local, spin a separate impl plan.

### 7.2 `multi_thread_default.rs` example

Three blocks: plain `#[tokio::main]` works (Send value); `tokio::spawn(monitor.run_for)`
`compile_fail` (Send future); working `tokio::select!` + spawned
`ChannelSink`/`subscribe` consumer. ~50 LoC. After §7.1.

### 7.3 `MinSeverity` const family + `info()`

Make `at_least`/`warning`/`error`/`info` all `const fn` (they aren't today,
`min_severity.rs:21`); `info()` = `at_least(Severity::Info)` (0.21 sweep §2a).

### 7.4 `Tick` payload elision (`CtxOnly` marker)

`src/monitor/handler.rs`: `pub struct CtxOnly; impl<E,F> Handler<E,CtxOnly> for F
where E: Event, F: Fn(&mut Ctx) -> Result<()> + Send + Sync + 'static` →
`.tick(period, |ctx| …)` (and any `|ctx|`-only handler) works. Three markers
distinguished by arity; if call-site inference is ambiguous, fall back to a
dedicated `tick_ctx` method (decide during impl).

### 7.5 CI doc-lint gate + migration guide

`.github/workflows/`: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`
+ `clippy … -W clippy::doc_lazy_continuation` (bit `761b6d4`/`32879eb`); mirror
in `justfile ci` + `netring/CLAUDE.md` pre-publish checklist.
`docs/MIGRATING_0.21_TO_0.22.md` (new) — the full breaking-change recipe book
(the summary table at the top of this plan, expanded): legacy removal,
protocol-role split, flat `FlowPacket`, `Layer: Sync`, `Tee::factory`→`LayerSpec`,
`KeyIndexed` gating, `report` signature, the `!Send` run-loop-future caveat.

---

## 8. Non-goals

- AF_XDP per-CPU mode (AF_PACKET fanout is the supported path).
- Cross-shard *event* correlation (merge aggregates state, not events).
- Multi-interface + sharding combination (singular `iface`).
- Kernel-side RST/ICMP eBPF (§6.2 step 3) — 0.23.
- Full Bevy-style compile-time `MonitorParam` validation — `ctx.split_*` + the
  new typed `state`/`bandwidth`/`report` accessors cover the ergonomics.
- HTTP/2 / QUIC / JA4+ parsers — inherited flowscope deferrals.
- YAML/Lua config DSL — declined (Rust handlers compose better).

---

## 9. Open questions

- **`short_kind()` slugs (§2.4).** Confirm flowscope's exact strings at
  `icmp/types.rs:599` before wiring the non-DU/non-MTU arms.
- **`merge_state` implicit `AddAssign`?** No — keep explicit `merge_state` +
  `state_auto_merge`; runtime TypeId can't detect `AddAssign`, silent `+=` is the
  worse failure. `FanoutWithoutMerge` nudges the choice.
- **`Layer: Sync` blast radius.** Breaking for external `Layer` impls with a
  non-`Sync` field; no shipped layer is affected. Migration-guide note.
- **`CtxOnly` inference (§7.4).** If `.tick`/`.on` overloading is ambiguous,
  ship `tick_ctx`. Decide at impl time.
- **eBPF map ABI ownership (§6.2).** flowscope owns the flow/key model → the BPF
  program + map layout live there; netring loads + reads. Confirm the ABI on the
  0.15 wishlist before committing the XDP backend.
- **Prelude size.** With ~15 new names, consider sub-preludes
  (`netring::prelude::icmp`) if the flat prelude feels crowded. Defer unless it
  bites.

---

## 10. Effort & sequencing

| Phase / item | Effort | Depends on |
|---|---|---|
| §1.1 dep bump | ~30 min | — |
| §1.2 Ctx infra | ~1 day | §1.1 |
| §1.3 R1 protocol roles | ~2 days | §1.1 |
| §1.4 R2 flat FlowPacket | ~1 day | §1.3 |
| §2.1 KeyIndexed re-export | ~half day | §1.1 |
| §2.2 label_table | ~half day | §1.2 |
| §2.3 bandwidth (`on_bandwidth`+view) | ~2 days | §1.2, §1.4, §3.2 |
| §2.4–2.5 IcmpError + on_icmp_error | ~1.5 days | §1.2, §1.3 |
| §2.6 TcpRst | ~half day | §1.3 |
| §2.7 all_l4/all_l7 | ~1 hour | §1.3 |
| §2.8 prelude + discoverability | ~half day | §2.* |
| §2.9 net_diagnostic refresh | ~half day | §2.3/2.5/2.6 |
| §3.1–3.4 Report/ReportSink + snapshot | ~3 days | §1.2 |
| §3.5 correlate toolkit (+wishlist) | ~half day | §2.1 |
| §4 legacy deletion | ~1 day | §2.9 |
| §5.1 merge worker | ~3 days | — |
| §5.2 LayerSpec + Layer:Sync | ~1.5 days | — |
| §6.1 bandwidth backend seam | ~1 day | §2.3 |
| §6.2 XDP backend spike + gate | ~1 week (time-boxed) | §6.1 |
| §7.1 Send-future decision | ~1 day | — |
| §7.2 multi_thread_default | ~2 hours | §7.1 |
| §7.3 MinSeverity const | ~30 min | — |
| §7.4 Tick elision | ~half day | — |
| §7.5 CI gate + migration guide | ~half day | all |

**Critical path:** §1.1 → §1.2 → §1.3 → §1.4 → §2.3 → §2.9 → §4 (~8 days). The
merge worker (§5.1) and the eBPF spike (§6.2) are the parallel long poles.
**Total: ~5–6 weeks** of focused work (vs the prior ~2-week polish scope) — a
single substantial cycle, not weekly drops.

Cross-phase invariants hold every commit: nextest green, clippy `-D warnings`
across the matrix, `cargo fmt --check`, `cargo test --doc`, dhat **Δ 0 / 0** on
per-packet paths, flowscope floor `>= 0.14.0`.

---

## 11. Provenance

- `0.22-design-input-from-net-diagnostic.md` — N1–N10 (→ §2/§7), R1 (→§1.3),
  R2 (→§1.4), R3 (→§3), R4+R6 (→§6), R5 (→§3.5); themes T1–T6.
- 0.21 Phase C plan §C.5/§C.6 (→§5); Phase H §H.5 + Send caveat (→§7).
- `0.21-doc-sweep-issues.md` (MinSeverity::info, doc lints, Send-future).
- flowscope 0.14 CHANGELOG + source (the surface §2 absorbs); wishlist retired.

---

## 12. Cycle close (on ship)

- Tag `0.22.0` (no `v` prefix). Delete this plan; update `plans/INDEX.md`.
- Bump `netring/Cargo.toml` → `0.22.0`; refresh `netring/CLAUDE.md` status.
- CHANGELOG `## 0.22.0` leads with the `net_diagnostic` before/after, then the
  protocol-role split + flat `FlowPacket`, then the report model, then legacy
  deletion + sharding; eBPF backend noted per the spike outcome.
- `cargo publish -p netring` (per explicit user approval).
- File the flowscope 0.15 wishlist: `RollingRate::merge_into`, `Bucketed<K,V>`/
  `Histogram<K,V>`, the eBPF bandwidth map ABI (if §6.2 went green), a per-flow
  ICMP correlation cache, and **`LabelTable`: make `Default` == `new()`**
  (found during §1.2 impl — `#[derive(Default)]` yields `inherit_builtin = false`,
  i.e. a whitelist-only table that silently drops the built-in port map, unlike
  `new()`. netring works around it with `unwrap_or_else(LabelTable::new)` +
  `#[allow(clippy::unwrap_or_default)]` in `MonitorBuilder::build`).
- Also wishlist: **reconcile `KeyIndexed`** (found in §2.1) — flowscope's 0.14
  version is an LRU cache (`get(&mut self)`) while netring's is a TTL map
  (`get(&self)` + `iter_fresh`/`contains_fresh`/`get_with_ts`); either add the
  immutable-read surface upstream or bless netring's as the canonical
  correlation map so netring can drop its copy.
- **Already shipped this cycle: flowscope 0.14.1** — the ICMP datagram-routing
  fix (`datagram_broadcast(IcmpParser)` delivering ICMP messages). Publish 0.14.1
  to crates.io, then drop the `[patch.crates-io] flowscope = { path = … }` from
  netring's workspace `Cargo.toml` and confirm the `>= 0.14.1` floor resolves.
- Open 0.23: kernel-side RST/ICMP eBPF (§6.2 step 3) is the natural headline.
