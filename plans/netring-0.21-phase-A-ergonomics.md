# netring 0.21 Phase A — Ergonomics polish + regression fixes

## 1. Summary

Thirteen sub-items closing the six 0.20→0.21 regressions (R1–R6) identified during the 0.20 head-to-head verification, plus seven additive ergonomics improvements (including the A.13 `AnomalySink` key-shape upgrade surfaced in the consolidation pass). The biggest single piece is **A.1**, the `BoxedHandler = Arc<dyn Fn + Send + Sync>` private storage swap — Phase C (sharding) depends on it.

## 2. Status

Not started. Targeted as the first phase on the `0.21-dev` branch — other phases reference its outputs (`Arc<dyn Fn>`, `ctx.emit`, `OwnedAnomaly` re-export).

## 3. Prerequisites

- netring 0.20.0 shipped (done).
- flowscope 0.13.0 dep bump (Phase H.1) — gives `KeyFields`/`AnomalyFields`/`OwnedAnomaly` for the re-export sub-items. Phase A.1–A.9 can land on flowscope 0.11.1; A.10/A.11 need 0.13.0 first.

## 4. Out of scope

- Bevy-style `MonitorParam` compile-time access validation — deferred to 0.22.
- The `ctx.split()` umbrella method (the `split_state_sink` / `split_state_counter` / `split_sink_counter` / `split_state_sink_counter` methods already ship in 0.20; A.3 documents them).

## 5. Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/monitor/dispatcher.rs` | `BoxedHandler` type alias swap; `Dispatcher::clone_for_shard` helper |
| Modify | `src/monitor/handler.rs` | Unchanged blanket impls (Fn-only already; verify) |
| Modify | `src/monitor/registry.rs` | Trampoline closures `Box::new` → `Arc::new` |
| Modify | `src/monitor/tick.rs` | Same swap for `BoxedTickHandler` |
| Modify | `src/monitor/mod.rs` | Split `.on::<E, _, _>` into `.on::<E>` + `.on_ctx::<E>`; `state_init`; `on_named`; deprecate `.on::<E, _, _>` |
| Modify | `src/ctx/mod.rs` | `ctx.emit(kind, sev) -> AnomalyWriter<'_>` method; doc cross-ref `state_mut` → `split_*` family |
| Modify | `src/anomaly/sink.rs` | `AnomalySink::write` key type upgrade `&dyn Debug` → `&dyn Key`; `with_dynamic(label, value)` on `AnomalyWriter`; `emit_owned() -> OwnedAnomaly` |
| New | `src/anomaly/key.rs` | `Key` super-trait combining `KeyFields + Debug + Send + Sync` |
| Modify | `src/anomaly/mod.rs` | `pub use key::Key;`; `pub use shipped_sinks::OwnedAnomaly;` (until A.10 supersedes) |
| Modify | `src/anomaly/shipped_sinks.rs` | Update `StdoutSink`, `StdoutJsonSink`, `TracingSink`, `ChannelSink` for the new `Key` signature |
| Modify | `src/detector_macro.rs` | Inject `__kind`/`__sev` bindings into emit body; `Detector::name` field |
| Modify | `src/protocol/event_typed.rs` | Add `FlowPacket<P>`, `FlowTick<P>`, `ParserClosed<P>` typed event markers |
| Modify | `src/monitor/run.rs` | Dispatch `FlowPacket`/`FlowTick`/`ParserClosed` arms (zero overhead when no handler registered) |
| Modify | `examples/monitor/basic.rs` | Rewrite to use `split_state_sink` + `ctx.emit` |
| Modify | `examples/monitor/detector_macro.rs` | Use `ctx.emit()` and macro-injected `__kind/__sev` |
| Modify | `examples/monitor/layered_sinks.rs` | Use `.on::<E>` (no turbofish) |
| Modify | `examples/monitor/async_handler.rs` | Use `.on::<E>` |
| Modify | `docs/WRITING_DETECTORS.md` | New "Holding multiple borrows" section + ctx.emit shortcut |

## 6. API

### A.1 — `Arc<dyn Fn>` handler storage swap

```rust
// Before (src/monitor/dispatcher.rs):
pub(crate) type BoxedHandler =
    Box<dyn FnMut(*const (), &mut Ctx<'_>) -> Result<()> + Send>;
pub(crate) type BoxedAsyncHandler = Box<dyn DynAsyncHandler>;

// After:
pub(crate) type BoxedHandler =
    Arc<dyn Fn(*const (), &mut Ctx<'_>) -> Result<()> + Send + Sync>;
pub(crate) type BoxedAsyncHandler = Arc<dyn DynAsyncHandler>;
```

The `Handler::call(&self, …)` trait already requires Fn semantics; the storage `FnMut` was unnecessarily restrictive. Zero user-facing change.

Adds `Dispatcher::clone_for_shard(&self) -> Self` — refcount-bump-per-slot.

### A.2 — Split `.on` + `ctx.emit` + macro injection

The `PayloadOnly` / `PayloadCtx` marker types stay **internal** — users never spell them. Each split method takes a single bounded handler type whose `Marker` is inferred:

```rust
// src/monitor/mod.rs
impl MonitorBuilder {
    /// Register a payload-only handler. Inference picks `PayloadOnly` automatically.
    pub fn on<E, H>(self, handler: H) -> Self
    where E: Event, H: Handler<E, PayloadOnly>
    { /* delegates to existing registry */ }

    /// Register a handler that also receives `&mut Ctx<'_>`.
    pub fn on_ctx<E, H>(self, handler: H) -> Self
    where E: Event, H: Handler<E, PayloadCtx>
    { /* delegates to existing registry */ }

    /// Deprecated three-generic form retained for one release cycle.
    #[deprecated(since = "0.21.0", note = "use `on::<E>` (payload-only) or `on_ctx::<E>` (payload + ctx); the marker is inferred")]
    pub fn on_with_marker<E, H, M>(self, handler: H) -> Self where E: Event, H: Handler<E, M>, M: 'static
    { self.handlers.register::<E, H, M>(handler); self }
}

// src/ctx/mod.rs
impl<'a> Ctx<'a> {
    /// Begin an anomaly emission with kind + severity. Uses `self.ts` as the timestamp.
    pub fn emit(&mut self, kind: &'static str, severity: Severity) -> AnomalyWriter<'_> {
        self.sink.begin(kind, severity, self.ts)
    }
}
```

The user calls `monitor.on::<Http>(|msg| { ... })` — one type generic only. No `<E, _, _>` turbofish. The markers stay as a private coherence trick the user doesn't see.

`detector!` macro injects `let __kind = $name; let __sev = Severity::$sev;` into the emit body. Users write `ctx.emit(__kind, __sev).with(...).emit()` and the kind slug isn't repeated.

### A.3 — Document existing `split_*`

No new API. Update `Ctx::state_mut`'s rustdoc with a "See also" pointing to `split_state_sink` / `split_state_counter` / `split_sink_counter` / `split_state_sink_counter`. Tutorial section. Example rewrite.

### A.4 — `state_init`

```rust
impl MonitorBuilder {
    pub fn state_init<T, F>(mut self, factory: F) -> Self
    where T: Send + 'static, F: FnOnce() -> T {
        *self.state_map.get_or_init_with::<T, _>(factory) = factory();
        self
    }
}
```

Drops the `T: Default` requirement. Lets users put `Arc<DashMap>`, `tokio::sync::Mutex`, etc. in the state map.

### A.5 — `with_dynamic`

```rust
impl<'sink> AnomalyWriter<'sink> {
    /// Allocating variant of `with(label, value)` for runtime-computed labels.
    /// One allocation per emit (the label `String`). Use only when `with` can't
    /// take a `&'static str`.
    pub fn with_dynamic(mut self, label: String, value: impl Into<Cow<'sink, str>>) -> Self { … }
}
```

### A.6 — Build-time counter validation

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// A detector references a counter type `K` that wasn't registered via `.counter::<K>(...)`.
    #[error("detector `{detector}` references counter type `{type_name}` but no `.counter::<{type_name}>(window, bucket)` was registered")]
    CounterNotRegistered { detector: &'static str, type_name: &'static str },
    // … existing variants …
}
```

Detectors declare the counter types they touch via a `Detector::declared_counters()` accessor:

```rust
impl<E, F> Detector<E, F> {
    /// Counter type-name slugs this detector accesses via `ctx.counter_mut::<K>`.
    /// Used by `MonitorBuilder::build()` for the validation pass.
    /// Default: empty (no counters touched).
    pub fn declared_counters(&self) -> &'static [&'static str] { self.declared_counters }
}
```

`detector!` and `pattern_detector!` macros stamp `declared_counters` from a new optional grammar element:

```rust
detector! {
    name: "DnsBurst",
    event: Dns,
    counters: [IpAddr],   // optional list of counter K type names
    severity: Warning,
    emit: |msg, ctx| { … },
}
```

Raw `.on::<E>(closure)` registrations are exempt (no metadata; validation skips). Documented limitation in the rustdoc — encourages users to write detectors via the macro.

`MonitorBuilder::build()` walks each registered `Detector::declared_counters` slug, checks each against the counter registry (which records `type_name` at registration), and returns `CounterNotRegistered` on miss.

### A.7 — `ctx.flow` doc clarification

No API change. Add rustdoc:

> For lifecycle events (`FlowStarted/Ended/Established<P>`) and message events, prefer `payload.key` — it's directly typed. `ctx.flow` carries the same value at a slightly less convenient access. For non-flow events (`Tick`), `ctx.flow` is `None`.

### A.8 — Restore `FlowPacket` / `FlowTick` / `ParserClosed` typed events

```rust
// src/protocol/event_typed.rs
pub struct FlowPacket<P: Protocol> {
    pub key: FiveTupleKey,
    pub side: FlowSide,
    pub len: usize,
    pub tcp: Option<TcpInfo>,
    pub ts: Timestamp,
    _p: PhantomData<P>,
}

pub struct FlowTick<P: Protocol> {
    pub key: FiveTupleKey,
    pub stats: FlowStats,
    pub ts: Timestamp,
    _p: PhantomData<P>,
}

pub struct ParserClosed<P: Protocol> {
    pub key: FiveTupleKey,
    pub parser_kind: &'static str,
    pub reason: ParserCloseReason,
    pub ts: Timestamp,
    _p: PhantomData<P>,
}

impl<P: Protocol> Event for FlowPacket<P> { type Payload = Self; }
// … same for FlowTick, ParserClosed.
```

`monitor/run.rs::dispatch_lifecycle` gets three new match arms; zero overhead when no handler registered (TypeId-lookup misses are constant-time).

### A.9 — Detector-name introspection

```rust
pub struct Detector<E, F> {
    pub handler: F,
    pub name: &'static str,       // NEW
    pub _marker: PhantomData<fn() -> E>,
}

impl MonitorBuilder {
    /// Register a handler with an explicit name for `Monitor::detector_names()` introspection.
    pub fn on_named<E: Event, H>(self, name: &'static str, handler: H) -> Self where H: … { … }
}

impl Monitor {
    pub fn detector_names(&self) -> impl Iterator<Item = &'static str> + '_ { … }
}
```

`detector!` macro stamps the declared `name:` slug into `Detector::name`. Raw closures registered via `.on::<E>` show up anonymously (excluded from `detector_names`).

### A.10 — `pub use OwnedAnomaly`

After Phase H.1 (flowscope 0.13.0 dep bump), replace the netring-side `OwnedAnomaly` in `shipped_sinks.rs` with `pub use flowscope::OwnedAnomaly`. Delete netring's definition.

If A.10 lands before Phase H.1, `pub use crate::anomaly::shipped_sinks::OwnedAnomaly` to surface it at `crate::anomaly` as an interim step.

### A.11 — `AnomalyWriter::emit_owned()`

```rust
impl<'sink> AnomalyWriter<'sink> {
    /// Materialize the writer as an OwnedAnomaly instead of firing the sink.
    /// Use for retention paths (ChannelSink already does this internally; this
    /// makes it user-controllable).
    pub fn emit_owned(self) -> OwnedAnomaly { … }
}
```

### A.12 — Examples + tutorial sweep

Rewrite all four monitor examples + the writing-detectors tutorial to use:
- `.on::<E>(...)` / `.on_ctx::<E>(...)` (no turbofish)
- `ctx.emit(kind, sev)` (no `let now = ctx.ts; ctx.sink_mut().begin(...)`)
- `ctx.split_state_sink::<T>()` for multi-borrow handlers
- Macro-emitted `__kind`/`__sev` bindings via `detector!`

### A.13 — `AnomalySink` key shape upgrade

Today's `AnomalySink::write(…, key: Option<&dyn Debug>, …)` passes the flow key as a `&dyn Debug` — opaque to sinks that want structured access. EveSink (Phase B.2) is the primary motivator: it needs `src_ip`/`src_port`/`dest_ip`/`dest_port`/`proto` as typed fields, not `format!("{:?}")` strings. The 0.20 shape forces an escape hatch (`EveSink::write_owned`) that breaks layered-sink composition.

Define a `netring::Key` trait that combines flowscope's `KeyFields` with `Debug` for human-readable rendering:

```rust
// src/anomaly/key.rs
use flowscope::KeyFields;

/// Anomaly key — combines structured 5-tuple access via [`KeyFields`]
/// with `Debug` for human-readable rendering. Blanket-impl'd for every
/// type satisfying both bounds; users implement neither directly.
pub trait Key: KeyFields + std::fmt::Debug + Send + Sync {}
impl<T: KeyFields + std::fmt::Debug + Send + Sync + ?Sized> Key for T {}
```

Tighten `AnomalySink::write`:

```rust
// src/anomaly/sink.rs (BREAKING)
pub trait AnomalySink: Send {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Key>,    // CHANGED from Option<&dyn Debug>
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    );

    fn flush(&mut self) -> Result<(), std::io::Error> { Ok(()) }
}
```

Tighten `AnomalyWriter::with_key`:

```rust
impl<'sink> AnomalyWriter<'sink> {
    pub fn with_key<K: Key>(mut self, key: &'sink K) -> Self {
        self.key_repr = Some(KeyRepr { key });
        self
    }
}
```

Sinks now have structured access:

```rust
// EveSink::write — no more escape hatch needed:
if let Some(key) = key {
    if let Some(src) = key.src_ip() { obj.insert("src_ip".into(), src.to_string().into()); }
    if let Some(p) = key.src_port() { obj.insert("src_port".into(), p.into()); }
    // … etc
}
// Plus Debug fallback for sinks that just want a slug:
let display_key = key.map(|k| format!("{k:?}"));
```

`StdoutSink` keeps its `key={k:?}` debug rendering via the `Debug` super-bound. `EveSink`, `MetricsSink`, `TracingSink` get typed-field access via `KeyFields`. `FiveTupleKey` already implements both (flowscope 0.13 ships `impl KeyFields for FiveTupleKey`; `Debug` is derived).

This is a **breaking change** to the `AnomalySink` trait — every custom sink impl needs the trait method signature update. User explicitly authorized backward-compat breaks for this cycle.

## 7. Implementation steps

1. **A.1** — change `BoxedHandler` / `BoxedAsyncHandler` / `BoxedTickHandler` aliases. Update trampoline closures in `HandlerRegistry::register` (one-line `Box::new` → `Arc::new`). Add `Dispatcher::clone_for_shard`. Run zero-alloc bench to confirm Δ 0/0 unchanged.
2. **A.2** — split `.on` into `.on` + `.on_ctx`. Add `#[deprecated]` on the old 3-generic shape. Add `Ctx::emit`. Update `detector!` macro to inject bindings.
3. **A.3** — rewrite `basic.rs:46-55`. Add rustdoc cross-ref. Tutorial section.
4. **A.4** — add `state_init`.
5. **A.5** — add `with_dynamic`.
6. **A.6** — add `Detector::declared_counters` accessor + `counters:` grammar element in `detector!` and `pattern_detector!` macros. Write `src/monitor/validate.rs`; call from `MonitorBuilder::build()`. Requires `CounterRegistry` to track type names at registration.
7. **A.7** — doc comment only.
8. **A.8** — add the three typed events; wire dispatch arms in `monitor/run.rs`. Verify zero-overhead with bench.
9. **A.9** — add `Detector::name` field; macro injection; `on_named` / `detector_names`.
10. **A.10** — after Phase H.1, swap to `pub use flowscope::OwnedAnomaly`.
11. **A.11** — `emit_owned` on `AnomalyWriter`.
12. **A.12** — example + tutorial sweep.
13. **A.13** — define `netring::Key` super-trait (`KeyFields + Debug + Send + Sync` with blanket impl). Tighten `AnomalySink::write` key parameter from `Option<&dyn Debug>` to `Option<&dyn Key>`. Tighten `AnomalyWriter::with_key`'s bound to `K: Key`. Update all four shipped sinks to read structured fields where they emit JSON/metrics/Eve.

## 8. Tests

- **A.1**: `tests/handler_arc_clone.rs` — register handler, clone dispatcher, dispatch through both, assert both ran.
- **A.1**: `cargo bench --bench zero_alloc -- handler_dispatch_5_http_slots` Δ 0 bytes / Δ 0 blocks.
- **A.2**: `tests/builder_on_vs_on_ctx.rs` — both forms compile + dispatch identically.
- **A.4**: `tests/state_init_factory.rs` — non-`Default` type slot.
- **A.5**: `tests/anomaly_with_dynamic.rs` — runtime-computed label round-trips.
- **A.6**: `tests/build_error_counter_not_registered.rs` — handler referencing unregistered `K` returns the error.
- **A.8**: `tests/typed_flow_packet_event.rs` — register `.on::<FlowPacket<Tcp>>(...)`, drive synthetic packets, assert handler fired.
- **A.9**: `tests/detector_name_introspection.rs` — `monitor.detector_names()` returns the macro-declared slugs in registration order.
- **A.11**: `tests/anomaly_emit_owned.rs` — round-trips through `OwnedAnomaly` cleanly.

Existing 419/419 tests must still pass.

## 9. Acceptance criteria

- `cargo nextest run -p netring --features tokio,channel,flow,parse,pcap,metrics,http,dns,tls,icmp,emit` all green.
- `cargo +stable clippy --workspace --all-targets --all-features -- -D warnings` clean.
- Zero-alloc bench unchanged (Δ 0/0).
- All four shipped monitor examples + tutorial use the new shortcuts.
- `cargo build --example monitor_basic --features "tokio,flow"` builds; reading the example demonstrates ~5 LoC win vs 0.20.

## 10. Risks

- **R1 — A.1 perf regression.** `Arc<dyn Fn>` vtable dispatch is theoretically identical to `Box<dyn FnMut>` dispatch, but Arc adds an inline 16-byte refcount header. Cache-line behavior should be the same; verify with bench.
- **R2 — A.6 build-time validation cost.** Walking every handler's TypeIds at build time is one-off; not a hot path. But the Event introspection helper (`type_name()`) adds boilerplate to every `Event` impl. Mitigation: blanket-impl via `std::any::type_name::<E::Payload>()` so users don't add anything.
- **R3 — A.8 dispatch overhead.** Adding three match arms to `dispatch_lifecycle` is +3 comparisons per packet. Negligible (~1ns); verify with bench.

## 11. Effort

- LoC delta: +750 (A.1 ~80, A.2 ~120, A.3 docs ~30, A.4 ~30, A.5 ~30, A.6 ~150, A.7 ~10, A.8 ~150, A.9 ~80, A.10 ~5, A.11 ~30, A.12 example sweep ~150, A.13 ~80).
- Time estimate: **~6.5 days**.

## 12. Provenance

- R1 (`.on::<E, _, _>` turbofish) → A.1, A.2.
- R2 (anomaly emit verbosity) → A.2 (`ctx.emit`).
- R3 (state_mut borrow gymnastics) → A.3 (documented; split_* already ship).
- R4 (FlowPacket/FlowTick/ParserClosed dropped) → A.8.
- R5 (no detector-name introspection) → A.9.
- R6 (`OwnedAnomaly` only in `shipped_sinks`) → A.10, A.11.

The `Arc<dyn Fn>` analysis for A.1 originally lived in `netring-0.20-phase-F3-handler-cloning-analysis.md` (deleted; content absorbed here and in Phase C).
