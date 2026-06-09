# netring 0.20 — Phase D: Async escape hatch + tower-style middleware

**Effort:** 3–4 days
**Predecessor:** [`Phase C`](./netring-0.20-phase-C-perf-hardening.md) — AnomalyWriter + dhat CI
**Successor:** [`Phase E`](./netring-0.20-phase-E-macro-prelude.md) — detector! macro + prelude + multi-iface

## 1. Goal

Two independent features that share Phase C's foundation:

1. **Async escape hatch.** An `AsyncHandler<E, M>` trait + `MonitorBuilder::on_async::<E>(handler)` method. Handlers that need to `.await` (open a Redis connection, send to a Kafka producer) opt in explicitly. The per-event `Box::pin` cost is paid only by handlers that asked for it.
2. **Tower-style middleware.** A `Layer` trait + 5 shipped layers (`DedupeAnomalies`, `RateLimitAnomalies`, `MinSeverity`, `Sample`, `Tee`). Composable. Wraps the anomaly sink chain.

After this phase the K8s monitor from the redesign spec compiles end-to-end with both async handlers and a middleware stack:

```rust
Monitor::builder()
    .interfaces(["eth0"])
    .protocol::<Tcp>()
    .protocol::<Icmp>()
    .on::<FlowEnded<Tcp>>(|...| Ok(()))               // sync
    .on_async::<Icmp>(|msg, redis: State<RedisPool>| async move { ... })  // async
    .layer(DedupeAnomalies::within(Duration::from_secs(60)))
    .layer(MinSeverity::warning())
    .sink(StdoutJsonSink::with_capacity(4096))
    .build()?
    .run_until_signal()
    .await?;
```

## 2. Scope

### In
- `AsyncHandler<E, M>` trait + macro for 0..8 extractors.
- `impl_async_handler!` generated impls over `AsyncFn(&E::Payload, ...) -> Result<()>`.
- `MonitorBuilder::on_async::<E>(handler)` registration.
- `Layer` trait (re-export `tower::Layer` for ecosystem-compat).
- 5 shipped layers: `DedupeAnomalies`, `RateLimitAnomalies`, `MinSeverity`, `Sample`, `Tee`.
- `MonitorBuilder::layer(...)` plumbing. (`MonitorBuilder::sink(...)` already shipped in Phase B; layers wrap whatever sink is set.)
- Tests for handler + layer composition.

### Out
- `detector!` macro — Phase E.
- Multi-interface support — Phase E.
- Per-CPU sharding — Phase F.
- Migration recipes — Phase G.

## 3. Dependencies

- Phase C merged: `AnomalySink` trait body, shipped sinks, `AnomalyWriter`, `Ctx::split_*`.
- `tower` crate added to `[dependencies]` (with `util` feature).
- `compact_str` crate added (for dedup keys — see Risk #5 for the size tradeoff vs `smallstr`).
- `Pin<Box<dyn Future>>` machinery (no new crate — `std::pin`).

## 4. Module layout

```
src/
├── monitor/
│   ├── async_handler.rs          A  — AsyncHandler trait + impl_async_handler! macro
│   └── mod.rs                    M  — wire on_async into MonitorBuilder
│
├── layer/                        A  — middleware
│   ├── mod.rs                    A  — re-export tower::Layer + 5 shipped layers
│   ├── dedupe.rs                 A  — DedupeAnomalies
│   ├── rate_limit.rs             A  — RateLimitAnomalies
│   ├── min_severity.rs           A  — MinSeverity
│   ├── sample.rs                 A  — Sample
│   └── tee.rs                    A  — Tee<S2>
│
tests/
├── async_handler.rs              A  — async handler 0..8 arities + actual await
├── layer_compose.rs              A  — middleware ordering correctness
└── layer_dedupe.rs               A  — window semantics
```

**LoC estimates:** ~900 LoC new (~250 LoC AsyncHandler + macro, ~500 LoC across 5 layers, ~150 LoC Monitor plumbing).

## 5. Detailed deliverables

### 5.1 `Cargo.toml` additions

```toml
[dependencies]
tower = { version = "0.5", features = ["util"] }
compact_str = "0.9"
```

`tower` is used for its `Layer` trait shape — netring doesn't depend on `tower::Service` machinery (anomaly emissions aren't requests/responses in the tower sense). The `Layer` re-export is for ecosystem-API consistency.

`compact_str` (24-byte inline + heap spill) replaces the originally-planned `smallstr` (const-generic capacity) because `smallstr` has not seen a release since 2022. Note: a 5-tuple key Debug-formats to ~38 chars, exceeding compact_str's 24-byte inline budget — dedup keys will heap-allocate. Acceptable for typical event rates (≤100k dedup-checks/sec); high-rate users should write a custom dedup layer with an arena-allocated key store.

### 5.2 `AsyncHandler<E, M>` trait — `src/monitor/async_handler.rs`

```rust
//! Async handler trait. Separate from `Handler` because async
//! handlers pay a `Box::pin` per event; the trait split lets the
//! framework dispatch sync handlers without ever boxing.

use std::future::Future;
use std::pin::Pin;

use crate::ctx::{Ctx, FromCtx};
use crate::error::Result;
use crate::protocol::event_typed::Event;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait AsyncHandler<E: Event, M>: Send + Sync + 'static {
    fn call<'a>(
        &'a self,
        payload: &'a E::Payload,
        ctx: &'a mut Ctx<'a>,
    ) -> BoxFuture<'a, Result<()>>;
}

macro_rules! impl_async_handler {
    () => {
        impl<E, F, Fut> AsyncHandler<E, ((),)> for F
        where
            E: Event,
            F: Fn(&E::Payload) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = Result<()>> + Send + 'static,
        {
            #[inline]
            fn call<'a>(
                &'a self,
                p: &'a E::Payload,
                _ctx: &'a mut Ctx<'a>,
            ) -> BoxFuture<'a, Result<()>> {
                Box::pin(self(p))
            }
        }
    };
    ( $($P:ident),+ ) => {
        impl<E, F, Fut, $($P),+> AsyncHandler<E, ($($P,)+)> for F
        where
            E: Event,
            F: for<'a> Fn(
                &'a E::Payload,
                $(<$P as FromCtx>::Target<'a>),+
            ) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = Result<()>> + Send + 'static,
            $($P: FromCtx + 'static),+
        {
            #[inline]
            fn call<'a>(
                &'a self,
                p: &'a E::Payload,
                ctx: &'a mut Ctx<'a>,
            ) -> BoxFuture<'a, Result<()>> {
                $(
                    let $P = <$P as FromCtx>::from_ctx(ctx);
                )+
                Box::pin(self(p, $($P),+))
            }
        }
    };
}

impl_async_handler!();
impl_async_handler!(P1);
impl_async_handler!(P1, P2);
impl_async_handler!(P1, P2, P3);
impl_async_handler!(P1, P2, P3, P4);
impl_async_handler!(P1, P2, P3, P4, P5);
impl_async_handler!(P1, P2, P3, P4, P5, P6);
impl_async_handler!(P1, P2, P3, P4, P5, P6, P7);
impl_async_handler!(P1, P2, P3, P4, P5, P6, P7, P8);
```

**Coherence note:** the async impl uses `((),)` (a tuple wrapping unit) for the 0-extractor case to avoid overlap with the sync `Handler<E, ()>` blanket impl. The `M` phantom parameter on `Handler` and `AsyncHandler` are independent.

### 5.3 `MonitorBuilder::on_async` — `src/monitor/mod.rs` addition

```rust
impl MonitorBuilder {
    /// Register an async handler.
    ///
    /// Each event dispatched to an async handler costs **one heap
    /// allocation** (the boxed future). Prefer the sync `on(...)`
    /// when possible.
    pub fn on_async<E, H, M>(mut self, handler: H) -> Self
    where E: Event, H: AsyncHandler<E, M>, M: 'static
    {
        self.handlers.register_async::<E, H, M>(handler);
        self
    }
}
```

`HandlerRegistry::register_async` is a sibling to `register`, with a slightly different signature on the stored boxed handler:

```rust
type BoxedAsyncHandler =
    Box<dyn for<'a> Fn(*const (), &'a mut Ctx<'a>) -> BoxFuture<'a, Result<()>> + Send + Sync>;

impl HandlerRegistry {
    pub fn register_async<E: Event, H: AsyncHandler<E, M>, M: 'static>(
        &mut self, handler: H,
    ) {
        let boxed: BoxedAsyncHandler = Box::new(move |ptr, ctx| {
            // SAFETY: see Phase B's register doc for invariant.
            let typed: &E::Payload = unsafe { &*(ptr as *const E::Payload) };
            handler.call(typed, ctx)
        });
        self.async_by_type
            .entry(TypeId::of::<E::Payload>())
            .or_default()
            .push(boxed);
    }
}
```

### 5.4 Dispatcher updates — `src/monitor/dispatcher.rs`

```rust
pub struct Dispatcher {
    slot_by_type: ArrayVec<(TypeId, u8), 16>,
    slots: Box<[Vec<HandlerSlot>]>,
    /// Phase D: async handler slots. Parallel structure to `slots`.
    async_slots: Box<[Vec<AsyncHandlerSlot>]>,
}

struct AsyncHandlerSlot {
    handler: BoxedAsyncHandler,
}

impl Dispatcher {
    /// Dispatch sync handlers (already in Phase B).
    pub fn dispatch<P: 'static>(&mut self, payload: &P, ctx: &mut Ctx<'_>) -> Result<()> {
        // (unchanged)
    }

    /// Dispatch async handlers. Returns a future that resolves
    /// when all registered async handlers for this payload type
    /// have completed.
    pub async fn dispatch_async<P: 'static>(
        &mut self,
        payload: &P,
        ctx: &mut Ctx<'_>,
    ) -> Result<()> {
        let Some(slot_idx) = self
            .slot_by_type
            .iter()
            .find(|(t, _)| *t == TypeId::of::<P>())
            .map(|(_, s)| *s as usize)
        else { return Ok(()) };

        let ptr = payload as *const P as *const ();
        for slot in &self.async_slots[slot_idx] {
            (slot.handler)(ptr, ctx).await?;
        }
        Ok(())
    }
}
```

`run_loop` calls both — sync first (zero cost when nothing's registered), then async:

```rust
// (1) Sync lifecycle dispatch (Phase B)
dispatch_lifecycle(&mut monitor, evt)?;

// (2) Async lifecycle dispatch (Phase D)
dispatch_lifecycle_async(&mut monitor, evt).await?;
```

### 5.5 `Layer` re-export + shipped layers — `src/layer/mod.rs`

```rust
//! Middleware over the anomaly sink chain. Each layer wraps an
//! `AnomalySink` and intercepts `begin` / `write` calls.

pub use tower::Layer;

mod dedupe;
mod min_severity;
mod rate_limit;
mod sample;
mod tee;

pub use dedupe::DedupeAnomalies;
pub use min_severity::MinSeverity;
pub use rate_limit::RateLimitAnomalies;
pub use sample::Sample;
pub use tee::Tee;
```

### 5.6 `DedupeAnomalies` — `src/layer/dedupe.rs`

```rust
use std::borrow::Cow;
use std::fmt::Debug;
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;
use compact_str::CompactString;

use crate::anomaly::sink::AnomalySink;
use crate::anomaly::severity::Severity;
use flowscope::Timestamp;

/// Suppress duplicate anomalies (same kind + same key Debug-string)
/// within a sliding window.
pub struct DedupeAnomalies<S> {
    inner: S,
    window: Duration,
    seen: FxHashMap<DedupeKey, Instant>,
}

type DedupeKey = (&'static str, CompactString);

impl<S> DedupeAnomalies<S> {
    pub fn new(inner: S, window: Duration) -> Self {
        Self { inner, window, seen: FxHashMap::default() }
    }

    pub fn within(window: Duration) -> impl tower::Layer<S, Service = DedupeAnomalies<S>>
    where S: AnomalySink
    {
        DedupeLayer { window, _phantom: std::marker::PhantomData }
    }
}

pub struct DedupeLayer<S> {
    window: Duration,
    _phantom: std::marker::PhantomData<fn() -> S>,
}

impl<S: AnomalySink> tower::Layer<S> for DedupeLayer<S> {
    type Service = DedupeAnomalies<S>;
    fn layer(&self, inner: S) -> Self::Service {
        DedupeAnomalies::new(inner, self.window)
    }
}

impl<S: AnomalySink> AnomalySink for DedupeAnomalies<S> {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Debug>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        let key_str: CompactString = key
            .map(|k| {
                let mut s = CompactString::new("");
                use std::fmt::Write;
                let _ = write!(&mut s, "{k:?}");
                s
            })
            .unwrap_or_default();
        let dedupe_key = (kind, key_str);

        let now = Instant::now();
        if let Some(prev) = self.seen.get(&dedupe_key) {
            if now.duration_since(*prev) < self.window { return }
        }
        self.seen.insert(dedupe_key, now);
        self.inner.write(kind, severity, ts, key, observations, metrics);
    }
}
```

### 5.7 `MinSeverity` — `src/layer/min_severity.rs`

```rust
use std::borrow::Cow;
use std::fmt::Debug;

use crate::anomaly::sink::AnomalySink;
use crate::anomaly::severity::Severity;
use flowscope::Timestamp;

/// Suppress anomalies below a threshold severity.
pub struct MinSeverity<S> {
    inner: S,
    floor: Severity,
}

impl<S> MinSeverity<S> {
    pub fn new(inner: S, floor: Severity) -> Self { Self { inner, floor } }
    pub fn warning() -> impl tower::Layer<S, Service = MinSeverity<S>>
    where S: AnomalySink {
        MinSeverityLayer { floor: Severity::Warning, _p: std::marker::PhantomData }
    }
    pub fn error() -> impl tower::Layer<S, Service = MinSeverity<S>>
    where S: AnomalySink {
        MinSeverityLayer { floor: Severity::Error, _p: std::marker::PhantomData }
    }
    pub fn at_least(floor: Severity) -> impl tower::Layer<S, Service = MinSeverity<S>>
    where S: AnomalySink {
        MinSeverityLayer { floor, _p: std::marker::PhantomData }
    }
}

pub struct MinSeverityLayer<S> {
    floor: Severity,
    _p: std::marker::PhantomData<fn() -> S>,
}

impl<S: AnomalySink> tower::Layer<S> for MinSeverityLayer<S> {
    type Service = MinSeverity<S>;
    fn layer(&self, inner: S) -> Self::Service { MinSeverity::new(inner, self.floor) }
}

impl<S: AnomalySink> AnomalySink for MinSeverity<S> {
    fn write(
        &mut self, kind: &'static str, severity: Severity, ts: Timestamp,
        key: Option<&dyn Debug>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        if severity < self.floor { return }
        self.inner.write(kind, severity, ts, key, observations, metrics);
    }
}
```

### 5.8 `RateLimitAnomalies` — `src/layer/rate_limit.rs`

```rust
//! Per-kind rate limit. Drops anomalies of a given kind when
//! they fire faster than the configured budget.

use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;

use crate::anomaly::sink::AnomalySink;
// ... full impl ~120 LoC; same shape as DedupeAnomalies but with
// token-bucket per-kind instead of per-(kind, key).
```

### 5.9 `Sample` — `src/layer/sample.rs`

```rust
//! Probabilistic sampling. Each anomaly is forwarded with
//! probability `rate`.

pub struct Sample<S> { inner: S, rate: f64, rng_state: u64 }

// xorshift inline so we don't pull rand crate.
// ~80 LoC.
```

### 5.10 `Tee<S2>` — `src/layer/tee.rs`

```rust
//! Fan-out: write each anomaly to both `inner` and `other` sinks.
pub struct Tee<S, S2> { inner: S, other: S2 }
// ~50 LoC.
```

### 5.11 Wiring middleware into `MonitorBuilder`

```rust
impl MonitorBuilder {
    /// Wrap the sink chain in a layer. Order matters: the first
    /// layer registered is the outermost (runs first per emission).
    ///
    /// `.sink(...)` lives in Phase B; this method extends that
    /// pipeline.
    pub fn layer<L>(self, layer: L) -> Self
    where L: tower::Layer<Box<dyn AnomalySink>>,
          L::Service: AnomalySink + 'static
    {
        // Internally: keep a chain of Box<dyn AnomalySink>; each
        // .layer() call wraps the current head.
        // ~30 LoC implementation.
        self
    }
}
```

The composition rule:

```rust
.layer(L1).layer(L2).sink(S)
// becomes
sink = L1.layer(L2.layer(S))
// so at runtime: emit → L1.write → L2.write → S.write
```

L1 is outermost. Document this clearly — users will get the ordering wrong otherwise.

## 6. Tests

`tests/async_handler.rs`:

```rust
#[tokio::test(flavor = "current_thread")]
async fn async_handler_compiles_and_awaits() {
    let _m = Monitor::builder()
        .interface("lo")
        .protocol::<Http>()
        .on_async::<Http>(|_msg| async move {
            tokio::task::yield_now().await;
            Ok(())
        })
        .build()
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn async_handler_with_extractors() {
    #[derive(Default)] struct St { count: u64 }
    let _m = Monitor::builder()
        .interface("lo")
        .state::<St>()
        .protocol::<Http>()
        .on_async::<Http>(|_msg, st: State<St>| async move {
            st.count += 1;
            Ok(())
        })
        .build()
        .unwrap();
}
```

`tests/layer_compose.rs`:

```rust
#[test]
fn min_severity_drops_below_floor() {
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let cap = captured.clone();
    let capture_sink = FnSink::new(move |kind, sev, _, _, _, _| {
        cap.lock().unwrap().push(format!("{kind} {sev}"));
    });
    let mut sink = MinSeverity::new(capture_sink, Severity::Warning);
    // info -> dropped
    sink.begin("Info", Severity::Info, Timestamp::default()).emit();
    // warning -> through
    sink.begin("Warn", Severity::Warning, Timestamp::default()).emit();
    // critical -> through
    sink.begin("Crit", Severity::Critical, Timestamp::default()).emit();
    let log = captured.lock().unwrap();
    assert_eq!(log.len(), 2);
}

#[test]
fn dedupe_suppresses_within_window() {
    // ~30 LoC test using a similar capture sink.
}

#[test]
fn rate_limit_drops_overflow_per_kind() {
    // ~30 LoC.
}

#[test]
fn sample_at_rate_zero_drops_all() {
    // ~20 LoC.
}

#[test]
fn tee_writes_to_both_sinks() {
    // ~20 LoC.
}
```

A test-only `FnSink<F>` helper lets tests capture writes:

```rust
struct FnSink<F>(F);
impl<F: FnMut(...)> AnomalySink for FnSink<F> { /* forwards to F */ }
```

## 7. Acceptance criteria

- [ ] `cargo build` clean with the new layer/async modules.
- [ ] `cargo nextest run` — 340+ tests pass.
- [ ] `cargo +stable clippy --all-targets -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
- [ ] dhat bench from Phase C still passes (≤512 B / 100k events) — async handlers were *not* added to the bench, so the budget is unchanged.
- [ ] All 5 layers compose; order is documented; each layer has unit tests covering its contract.
- [ ] An async handler with 0..8 extractors compiles + runs.

## 8. Risks + mitigations

1. **`AsyncFn` trait family stabilization status.**
   Stabilized in Rust 1.85 (Mar 2025). MSRV 1.95 well clear. No risk.

2. **Coherence between `Handler<E, ()>` and `AsyncHandler<E, ((),)>`.**
   Separate marker tuples sidestep overlap. Verify with a test that registers both sync + async handlers for the same event type:
   ```rust
   .on::<Http>(|_| Ok(()))
   .on_async::<Http>(|_| async { Ok(()) })
   ```
   Both compile; both fire on each Http event.

3. **`tower::Layer` `Service` associated type confusion.**
   We're using `Service` to mean "the wrapped `AnomalySink`," not in tower's HTTP-service sense. Document in `layer/mod.rs` rustdoc. If this causes confusion in PRs, fall back to a netring-internal `Layer` trait (30 LoC):
   ```rust
   pub trait Layer<S> { type Wrapped; fn wrap(&self, inner: S) -> Self::Wrapped; }
   ```

4. **Layer order is unintuitive.**
   "First registered = outermost = runs first" is the convention from `tracing-subscriber` and `tower::ServiceBuilder`. Document with a `// outer → inner` diagram in `MonitorBuilder::layer` rustdoc.

5. **`CompactString` heap-spills on >24-byte keys.**
   A `FiveTupleKey` `Debug`-formats to ~38 bytes typically — past compact_str's 24-byte inline budget. Every dedup-check on a typical key allocates. Acceptable for moderate event rates; high-rate users build a custom dedup layer with an arena. Escape hatch if a real perf issue surfaces: hand-rolled `enum DedupKey { Inline([u8; 64], u8), Heap(Box<str>) }` (~30 LoC).

6. **Per-event `Box::pin` cost in `dispatch_async`.**
   This is the documented cost of `on_async`. Test that the dhat benchmark with `on_async` registered shows the cost is bounded (one box per event, not more).

## 9. Estimated effort + commit shape

**Total: 3–4 working days.** ~900 LoC new code + ~300 LoC tests.

**Commits (4):**

- `netring 0.20 (D.1): AsyncHandler trait + impl_async_handler! macro 0..8 arities` — ~250 LoC.
- `netring 0.20 (D.2): MonitorBuilder::on_async + Dispatcher::dispatch_async + run_loop integration` — ~150 LoC.
- `netring 0.20 (D.3): tower::Layer re-export + 5 shipped layers + MonitorBuilder::layer + .sink` — ~500 LoC + tests.
- `netring 0.20 (D.4): layer composition tests + dedup-key benchmarking + layer-ordering rustdoc` — ~100 LoC.

## 10. Cross-phase notes

- **Phase E** `detector!` macro can expand to either sync or async handlers via syntax (`detector! async { ... }` for async).
- **Phase E** prelude re-exports the 5 layers at `netring::prelude::{DedupeAnomalies, MinSeverity, ...}`.
- **Phase F** per-CPU sharding: each shard has its own sink chain. Layers don't need to be `Send + Sync` for per-CPU mode (the sink is local to the shard) — current trait bounds allow this.
- **Phase G** migration recipes show how `FlowAnomalyRule::with_min_severity(Severity::Warning)` (a 0.19 one-off) becomes `.layer(MinSeverity::warning())`.

Ready to execute once Phase C is merged.
