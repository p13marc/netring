# netring 0.20 — Phase C: Performance hardening + AnomalyWriter + dhat CI gate

**Effort:** 2–3 days
**Predecessor:** [`Phase B`](./netring-0.20-phase-B-handler-trait.md) — Handler trait + dispatcher
**Successor:** [`Phase D`](./netring-0.20-phase-D-middleware.md) — async + middleware

## 1. Goal

Lock in the zero-allocation contract before more features pile on top. After this phase:

- `AnomalySink` has the real `begin()` API; user handlers emit anomalies via `AnomalyWriter` which uses `ArrayVec<_, 8>` + `Cow<'static, str>` for zero-alloc on the common path.
- Shipped sinks: `StdoutSink`, `StdoutJsonSink`, `TracingSink`, `ChannelSink` — each preallocates its buffer once.
- `Ctx` gains `split_state_sink::<T>()`, `split_state_counter::<T, K>()`, `split_state_sink_counter::<T, K>()` for handlers that need disjoint simultaneous access.
- `benches/zero_alloc.rs` ships, gated on the new `bench-zero-alloc` feature; CI fails if the steady-state delta exceeds 512 bytes per 100k events.
- Test the perf contract on representative shapes (Tcp lifecycle, Http message, Anomaly emit).

The phase doesn't add user-visible features. It hardens what Phase B built so Phases D–G can't accidentally regress it.

## 2. Scope

### In
- Real `AnomalySink` trait body — `begin(kind, severity, ts) -> AnomalyWriter<'_>` + `flush()`.
- `AnomalyWriter<'sink>` with `with_key`, `with(label, value)`, `with_metric`, `emit` — inline `ArrayVec<_, 8>` storage.
- `AnomalySinkWrite` extension trait for the actual `write` callback per sink impl.
- 4 shipped sinks: `StdoutSink`, `StdoutJsonSink`, `TracingSink`, `ChannelSink`.
- `Severity` enum (Info/Warning/Error/Critical) — copied from existing `netring::anomaly::Severity`.
- `Ctx::split_*` methods using audited `unsafe` for field-disjoint projection.
- `benches/zero_alloc.rs` — dhat-gated benchmark over 100k synthetic events.
- New `bench-zero-alloc` Cargo feature.
- CI job in `.github/workflows/ci.yml`.

### Out
- New event types — Phases B/E/F.
- Async handlers — Phase D.
- Tower layers — Phase D.
- Per-CPU sharding — Phase F.

## 3. Dependencies

- Phase B merged: `Ctx<'a>`, `Sink<A>` extractor stub, `Dispatcher`, `Monitor` builder skeleton.
- `dhat` crate added to `[dev-dependencies]`.
- `arrayvec` already added in Phase B; reuse here.
- `bytes` crate (already a workspace dep).

## 4. Module layout

```
src/
├── anomaly/
│   ├── mod.rs                    M  — re-export sink trait + writer + shipped sinks
│   ├── sink.rs                   M  — flesh out AnomalySink + AnomalyWriter
│   ├── severity.rs               A  — Severity enum (kept simple; matches 0.19.0)
│   └── shipped_sinks.rs          A  — StdoutSink, StdoutJsonSink, TracingSink, ChannelSink
│
├── ctx/
│   └── split.rs                  A  — split_state_sink etc. with audited unsafe
│
benches/
└── zero_alloc.rs                 A  — dhat-gated regression test
```

`Cargo.toml` adds:
```toml
[dev-dependencies]
dhat = "0.3"

[features]
bench-zero-alloc = ["dep:dhat"]

[[bench]]
name = "zero_alloc"
harness = false
required-features = ["bench-zero-alloc", "monitor"]
```

**LoC estimates:** ~700 LoC new (AnomalyWriter ~250, shipped sinks ~250, split helpers ~80, bench ~120) + ~200 LoC tests.

## 5. Detailed deliverables

### 5.1 `Severity` — `src/anomaly/severity.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl Default for Severity { fn default() -> Self { Self::Info } }

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        })
    }
}

impl From<flowscope::event::Severity> for Severity {
    fn from(s: flowscope::event::Severity) -> Self {
        use flowscope::event::Severity as F;
        match s {
            F::Info => Self::Info,
            F::Warning => Self::Warning,
            F::Error => Self::Error,
            F::Critical => Self::Critical,
            _ => Self::Warning,
        }
    }
}
```

### 5.2 `AnomalySink` + `AnomalyWriter` — `src/anomaly/sink.rs`

```rust
//! AnomalySink — destination for anomaly emissions.
//!
//! Handlers do NOT construct an `Anomaly` struct value. They use
//! the `AnomalyWriter` builder, which writes directly into the
//! sink's pre-allocated buffer. The framework never materializes
//! an `Anomaly<K>` value on the hot path.

use std::borrow::Cow;
use std::fmt::Debug;

use arrayvec::ArrayVec;
use flowscope::Timestamp;

use crate::anomaly::severity::Severity;

pub trait AnomalySink: Send {
    /// Begin building an anomaly. The returned `AnomalyWriter`
    /// is filled via `.with_*` calls and finalized with `.emit()`.
    fn begin(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
    ) -> AnomalyWriter<'_>;

    /// Flush any internal buffering. Called on shutdown.
    fn flush(&mut self) -> Result<(), std::io::Error> { Ok(()) }
}

/// Builder for a single anomaly. Lives on the stack.
/// `ArrayVec<_, 8>` inlines observations + metrics; overflow
/// silently drops the excess (documented; user can switch to
/// a custom sink for >8).
pub struct AnomalyWriter<'sink> {
    sink: &'sink mut dyn AnomalySink,
    kind: &'static str,
    severity: Severity,
    ts: Timestamp,
    key_repr: Option<KeyRepr<'sink>>,
    obs: ArrayVec<(&'static str, Cow<'sink, str>), 8>,
    metrics: ArrayVec<(&'static str, f64), 8>,
}

/// Erased borrow of a Debug-able key, avoiding the K type
/// parameter on AnomalyWriter (lets it pass through `&mut dyn
/// AnomalySink` without monomorphizing).
struct KeyRepr<'a> {
    debug: &'a dyn Debug,
}

impl<'sink> AnomalyWriter<'sink> {
    pub(crate) fn new(
        sink: &'sink mut dyn AnomalySink,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
    ) -> Self {
        Self {
            sink, kind, severity, ts,
            key_repr: None,
            obs: ArrayVec::new(),
            metrics: ArrayVec::new(),
        }
    }

    /// Attach a key. Borrowed via `&dyn Debug` so the writer
    /// stays K-erased. Caller's key must outlive the writer
    /// (held by the call frame).
    pub fn with_key<K: Debug>(mut self, key: &'sink K) -> Self {
        self.key_repr = Some(KeyRepr { debug: key });
        self
    }

    /// Attach an observation. `Cow<'sink, str>`: `&'static str`
    /// literals pass through with zero allocation; user-built
    /// `String` values cost one allocation per emit.
    pub fn with(
        mut self,
        label: &'static str,
        value: impl Into<Cow<'sink, str>>,
    ) -> Self {
        let _ = self.obs.try_push((label, value.into()));
        self
    }

    pub fn with_metric(mut self, label: &'static str, value: f64) -> Self {
        let _ = self.metrics.try_push((label, value));
        self
    }

    /// Emit. Forwards to the sink's `write` callback.
    pub fn emit(self) {
        // The sink trait carries `write` as a method that takes
        // borrowed slices, not the writer itself; we extract the
        // pieces and re-borrow.
        self.sink.write(
            self.kind,
            self.severity,
            self.ts,
            self.key_repr.as_ref().map(|k| k.debug),
            &self.obs,
            &self.metrics,
        );
    }
}

/// Extension trait — sinks implement this to receive the
/// rendered anomaly. The base `AnomalySink` trait only exposes
/// `begin` / `flush` so users can swap sinks via `&mut dyn`.
pub trait AnomalySinkWrite: AnomalySink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Debug>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    );
}

// The `write` method needs to live on AnomalySink so AnomalyWriter
// can call it without an extra trait bound. So we put it on the
// AnomalySink trait directly and blanket-impl AnomalySinkWrite.
// (Practical: merge AnomalySinkWrite back into AnomalySink in the
// final code; AnomalySinkWrite shown above is for clarity. In the
// real PR keep AnomalySink as the only trait.)
//
// Revised structure:
impl<'sink> dyn AnomalySink + 'sink {
    // (No additional methods needed — write is part of AnomalySink.)
}
```

**Decision:** the real PR merges `AnomalySinkWrite` into `AnomalySink`. The split shown above is for clarity in the plan; the implementation has one trait:

```rust
pub trait AnomalySink: Send {
    fn begin(&mut self, kind: &'static str, severity: Severity, ts: Timestamp)
        -> AnomalyWriter<'_>;

    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Debug>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    );

    fn flush(&mut self) -> Result<(), std::io::Error> { Ok(()) }
}
```

`AnomalyWriter::emit` calls `self.sink.write(...)`. Sinks override `write` to render; `begin` has a default impl that constructs the writer:

```rust
fn begin(&mut self, kind: &'static str, severity: Severity, ts: Timestamp)
    -> AnomalyWriter<'_> {
    AnomalyWriter::new(self, kind, severity, ts)
}
```

### 5.3 Shipped sinks — `src/anomaly/shipped_sinks.rs`

```rust
use std::borrow::Cow;
use std::fmt::Debug;
use std::io::Write;

use flowscope::Timestamp;

use crate::anomaly::severity::Severity;
use crate::anomaly::sink::AnomalySink;

/// One line of human-readable text per anomaly to stdout.
/// Pre-allocated buffer; reused across anomalies.
pub struct StdoutSink {
    buf: Vec<u8>,
}

impl StdoutSink {
    pub fn with_capacity(cap: usize) -> Self {
        Self { buf: Vec::with_capacity(cap) }
    }
}

impl Default for StdoutSink {
    fn default() -> Self { Self::with_capacity(4096) }
}

impl AnomalySink for StdoutSink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Debug>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        self.buf.clear();
        let _ = write!(&mut self.buf, "[{severity}] {kind} ts={ts}");
        if let Some(k) = key { let _ = write!(&mut self.buf, " key={k:?}"); }
        for (l, v) in observations { let _ = write!(&mut self.buf, " {l}={v}"); }
        for (l, v) in metrics { let _ = write!(&mut self.buf, " {l}={v:.2}"); }
        let _ = writeln!(&mut self.buf);
        let _ = std::io::stdout().write_all(&self.buf);
    }
}

/// One line of JSON per anomaly to stdout.
pub struct StdoutJsonSink {
    buf: Vec<u8>,
}

impl StdoutJsonSink {
    pub fn with_capacity(cap: usize) -> Self {
        Self { buf: Vec::with_capacity(cap) }
    }
}

impl AnomalySink for StdoutJsonSink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Debug>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        self.buf.clear();
        // Hand-rolled JSON to avoid serde_json allocation for the
        // outer object; uses serde_json only when escaping is needed.
        // For Phase C ship a simple version that uses serde_json::Map
        // (one allocation per emit) and ship a zero-alloc variant
        // as a follow-up if needed.
        let key_str = key.map(|k| format!("{k:?}")).unwrap_or_default();
        let mut obj = serde_json::Map::with_capacity(6);
        obj.insert("severity".into(), severity.to_string().into());
        obj.insert("kind".into(), kind.into());
        obj.insert("ts_secs".into(), ts.sec.into());
        obj.insert("ts_nanos".into(), ts.nsec.into());
        if !key_str.is_empty() {
            obj.insert("key".into(), key_str.into());
        }
        let mut obs_map = serde_json::Map::with_capacity(observations.len());
        for (l, v) in observations { obs_map.insert(l.to_string(), v.as_ref().into()); }
        obj.insert("observations".into(), obs_map.into());
        let mut met_map = serde_json::Map::with_capacity(metrics.len());
        for (l, v) in metrics {
            met_map.insert(l.to_string(),
                if v.is_finite() { (*v).into() } else { serde_json::Value::Null });
        }
        obj.insert("metrics".into(), met_map.into());
        let _ = serde_json::to_writer(&mut self.buf, &obj);
        self.buf.push(b'\n');
        let _ = std::io::stdout().write_all(&self.buf);
    }
}

/// Tracing emission sink. Emits each anomaly as a tracing event
/// at the level corresponding to its Severity.
pub struct TracingSink;

impl AnomalySink for TracingSink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Debug>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        let key_dbg = key.map(|k| format!("{k:?}"));
        let _ = (kind, severity, ts, key_dbg, observations, metrics);
        // tracing::event! macros — see rule.rs:emit_tracing in 0.19
        // for the pattern.
    }
}

/// Forwards each anomaly to a tokio mpsc channel as an owned
/// payload. Sinks that need to *retain* anomalies across the
/// dispatch frame can use this.
pub struct ChannelSink {
    tx: tokio::sync::mpsc::UnboundedSender<OwnedAnomaly>,
}

impl ChannelSink {
    pub fn new(tx: tokio::sync::mpsc::UnboundedSender<OwnedAnomaly>) -> Self {
        Self { tx }
    }
}

impl AnomalySink for ChannelSink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Debug>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        let owned = OwnedAnomaly {
            kind,
            severity,
            ts,
            key: key.map(|k| format!("{k:?}")),
            observations: observations
                .iter()
                .map(|(l, v)| (*l, v.to_string()))
                .collect(),
            metrics: metrics.iter().map(|(l, v)| (*l, *v)).collect(),
        };
        let _ = self.tx.send(owned);
    }
}

#[derive(Debug, Clone)]
pub struct OwnedAnomaly {
    pub kind: &'static str,
    pub severity: Severity,
    pub ts: Timestamp,
    pub key: Option<String>,
    pub observations: Vec<(&'static str, String)>,
    pub metrics: Vec<(&'static str, f64)>,
}
```

The `ChannelSink` is the only shipped sink that allocates per anomaly (intentional — it has to retain the anomaly past the dispatch frame). Document this prominently.

### 5.4 `Ctx::split_*` projection helpers — `src/ctx/split.rs`

```rust
//! Disjoint-field projection helpers on `Ctx`.
//!
//! Background: `FromCtx` extractors borrow from `Ctx` sequentially
//! (one at a time), so two `&mut`-extractors in the same handler
//! signature work only when they hit distinct `Ctx` fields. For
//! handlers that genuinely need simultaneous `&mut` access to two
//! or three Ctx fields, these helpers project disjoint references
//! via audited `unsafe`.
//!
//! Each method's safety argument: the projected fields are
//! distinct struct fields of `Ctx`; reading and writing them
//! simultaneously cannot alias.

use std::hash::Hash;

use crate::anomaly::sink::AnomalySink;
use crate::correlate::TimeBucketedCounter;
use crate::ctx::Ctx;

impl<'a> Ctx<'a> {
    /// Borrow `(&mut T, &mut dyn AnomalySink)` simultaneously.
    pub fn split_state_sink<T>(&mut self) -> (&mut T, &mut dyn AnomalySink)
    where T: Default + Send + 'static
    {
        let state: &mut T = self.state_map.get_or_init_mut::<T>();
        // SAFETY: state_map and sink are distinct fields of Ctx.
        // The state_map borrow above produces an `&mut T` that
        // is independent of the sink field. We re-borrow sink
        // via raw pointer to detach the borrow from `self.state_map`'s
        // lifetime tracking.
        let sink: &mut dyn AnomalySink = unsafe { &mut *(self.sink as *mut _) };
        (state, sink)
    }

    pub fn split_state_counter<T, K>(&mut self)
        -> (&mut T, &mut TimeBucketedCounter<K>)
    where T: Default + Send + 'static, K: Eq + Hash + Send + 'static
    {
        let state: &mut T = self.state_map.get_or_init_mut::<T>();
        let counter: &mut TimeBucketedCounter<K> = unsafe {
            // SAFETY: counters and state_map are distinct fields.
            &mut *(self.counters.get_mut::<K>() as *mut _)
        };
        (state, counter)
    }

    pub fn split_state_sink_counter<T, K>(&mut self)
        -> (&mut T, &mut dyn AnomalySink, &mut TimeBucketedCounter<K>)
    where T: Default + Send + 'static, K: Eq + Hash + Send + 'static
    {
        let state: &mut T = self.state_map.get_or_init_mut::<T>();
        let sink: &mut dyn AnomalySink = unsafe { &mut *(self.sink as *mut _) };
        let counter: &mut TimeBucketedCounter<K> = unsafe {
            &mut *(self.counters.get_mut::<K>() as *mut _)
        };
        (state, sink, counter)
    }

    /// `(&mut Sink, &mut Counter)` — useful for emit + counter
    /// increment in the same closure.
    pub fn split_sink_counter<K>(&mut self)
        -> (&mut dyn AnomalySink, &mut TimeBucketedCounter<K>)
    where K: Eq + Hash + Send + 'static
    {
        let sink: &mut dyn AnomalySink = unsafe { &mut *(self.sink as *mut _) };
        let counter: &mut TimeBucketedCounter<K> = self.counters.get_mut::<K>();
        (sink, counter)
    }
}
```

### 5.5 dhat-gated benchmark — `benches/zero_alloc.rs`

```rust
//! Allocation-regression test gated by `dhat`. Runs 100k synthetic
//! events through a fully-wired Monitor (3 protocols + 5 handlers
//! + 1 anomaly sink); asserts steady-state heap delta < 512 bytes.

#![cfg(feature = "bench-zero-alloc")]

use std::time::Duration;
use netring::anomaly::{
    sink::AnomalySink, shipped_sinks::StdoutJsonSink, severity::Severity,
};
use netring::ctx::{Ctx, Now, State, Sink};
use netring::monitor::Monitor;
use netring::protocol::builtin::{Http, Tcp};
use netring::protocol::event_typed::{FlowEnded, FlowStarted};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Default)]
struct Counters {
    starts: u64,
    ends: u64,
    http_msgs: u64,
}

fn main() {
    // dhat 0.3 canonical: builder-style with `.testing()` for
    // tests (enables dhat::assert_eq!) or omit for production.
    let _profiler = dhat::Profiler::builder().testing().build();

    let mut monitor = Monitor::builder()
        .interface("dummy")  // run_loop never opens this — see below
        .protocol::<Tcp>()
        .protocol::<Http>()
        .state::<Counters>()
        .on::<FlowStarted<Tcp>>(|_evt, c: State<Counters>| { c.starts += 1; Ok(()) })
        .on::<FlowEnded<Tcp>>(|_evt, c: State<Counters>| { c.ends += 1; Ok(()) })
        .on::<Http>(|_msg, c: State<Counters>| { c.http_msgs += 1; Ok(()) })
        .sink(StdoutJsonSink::with_capacity(4096))
        .build()
        .expect("build");

    // Warm up — let any one-time allocations settle.
    for _ in 0..10_000 { drive_one_synthetic_event(&mut monitor); }

    let before = dhat::HeapStats::get();
    for _ in 0..100_000 { drive_one_synthetic_event(&mut monitor); }
    let after = dhat::HeapStats::get();

    let delta_bytes = after.curr_bytes as i64 - before.curr_bytes as i64;
    let delta_blocks = after.curr_blocks as i64 - before.curr_blocks as i64;

    eprintln!("100k events: Δ {delta_bytes} bytes, Δ {delta_blocks} blocks");
    assert!(delta_bytes < 512,
            "alloc regression: {delta_bytes} bytes (limit 512). \
             See dhat-heap.json for the offending call site.");
    assert!(delta_blocks < 100,
            "block regression: {delta_blocks} blocks (limit 100)");
}

fn drive_one_synthetic_event(_m: &mut Monitor) {
    // Synthesize a FlowStarted<Tcp> event and dispatch it directly.
    // The benchmark bypasses AsyncCapture (no kernel involvement);
    // it exercises the dispatcher + sink + handler path only.
    //
    // TODO: implement when Monitor exposes a `dispatch_synthetic`
    // test-only entry point. Phase B should add one under
    // `#[cfg(feature = "bench-zero-alloc")]`.
}
```

A small `Monitor::dispatch_synthetic_for_bench(event)` test entry point under `#[cfg(feature = "bench-zero-alloc")]` is added in Phase B's `Monitor` impl so the benchmark can drive events without an `AsyncCapture`.

### 5.6 CI integration

`.github/workflows/ci.yml` — add a new job:

```yaml
zero-alloc:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v5
    - uses: dtolnay/rust-toolchain@stable
    - uses: Swatinem/rust-cache@v2
    - name: Run zero-allocation regression benchmark
      run: cargo bench --features bench-zero-alloc,monitor --bench zero_alloc
    - uses: actions/upload-artifact@v4
      if: failure()
      with:
        name: dhat-heap
        path: dhat-heap.json
```

## 6. Tests

### Inline unit tests

`src/anomaly/sink.rs`:
- `AnomalyWriter` accepts ≤8 observations / ≤8 metrics without growing.
- 9th observation silently drops (current contract); change-detector test against `arrayvec::CapacityError` if we change to err-on-overflow.
- `&'static str` literals pass through `with` without `Cow::Owned`.

`src/anomaly/shipped_sinks.rs`:
- `StdoutSink` reuses its buffer across emissions (test by inspecting `buf.capacity()`).
- `StdoutJsonSink` emits valid JSON.
- `ChannelSink` forwards owned anomalies on the channel.

`src/ctx/split.rs`:
- Soundness via `miri`: `cargo +nightly miri test --tests` — add to CI matrix.
- Functional: `(state, sink) = ctx.split_state_sink()` lets the caller mutate state and emit through sink in the same expression.

### Integration tests

`tests/anomaly_writer.rs`:

```rust
#[test]
fn writer_emits_to_stdout_sink() {
    let mut sink = StdoutSink::with_capacity(256);
    sink.begin("TestKind", Severity::Warning, Timestamp::new(1, 0))
        .with("note", "hello")
        .with_metric("count", 42.0)
        .emit();
    // No assertion — verify by running with --nocapture and eyeballing.
}

#[test]
fn writer_static_str_value_is_zero_alloc() {
    let mut sink = NoopSink;
    // Use a Profiler if the test runs under feature flag.
    sink.begin("K", Severity::Info, Timestamp::default())
        .with("label", "static-literal")
        .emit();
}
```

`tests/ctx_split.rs`:

```rust
use netring::ctx::{Ctx, ...};

#[test]
fn split_state_sink_is_disjoint() {
    // Construct a Ctx manually; call split_state_sink<MyState>();
    // mutate both simultaneously; assert independence.
}
```

## 7. Acceptance criteria

- [ ] `cargo build --features bench-zero-alloc,monitor` clean.
- [ ] `cargo nextest run` — all existing tests pass + new tests (~325+ total).
- [ ] `cargo +stable clippy --all-targets -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
- [ ] `cargo bench --features bench-zero-alloc,monitor --bench zero_alloc` runs and passes the 512-byte threshold.
- [ ] `cargo +nightly miri test --features monitor split` passes (soundness check for `Ctx::split_*`).
- [ ] CI `zero-alloc` job is wired and runs on every PR.
- [ ] `dhat-heap.json` is uploadable as a CI artifact on failure.

## 8. Risks + mitigations

1. **`dhat` API changes between versions.**
   `dhat = "0.3"` is stable; pin tightly. Canonical API: `Profiler::builder().testing().build()`, `HeapStats::get()` (with `.curr_bytes` + `.curr_blocks` fields), `dhat::Alloc` as global allocator. The older `Profiler::new_heap()` constructor still works for production-mode profiles.

2. **Tolerance threshold of 512 bytes may need tuning.**
   tokio's scheduler and some flowscope internals may allocate small amounts on rare events. Start strict (512 bytes); relax only with a documented justification. Don't paper over real regressions.

3. **`unsafe` in `Ctx::split_*` could regress soundness.**
   Mitigation: add `cargo +nightly miri test` to CI. Each `unsafe` block has an inline `// SAFETY:` comment justifying the projection.

4. **`AnomalyWriter::with` silently drops the 9th observation.**
   Trade-off: easier to use than `Result`-returning. Document prominently. Add a clippy-equivalent lint comment in `with`'s rustdoc: "use a custom AnomalySink if you need more than 8 observations per anomaly."

5. **`ChannelSink` allocates per anomaly.**
   Necessary — it has to retain the anomaly. Document. Users who don't need retention should use `StdoutJsonSink`, `StdoutSink`, or `TracingSink`.

6. **`StdoutJsonSink` allocates in the serde_json path.**
   Acceptable for Phase C. A follow-up phase could ship a hand-rolled zero-alloc JSON variant if a user reports this as a bottleneck.

## 9. Estimated effort + commit shape

**Total: 2–3 working days.** ~700 LoC new code + ~250 LoC tests.

**Commits (3):**

- `netring 0.20 (C.1): AnomalySink trait + AnomalyWriter + Severity enum` — ~300 LoC. Inline tests for writer.
- `netring 0.20 (C.2): StdoutSink + StdoutJsonSink + TracingSink + ChannelSink` — ~300 LoC. Sink-impl tests.
- `netring 0.20 (C.3): Ctx::split_* + benches/zero_alloc.rs + CI gate` — ~300 LoC + CI YAML. miri job added; dhat bench passes.

## 10. Cross-phase notes

- **Phase D** layers wrap `&mut dyn AnomalySink` around middleware (`DedupeAnomalies` etc.) — the trait must stay object-safe. The current shape (no generics on methods) is object-safe. ✓
- **Phase E** `detector!` macro expands to handler closures that call `sink.begin(...).with(...).emit()` — directly on top of this phase's API.
- **Phase F** per-CPU sharding gives each shard its own `Ctx`, its own `StateMap`, its own sink. The split-projection helpers stay; the per-CPU layer wraps them.
- **Phase G** migrates existing user detectors from the 0.19.0 `Anomaly<K>` builder API to the new `AnomalyWriter`. Sample diff in the migration guide.

Ready to execute once Phase B is merged.
