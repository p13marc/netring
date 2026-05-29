# Plan 26 — `MultiStreamConfig` + `flow_stream_with` for `Multi*Stream`s

## Summary

Add config-at-construction for `MultiFlowStream` / `MultiSessionStream` /
`MultiDatagramStream`. Today these types are built via
`AsyncMultiCapture::{flow,session,datagram}_stream(extractor, ...)`
constructors that apply default tracker config to each per-source
stream and offer no way to pass `with_dedup`, `with_config`,
`with_idle_timeout_fn`, or `with_pcap_tap` uniformly.

The shipped fix is **not** post-hoc `with_*` chaining on the
Multi*Stream (which the simple-nms ask sketched) — that's
architecturally incompatible with the `Pin<Box<dyn Stream + Send>>`
opaque-fan-in that backs `SelectState`. Instead: a new
`MultiStreamConfig` builder passed to new
`*_stream_with(extractor, config, ...)` constructors. The per-source
streams get configured during construction; the Multi*Stream's
public surface only adds the new constructors.

Closes simple-nms wishlist item **N2.1**.

## Status

Planned — targets 0.16.0 (after 0.15.0 ships plans 24 + 25).

## Prerequisites

- Plan 20 (`StreamCapture`) — for the existing accessor pattern.
- Plan 22 (`AsyncMultiCapture`) — the types being extended.

## Out of scope

- **Post-hoc `multi.with_dedup(dedup)` / `with_config(cfg)` on a
  built `Multi*Stream`**. The Multi*Stream's inner streams are
  boxed behind `SelectState`'s opaque trait-object fan-in; we
  cannot reach back through to apply config without unboxing
  (which would force public exposure of the per-source stream
  type). Config goes in at construction.
- **Per-source-different configs in `MultiStreamConfig`**. The
  config is uniform across sources. Heterogeneous setups use
  `AsyncMultiCapture::from_captures` with hand-built per-source
  `FlowStream`s (existing path).
- **A `pcap_tap` factory closure** in `MultiStreamConfig` for v1.
  Recording one pcap per source from a single config is awkward
  (per-source file paths, label substitution). Users who need
  per-source pcap output build per-source streams and
  `from_captures` them. Revisit if asked.

---

## Background — why config-at-construction

### The architecture constraint

`MultiFlowStream`'s internal:

```rust
struct SelectState<S> { streams: Vec<Option<S>>, … }
struct MultiFlowStream<E> {
    select: SelectState<FlowStream<Capture, E, (), NoReassembler>>,
    labels: Arc<Vec<String>>,
    capture_handles: Vec<…>,
}
```

The `S` parameter inside `SelectState` is the concrete inner
`FlowStream<Capture, E, …>`. To set `with_config` post-hoc, we'd
need either:

1. **`FlowStream::with_config(&mut self, …)`** — mutating, against
   the existing consuming-builder convention.
2. **Public access to `SelectState::streams`** — leaks internal
   shape.
3. **Tear down and rebuild on `with_*` call** — wasteful.

None of these are good. The clean answer: apply config to each
per-source `FlowStream` **during its construction**, then hand the
configured streams to `SelectState`. That requires the multi-side
constructor to accept the config.

### Why `MultiStreamConfig` is its own builder, not a re-use of `FlowTrackerConfig`

`FlowTrackerConfig` is flowscope's per-tracker knob bundle (idle
timeouts, max flows, sweep interval, etc.). The multi-stream
config also wants:

- An optional `Dedup` template (cloned per source).
- An optional `IdleTimeoutFn<K>` (also cloned/Arc'd per source).
- A `monotonic_ts` toggle.

These are netring-side concerns (composition over a tracker).
Mixing them into `FlowTrackerConfig` would muddy flowscope's
API. So a netring-owned `MultiStreamConfig` that *contains*
`FlowTrackerConfig` is the right shape.

### Why per-source dedup is cloned, not shared

Each source has its own kernel ring with its own packet stream.
Sharing one `Dedup` across sources via `Arc<Mutex<_>>` would
serialise all per-source dedup checks — defeating the multi-source
parallelism. Clone the template per source instead; per-source
dedup state is what users actually want.

`Dedup` is not currently `Clone`. Plan adds `Clone` impl. Trivial:
`Vec<Option<Entry>>` + `usize` + scalars.

---

## Files

### NEW

```
netring/netring/src/async_adapters/multi_config.rs   (MultiStreamConfig builder)
netring/netring/tests/multi_stream_config.rs         (integration)
```

### MODIFY

```
netring/netring/src/async_adapters/mod.rs            (mod multi_config + re-export)
netring/netring/src/async_adapters/multi_streams.rs  (new *_stream_with constructors)
netring/netring/src/async_adapters/multi_capture.rs  (new flow_stream_with / … entry points)
netring/netring/src/dedup.rs                         (impl Clone for Dedup)
netring/netring/src/lib.rs                           (re-exports)
netring/CHANGELOG.md
```

---

## API delta

### `MultiStreamConfig`

```rust
// netring/src/async_adapters/multi_config.rs

use std::sync::Arc;
use std::time::Duration;
use flowscope::{FlowTrackerConfig, IdleTimeoutFn, L4Proto};
use crate::Dedup;

/// Per-source config applied uniformly to every inner stream of a
/// [`MultiFlowStream`] / [`MultiSessionStream`] / [`MultiDatagramStream`].
///
/// The `tracker_config` is cloned per source. The `dedup` template,
/// if set, is cloned per source so each source has its own
/// independent dedup state. `idle_timeout_fn`, if set, is shared
/// via `Arc` and applied uniformly.
#[derive(Debug, Clone, Default)]
pub struct MultiStreamConfig<K> {
    /// Tracker config applied to each inner per-source tracker.
    pub tracker_config: FlowTrackerConfig,
    /// Optional dedup template, cloned per source.
    pub dedup: Option<Dedup>,
    /// Optional per-key idle-timeout predicate, applied uniformly.
    pub idle_timeout_fn: Option<Arc<dyn Fn(&K, Option<L4Proto>) -> Option<Duration> + Send + Sync + 'static>>,
    /// Apply monotonic-timestamp clamping to each inner stream.
    /// Default `false`.
    pub monotonic_ts: bool,
}

impl<K> MultiStreamConfig<K> {
    pub fn new() -> Self { Self::default() }

    pub fn with_tracker_config(mut self, c: FlowTrackerConfig) -> Self {
        self.tracker_config = c;
        self
    }

    pub fn with_dedup(mut self, d: Dedup) -> Self {
        self.dedup = Some(d);
        self
    }

    pub fn with_idle_timeout_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&K, Option<L4Proto>) -> Option<Duration> + Send + Sync + 'static,
    {
        self.idle_timeout_fn = Some(Arc::new(f));
        self
    }

    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.monotonic_ts = enable;
        self
    }
}
```

### New constructors on `AsyncMultiCapture`

```rust
impl AsyncMultiCapture {
    /// Like [`flow_stream`](Self::flow_stream) but applies `config`
    /// to every inner per-source stream.
    pub fn flow_stream_with<E>(
        self,
        extractor: E,
        config: MultiStreamConfig<E::Key>,
    ) -> MultiFlowStream<E>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Clone + Unpin + Send + 'static,
    {
        let (captures, labels) = self.into_captures();
        MultiFlowStream::new_with_config(captures, labels, extractor, config)
    }

    pub fn session_stream_with<E, F>(
        self,
        extractor: E,
        factory: F,
        config: MultiStreamConfig<E::Key>,
    ) -> MultiSessionStream<E, F>
    where /* same bounds as session_stream */;

    pub fn datagram_stream_with<E, F>(
        self,
        extractor: E,
        factory: F,
        config: MultiStreamConfig<E::Key>,
    ) -> MultiDatagramStream<E, F>
    where /* … */;
}
```

The existing `flow_stream(extractor)` / `session_stream(...)` /
`datagram_stream(...)` stay as shortcuts that pass
`MultiStreamConfig::default()`. **No breaking change** on the
existing constructors. The plan adds methods, doesn't remove.

### Internal: `MultiFlowStream::new_with_config`

```rust
impl<E> MultiFlowStream<E>
where
    E: FlowExtractor + Clone + Unpin + Send + 'static,
    E::Key: Clone + Unpin + Send + 'static,
{
    pub(crate) fn new_with_config(
        captures: Vec<AsyncCapture<Capture>>,
        labels: Vec<String>,
        extractor: E,
        config: MultiStreamConfig<E::Key>,
    ) -> Self {
        let streams = captures
            .into_iter()
            .map(|cap| {
                let mut s = cap
                    .flow_stream(extractor.clone())
                    .with_config(config.tracker_config.clone());
                if let Some(d) = &config.dedup {
                    s = s.with_dedup(d.clone());
                }
                if let Some(f) = &config.idle_timeout_fn {
                    let f = f.clone();
                    s = s.with_idle_timeout_fn(move |k, l4| f(k, l4));
                }
                if config.monotonic_ts {
                    s = s.with_monotonic_timestamps(true);
                }
                s
            })
            .collect();
        Self {
            select: SelectState::new(streams),
            labels: Arc::new(labels),
            // … existing capture_handles plumbing …
        }
    }
}
```

The existing `new(captures, labels, extractor)` becomes a thin
wrapper:

```rust
pub(crate) fn new(captures: Vec<…>, labels: Vec<…>, extractor: E) -> Self {
    Self::new_with_config(captures, labels, extractor, MultiStreamConfig::default())
}
```

Same shape for `MultiSessionStream::new_with_config` and
`MultiDatagramStream::new_with_config`.

### `impl Clone for Dedup`

```rust
// netring/src/dedup.rs

impl Clone for Dedup {
    fn clone(&self) -> Self {
        Self {
            ring: self.ring.clone(),
            head: self.head,
            window: self.window,
            direction_aware: self.direction_aware,
            dropped: 0,           // counters reset on clone
            seen: 0,
        }
    }
}
```

Per-source clones start with zero counters — each source's dedup
counts independently. Same shape as `Dedup::reset()`.

---

## Implementation steps

1. **`dedup.rs`**: add `impl Clone for Dedup`. Document
   counter-reset behaviour.
2. **`multi_config.rs`**: define `MultiStreamConfig` + builder
   methods.
3. **`async_adapters/mod.rs`**: `pub mod multi_config; pub use multi_config::MultiStreamConfig;`.
4. **`lib.rs`**: re-export `MultiStreamConfig`.
5. **`multi_streams.rs`**:
   - Add `MultiFlowStream::new_with_config(...)`.
   - Refactor `MultiFlowStream::new(...)` to delegate.
   - Same for `MultiSessionStream` and `MultiDatagramStream`.
6. **`multi_capture.rs` (or the entry-points block at the end of
   `multi_streams.rs`)**: add `flow_stream_with`,
   `session_stream_with`, `datagram_stream_with`.
7. **CHANGELOG entry** under 0.16.0.
8. **Integration test** (see below).

---

## Tests

### Integration: `tests/multi_stream_config.rs`

Gated `#[cfg(all(feature = "integration-tests", feature = "tokio", feature = "flow"))]`.

1. **`flow_stream_with` applies tracker config**. Build with
   `MultiStreamConfig::default().with_tracker_config(custom)`,
   confirm each source's `per_source_tracker_stats` reflects the
   custom sweep cadence.
2. **`with_dedup` template is cloned per source**. Build two-source
   multi with a `Dedup::loopback()` template. Send identical
   packets to both sources; per-source dedup counters increment
   independently (not shared).
3. **`with_idle_timeout_fn` applies uniformly**. Set a predicate
   that returns `Some(1ms)` for port 80; idle one source's
   port-80 flow; verify it expires within 10ms while other ports
   stay alive.
4. **`monotonic_ts` true** is reflected: per-source timestamp
   step-backs get clamped.
5. **Default constructors unchanged**: `multi.flow_stream(ext)`
   produces a stream behaviourally identical to
   `multi.flow_stream_with(ext, MultiStreamConfig::default())`.

### Unit (`multi_config.rs`)

Builder accessors — set/read each field round-trips.

---

## Acceptance criteria

- [ ] `MultiStreamConfig<K>` exists with the four builder methods.
- [ ] `AsyncMultiCapture::flow_stream_with` /
      `session_stream_with` / `datagram_stream_with` exist and
      apply the config to every inner stream.
- [ ] Existing `flow_stream` / `session_stream` / `datagram_stream`
      remain working as `MultiStreamConfig::default()` shortcuts.
- [ ] `Dedup: Clone` (counter-reset semantics documented).
- [ ] Integration test passes.
- [ ] `cargo clippy --all-features --tests -- -D warnings` clean.
- [ ] CHANGELOG entry under 0.16.0.

---

## Risks

- **`idle_timeout_fn: Arc<dyn Fn …>` requires `Sync`**, but
  `FlowStream::with_idle_timeout_fn` takes `Fn + Send + 'static`
  (no `Sync`). The Arc clone needs to invoke the closure per
  source; either bump the closure bound to `Sync` (breaking) or
  wrap the Arc in a per-source `move` closure capturing the Arc by
  clone — chosen. ~3 LoC.
- **`Dedup: Clone` semantics**: cloning produces a fresh dedup
  *state* (ring + counters reset), not a snapshot of running
  counters. Document loudly. Users expecting "clone preserves
  current state" would be surprised; the per-source-template use
  case wants the reset behaviour explicitly.
- **`MultiStreamConfig<K>` is generic on the key type**, which
  means simple-nms (with a known `FiveTupleKey`) can write
  `MultiStreamConfig::<FiveTupleKey>::new()`. The default
  constructor's idle-timeout-fn slot is `None` so the generic
  parameter is unconstrained without further bounds — Rust handles
  this fine via `_` inference at call site.
- **Builder vs config-struct shape**: `MultiStreamConfig` mirrors
  `with_*` builder semantics (consuming `Self`), not a plain
  struct (since `idle_timeout_fn` holds a closure). Public field
  access works for the simpler knobs (`tracker_config`,
  `monotonic_ts`); the closure-bearing fields need the methods.

---

## Effort

- Code: ~150 LoC.
- Test: ~150 LoC.
- CHANGELOG: 6 lines.
- **Estimate**: 1 day. Most of the time is the per-source
  per-config plumbing inside the `new_with_config` constructors.
