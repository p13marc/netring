# Plan 40 — Observability (`metrics` + `tracing`)

## Summary

Wire `metrics` counters (already used for capture) and `tracing`
spans into the flow stack. Operators get drop-in Prometheus /
OpenTelemetry / log integration without writing per-flow
instrumentation.

## Status

Not started.

## Prerequisites

- Plans 00–04 published.
- (Soft) Plan 11 benchmarks — so we can prove the `tracing` overhead
  is acceptable.

## Out of scope

- Custom dashboards or scrapers. Ship metric names; users wire
  Prometheus / Grafana / etc.
- Distributed tracing of cross-process flows.

---

## Goals

1. **Counters** for: flows created, ended (per reason), evictions,
   unmatched packets, parse errors.
2. **Histograms** for: per-flow byte counts on Ended, per-flow
   duration on Ended.
3. **Gauges** for: live flow count, hash table memory pressure.
4. **Tracing spans** (opt-in): one span per flow lifetime, fields
   for endpoints + stats + reason. `INFO`-level for new flows;
   `DEBUG` for per-packet.

---

## API

### Metrics

Behind a `metrics` feature on `netring-flow`:

```rust
// Names follow `metrics` crate conventions (snake_case prefix).

netring_flow_flows_created_total{l4="tcp"}        counter
netring_flow_flows_ended_total{reason="fin"}      counter
netring_flow_flows_ended_total{reason="rst"}      counter
netring_flow_flows_ended_total{reason="idle"}     counter
netring_flow_flows_ended_total{reason="evicted"}  counter
netring_flow_flows_active                          gauge
netring_flow_packets_unmatched_total              counter

netring_flow_bytes_total{side="initiator"}        counter (sum of all flows)
netring_flow_bytes_total{side="responder"}        counter

netring_flow_duration_seconds                     histogram (Ended events)
netring_flow_packets                               histogram (Ended events)
```

Implementation: `FlowTracker::track` increments counters in the
hot path. Behind `#[cfg(feature = "metrics")]` so the cost is
a compile-time zero when the feature is off.

```rust
#[cfg(feature = "metrics")]
fn record_new_flow(l4: Option<L4Proto>) {
    metrics::counter!("netring_flow_flows_created_total", "l4" => l4_label(l4)).increment(1);
    metrics::gauge!("netring_flow_flows_active").increment(1.0);
}

#[cfg(not(feature = "metrics"))]
#[inline(always)]
fn record_new_flow(_: Option<L4Proto>) {}
```

### Tracing

Behind a `tracing` feature on `netring-flow`:

```rust
use tracing::{debug, info, info_span, instrument};

#[cfg(feature = "tracing")]
let _span = info_span!("flow", proto = ?l4, init = ?key.a, resp = ?key.b).entered();
```

One span per flow on creation. Closes when the flow's `Ended` event
fires. Per-packet `debug!` events optional (heavy; off by default).

---

## Files

### MODIFIED

- `netring-flow/Cargo.toml` — add `metrics` and `tracing` optional
  deps. Wire to features.
- `netring-flow/src/tracker.rs` — add observation calls at each
  state transition.

### NEW

- `docs/OBSERVABILITY.md` — per-metric documentation, recommended
  Prometheus scrape config, Grafana panel queries.

---

## Cargo.toml deltas

```toml
[features]
metrics = ["dep:metrics"]
tracing = ["dep:tracing"]

[dependencies]
metrics = { version = "0.24", optional = true }
tracing = { version = "0.1", default-features = false, features = ["std", "attributes"], optional = true }
```

Both are zero-overhead when off (compile-time stripped).

---

## Implementation steps

1. **Land tiny `obs` module** in `netring-flow`:
   ```rust
   #[cfg(feature = "metrics")]
   pub(crate) mod obs {
       pub fn record_flow_created(l4: Option<L4Proto>) { ... }
       pub fn record_flow_ended(reason: EndReason, stats: &FlowStats) { ... }
       pub fn record_packet_unmatched() { ... }
       // etc
   }
   #[cfg(not(feature = "metrics"))]
   pub(crate) mod obs {
       pub fn record_flow_created(_: Option<L4Proto>) {}
       pub fn record_flow_ended(_: EndReason, _: &FlowStats) {}
       pub fn record_packet_unmatched() {}
   }
   ```
2. **Wire calls** at each state transition in `FlowTracker::track`,
   `sweep`, `set_config`.
3. **Add tracing spans** via a separate `#[cfg(feature = "tracing")]`
   gate — wrap key calls with `info_span!` enter/exit.
4. **Document** every metric + label dimension in
   `docs/OBSERVABILITY.md`.
5. **Export** the metric names as constants for users to reference:
   ```rust
   pub const METRIC_FLOWS_CREATED: &str = "netring_flow_flows_created_total";
   ```
6. **Bench**: re-run Plan 11 benches with `--features metrics,tracing`
   and document the overhead.

---

## Tests

- Compile-only test that `--no-default-features` works.
- Integration test that exercises the tracker once with
  `metrics-util::debugging::DebuggingRecorder` snapshot, verify
  counter values.

---

## Acceptance criteria

- [ ] `metrics` feature compiles cleanly.
- [ ] `tracing` feature compiles cleanly.
- [ ] All counters/gauges/histograms populate as expected.
- [ ] `docs/OBSERVABILITY.md` lists every metric.
- [ ] Bench delta from Plan 11 is documented (target: <5% overhead
      with `metrics`; <10% with `tracing` at INFO).

---

## Risks

1. **`metrics` crate label allocations.** `metrics::counter!`
   accepts string labels which may allocate. For per-packet calls
   this matters. Use `&'static str` labels everywhere; verify with
   `cargo expand`.
2. **`tracing` overhead.** Per-flow spans are cheap (one allocation
   per flow); per-packet `debug!` is expensive. Per-packet spans
   off by default; document the cost.
3. **Cardinality explosion.** Don't use flow keys as label values
   — that creates one time series per flow. Stick to coarse labels
   (l4 protocol, ended reason).
4. **`metrics` ABI.** It changed between 0.21 and 0.24. Pin the
   workspace dep to whatever's current; coordinate with `netring`'s
   existing `metrics` use.

---

## Effort

- LOC: ~250 (mostly the obs module + wiring).
- Time: 1.5 days (most effort is the docs and verifying overhead).
