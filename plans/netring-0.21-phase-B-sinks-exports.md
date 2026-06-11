# netring 0.21 Phase B — Sinks & exports

## 1. Summary

Two new sinks (`EveSink` for Suricata EVE JSON, `MetricsSink` for the `metrics` facade), two new examples, the `Tee::factory` constructor for per-shard fan-out, and the upstream re-exports that obsolete several netring-side types.

After flowscope 0.13.0 shipped `OwnedAnomaly` + `EveJsonWriter::write_owned_anomaly` + `DetectorScore`, this phase shrank from ~6 days (original plan: build the EVE schema from scratch) to ~1.5 days.

## 2. Status

Not started. Depends on Phase H.1 (flowscope 0.13 dep bump) for the upstream re-exports.

## 3. Prerequisites

- Phase A.10 + A.11 — `OwnedAnomaly` re-export path and `emit_owned()` writer method.
- Phase H.1 — `flowscope = 0.13.0` dependency landed.

## 4. Out of scope

- **OpenTelemetry direct adapter.** `MetricsSink` targets the `metrics` facade; OTel users install `metrics-exporter-otel` themselves.
- **Custom EVE event types beyond `anomaly`.** flowscope's writer also emits `event_type: "flow"` and `"stats"` for `FlowEvent`s; `EveSink` only handles netring-shape anomalies. Bridging both is a follow-up.

## 5. Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/anomaly/eve_sink.rs` | `EveSink` adapter over `flowscope::emit::EveJsonWriter` |
| New | `src/anomaly/metrics_sink.rs` | `MetricsSink` adapter for the `metrics` facade |
| Modify | `src/anomaly/mod.rs` | Module wiring; re-exports of upstream `OwnedAnomaly`/`KeyFields`/`AnomalyFields`/`DetectorScore` |
| Modify | `src/anomaly/shipped_sinks.rs` | Delete the netring-side `OwnedAnomaly` struct (replaced by upstream); update `ChannelSink` to use upstream `OwnedAnomaly` |
| Modify | `src/layer/tee.rs` | `Tee::factory(factory_fn)` constructor for per-shard fan-out |
| Modify | `src/prelude.rs` | Add `EveSink`, `MetricsSink`, `OwnedAnomaly`, `KeyFields`, `AnomalyFields`, `DetectorScore` |
| Modify | `Cargo.toml` | Feature gates: `eve-sink = ["flowscope/emit-eve"]`, `metrics-sink = ["dep:metrics"]` |
| New | `examples/monitor/eve_to_filebeat.rs` | EveSink end-to-end demo |
| New | `examples/monitor/prometheus_export.rs` | MetricsSink + Prometheus exporter demo |

## 6. API

### B.1 — Upstream re-exports

```rust
// src/anomaly/mod.rs
pub use flowscope::{KeyFields, AnomalyFields, OwnedAnomaly};
pub use flowscope::detect::patterns::DetectorScore;
// shipped_sinks::OwnedAnomaly deleted entirely (was a netring-side duplicate).
```

### B.2 — `EveSink`

Depends on Phase A.13 — the tightened `AnomalySink::write` key parameter (`Option<&dyn Key>`) gives structured field access without an escape hatch.

```rust
// src/anomaly/eve_sink.rs
use std::io::Write;
use flowscope::emit::{EveJsonWriter, EveOptions};
use flowscope::{OwnedAnomaly, Timestamp};
use crate::anomaly::{AnomalySink, Key, Severity};

pub struct EveSink<W: Write> {
    inner: EveJsonWriter<W>,
}

impl<W: Write> EveSink<W> {
    pub fn new(sink: W, options: EveOptions) -> Self {
        Self { inner: EveJsonWriter::new(sink, options) }
    }
}

impl<W: Write + Send> AnomalySink for EveSink<W> {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Key>,
        observations: &[(&'static str, std::borrow::Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        let mut anomaly = OwnedAnomaly::new(kind, severity, ts);
        if let Some(k) = key {
            anomaly = anomaly.with_key(k);   // structured 5-tuple flatten via KeyFields
        }
        for (label, value) in observations {
            anomaly = anomaly.with_observation(*label, value.as_ref());
        }
        for (label, value) in metrics {
            anomaly = anomaly.with_metric(*label, *value);
        }
        let _ = self.inner.write_owned_anomaly(&anomaly);
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.inner.flush()
    }
}
```

No `write_owned` escape hatch needed — A.13 makes the structured path the canonical one.

### B.3 — `MetricsSink`

```rust
// src/anomaly/metrics_sink.rs (feature = "metrics-sink")
use crate::anomaly::{AnomalySink, Severity};

pub struct MetricsSink {
    counter_name: &'static str,
    histogram_name: &'static str,
}

impl Default for MetricsSink {
    fn default() -> Self {
        Self {
            counter_name: "netring_anomaly_total",
            histogram_name: "netring_anomaly_metric",
        }
    }
}

impl AnomalySink for MetricsSink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        _ts: Timestamp,
        _key: Option<&dyn std::fmt::Debug>,
        _observations: &[(&'static str, std::borrow::Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        metrics::counter!(
            self.counter_name,
            "kind" => kind,
            "severity" => severity.as_str(),
        ).increment(1);
        for (label, value) in metrics {
            metrics::histogram!(
                self.histogram_name,
                "metric" => *label,
            ).record(*value);
        }
    }
}
```

**Cardinality contract** (documented in the rustdoc): only `kind` and `severity` become labels. The 5-tuple `key`, per-anomaly observations, and metric names are NEVER promoted to labels — that would create unbounded label cardinality.

### B.4 — `Tee::factory`

```rust
// src/layer/tee.rs
impl Tee {
    /// Static-secondary constructor (existing).
    pub fn new(secondary: Box<dyn AnomalySink>) -> Self { … }

    /// Factory constructor for per-shard fan-out — each shard builds
    /// its own secondary instance. Required for Phase C sharding
    /// where layers can't share a `Box<dyn AnomalySink>` across shards.
    pub fn factory<F>(secondary_factory: F) -> Self
    where F: Fn() -> Box<dyn AnomalySink> + Send + Sync + 'static { … }
}
```

### B.5 — `eve_to_filebeat.rs` example

```rust
// examples/monitor/eve_to_filebeat.rs
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = std::io::stdout();
    let eve = EveSink::new(stdout, flowscope::emit::EveOptions {
        in_iface: "eth0".into(),
        ..Default::default()
    });

    Monitor::builder()
        .interface("eth0")
        .protocol::<Tcp>()
        .on_ctx::<FlowStarted<Tcp>>(|evt, ctx| {
            ctx.emit("TcpFlowStarted", Severity::Info)
                .with_key(&evt.key)
                .emit();
            Ok(())
        })
        .sink(eve)
        .build()?
        .run_until_signal()
        .await
}
```

Comment block at the bottom: matching Filebeat configuration to ingest the stdout stream.

### B.6 — `prometheus_export.rs` example

Uses `metrics-exporter-prometheus`. Shows the user installing a `PrometheusBuilder` + spawning the HTTP exporter on `:9090`, then `MetricsSink::default()` feeds counters/histograms. Comment block: `curl http://localhost:9090/metrics` to verify.

## 7. Implementation steps

1. **H.1 prereq** lands flowscope 0.13.0. Once available, add the upstream re-exports (B.1) and delete the netring `OwnedAnomaly` duplicate.
2. **B.2** — write `EveSink`. The bulk is the trait `write()` implementation that constructs an `OwnedAnomaly` from the structured `&dyn Key` (Phase A.13) and delegates to `EveJsonWriter::write_owned_anomaly`. No escape hatch — A.13's structured key removes the need.
3. **B.3** — write `MetricsSink` behind `metrics-sink` feature.
4. **B.4** — add `Tee::factory`.
5. **B.5/B.6** — examples + matching Filebeat / Prometheus config in the example header comments.

## 8. Tests

- `tests/eve_sink_emits_valid_json.rs` — emit one anomaly through `EveSink`, parse the resulting JSON line with `serde_json::from_str`, assert `event_type: "anomaly"`, `kind`, `severity`, observation/metric nesting.
- `tests/metrics_sink_increments_counter.rs` — install a snapshotting recorder, emit two anomalies, assert `netring_anomaly_total{kind=…}` is 2.
- `tests/tee_factory_per_shard.rs` — synthetic shard count, assert each shard built its own secondary instance.
- Example smoke: `cargo build --example eve_to_filebeat --features "tokio,flow,eve-sink"` succeeds.

## 9. Acceptance criteria

- `EveSink` JSON output matches the EVE schema (cross-check one fixture against flowscope's own EVE writer tests).
- `MetricsSink` cardinality stays bounded — the test snapshot has at most O(kind × severity) label combinations.
- Examples build + run; the Filebeat/Prometheus config in the header is syntactically valid.

## 10. Risks

- **R1 — Cardinality blow-up in `MetricsSink`.** The Sink trait surface gives us `kind` (small, finite slug set) and `severity` (4 variants). Both safe as labels. But if a user adds an `MetricsSink` middleware that promotes observation labels to metric labels, cardinality explodes. **Mitigation:** the cardinality contract is documented in the rustdoc + the example. No promote-observations escape hatch.
- **R2 — ~~`AnomalySink::write` loses 5-tuple structure~~** — resolved by Phase A.13 (`Key` super-trait + tightened sink signature).

## 11. Effort

- LoC delta: +400 (EveSink ~120, MetricsSink ~80, Tee::factory ~30, examples ~120, tests ~50).
- Time estimate: **~1.5 days** (was 3 days, originally 6).

## 12. Provenance

- §2.7 (AnomalyKey trait) — replaced by upstream `KeyFields` + `AnomalyFields`.
- §2.18 (Prometheus/OTel) → B.3.
- §2.13 (`Tee::factory`) → B.4.
- §2.17 (EVE/Filebeat) → B.2.
- Round-2 wishlist plans 147 (EveJsonWriter::write_anomaly_custom) + 151 (OwnedAnomaly) shipped upstream and obsoleted ~5 days of original Phase B scope.
