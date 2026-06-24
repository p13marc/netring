# netring-exporters

Heavyweight anomaly exporters for [netring](https://github.com/p13marc/netring),
kept in a companion crate so the core stays free of their dependency trees
(0.25 W5).

The anomaly exporters implement netring's `AnomalySink`, so they drop straight
into `MonitorBuilder::sink(...)`; the metrics exporter rides an
`on_capture_stats` handler.

| Feature | Exporter | Transport |
|---|---|---|
| `otlp` (default) | `OtlpAnomalySink` | OTLP/HTTP-JSON `logs` over a blocking HTTP client (`ureq`) |
| `otlp` (default) | `OtlpMetricsExporter` | OTLP/HTTP-JSON `metrics` (capture counters) over `ureq` |
| `parquet` | `ParquetFlowExporter` | columnar Parquet flow export (`arrow` + `parquet`) |
| `kafka` | `KafkaSink` | Kafka producer (`rdkafka` → librdkafka, a C dependency) |

```rust
use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;
use netring_exporters::OtlpAnomalySink;

let monitor = Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()
    .sink(OtlpAnomalySink::new("http://localhost:4318/v1/logs", "netring"))
    .build()?;
```

`OtlpMetricsExporter` pushes the per-source capture counters
(`netring.capture.packets` / `.drops` / `.freezes` cumulative Sums, plus the
windowed `.drop_rate` Gauge) to `/v1/metrics` once per sample period:

```rust
use std::time::Duration;
use netring_exporters::OtlpMetricsExporter;

let exporter = OtlpMetricsExporter::new("http://localhost:4318/v1/metrics", "netring");
let monitor = Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()
    .on_capture_stats(Duration::from_secs(10), move |t, _ctx| {
        let _ = exporter.export(t);
        Ok(())
    })
    .build()?;
```

## Examples

Runnable demos under [`examples/`](examples) (each prints what it would send, so
they run without a live collector/broker):

| Example | Feature | What it shows |
|---|---|---|
| `otlp_anomalies` | `otlp` | `OtlpAnomalySink` → OTLP/HTTP-JSON logs to `/v1/logs`, dropped into `.sink(..)` |
| `otlp_metrics` | `otlp` | `OtlpMetricsExporter` mapping `CaptureTelemetry` (packets/drops/freezes → Sums, drop_rate → Gauge) to `/v1/metrics`, driven from `on_capture_stats` |
| `parquet_flows` | `parquet` | `ParquetFlowExporter` (impl `netring::export::FlowExporter`) writing flow records as ZSTD-compressed Parquet with a flat OTel/OCSF-named schema |

```sh
cargo run -p netring-exporters --example otlp_metrics --features otlp
cargo run -p netring-exporters --example parquet_flows --features parquet
```

## Why a separate crate?

`rdkafka` pulls **librdkafka** (a C library) and `ureq` pulls a TLS stack —
neither belongs in netring's zero-dependency-creep core. Pulling them only when
you actually export keeps `cargo build -p netring` lean.

## Building

- `otlp` (default): pure-Rust HTTP + TLS, builds anywhere.
- `kafka`: needs librdkafka. `rdkafka` builds a bundled copy via cmake by
  default; install `cmake` + a C toolchain, or enable `rdkafka/dynamic-linking`
  to link a system librdkafka.

Anomaly→wire-format conversion is unit-tested without a collector/broker; the
live transport is validated against your OTLP collector / Kafka cluster.
