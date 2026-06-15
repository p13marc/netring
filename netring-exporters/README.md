# netring-exporters

Heavyweight anomaly exporters for [netring](https://github.com/p13marc/netring),
kept in a companion crate so the core stays free of their dependency trees
(0.25 W5).

Each exporter implements netring's `AnomalySink`, so it drops straight into
`MonitorBuilder::sink(...)`.

| Feature | Sink | Transport |
|---|---|---|
| `otlp` (default) | `OtlpAnomalySink` | OTLP/HTTP-JSON `logs` over a blocking HTTP client (`ureq`) |
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
