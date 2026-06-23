//! Heavyweight anomaly exporters for [netring](https://docs.rs/netring),
//! kept in a companion crate so the core stays free of their dependency trees
//! (0.25 W5).
//!
//! Each exporter implements netring's
//! [`AnomalySink`](netring::anomaly::sink::AnomalySink), so it drops straight
//! into `MonitorBuilder::sink(...)`:
//!
//! ```no_run
//! # #[cfg(feature = "otlp")]
//! # fn _ex() -> Result<(), netring::Error> {
//! use netring::monitor::Monitor;
//! use netring::protocol::builtin::Tcp;
//! use netring_exporters::OtlpAnomalySink;
//!
//! let _m = Monitor::builder()
//!     .interface("eth0")
//!     .protocol::<Tcp>()
//!     .sink(OtlpAnomalySink::new("http://localhost:4318/v1/logs", "netring"))
//!     .build()?;
//! # Ok(()) }
//! ```
//!
//! ## Exporters
//!
//! | Feature | Sink | Transport |
//! |---|---|---|
//! | `otlp` (default) | [`OtlpAnomalySink`] | OTLP/HTTP-JSON `logs` over blocking HTTP (`ureq`) |
//! | `otlp` (default) | [`OtlpMetricsExporter`] | OTLP/HTTP-JSON `metrics` (capture counters) over `ureq` |
//! | `kafka` | [`KafkaSink`] | Kafka producer (`rdkafka` → librdkafka C dependency) |
//!
//! [`OtlpMetricsExporter`] is **not** an `AnomalySink` — it pushes capture
//! telemetry from an
//! [`on_capture_stats`](netring::monitor::MonitorBuilder::on_capture_stats)
//! handler; see its docs for the wiring recipe.

#[cfg(feature = "otlp")]
mod metrics;
#[cfg(feature = "otlp")]
mod otlp;
#[cfg(feature = "otlp")]
pub use metrics::OtlpMetricsExporter;
#[cfg(feature = "otlp")]
pub use otlp::OtlpAnomalySink;

#[cfg(feature = "kafka")]
mod kafka;
#[cfg(feature = "kafka")]
pub use kafka::KafkaSink;
