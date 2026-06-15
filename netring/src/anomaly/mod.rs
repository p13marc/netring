//! Anomaly value types + emission sinks.
//!
//! The [`Anomaly`] / [`AnomalyContext`] / [`Severity`] value types
//! describe a structured finding; the [`sink::AnomalySink`] trait +
//! the shipped sinks ([`shipped_sinks`], [`eve_sink`], [`metrics_sink`])
//! ship them somewhere.
//!
//! Detectors are written on the declarative
//! [`Monitor::builder()`](crate::monitor::Monitor) API — `on`/`on_ctx`
//! handlers, the [`detector!`](crate::detector) /
//! [`pattern_detector!`](crate::pattern_detector) macros — which emit
//! through `ctx.emit(kind, severity)`:
//!
//! ```no_run
//! # #[cfg(all(feature = "tokio", feature = "flow"))]
//! # async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! use netring::prelude::*;
//!
//! Monitor::builder()
//!     .interface("eth0")
//!     .protocol::<Tcp>()
//!     .on_ctx::<FlowStarted<Tcp>>(|evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
//!         ctx.emit("FlowStarted", Severity::Info).with_key(&evt.key).emit();
//!         Ok(())
//!     })
//!     .sink(StdoutSink::default())
//!     .build()?
//!     .run_until_signal()
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! The 0.19 `AnomalyMonitor` / `AnomalyRule` harness was removed in 0.22.

#[cfg(feature = "eve-sink")]
pub mod eve_sink;
pub mod key;
#[cfg(feature = "metrics")]
pub mod metrics_sink;
mod rule;
#[cfg(feature = "syslog")]
pub mod syslog_sink;

pub mod shipped_sinks;
pub mod sink;

pub use key::{Key, KeyFields};
// 0.22: the 0.19 `AnomalyMonitor` / `AnomalyRule` / `FlowAnomalyRule`
// API is removed. The `Anomaly` / `AnomalyContext` / `Severity` value
// types stay — they back the 0.20+ sinks + the `serde` feature.
pub use rule::{Anomaly, AnomalyContext, Severity};

/// 0.21 A.10 — canonical owned-anomaly value type is now upstream.
/// Re-exported here so `crate::anomaly::OwnedAnomaly` works regardless
/// of which sink consumed it.
pub use flowscope::OwnedAnomaly;

/// 0.21 I.1: flowscope's per-detector `DetectorScore` trait — used
/// by `pattern_detector!` so detectors with heterogeneous input
/// shapes (port-scan = `(K, ConnectionOutcome)`, beacon = `(K, ts,
/// bytes)`, DGA = `&str`) all emit through one canonical
/// `into_anomaly(ts) -> OwnedAnomaly` path.
pub use flowscope::DetectorScore;

/// 0.21 B.1: flowscope's structured-anomaly accessor trait. Used
/// by sinks that route per-anomaly fields (e.g. EveSink, MetricsSink)
/// to avoid stringifying everything through observations. Mirrors
/// `KeyFields` on the key side.
pub use flowscope::AnomalyFields;

#[cfg(feature = "eve-sink")]
pub use eve_sink::EveSink;
/// 0.25 W1d: Suricata `event_type: "tls"` EVE protocol records.
#[cfg(all(feature = "eve-sink", feature = "tls"))]
pub use eve_sink::{EveTlsSink, eve_tls_record};

/// 0.24 Phase D — `SyslogSink` RFC 5424 adapter. Gated on the `syslog`
/// Cargo feature (no deps).
#[cfg(feature = "syslog")]
pub use syslog_sink::{SyslogFacility, SyslogSink};

/// 0.21 B.3 — `MetricsSink` adapter over the `metrics`-rs facade.
/// Gated on the same `metrics` Cargo feature that pulls the
/// `metrics` crate.
#[cfg(feature = "metrics")]
pub use metrics_sink::MetricsSink;
