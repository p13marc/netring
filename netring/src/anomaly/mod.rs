//! Multi-protocol anomaly correlation harness.
//!
//! Built on top of [`ProtocolEvent`](crate::protocol::ProtocolEvent),
//! `AnomalyMonitor` lets you compose detectors as small typed rules
//! (each implementing the [`AnomalyRule`] trait), feed them events
//! and periodic ticks, and collect their findings as
//! [`Anomaly`] records.
//!
//! Compared to writing each detector as a hand-rolled
//! `tokio::select!` over multiple streams (see
//! `examples/anomaly/dns_resolved_no_connection.rs`), the harness
//! collapses the boilerplate to:
//!
//! 1. one `ProtocolMonitorBuilder` to declare which protocols to
//!    observe,
//! 2. one `AnomalyMonitor` populated via `.with_rule(...)`, and
//! 3. one event-loop calling `monitor.observe(&evt)` + a tick that
//!    calls `monitor.on_tick(now)`.
//!
//! ```no_run
//! # #[cfg(all(feature = "tokio", feature = "flow"))]
//! # async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::Duration;
//! use futures::StreamExt;
//! use flowscope::Timestamp;
//! use netring::anomaly::{Anomaly, AnomalyMonitor, AnomalyRule, Severity};
//! use netring::flow::extract::{FiveTuple, FiveTupleKey};
//! use netring::protocol::{ProtocolEvent, ProtocolMonitorBuilder};
//!
//! struct AlwaysFires;
//! impl AnomalyRule<FiveTupleKey> for AlwaysFires {
//!     fn name(&self) -> &'static str { "always_fires" }
//!     fn observe(&mut self, evt: &ProtocolEvent<FiveTupleKey>, emit: &mut Vec<Anomaly<FiveTupleKey>>) {
//!         emit.push(Anomaly::new(self.name(), Severity::Info, evt.timestamp())
//!             .with_key_opt(evt.key().cloned()));
//!     }
//! }
//!
//! let mut monitor = ProtocolMonitorBuilder::new()
//!     .interface("eth0")
//!     .flow()
//!     .build(FiveTuple::bidirectional())?;
//!
//! let mut rules = AnomalyMonitor::<FiveTupleKey>::new()
//!     .with_rule(AlwaysFires);
//!
//! let mut sweep = tokio::time::interval(Duration::from_secs(1));
//! loop {
//!     tokio::select! {
//!         Some(evt) = monitor.next() => {
//!             for a in rules.observe(&evt?) { println!("{}", a.kind); }
//!         }
//!         _ = sweep.tick() => {
//!             for a in rules.on_tick(Timestamp::default()) { println!("{}", a.kind); }
//!         }
//!     }
//! }
//! # }
//! ```

mod builtin;
#[cfg(feature = "eve-sink")]
pub mod eve_sink;
pub mod key;
#[cfg(feature = "metrics")]
pub mod metrics_sink;
mod monitor;
mod rule;

pub mod shipped_sinks;
pub mod sink;

pub use builtin::FlowAnomalyRule;
pub use key::{Key, KeyFields};
pub use monitor::AnomalyMonitor;
pub use rule::{Anomaly, AnomalyContext, AnomalyRule, Severity};

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

#[cfg(feature = "eve-sink")]
pub use eve_sink::EveSink;

/// 0.21 B.3 — `MetricsSink` adapter over the `metrics`-rs facade.
/// Gated on the same `metrics` Cargo feature that pulls the
/// `metrics` crate.
#[cfg(feature = "metrics")]
pub use metrics_sink::MetricsSink;
