//! Glob-importable re-exports of the canonical netring API.
//!
//! ```no_run
//! use netring::prelude::*;
//! ```
//!
//! Brings in the names a typical monitor + detector needs.
//! Power users reach past this module to
//! [`crate::protocol`], [`crate::ctx`], [`crate::layer`], etc.
//! directly.

// ─── Core builder + run modes ────────────────────────────────────
pub use crate::monitor::{Handler, Monitor, MonitorBuilder};

// ─── Async + middleware (Phase D) ────────────────────────────────
pub use crate::monitor::AsyncHandler;

// ─── Protocol markers (built-in) ─────────────────────────────────
#[cfg(feature = "dns")]
pub use crate::protocol::builtin::Dns;
#[cfg(feature = "http")]
pub use crate::protocol::builtin::Http;
pub use crate::protocol::builtin::Icmp;
pub use crate::protocol::builtin::{Tcp, Udp};
#[cfg(feature = "tls")]
pub use crate::protocol::builtin::{Tls, TlsHandshake};

// ─── Protocol trait + dispatch types (for custom Protocol impls) ─
pub use crate::protocol::{Dispatch, FlowKey, Protocol, ProtocolInitError, SignatureMatch};

// ─── Event types ─────────────────────────────────────────────────
pub use crate::protocol::event_typed::{
    AnyFlowAnomaly, FlowEnded, FlowEstablished, FlowStarted, Tick,
};

// ─── Per-event Ctx ───────────────────────────────────────────────
pub use crate::ctx::{Ctx, SourceIdx};

// ─── Anomaly emission ────────────────────────────────────────────
pub use crate::anomaly::OwnedAnomaly;
pub use crate::anomaly::Severity;
#[cfg(feature = "eve-sink")]
pub use crate::anomaly::eve_sink::EveSink;
#[cfg(feature = "metrics")]
pub use crate::anomaly::metrics_sink::MetricsSink;
#[cfg(feature = "serde")]
pub use crate::anomaly::shipped_sinks::StdoutJsonSink;
pub use crate::anomaly::shipped_sinks::{ChannelSink, StdoutSink, TracingSink};
pub use crate::anomaly::sink::{AnomalySink, AnomalySinkExt, AnomalyWriter, NoopSink};

// ─── Middleware (Phase D) ────────────────────────────────────────
pub use crate::layer::{DedupeAnomalies, Layer, MinSeverity, RateLimitAnomalies, Sample, Tee};

// ─── Sliding-window correlate primitives ─────────────────────────
pub use crate::correlate::{KeyIndexed, TimeBucketedCounter};

// ─── Common external types ───────────────────────────────────────
pub use flowscope::{EndReason, FlowSide, L4Proto, Timestamp};
pub use std::time::Duration;

// ─── The detector! macro ────────────────────────────────────────
// `detector!` is `#[macro_export]` so it's reachable as
// `crate::detector!` — but the `pub use` re-export of a macro
// works at the crate root, not via the prelude `pub use` chain.
// Users get the macro via `use netring::detector;` (always-on
// when feature gates allow). The prelude doesn't need to
// re-export it explicitly — including it in `use netring::prelude::*;`
// implicitly imports the crate-root macro under standard
// 2024-edition macro hygiene rules.
