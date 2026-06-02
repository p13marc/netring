//! [`AnomalyRule`] trait + [`Anomaly`] value type.

use flowscope::Timestamp;

use crate::protocol::ProtocolEvent;

/// Severity tier carried on every [`Anomaly`].
///
/// Rule authors pick the tier; the [`AnomalyMonitor`](super::AnomalyMonitor)
/// is policy-neutral about what to do with it (log, page, alert).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational — pattern of interest, no immediate action.
    Info,
    /// Worth surfacing in dashboards.
    Warning,
    /// Indicates a real problem.
    Error,
    /// Page someone.
    Critical,
}

/// A single anomaly produced by an [`AnomalyRule`].
///
/// The `kind` identifies the detector that fired (use a short
/// stable slug — e.g. `"DnsResolvedNoConnection"`). `key` is the
/// flow / host / IP the anomaly is about (when applicable). The
/// [`AnomalyContext`] carries detector-specific observations and
/// numeric metrics for structured downstream sinks.
#[derive(Debug, Clone)]
pub struct Anomaly<K> {
    /// Stable detector identifier (e.g. `"DnsResolvedNoConnection"`).
    pub kind: &'static str,
    /// Severity tier.
    pub severity: Severity,
    /// Optional flow / host / IP this anomaly is about.
    pub key: Option<K>,
    /// When the anomaly fired (clock domain matches the carrying
    /// event's `Timestamp`).
    pub ts: Timestamp,
    /// Detector-specific context.
    pub context: AnomalyContext,
}

impl<K> Anomaly<K> {
    /// Construct a bare anomaly. Use `with_*` chainable setters to
    /// fill in key + context.
    pub fn new(kind: &'static str, severity: Severity, ts: Timestamp) -> Self {
        Self {
            kind,
            severity,
            key: None,
            ts,
            context: AnomalyContext::default(),
        }
    }

    /// Attach the flow / host / IP this anomaly applies to.
    pub fn with_key(mut self, key: K) -> Self {
        self.key = Some(key);
        self
    }

    /// Same as [`Self::with_key`] but accepting an `Option<K>` —
    /// convenient when reading from [`ProtocolEvent::key`].
    pub fn with_key_opt(mut self, key: Option<K>) -> Self {
        self.key = key;
        self
    }

    /// Append a free-form observation: a static label + a
    /// stringified value. Use sparingly for human-readable detail.
    pub fn with_observation(mut self, label: &'static str, value: impl Into<String>) -> Self {
        self.context.observations.push((label, value.into()));
        self
    }

    /// Append a numeric metric — useful when an anomaly carries a
    /// threshold (`"latency_ms": 432.0`) for downstream alerting.
    pub fn with_metric(mut self, label: &'static str, value: f64) -> Self {
        self.context.metrics.push((label, value));
        self
    }
}

/// Per-anomaly context: free-form observations + numeric metrics.
///
/// Detectors should put rich human-readable details in
/// [`observations`](Self::observations) and machine-readable
/// thresholds in [`metrics`](Self::metrics).
#[derive(Debug, Clone, Default)]
pub struct AnomalyContext {
    /// `(label, value)` observations — e.g. `("qname",
    /// "example.com")`.
    pub observations: Vec<(&'static str, String)>,
    /// `(label, value)` metrics — e.g. `("rtt_ms", 432.5)`.
    pub metrics: Vec<(&'static str, f64)>,
}

/// One anomaly detector.
///
/// Implement [`observe`](Self::observe) to react to per-event
/// state, [`on_tick`](Self::on_tick) for time-bound detections
/// (drains, sweeps, sliding windows). Both methods push any
/// findings into the shared `emit` buffer — the
/// [`AnomalyMonitor`](super::AnomalyMonitor) reuses one allocation
/// across rules.
pub trait AnomalyRule<K>: Send {
    /// Stable detector identifier — also used as the default
    /// `Anomaly::kind` slug.
    fn name(&self) -> &'static str;

    /// Inspect an event and append any anomalies it surfaces.
    fn observe(&mut self, evt: &ProtocolEvent<K>, emit: &mut Vec<Anomaly<K>>);

    /// Time-bound detection hook — called once per sweep tick from
    /// [`AnomalyMonitor::on_tick`](super::AnomalyMonitor::on_tick).
    /// Default no-op: rules that don't need it can ignore it.
    fn on_tick(&mut self, _now: Timestamp, _emit: &mut Vec<Anomaly<K>>) {}
}
