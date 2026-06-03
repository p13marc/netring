//! [`AnomalyRule`] trait + [`Anomaly`] value type.

use flowscope::Timestamp;

use crate::protocol::ProtocolEvent;

impl From<flowscope::event::Severity> for Severity {
    fn from(s: flowscope::event::Severity) -> Self {
        // 1:1 variant mapping; the enums were intentionally designed
        // with the same shape + order so threshold filters port
        // across the boundary unchanged.
        match s {
            flowscope::event::Severity::Info => Severity::Info,
            flowscope::event::Severity::Warning => Severity::Warning,
            flowscope::event::Severity::Error => Severity::Error,
            flowscope::event::Severity::Critical => Severity::Critical,
            _ => Severity::Warning,
        }
    }
}

/// Severity tier carried on every [`Anomaly`].
///
/// Rule authors pick the tier; the [`AnomalyMonitor`](super::AnomalyMonitor)
/// is policy-neutral about what to do with it (log, page, alert).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Severity {
    /// Informational — pattern of interest, no immediate action.
    #[default]
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

impl std::fmt::Display for Severity {
    /// Lowercase short label (`info` / `warning` / `error` /
    /// `critical`) matching flowscope's metric-vocabulary
    /// convention.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        })
    }
}

impl<K: std::fmt::Debug> std::fmt::Display for Anomaly<K> {
    /// One-line greppable rendering. Saves callers from writing
    /// their own `print_anomaly` helper. Format:
    ///
    /// ```text
    /// [<severity>] <kind> ts=<ts> [key=<Debug-K>] [obs1=v1 ...] [metric1=v1 ...]
    /// ```
    ///
    /// `K` only needs `Debug`; severity is rendered via its own
    /// `Display`. Metrics are formatted with 2 decimal places.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {} ts={}", self.severity, self.kind, self.ts)?;
        if let Some(k) = &self.key {
            write!(f, " key={k:?}")?;
        }
        for (label, value) in &self.context.observations {
            write!(f, " {label}={value}")?;
        }
        for (label, value) in &self.context.metrics {
            write!(f, " {label}={value:.2}")?;
        }
        Ok(())
    }
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

impl<K: std::fmt::Debug> Anomaly<K> {
    /// Render as a single line of JSON — ready to pipe into
    /// Vector / Fluentd / Loki / any line-oriented sink.
    ///
    /// Field shape:
    ///
    /// ```json
    /// {"severity":"warning","kind":"DnsBurst","ts_secs":42,"ts_nanos":0,
    ///  "key":"FiveTupleKey { ... }","observations":{"src_ip":"10.0.0.1"},
    ///  "metrics":{"count":42.0}}
    /// ```
    ///
    /// `key` is rendered via `Debug` and JSON-escaped. Omitted when
    /// the anomaly has no key. `observations` and `metrics` are
    /// always present (possibly empty objects). The output is
    /// **one line, terminated with no newline** — caller decides.
    ///
    /// Zero external deps; no `serde`. Escaping covers `\`, `"`,
    /// and the C0 control set (RFC 8259 §7). NaN / ±Inf metrics
    /// are mapped to `null`.
    pub fn to_json_line(&self) -> String {
        let mut s = String::with_capacity(96);
        s.push('{');
        s.push_str("\"severity\":");
        // `Display for Severity` returns the metric-vocabulary
        // token already. Re-use it instead of duplicating the map.
        json_string(&mut s, &self.severity.to_string());
        s.push_str(",\"kind\":");
        json_string(&mut s, self.kind);
        s.push_str(",\"ts_secs\":");
        s.push_str(&self.ts.sec.to_string());
        s.push_str(",\"ts_nanos\":");
        s.push_str(&self.ts.nsec.to_string());
        if let Some(k) = &self.key {
            s.push_str(",\"key\":");
            let dbg = format!("{k:?}");
            json_string(&mut s, &dbg);
        }
        s.push_str(",\"observations\":{");
        for (i, (label, value)) in self.context.observations.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            json_string(&mut s, label);
            s.push(':');
            json_string(&mut s, value);
        }
        s.push('}');
        s.push_str(",\"metrics\":{");
        for (i, (label, value)) in self.context.metrics.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            json_string(&mut s, label);
            s.push(':');
            if value.is_finite() {
                s.push_str(&format!("{value}"));
            } else {
                s.push_str("null");
            }
        }
        s.push('}');
        s.push('}');
        s
    }
}

impl<K: std::fmt::Debug> Anomaly<K> {
    /// Emit this anomaly through the [`tracing`] crate at the
    /// level matching its [`Severity`].
    ///
    /// | `Severity` | tracing `Level` |
    /// |---|---|
    /// | `Info` | `INFO` |
    /// | `Warning` | `WARN` |
    /// | `Error` | `ERROR` |
    /// | `Critical` | `ERROR` (with a `critical = true` field) |
    ///
    /// Tracing's structured-field model is compile-time — we
    /// can't enumerate the dynamic `observations` / `metrics`
    /// vectors as individual fields. Instead the full structured
    /// payload is attached as a `payload` field carrying the
    /// JSON line (same shape as [`Self::to_json_line`]).
    /// Subscribers that want the typed fields (`severity`,
    /// `kind`, `ts_secs`, `ts_nanos`, optional `key`) can read
    /// them directly off the event; subscribers that want the
    /// full payload parse the `payload` field.
    ///
    /// Target: `"netring.anomaly"` — set
    /// `RUST_LOG=netring.anomaly=info` (or filter via
    /// `EnvFilter`) to route detector events independently of
    /// the rest of netring's logs.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use flowscope::Timestamp;
    /// # use netring::anomaly::{Anomaly, Severity};
    /// let a: Anomaly<u32> = Anomaly::new("DnsBurst", Severity::Warning, Timestamp::new(0, 0));
    /// a.emit_tracing();
    /// ```
    pub fn emit_tracing(&self) {
        let payload = self.to_json_line();
        let key_dbg = self.key.as_ref().map(|k| format!("{k:?}"));
        let key_str: &str = key_dbg.as_deref().unwrap_or("");

        // tracing's structured fields must be compile-time
        // literal idents; we can't iterate the per-anomaly
        // observations/metrics here. Pin the fixed fields +
        // ship the full structure on `payload`. Subscribers
        // that want per-field structure should split on
        // payload + use serde_json (or any JSON parser) to
        // unpack.
        match self.severity {
            Severity::Info => tracing::event!(
                target: "netring.anomaly",
                tracing::Level::INFO,
                kind = self.kind,
                severity = "info",
                ts_secs = self.ts.sec,
                ts_nanos = self.ts.nsec,
                key = key_str,
                payload = %payload,
            ),
            Severity::Warning => tracing::event!(
                target: "netring.anomaly",
                tracing::Level::WARN,
                kind = self.kind,
                severity = "warning",
                ts_secs = self.ts.sec,
                ts_nanos = self.ts.nsec,
                key = key_str,
                payload = %payload,
            ),
            Severity::Error => tracing::event!(
                target: "netring.anomaly",
                tracing::Level::ERROR,
                kind = self.kind,
                severity = "error",
                ts_secs = self.ts.sec,
                ts_nanos = self.ts.nsec,
                key = key_str,
                payload = %payload,
            ),
            Severity::Critical => tracing::event!(
                target: "netring.anomaly",
                tracing::Level::ERROR,
                critical = true,
                kind = self.kind,
                severity = "critical",
                ts_secs = self.ts.sec,
                ts_nanos = self.ts.nsec,
                key = key_str,
                payload = %payload,
            ),
        }
    }
}

/// Escape `value` per RFC 8259 §7 and append it to `out` wrapped in
/// double quotes. Only handles the control set + `\` + `"`; the rest
/// passes through as UTF-8.
fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
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
