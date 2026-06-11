//! Ready-to-use [`AnomalySink`] implementations.
//!
//! All four shipped sinks reuse their internal scratch buffer
//! across calls so a hot detector path doesn't allocate per
//! anomaly. Allocation-vs-retention trade-offs:
//!
//! | Sink              | Per-anomaly allocations | Behaviour                                  |
//! |-------------------|-------------------------|--------------------------------------------|
//! | [`StdoutSink`]    | 0 (buf reused)          | One greppable line of text to stdout       |
//! | [`StdoutJsonSink`]| 1 (serde_json::Map)     | One JSON line to stdout (feature `serde`)  |
//! | [`TracingSink`]   | 0 (tracing event!)      | `tracing::event!` at the matching Level    |
//! | [`ChannelSink`]   | 1 ([`OwnedAnomaly`])    | tokio mpsc; lets consumers retain anomalies |

use std::borrow::Cow;
use std::io::Write;

use flowscope::Timestamp;

use crate::anomaly::Severity;
use crate::anomaly::sink::AnomalySink;

// ─── StdoutSink ─────────────────────────────────────────────────

/// One greppable line of human-readable text per anomaly,
/// written to stdout. The internal scratch buffer is reused
/// across calls — steady-state allocation is zero.
///
/// Format:
/// ```text
/// [<severity>] <kind> ts=<ts> [key=<Debug-K>] [obs1=v1 ...] [m1=v1 ...]
/// ```
pub struct StdoutSink {
    buf: Vec<u8>,
}

impl StdoutSink {
    /// Construct with a specific scratch-buffer capacity.
    /// Pre-sizing avoids the first-emit reallocation in
    /// allocation-sensitive paths.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::with_capacity(4096)
    }
}

impl AnomalySink for StdoutSink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn crate::anomaly::Key>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        self.buf.clear();
        let _ = write!(&mut self.buf, "[{severity}] {kind} ts={ts}");
        if let Some(k) = key {
            let _ = write!(&mut self.buf, " key={k:?}");
        }
        for (l, v) in observations {
            let _ = write!(&mut self.buf, " {l}={v}");
        }
        for (l, v) in metrics {
            let _ = write!(&mut self.buf, " {l}={v:.2}");
        }
        let _ = writeln!(&mut self.buf);
        let _ = std::io::stdout().write_all(&self.buf);
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        std::io::stdout().flush()
    }
}

// ─── StdoutJsonSink (feature = "serde") ────────────────────────

/// One JSON object per anomaly, written to stdout. Uses
/// `serde_json::Map` internally — costs one allocation per emit
/// (the map). Acceptable for line-oriented log shippers; users
/// who need hand-rolled zero-alloc JSON can ship their own sink.
#[cfg(feature = "serde")]
pub struct StdoutJsonSink {
    buf: Vec<u8>,
}

#[cfg(feature = "serde")]
impl StdoutJsonSink {
    /// Construct with a specific scratch-buffer capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }
}

#[cfg(feature = "serde")]
impl Default for StdoutJsonSink {
    fn default() -> Self {
        Self::with_capacity(4096)
    }
}

#[cfg(feature = "serde")]
impl AnomalySink for StdoutJsonSink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn crate::anomaly::Key>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        use serde_json::{Map, Value};
        self.buf.clear();
        let mut obj = Map::with_capacity(6);
        obj.insert("severity".into(), severity.to_string().into());
        obj.insert("kind".into(), kind.into());
        obj.insert("ts_sec".into(), ts.sec.into());
        obj.insert("ts_nsec".into(), ts.nsec.into());
        if let Some(k) = key {
            obj.insert("key".into(), format!("{k:?}").into());
        }
        if !observations.is_empty() {
            let mut obs_map = Map::with_capacity(observations.len());
            for (l, v) in observations {
                obs_map.insert((*l).to_string(), v.as_ref().into());
            }
            obj.insert("observations".into(), obs_map.into());
        }
        if !metrics.is_empty() {
            let mut met_map = Map::with_capacity(metrics.len());
            for (l, v) in metrics {
                met_map.insert(
                    (*l).to_string(),
                    if v.is_finite() {
                        Value::from(*v)
                    } else {
                        Value::Null
                    },
                );
            }
            obj.insert("metrics".into(), met_map.into());
        }
        let _ = serde_json::to_writer(&mut self.buf, &obj);
        self.buf.push(b'\n');
        let _ = std::io::stdout().write_all(&self.buf);
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        std::io::stdout().flush()
    }
}

// ─── TracingSink ────────────────────────────────────────────────

/// Emits each anomaly as a `tracing::event!` at the level
/// matching its [`Severity`]:
///
/// - `Info`     → `tracing::Level::INFO`
/// - `Warning`  → `tracing::Level::WARN`
/// - `Error`    → `tracing::Level::ERROR`
/// - `Critical` → `tracing::Level::ERROR` (tracing has no separate "critical")
///
/// The event carries `kind`, the formatted key (if any), and the
/// observations + metrics as message-string fields. Compatible
/// with any `tracing::Subscriber` (JSON, OTLP, stdout, …).
pub struct TracingSink {
    msg_buf: String,
}

impl TracingSink {
    /// Construct with a scratch String for the rendered message body.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            msg_buf: String::with_capacity(cap),
        }
    }
}

impl Default for TracingSink {
    fn default() -> Self {
        Self::with_capacity(512)
    }
}

impl AnomalySink for TracingSink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn crate::anomaly::Key>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        use std::fmt::Write as _;
        self.msg_buf.clear();
        if let Some(k) = key {
            let _ = write!(&mut self.msg_buf, "key={k:?}");
        }
        for (l, v) in observations {
            if !self.msg_buf.is_empty() {
                self.msg_buf.push(' ');
            }
            let _ = write!(&mut self.msg_buf, "{l}={v}");
        }
        for (l, v) in metrics {
            if !self.msg_buf.is_empty() {
                self.msg_buf.push(' ');
            }
            let _ = write!(&mut self.msg_buf, "{l}={v:.2}");
        }
        match severity {
            Severity::Info => {
                tracing::info!(target: "netring::anomaly", kind, ts_sec = ts.sec, ts_nsec = ts.nsec, "{}", self.msg_buf)
            }
            Severity::Warning => {
                tracing::warn!(target: "netring::anomaly", kind, ts_sec = ts.sec, ts_nsec = ts.nsec, "{}", self.msg_buf)
            }
            Severity::Error | Severity::Critical => {
                tracing::error!(target: "netring::anomaly", kind, severity = %severity, ts_sec = ts.sec, ts_nsec = ts.nsec, "{}", self.msg_buf)
            }
        }
    }
}

// ─── ChannelSink ────────────────────────────────────────────────

/// Forwards each anomaly to a tokio mpsc channel as a
/// [`flowscope::OwnedAnomaly`]. Use when a downstream task —
/// exporter, alerter, archiver — needs to retain the anomaly
/// past the dispatch frame.
///
/// 0.21 A.10 — `OwnedAnomaly` is now the canonical upstream
/// value type. Structured 5-tuple fields (`src_ip`, `src_port`,
/// `dest_ip`, `dest_port`, `proto`) are populated when the
/// caller's key downcasts to [`flowscope::extract::FiveTupleKey`]
/// (the common path for flow-shape detectors); other key types
/// (`IpAddr`, `u32`, etc.) leave the 5-tuple fields `None` —
/// the consumer can still recover the human render via the
/// `flowscope_kind` bridge or the originating handler context.
pub struct ChannelSink {
    tx: tokio::sync::mpsc::UnboundedSender<flowscope::OwnedAnomaly>,
}

impl ChannelSink {
    /// Wrap an existing sender. The matching receiver typically
    /// lives in a spawned task that drains and re-emits.
    pub fn new(tx: tokio::sync::mpsc::UnboundedSender<flowscope::OwnedAnomaly>) -> Self {
        Self { tx }
    }

    /// Convenience constructor — returns `(sink, receiver)`.
    pub fn channel() -> (
        Self,
        tokio::sync::mpsc::UnboundedReceiver<flowscope::OwnedAnomaly>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Self::new(tx), rx)
    }
}

impl AnomalySink for ChannelSink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn crate::anomaly::Key>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        let mut owned = flowscope::OwnedAnomaly::new(kind, severity.into(), ts);
        if let Some(k) = key {
            // Structured 5-tuple flatten via KeyFields downcast.
            if let Some(fkey) = k
                .as_any()
                .downcast_ref::<flowscope::extract::FiveTupleKey>()
            {
                owned = owned.with_key(fkey);
            }
        }
        for (label, value) in observations {
            owned = owned.with_observation(label, value.to_string());
        }
        for (label, value) in metrics {
            owned = owned.with_metric(label, *value);
        }
        let _ = self.tx.send(owned);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::sink::AnomalySinkExt;

    #[test]
    fn stdout_sink_default_uses_4kib_buffer() {
        let s = StdoutSink::default();
        assert!(s.buf.capacity() >= 4096);
    }

    #[test]
    fn stdout_sink_emits_and_reuses_buffer() {
        // Steady-state: small anomalies don't grow the prepared
        // scratch buffer past its initial capacity. We clear the
        // buffer at the *start* of each emit (so it briefly
        // contains the prior render between calls — that's
        // expected and harmless).
        let mut s = StdoutSink::with_capacity(256);
        let initial_cap = s.buf.capacity();
        s.begin("Test", Severity::Info, Timestamp::new(0, 0))
            .with("note", "hi")
            .emit();
        s.begin("Again", Severity::Info, Timestamp::new(0, 0))
            .with("note", "hi")
            .emit();
        assert_eq!(
            s.buf.capacity(),
            initial_cap,
            "small anomaly must not grow the buffer past its prepared cap"
        );
    }

    #[test]
    fn tracing_sink_default_uses_512b_buffer() {
        let s = TracingSink::default();
        assert!(s.msg_buf.capacity() >= 512);
    }

    #[test]
    fn tracing_sink_emits_without_panic() {
        // Without a subscriber installed, tracing events are
        // dropped but the sink still must complete the call.
        let mut s = TracingSink::default();
        s.begin("T", Severity::Warning, Timestamp::new(0, 0))
            .with("note", "hi")
            .with_metric("n", 1.0)
            .emit();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn channel_sink_forwards_owned_anomaly() {
        let (mut sink, mut rx) = ChannelSink::channel();
        sink.begin("Forwarded", Severity::Critical, Timestamp::new(1, 2))
            .with("a", "x")
            .with_metric("b", 3.0)
            .emit();
        let received = rx.recv().await.expect("channel did not deliver");
        // 0.21 A.10: OwnedAnomaly now sourced from flowscope. `kind`
        // is `Cow<'static, str>`; `severity` is flowscope's enum.
        assert_eq!(received.kind, "Forwarded");
        assert_eq!(received.severity, flowscope::event::Severity::Critical);
        assert_eq!(received.observations[0].0, "a");
        assert_eq!(received.observations[0].1.as_ref(), "x");
        assert_eq!(received.metrics[0], ("b", 3.0));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn stdout_json_sink_emits_valid_json() {
        let mut s = StdoutJsonSink::with_capacity(512);
        s.begin("JsonKind", Severity::Info, Timestamp::new(1, 2))
            .with("note", "value")
            .with_metric("count", 7.5)
            .emit();
        // s.buf has been replaced with the rendered bytes (then
        // flushed to stdout, but kept in self.buf since we
        // wrote to `&mut self.buf`).
        let s_str = std::str::from_utf8(&s.buf).expect("UTF-8 JSON bytes");
        // The line ends with '\n'; trim before parse.
        let payload = s_str.trim_end_matches('\n');
        let v: serde_json::Value = serde_json::from_str(payload).expect("valid JSON");
        assert_eq!(v["kind"], "JsonKind");
        assert_eq!(v["severity"], "info");
    }
}
