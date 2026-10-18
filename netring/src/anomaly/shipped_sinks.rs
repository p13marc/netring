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
//! | [`ChannelSink`]   | 1 ([`OwnedAnomaly`](crate::anomaly::OwnedAnomaly))    | tokio mpsc; lets consumers retain anomalies |

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::anomaly::Severity;
use crate::anomaly::sink::{AnomalyRecord, AnomalySink, endpoint_text};

// ─── StdoutSink ─────────────────────────────────────────────────

/// One greppable line of human-readable text per anomaly,
/// written to stdout. The internal scratch buffer is reused
/// across calls — steady-state allocation is zero.
///
/// Format:
/// ```text
/// [<severity>] <kind> ts=<ts> [src=<ip:port> dst=<ip:port> [proto=<p>] | key=<Debug-K>] [obs1=v1 ...] [m1=v1 ...]
/// ```
///
/// `src` / `dst` are the record's [`Endpoints`](crate::anomaly::sink::Endpoints)
/// (the flow's initiator first when known); a key without endpoints (a
/// host, a counter key) prints as `key=` instead.
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

/// ` src=… dst=… [proto=…]` for the record's endpoints, else ` key=<Debug>`.
fn write_subject(out: &mut impl std::fmt::Write, r: &AnomalyRecord<'_>) {
    if let Some(e) = r.endpoints {
        let _ = write!(
            out,
            " src={} dst={}",
            endpoint_text(e.src_ip, e.src_port),
            endpoint_text(e.dest_ip, e.dest_port)
        );
        if let Some(p) = e.proto {
            let _ = write!(out, " proto={p}");
        }
    } else if let Some(k) = r.key {
        let _ = write!(out, " key={k:?}");
    }
}

/// `std::fmt::Write` over the reused byte buffer.
struct BufFmt<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for BufFmt<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

impl AnomalySink for StdoutSink {
    fn write(&mut self, r: &AnomalyRecord<'_>) {
        self.buf.clear();
        let (severity, kind, ts) = (r.severity, r.kind, r.ts);
        let _ = write!(&mut self.buf, "[{severity}] {kind} ts={ts}");
        write_subject(&mut BufFmt(&mut self.buf), r);
        for (l, v) in r.observations {
            let _ = write!(&mut self.buf, " {l}={v}");
        }
        for (l, v) in r.metrics {
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
    fn write(&mut self, r: &AnomalyRecord<'_>) {
        use serde_json::{Map, Value};
        let (observations, metrics) = (r.observations, r.metrics);
        self.buf.clear();
        let mut obj = Map::with_capacity(12);
        obj.insert("severity".into(), r.severity.to_string().into());
        obj.insert("kind".into(), r.kind.into());
        obj.insert("ts_sec".into(), r.ts.sec.into());
        obj.insert("ts_nsec".into(), r.ts.nsec.into());
        if let Some(k) = r.key {
            obj.insert("key".into(), format!("{k:?}").into());
        }
        // 0.32 (#215): the endpoints, initiator first when `directional`.
        if let Some(e) = r.endpoints {
            if let Some(ip) = e.src_ip {
                obj.insert("src_ip".into(), ip.to_string().into());
            }
            if let Some(p) = e.src_port {
                obj.insert("src_port".into(), p.into());
            }
            if let Some(ip) = e.dest_ip {
                obj.insert("dest_ip".into(), ip.to_string().into());
            }
            if let Some(p) = e.dest_port {
                obj.insert("dest_port".into(), p.into());
            }
            if let Some(p) = e.proto {
                obj.insert("proto".into(), p.into());
            }
            obj.insert("directional".into(), e.directional.into());
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
/// The event carries `kind`, and a message with the endpoints
/// (`src=… dst=… proto=…`, the flow's initiator first when known) or else
/// the formatted key (`key=…`), then the observations + metrics. Compatible
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
    fn write(&mut self, r: &AnomalyRecord<'_>) {
        use std::fmt::Write as _;
        let (kind, severity, ts) = (r.kind, r.severity, r.ts);
        self.msg_buf.clear();
        write_subject(&mut self.msg_buf, r);
        // `write_subject` leads with a separator; the message doesn't.
        if self.msg_buf.starts_with(' ') {
            self.msg_buf.remove(0);
        }
        for (l, v) in r.observations {
            if !self.msg_buf.is_empty() {
                self.msg_buf.push(' ');
            }
            let _ = write!(&mut self.msg_buf, "{l}={v}");
        }
        for (l, v) in r.metrics {
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
    tx: ChannelTx,
}

/// Backpressure backing for [`ChannelSink`]. The unbounded variant never drops
/// but can grow without bound under a slow consumer; the bounded variant
/// **never blocks the capture task** — when the channel is full the anomaly is
/// dropped and a counter is incremented (the honest backpressure contract; see
/// `docs/ASYNC_GUIDE.md`).
enum ChannelTx {
    Unbounded(tokio::sync::mpsc::UnboundedSender<flowscope::OwnedAnomaly>),
    Bounded {
        tx: tokio::sync::mpsc::Sender<flowscope::OwnedAnomaly>,
        dropped: Arc<AtomicU64>,
    },
}

impl ChannelSink {
    /// Wrap an existing unbounded sender. The matching receiver typically
    /// lives in a spawned task that drains and re-emits.
    pub fn new(tx: tokio::sync::mpsc::UnboundedSender<flowscope::OwnedAnomaly>) -> Self {
        Self {
            tx: ChannelTx::Unbounded(tx),
        }
    }

    /// Convenience constructor — returns `(sink, receiver)` over an **unbounded**
    /// channel. Prefer [`Self::bounded`] in production, where a slow consumer
    /// would otherwise grow memory without bound.
    pub fn channel() -> (
        Self,
        tokio::sync::mpsc::UnboundedReceiver<flowscope::OwnedAnomaly>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Self::new(tx), rx)
    }

    /// 0.24 Phase B: a **bounded** channel sink (drop-newest with a count).
    ///
    /// Returns `(sink, receiver, dropped)`. The capture task **never blocks**:
    /// when the channel is full, `write` drops the anomaly and increments the
    /// returned `dropped` counter (surface it through telemetry / metrics). The
    /// caller drains the receiver in a spawned task. `capacity` is at least 1
    /// (`0` is taken as `1`).
    pub fn bounded(
        capacity: usize,
    ) -> (
        Self,
        tokio::sync::mpsc::Receiver<flowscope::OwnedAnomaly>,
        Arc<AtomicU64>,
    ) {
        // tokio's bounded channel panics on a zero capacity.
        let (tx, rx) = tokio::sync::mpsc::channel(capacity.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        (
            Self {
                tx: ChannelTx::Bounded {
                    tx,
                    dropped: Arc::clone(&dropped),
                },
            },
            rx,
            dropped,
        )
    }
}

impl AnomalySink for ChannelSink {
    fn write(&mut self, r: &AnomalyRecord<'_>) {
        // The owned copy's 5-tuple is the record's endpoints (initiator
        // first when known).
        let owned = r.to_owned_anomaly();
        match &self.tx {
            ChannelTx::Unbounded(tx) => {
                let _ = tx.send(owned);
            }
            ChannelTx::Bounded { tx, dropped } => {
                // try_send never blocks: a full (or closed) channel drops the
                // anomaly and bumps the counter rather than stalling capture.
                if tx.try_send(owned).is_err() {
                    dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::sink::{AnomalySink, AnomalySinkExt};
    use flowscope::Timestamp;

    #[test]
    fn bounded_channel_sink_drops_with_count_when_full() {
        // 0.24 Phase B backpressure contract: a full bounded channel drops the
        // anomaly + counts it instead of blocking the capture task.
        let (mut sink, _rx, dropped) = ChannelSink::bounded(2);
        for _ in 0..5 {
            sink.write(&AnomalyRecord::new(
                "Test",
                Severity::Warning,
                Timestamp::new(0, 0),
            ));
        }
        // Receiver never drained: 2 fit in the buffer, the other 3 are dropped.
        assert_eq!(dropped.load(Ordering::Relaxed), 3);
    }

    /// A zero capacity is a one-slot channel, not a tokio panic.
    #[test]
    fn bounded_channel_sink_with_zero_capacity_holds_one() {
        let (mut sink, mut rx, dropped) = ChannelSink::bounded(0);
        for _ in 0..2 {
            sink.write(&AnomalyRecord::new(
                "T",
                Severity::Info,
                Timestamp::new(0, 0),
            ));
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn bounded_channel_sink_delivers_until_full() {
        let (mut sink, mut rx, dropped) = ChannelSink::bounded(4);
        for _ in 0..3 {
            sink.write(&AnomalyRecord::new(
                "T",
                Severity::Info,
                Timestamp::new(0, 0),
            ));
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        let mut got = 0;
        while rx.try_recv().is_ok() {
            got += 1;
        }
        assert_eq!(got, 3);
    }

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
        // 0.21 A.10: OwnedAnomaly now sourced from flowscope. flowscope 0.22:
        // `kind` is a typed `DetectorKind` (`as_str()` → the slug); `severity`
        // is flowscope's enum.
        assert_eq!(received.kind.as_str(), "Forwarded");
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
        assert!(v.get("src_ip").is_none(), "no key, no endpoints");
    }

    /// #215: the JSON line carries the endpoints, initiator first.
    #[cfg(feature = "serde")]
    #[test]
    fn stdout_json_sink_carries_the_endpoints() {
        let key = flowscope::extract::FiveTupleKey::new(
            flowscope::L4Proto::Udp,
            "10.0.0.1:53".parse().unwrap(),
            "10.0.0.9:5353".parse().unwrap(),
        );
        let mut s = StdoutJsonSink::with_capacity(512);
        s.begin("K", Severity::Info, Timestamp::new(1, 2))
            .with_flow(&key, flowscope::Orientation::Reverse)
            .emit();
        let v: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&s.buf).unwrap().trim_end()).unwrap();
        assert_eq!(v["src_ip"], "10.0.0.9");
        assert_eq!(v["src_port"], 5353);
        assert_eq!(v["dest_ip"], "10.0.0.1");
        assert_eq!(v["dest_port"], 53);
        assert_eq!(v["proto"], "UDP");
        assert_eq!(v["directional"], true);
    }

    /// The text line prints `src=` / `dst=` for a flow key.
    #[test]
    fn stdout_sink_prints_the_endpoints() {
        let key = flowscope::extract::FiveTupleKey::new(
            flowscope::L4Proto::Tcp,
            "10.0.0.1:80".parse().unwrap(),
            "10.0.0.9:40000".parse().unwrap(),
        );
        let mut s = StdoutSink::with_capacity(256);
        s.begin("K", Severity::Info, Timestamp::new(0, 0))
            .with_flow(&key, flowscope::Orientation::Reverse)
            .emit();
        let line = std::str::from_utf8(&s.buf).unwrap();
        assert!(
            line.contains(" src=10.0.0.9:40000 dst=10.0.0.1:80 proto=TCP"),
            "{line}"
        );
        assert!(!line.contains("key="), "{line}");
    }
}
