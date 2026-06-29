//! [`EveSink`] — Suricata EVE JSON adapter for the
//! [`AnomalySink`] chain.
//!
//! Thin wrapper over [`flowscope::emit::EveJsonWriter`]: each
//! [`AnomalySink::write`] call constructs a
//! [`flowscope::OwnedAnomaly`] from the accumulated writer state
//! (with structured 5-tuple fields when the attached key
//! downcasts to [`flowscope::extract::FiveTupleKey`]) and forwards
//! it via [`flowscope::emit::EveJsonWriter::write_owned_anomaly`].
//!
//! Schema-compatible with Filebeat's Suricata module, Splunk's
//! Suricata TA, Tenzir's `read_suricata` pipeline, and any
//! Elastic Common Schema converter: drop the resulting NDJSON
//! into an existing Suricata-aware pipeline and detector slugs
//! arrive as `event_type: "anomaly"` records.
//!
//! ## Allocation envelope
//!
//! Per emit:
//! - one [`flowscope::OwnedAnomaly`] (folded `kind`/severity/ts +
//!   structured 5-tuple + `SmallVec<[..; 4]>` observations +
//!   metrics — zero-alloc for the typical 2–5 entry case)
//! - one `serde_json::Map` inside the upstream writer
//!
//! The internal scratch buffer on `EveJsonWriter` is reused across
//! calls; the cost is steady-state ~1 allocation per emit.
//!
//! ## Cardinality contract
//!
//! No labels are emitted as metric dimensions — the EVE schema
//! treats `anomaly.event` (the kind slug) as a free-form string.
//! No risk of unbounded cardinality from observation labels: they
//! land under `anomaly.labels.<label>` and are scoped to the
//! anomaly object.

use std::borrow::Cow;
use std::io::Write;

use flowscope::Timestamp;
use flowscope::emit::{EveJsonWriter, EveOptions};

use crate::anomaly::Severity;
use crate::anomaly::key::Key;
use crate::anomaly::sink::AnomalySink;

/// Suricata EVE JSON anomaly sink. Wraps any `W: Write + Send`
/// and forwards each anomaly as a single EVE JSON line.
///
/// Construct via [`EveSink::new`] with explicit options or
/// [`EveSink::stdout`] for the canonical pipeline shape.
pub struct EveSink<W: Write + Send> {
    inner: EveJsonWriter<W>,
}

impl<W: Write + Send> EveSink<W> {
    /// Wrap `sink` with the supplied EVE options.
    pub fn new(sink: W, options: EveOptions) -> Self {
        Self {
            inner: EveJsonWriter::with_options(sink, options),
        }
    }

    /// Borrow the inner writer — mostly useful for tests that
    /// want to assert on the underlying `Write` sink (e.g. an
    /// in-memory `Vec<u8>`).
    pub fn writer(&self) -> &EveJsonWriter<W> {
        &self.inner
    }

    /// Consume the sink and recover the inner `W` for inspection or
    /// downstream chaining. Useful in tests that want to read back
    /// the emitted bytes (`Vec<u8>` as the writer is the canonical
    /// pattern).
    pub fn finish(self) -> std::io::Result<W> {
        self.inner.finish()
    }
}

impl EveSink<std::io::Stdout> {
    /// Convenience constructor — `EveSink::stdout(opts)` for the
    /// canonical "tail this and pipe into Filebeat" shape.
    pub fn stdout(options: EveOptions) -> Self {
        Self::new(std::io::stdout(), options)
    }
}

impl<W: Write + Send> AnomalySink for EveSink<W> {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Key>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        // Build the OwnedAnomaly from the writer state. Same
        // pattern as AnomalyWriter::emit_owned + ChannelSink
        // (downcast key to FiveTupleKey for structured 5-tuple
        // flatten). Keys that don't downcast keep `src_ip` etc.
        // `None` — EveJsonWriter omits those fields rather than
        // emitting `null` per its schema convention.
        let mut owned = flowscope::OwnedAnomaly::new(kind, severity.into(), ts);
        if let Some(k) = key
            && let Some(fkey) = k
                .as_any()
                .downcast_ref::<flowscope::extract::FiveTupleKey>()
        {
            owned = owned.with_key(fkey);
        }
        for (label, value) in observations {
            owned = owned.with_observation(label, value.to_string());
        }
        for (label, value) in metrics {
            owned = owned.with_metric(label, *value);
        }
        // EveJsonWriter::write_owned_anomaly returns io::Result —
        // swallow errors here matching the StdoutSink pattern; the
        // EVE writer never panics on serialize and write errors are
        // typically broken stdout, which is operator-recoverable.
        let _ = self.inner.write_owned_anomaly(&owned);
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.inner.flush()
    }
}

/// Build a Suricata-compatible `event_type: "tls"` EVE record from a
/// [`TlsFingerprint`](crate::monitor::TlsFingerprint) (0.25 W1d / E2).
///
/// Emits the `tls` sub-object (`sni`, `ja3`/`ja3.hash`, `ja4`, `ja4s` when the
/// `ja4plus` feature is on, `alpn`) plus the flow 5-tuple
/// (`src_ip`/`src_port`/`dest_ip`/`dest_port`/`proto`) when the fingerprint
/// carries its key, the ISO-8601 `timestamp`, and `in_iface`. Drop the line
/// into any Suricata-aware pipeline alongside the `event_type: "anomaly"`
/// records [`EveSink`] produces.
///
/// `src`/`dest` follow the key's `a`/`b` endpoints — canonically ordered under
/// the default bidirectional extractor, not connection direction.
#[cfg(feature = "tls")]
pub fn eve_tls_record(
    fp: &crate::monitor::TlsFingerprint,
    ts: Timestamp,
    in_iface: &str,
) -> serde_json::Value {
    use serde_json::json;

    let mut tls = serde_json::Map::new();
    if let Some(sni) = &fp.sni {
        tls.insert("sni".into(), json!(sni));
    }
    if let Some(alpn) = &fp.alpn {
        tls.insert("alpn".into(), json!(alpn));
    }
    if let Some(ja3) = &fp.ja3 {
        // Suricata nests JA3 as `ja3.hash` (string `ja3` kept too for
        // tools that read the flat field).
        tls.insert("ja3".into(), json!({ "hash": ja3 }));
    }
    if let Some(ja4) = &fp.ja4 {
        tls.insert("ja4".into(), json!(ja4));
    }
    #[cfg(feature = "ja4plus")]
    if let Some(ja4s) = &fp.ja4s {
        tls.insert("ja4s".into(), json!(ja4s));
    }

    let mut obj = serde_json::Map::new();
    obj.insert("timestamp".into(), json!(ts.to_iso8601()));
    obj.insert("event_type".into(), json!("tls"));
    if !in_iface.is_empty() {
        obj.insert("in_iface".into(), json!(in_iface));
    }
    if let Some(key) = &fp.key {
        obj.insert("src_ip".into(), json!(key.a.ip().to_string()));
        obj.insert("src_port".into(), json!(key.a.port()));
        obj.insert("dest_ip".into(), json!(key.b.ip().to_string()));
        obj.insert("dest_port".into(), json!(key.b.port()));
        obj.insert("proto".into(), json!(l4_proto_str(key.proto)));
    }
    obj.insert("tls".into(), serde_json::Value::Object(tls));
    serde_json::Value::Object(obj)
}

/// Suricata `proto` string for an L4 protocol.
#[cfg(feature = "tls")]
fn l4_proto_str(proto: flowscope::L4Proto) -> &'static str {
    use flowscope::L4Proto::*;
    match proto {
        Tcp => "TCP",
        Udp => "UDP",
        Icmp => "ICMP",
        IcmpV6 => "IPv6-ICMP",
        _ => "TCP",
    }
}

/// Writes Suricata `event_type: "tls"` EVE records — the protocol-record
/// companion to [`EveSink`] (which carries `event_type: "anomaly"`), since
/// flowscope's EVE writer scopes out per-protocol records (0.25 W1d / E2).
///
/// Wire it through [`on_fingerprint`](crate::monitor::MonitorBuilder::on_fingerprint)
/// — e.g. behind an `Arc<Mutex<EveTlsSink<W>>>` — to log every TLS handshake:
///
/// ```no_run
/// # #[cfg(all(feature = "eve-sink", feature = "tls"))]
/// # fn _ex() {
/// use std::sync::{Arc, Mutex};
/// use netring::anomaly::EveTlsSink;
/// use netring::monitor::Monitor;
///
/// let sink = Arc::new(Mutex::new(EveTlsSink::new(std::io::stdout(), "eth0")));
/// let s = Arc::clone(&sink);
/// let _m = Monitor::builder()
///     .interface("eth0")
///     .on_fingerprint(move |fp, ctx| {
///         let _ = s.lock().unwrap().write_tls(fp, ctx.ts);
///         Ok(())
///     });
/// # }
/// ```
#[cfg(feature = "tls")]
pub struct EveTlsSink<W: Write + Send> {
    writer: W,
    in_iface: String,
}

#[cfg(feature = "tls")]
impl<W: Write + Send> EveTlsSink<W> {
    /// Wrap a writer; `in_iface` is stamped on each record (empty = omitted).
    pub fn new(writer: W, in_iface: impl Into<String>) -> Self {
        Self {
            writer,
            in_iface: in_iface.into(),
        }
    }

    /// Write one `event_type: "tls"` NDJSON line for `fp` at time `ts`.
    pub fn write_tls(
        &mut self,
        fp: &crate::monitor::TlsFingerprint,
        ts: Timestamp,
    ) -> std::io::Result<()> {
        let rec = eve_tls_record(fp, ts, &self.in_iface);
        writeln!(self.writer, "{rec}")
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    /// Recover the inner writer (tests read back the bytes).
    pub fn into_inner(self) -> W {
        self.writer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::sink::AnomalySinkExt;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn eve_options() -> EveOptions {
        let mut o = EveOptions::default();
        o.in_iface = "eth0".into();
        o
    }

    #[cfg(feature = "tls")]
    #[test]
    fn eve_tls_record_carries_event_type_fivetuple_and_fingerprint() {
        use crate::monitor::TlsFingerprint;

        let mut hs = flowscope::tls::TlsHandshake::default();
        hs.sni = Some("example.com".into());
        hs.server_alpn = Some("h2".into());
        hs.ja3 = Some("deadbeef".into());
        hs.ja4 = Some("t13d1516h2_test".into());
        let key = flowscope::extract::FiveTupleKey::new(
            flowscope::L4Proto::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
        );
        let fp = TlsFingerprint::from_handshake(&hs, Some(key));

        let v = eve_tls_record(&fp, Timestamp::from_unix_f64(1000.0), "eth0");
        assert_eq!(v["event_type"], "tls");
        assert_eq!(v["in_iface"], "eth0");
        assert_eq!(v["src_ip"], "10.0.0.1");
        assert_eq!(v["dest_port"], 443);
        assert_eq!(v["proto"], "TCP");
        assert_eq!(v["tls"]["sni"], "example.com");
        assert_eq!(v["tls"]["ja3"]["hash"], "deadbeef");
        assert_eq!(v["tls"]["ja4"], "t13d1516h2_test");
        assert_eq!(v["tls"]["alpn"], "h2");
        assert!(v["timestamp"].is_string());

        // The sink writes one NDJSON line ending in a newline.
        let mut sink = EveTlsSink::new(Vec::<u8>::new(), "eth0");
        sink.write_tls(&fp, Timestamp::from_unix_f64(1000.0))
            .unwrap();
        let out = String::from_utf8(sink.into_inner()).unwrap();
        assert_eq!(out.lines().count(), 1);
        assert!(out.ends_with('\n'));
        assert!(out.contains("\"event_type\":\"tls\""), "out = {out}");
    }

    #[test]
    fn eve_sink_emits_valid_json_with_5tuple_when_key_is_five_tuple() {
        let mut sink = EveSink::new(Vec::<u8>::new(), eve_options());

        let key = flowscope::extract::FiveTupleKey::new(
            flowscope::L4Proto::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
        );
        sink.begin(
            "PortScan",
            Severity::Warning,
            Timestamp::new(1_700_000_000, 0),
        )
        .with_key(&key)
        .with("note", "rapid SYN")
        .with_metric("rate_pps", 320.0)
        .emit();

        let bytes = sink.finish().expect("EveJsonWriter::finish recovers Vec");
        let line = std::str::from_utf8(&bytes).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(line.trim()).expect("EveSink emits valid JSON");

        assert_eq!(parsed["event_type"], "anomaly");
        assert_eq!(parsed["anomaly"]["event"], "PortScan");
        assert_eq!(parsed["in_iface"], "eth0");
        assert_eq!(parsed["src_ip"], "10.0.0.1");
        assert_eq!(parsed["src_port"], 12345);
        assert_eq!(parsed["dest_ip"], "10.0.0.2");
        assert_eq!(parsed["dest_port"], 443);
        assert_eq!(parsed["proto"], "TCP");
        assert_eq!(parsed["anomaly"]["labels"]["note"], "rapid SYN");
        assert_eq!(parsed["anomaly"]["metrics"]["rate_pps"], 320.0);
    }

    #[test]
    fn eve_sink_emits_record_without_5tuple_when_key_is_not_five_tuple() {
        let mut sink = EveSink::new(Vec::<u8>::new(), eve_options());

        // A non-FiveTupleKey key — `u32` falls through the
        // downcast and the 5-tuple fields stay None / omitted.
        let key: u32 = 42;
        sink.begin("DgaQuery", Severity::Info, Timestamp::new(1_700_000_000, 0))
            .with_key(&key)
            .with("qname", "kjasdfkasdf.example")
            .emit();

        let bytes = sink.finish().expect("finish ok");
        let line = std::str::from_utf8(&bytes).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

        assert_eq!(parsed["event_type"], "anomaly");
        assert_eq!(parsed["anomaly"]["event"], "DgaQuery");
        assert!(
            parsed.get("src_ip").is_none() || parsed["src_ip"].is_null(),
            "non-FiveTupleKey key leaves src_ip None"
        );
        assert_eq!(parsed["anomaly"]["labels"]["qname"], "kjasdfkasdf.example");
    }
}
