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

    #[test]
    fn eve_sink_emits_valid_json_with_5tuple_when_key_is_five_tuple() {
        let mut sink = EveSink::new(Vec::<u8>::new(), eve_options());

        let key = flowscope::extract::FiveTupleKey {
            proto: flowscope::L4Proto::Tcp,
            a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
            b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
        };
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
