//! [`OcsfSink`] — Open Cybersecurity Schema Framework adapter for the
//! [`AnomalySink`] chain (issue #50).
//!
//! Each [`AnomalySink::write`] call maps the anomaly to one OCSF
//! **Detection Finding** (`class_uid` 2004, `category_uid` 2 — Findings) JSON
//! object and writes it as an NDJSON line. Detection Finding is OCSF's class
//! for security detections/alerts, so a netring anomaly — a detector firing
//! about a flow / host — lands naturally there.
//!
//! The 5-tuple key (when present) flattens into `src_endpoint` / `dst_endpoint`
//! plus `connection_info`; observation labels land under `unmapped`. The output
//! is schema-targetable by AWS Security Lake, Splunk (OCSF add-on), and any OCSF
//! 1.x consumer — point it at `OcsfSink::stdout()` and pipe.
//!
//! Gated behind the opt-in `ocsf-sink` feature (pulls only `serde_json`).

use std::borrow::Cow;
use std::io::Write;

use flowscope::Timestamp;
use serde_json::{Map, Value, json};

use crate::anomaly::Severity;
use crate::anomaly::key::Key;
use crate::anomaly::sink::AnomalySink;

/// OCSF schema version the emitted records conform to.
const OCSF_VERSION: &str = "1.3.0";

/// OCSF Detection Finding anomaly sink. Wraps any `W: Write + Send` and
/// forwards each anomaly as one OCSF NDJSON line.
pub struct OcsfSink<W: Write + Send> {
    out: W,
    product_name: &'static str,
    vendor_name: &'static str,
}

impl<W: Write + Send> OcsfSink<W> {
    /// Wrap `out`; products default to `netring` / `netring`.
    pub fn new(out: W) -> Self {
        Self {
            out,
            product_name: "netring",
            vendor_name: "netring",
        }
    }

    /// Override the OCSF `metadata.product.name` / `vendor_name` (e.g. your
    /// sensor's product identity).
    pub fn product(mut self, name: &'static str, vendor: &'static str) -> Self {
        self.product_name = name;
        self.vendor_name = vendor;
        self
    }

    /// Recover the inner writer (e.g. to read back the bytes in tests).
    pub fn into_inner(self) -> W {
        self.out
    }
}

impl OcsfSink<std::io::Stdout> {
    /// Convenience: `OcsfSink::stdout()` for the canonical "tail and ingest"
    /// shape.
    pub fn stdout() -> Self {
        Self::new(std::io::stdout())
    }
}

/// netring [`Severity`] → OCSF `severity_id` (+ display name) per OCSF §severity.
fn ocsf_severity(s: Severity) -> (u8, &'static str) {
    match s {
        Severity::Info => (1, "Informational"),
        Severity::Warning => (3, "Medium"),
        Severity::Error => (4, "High"),
        Severity::Critical => (5, "Critical"),
    }
}

/// L4 protocol → IANA protocol number for `connection_info.protocol_num`.
fn proto_num(p: flowscope::L4Proto) -> u8 {
    use flowscope::L4Proto::*;
    match p {
        Tcp => 6,
        Udp => 17,
        Icmp => 1,
        IcmpV6 => 58,
        Sctp => 132,
        Other(n) => n,
        _ => 0,
    }
}

fn ts_millis(ts: Timestamp) -> i64 {
    ts.sec as i64 * 1000 + ts.nsec as i64 / 1_000_000
}

impl<W: Write + Send> AnomalySink for OcsfSink<W> {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Key>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        let (severity_id, severity_name) = ocsf_severity(severity);

        // Detection Finding (2004): activity_id 1 = Create.
        // type_uid = class_uid * 100 + activity_id.
        let mut ev = json!({
            "activity_id": 1,
            "activity_name": "Create",
            "category_uid": 2,
            "category_name": "Findings",
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "type_uid": 200_401,
            "time": ts_millis(ts),
            "severity_id": severity_id,
            "severity": severity_name,
            "status_id": 1,
            "status": "New",
            "message": kind,
            "metadata": {
                "product": { "name": self.product_name, "vendor_name": self.vendor_name },
                "version": OCSF_VERSION,
                "uid": kind,
            },
            "finding_info": { "title": kind, "uid": kind },
        });

        // 5-tuple → endpoints + connection_info (when the key downcasts).
        if let Some(k) = key
            && let Some(fk) = k
                .as_any()
                .downcast_ref::<flowscope::extract::FiveTupleKey>()
        {
            ev["src_endpoint"] = json!({ "ip": fk.a.ip().to_string(), "port": fk.a.port() });
            ev["dst_endpoint"] = json!({ "ip": fk.b.ip().to_string(), "port": fk.b.port() });
            ev["connection_info"] = json!({ "protocol_num": proto_num(fk.proto) });
        }

        // Observation labels + metrics → `unmapped` (OCSF's escape hatch for
        // product-specific fields that don't map to a schema attribute).
        if !observations.is_empty() || !metrics.is_empty() {
            let mut unmapped = Map::new();
            for (label, value) in observations {
                unmapped.insert((*label).to_string(), Value::String(value.to_string()));
            }
            for (label, value) in metrics {
                unmapped.insert((*label).to_string(), json!(value));
            }
            ev["unmapped"] = Value::Object(unmapped);
        }

        // One NDJSON line per finding. Write errors (broken stdout/pipe) are
        // operator-recoverable and swallowed, matching `StdoutSink` / `EveSink`.
        if serde_json::to_writer(&mut self.out, &ev).is_ok() {
            let _ = self.out.write_all(b"\n");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn key() -> flowscope::extract::FiveTupleKey {
        flowscope::extract::FiveTupleKey {
            proto: flowscope::L4Proto::Tcp,
            a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 44321),
            b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 443),
        }
    }

    #[test]
    fn maps_anomaly_to_ocsf_detection_finding() {
        let mut sink = OcsfSink::new(Vec::<u8>::new());
        let k = key();
        sink.write(
            "ioc_match",
            Severity::Critical,
            Timestamp {
                sec: 1700,
                nsec: 500_000_000,
            },
            Some(&k),
            &[("indicator", Cow::Borrowed("evil.example"))],
            &[("score", 9.5)],
        );
        let bytes = sink.into_inner();
        let line = std::str::from_utf8(&bytes).unwrap().trim();
        let v: Value = serde_json::from_str(line).unwrap();

        assert_eq!(v["class_uid"], 2004);
        assert_eq!(v["category_uid"], 2);
        assert_eq!(v["type_uid"], 200_401);
        assert_eq!(v["severity_id"], 5);
        assert_eq!(v["severity"], "Critical");
        assert_eq!(v["time"], 1_700_500i64);
        assert_eq!(v["finding_info"]["title"], "ioc_match");
        assert_eq!(v["metadata"]["product"]["name"], "netring");
        assert_eq!(v["metadata"]["version"], OCSF_VERSION);
        assert_eq!(v["src_endpoint"]["ip"], "10.0.0.1");
        assert_eq!(v["src_endpoint"]["port"], 44321);
        assert_eq!(v["dst_endpoint"]["ip"], "203.0.113.7");
        assert_eq!(v["dst_endpoint"]["port"], 443);
        assert_eq!(v["connection_info"]["protocol_num"], 6);
        assert_eq!(v["unmapped"]["indicator"], "evil.example");
        assert_eq!(v["unmapped"]["score"], 9.5);
    }

    #[test]
    fn keyless_anomaly_omits_endpoints() {
        let mut sink = OcsfSink::new(Vec::<u8>::new());
        sink.write(
            "PortScan",
            Severity::Warning,
            Timestamp { sec: 1, nsec: 0 },
            None,
            &[],
            &[],
        );
        let bytes = sink.into_inner();
        let v: Value = serde_json::from_str(std::str::from_utf8(&bytes).unwrap().trim()).unwrap();
        assert_eq!(v["severity_id"], 3);
        assert!(v.get("src_endpoint").is_none());
        assert!(v.get("unmapped").is_none());
    }
}
