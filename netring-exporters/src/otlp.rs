//! OTLP/HTTP-JSON anomaly exporter (0.25 W5).
//!
//! Maps each netring anomaly to an OpenTelemetry [LogRecord] and ships a batch
//! to an OTLP/HTTP collector (`/v1/logs`) as JSON over a **blocking** HTTP
//! client (`ureq`) — matching the synchronous `AnomalySink` contract without
//! dragging an async runtime into the exporter.
//!
//! [LogRecord]: https://opentelemetry.io/docs/specs/otlp/#otlphttp

use std::io;

use netring::anomaly::Severity;
use netring::anomaly::sink::{AnomalyRecord, AnomalySink};
use serde_json::{Value, json};

/// OTLP severity number for a netring [`Severity`] (per the OTLP spec's
/// `SeverityNumber`: INFO=9, WARN=13, ERROR=17, FATAL=21).
fn severity_number(s: Severity) -> u8 {
    match s {
        Severity::Info => 9,
        Severity::Warning => 13,
        Severity::Error => 17,
        Severity::Critical => 21,
        // `Severity` is `#[non_exhaustive]`: a future level maps to OTLP
        // UNSPECIFIED (0) until this exporter learns its number, rather than
        // guessing a wrong one.
        _ => 0,
    }
}

/// Build the OTLP `LogRecord` JSON for one anomaly. Pure — unit-tested without
/// a collector.
///
/// netring 0.32 (#215): the record's endpoints become the OpenTelemetry
/// semantic-convention attributes `source.address` / `source.port` /
/// `destination.address` / `destination.port` / `network.transport` (the
/// flow's initiator as the source when the endpoints are directional).
pub(crate) fn build_log_record(record: &AnomalyRecord<'_>) -> Value {
    let (kind, severity, ts) = (record.kind, record.severity, record.ts);
    let mut attributes = vec![kv("anomaly.kind", json!(kind))];
    if let Some(k) = record.key {
        // `&dyn Key` only exposes `Debug`; the 5-tuple is in its repr.
        attributes.push(kv("anomaly.key", json!(format!("{k:?}"))));
    }
    if let Some(e) = record.endpoints {
        if let Some(ip) = e.src_ip {
            attributes.push(kv("source.address", json!(ip.to_string())));
        }
        if let Some(p) = e.src_port {
            attributes.push(kv("source.port", json!(p)));
        }
        if let Some(ip) = e.dest_ip {
            attributes.push(kv("destination.address", json!(ip.to_string())));
        }
        if let Some(p) = e.dest_port {
            attributes.push(kv("destination.port", json!(p)));
        }
        if let Some(t) = e.proto.and_then(network_transport) {
            attributes.push(kv("network.transport", json!(t)));
        }
    }
    for (name, value) in record.observations {
        attributes.push(kv(&format!("anomaly.{name}"), json!(value.as_ref())));
    }
    for (name, value) in record.metrics {
        attributes.push(kv(&format!("anomaly.{name}"), json!(value)));
    }

    let time_unix_nano = (ts.to_unix_f64() * 1e9) as u64;
    json!({
        // OTLP encodes 64-bit values as decimal strings in JSON.
        "timeUnixNano": time_unix_nano.to_string(),
        "severityNumber": severity_number(severity),
        "severityText": format!("{severity:?}"),
        "body": { "stringValue": kind },
        "attributes": attributes,
    })
}

/// OpenTelemetry `network.transport` value for an endpoints protocol label
/// (`tcp`, `udp`; ICMP / SCTP have no well-known value — omitted).
fn network_transport(proto: &str) -> Option<&'static str> {
    match proto {
        "TCP" => Some("tcp"),
        "UDP" => Some("udp"),
        _ => None,
    }
}

/// Wrap a batch of `LogRecord`s in the OTLP `logs` request envelope
/// (`resourceLogs` → `scopeLogs` → `logRecords`). Pure — unit-tested.
fn build_envelope(service_name: &str, records: &[Value]) -> Value {
    json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [kv("service.name", json!(service_name))],
            },
            "scopeLogs": [{
                "scope": { "name": "netring" },
                "logRecords": records,
            }],
        }],
    })
}

/// One OTLP key/value attribute, wrapping `value` in the correct OTLP
/// `AnyValue` variant.
fn kv(key: &str, value: Value) -> Value {
    let any = match value {
        Value::String(s) => json!({ "stringValue": s }),
        Value::Number(n) if n.is_f64() => json!({ "doubleValue": n.as_f64() }),
        Value::Number(n) => json!({ "intValue": n.to_string() }),
        Value::Bool(b) => json!({ "boolValue": b }),
        other => json!({ "stringValue": other.to_string() }),
    };
    json!({ "key": key, "value": any })
}

/// Exports netring anomalies to an OTLP/HTTP collector as OpenTelemetry logs.
///
/// Anomalies are buffered and POSTed as one OTLP `logs` request when the batch
/// fills or on [`flush`](AnomalySink::flush) (e.g. at monitor shutdown). Export
/// failures are logged at `warn` and the batch is retained for the next attempt
/// — an unreachable collector never tears down the capture pipeline.
pub struct OtlpAnomalySink {
    endpoint: String,
    service_name: String,
    batch: Vec<Value>,
    batch_size: usize,
    agent: ureq::Agent,
}

impl OtlpAnomalySink {
    /// Create a sink posting to `endpoint` (e.g.
    /// `http://localhost:4318/v1/logs`), tagging records with `service_name`.
    /// Default batch size is 64; tune with [`batch_size`](Self::batch_size).
    pub fn new(endpoint: impl Into<String>, service_name: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            service_name: service_name.into(),
            batch: Vec::new(),
            batch_size: 64,
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(std::time::Duration::from_secs(5)))
                .build()
                .new_agent(),
        }
    }

    /// Flush the batch once this many records have accumulated. Default 64.
    pub fn batch_size(mut self, n: usize) -> Self {
        self.batch_size = n.max(1);
        self
    }

    /// POST the buffered records as one OTLP `logs` request, clearing the batch
    /// on success. A no-op when empty.
    fn post_batch(&mut self) -> io::Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }
        let envelope = build_envelope(&self.service_name, &self.batch);
        self.agent
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .send(envelope.to_string())
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.batch.clear();
        Ok(())
    }
}

impl AnomalySink for OtlpAnomalySink {
    fn write(&mut self, record: &AnomalyRecord<'_>) {
        self.batch.push(build_log_record(record));
        if self.batch.len() >= self.batch_size
            && let Err(e) = self.post_batch()
        {
            tracing::warn!(error = %e, "OTLP export failed; retaining batch");
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Err(e) = self.post_batch() {
            tracing::warn!(error = %e, "OTLP export failed on flush");
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use netring::Timestamp;
    use netring::anomaly::sink::Endpoints;

    use super::*;

    #[test]
    fn log_record_carries_otlp_shape() {
        let rec = build_log_record(
            &AnomalyRecord::new(
                "PortScan",
                Severity::Warning,
                Timestamp::new(1_700_000_000, 0),
            )
            .with_observations(&[("detail", Cow::Borrowed("fast connect rate"))])
            .with_metrics(&[("rate", 42.0)]),
        );
        assert_eq!(rec["severityNumber"], 13);
        assert_eq!(rec["severityText"], "Warning");
        assert_eq!(rec["body"]["stringValue"], "PortScan");
        // timeUnixNano is a decimal string of nanoseconds.
        assert_eq!(rec["timeUnixNano"], "1700000000000000000");
        let attrs = rec["attributes"].as_array().unwrap();
        // anomaly.kind + the two anomaly.* attributes.
        assert!(attrs.iter().any(|a| a["key"] == "anomaly.kind"));
        assert!(
            attrs.iter().any(|a| a["key"] == "anomaly.detail"
                && a["value"]["stringValue"] == "fast connect rate")
        );
        assert!(
            attrs
                .iter()
                .any(|a| a["key"] == "anomaly.rate" && a["value"]["doubleValue"] == 42.0)
        );
    }

    #[test]
    fn envelope_nests_records_under_resource_and_scope() {
        let rec = build_log_record(&AnomalyRecord::new(
            "X",
            Severity::Info,
            Timestamp::new(1, 0),
        ));
        let env = build_envelope("my-svc", std::slice::from_ref(&rec));
        // service.name on the resource.
        let res_attrs = env["resourceLogs"][0]["resource"]["attributes"]
            .as_array()
            .unwrap();
        assert!(
            res_attrs
                .iter()
                .any(|a| a["key"] == "service.name" && a["value"]["stringValue"] == "my-svc")
        );
        // the record under scopeLogs[0].logRecords.
        let logs = env["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
            .as_array()
            .unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0]["body"]["stringValue"], "X");
    }

    /// netring 0.32 (#215): the endpoints as OTel semantic-convention
    /// attributes, initiator as the source.
    #[test]
    fn log_record_carries_the_endpoints() {
        let key = netring::flow::extract::FiveTupleKey::new(
            netring::flow::L4Proto::Tcp,
            "10.0.0.1:80".parse().unwrap(),
            "10.0.0.2:40000".parse().unwrap(),
        );
        let rec = build_log_record(
            &AnomalyRecord::new("X", Severity::Info, Timestamp::new(1, 0))
                .with_endpoints(Endpoints::from_flow(
                    &key,
                    netring::flow::Orientation::Reverse,
                ))
                .with_key(&key),
        );
        let attrs = rec["attributes"].as_array().unwrap();
        let attr = |k: &str| {
            attrs
                .iter()
                .find(|a| a["key"] == k)
                .unwrap_or_else(|| panic!("no {k}: {attrs:?}"))["value"]
                .clone()
        };
        assert_eq!(attr("source.address")["stringValue"], "10.0.0.2");
        assert_eq!(attr("source.port")["intValue"], "40000");
        assert_eq!(attr("destination.address")["stringValue"], "10.0.0.1");
        assert_eq!(attr("destination.port")["intValue"], "80");
        assert_eq!(attr("network.transport")["stringValue"], "tcp");
    }

    #[test]
    fn severity_numbers_match_otlp_spec() {
        assert_eq!(severity_number(Severity::Info), 9);
        assert_eq!(severity_number(Severity::Warning), 13);
        assert_eq!(severity_number(Severity::Error), 17);
        assert_eq!(severity_number(Severity::Critical), 21);
    }
}
