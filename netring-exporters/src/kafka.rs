//! Kafka anomaly exporter (0.25 W5, feature `kafka`).
//!
//! Produces each anomaly as a JSON message to a Kafka topic via `rdkafka`
//! (librdkafka). This is the reason netring-exporters is a separate crate:
//! `rdkafka` pulls a C dependency (librdkafka) that has no place in netring's
//! core. Building this feature needs librdkafka available (system package or
//! rdkafka's bundled `cmake-build`).

use std::borrow::Cow;
use std::io;
use std::time::Duration;

use netring::Timestamp;
use netring::anomaly::Severity;
use netring::anomaly::key::Key;
use netring::anomaly::sink::AnomalySink;
use rdkafka::ClientConfig;
use rdkafka::producer::{BaseProducer, BaseRecord, Producer};
use serde_json::json;

/// Build the JSON message body for one anomaly. Pure — unit-tested without a
/// broker.
pub(crate) fn build_message(
    kind: &'static str,
    severity: Severity,
    ts: Timestamp,
    key: Option<&dyn Key>,
    observations: &[(&'static str, Cow<'_, str>)],
    metrics: &[(&'static str, f64)],
) -> String {
    let obs: serde_json::Map<String, serde_json::Value> = observations
        .iter()
        .map(|(k, v)| ((*k).to_string(), json!(v.as_ref())))
        .collect();
    let met: serde_json::Map<String, serde_json::Value> = metrics
        .iter()
        .map(|(k, v)| ((*k).to_string(), json!(v)))
        .collect();
    json!({
        "kind": kind,
        "severity": format!("{severity:?}"),
        "ts_unix": ts.to_unix_f64(),
        "key": key.map(|k| format!("{k:?}")),
        "observations": obs,
        "metrics": met,
    })
    .to_string()
}

/// Exports netring anomalies to a Kafka topic as JSON messages.
///
/// Each anomaly is produced to `topic`; [`flush`](AnomalySink::flush) drains
/// the producer queue (e.g. at shutdown). Produce errors are logged at `warn`
/// rather than tearing down the capture pipeline.
pub struct KafkaSink {
    producer: BaseProducer,
    topic: String,
}

impl KafkaSink {
    /// Connect a producer to `brokers` (comma-separated `host:port`) targeting
    /// `topic`.
    pub fn new(
        brokers: &str,
        topic: impl Into<String>,
    ) -> Result<Self, rdkafka::error::KafkaError> {
        let producer: BaseProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .create()?;
        Ok(Self {
            producer,
            topic: topic.into(),
        })
    }
}

impl AnomalySink for KafkaSink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Key>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        let payload = build_message(kind, severity, ts, key, observations, metrics);
        // Key the message by anomaly kind for partition affinity.
        let record = BaseRecord::to(&self.topic).payload(&payload).key(kind);
        if let Err((e, _)) = self.producer.send(record) {
            tracing::warn!(error = %e, "Kafka produce failed");
        }
        // Serve delivery callbacks without blocking the capture loop.
        self.producer.poll(Duration::from_millis(0));
    }

    fn flush(&mut self) -> io::Result<()> {
        Producer::flush(&self.producer, Duration::from_secs(5))
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_has_core_fields() {
        let msg = build_message(
            "BeaconDetected",
            Severity::Error,
            Timestamp::new(1_700_000_000, 0),
            None,
            &[("host", Cow::Borrowed("c2.example"))],
            &[("interval_s", 60.0)],
        );
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(v["kind"], "BeaconDetected");
        assert_eq!(v["severity"], "Error");
        assert_eq!(v["observations"]["host"], "c2.example");
        assert_eq!(v["metrics"]["interval_s"], 60.0);
    }
}
