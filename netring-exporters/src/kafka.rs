//! Kafka anomaly exporter (0.25 W5, feature `kafka`).
//!
//! Produces each anomaly as a JSON message to a Kafka topic via `rdkafka`
//! (librdkafka). This is the reason netring-exporters is a separate crate:
//! `rdkafka` pulls a C dependency (librdkafka) that has no place in netring's
//! core. Building this feature needs librdkafka available (system package or
//! rdkafka's bundled `cmake-build`).

use std::io;
use std::time::Duration;

use netring::anomaly::sink::{AnomalyRecord, AnomalySink};
use rdkafka::ClientConfig;
use rdkafka::producer::{BaseProducer, BaseRecord, Producer};
use serde_json::json;

/// Build the JSON message body for one anomaly. Pure — unit-tested without a
/// broker.
///
/// netring 0.32 (#215): the record's endpoints add `src_ip` / `src_port` /
/// `dest_ip` / `dest_port` / `proto` (the flow's initiator as the source when
/// `directional` is `true`; omitted when unknown).
pub(crate) fn build_message(record: &AnomalyRecord<'_>) -> String {
    let obs: serde_json::Map<String, serde_json::Value> = record
        .observations
        .iter()
        .map(|(k, v)| ((*k).to_string(), json!(v.as_ref())))
        .collect();
    let met: serde_json::Map<String, serde_json::Value> = record
        .metrics
        .iter()
        .map(|(k, v)| ((*k).to_string(), json!(v)))
        .collect();
    let mut msg = json!({
        "kind": record.kind,
        "severity": format!("{:?}", record.severity),
        "ts_unix": record.ts.to_unix_f64(),
        "key": record.key.map(|k| format!("{k:?}")),
        "observations": obs,
        "metrics": met,
    });
    if let Some(e) = record.endpoints {
        let m = msg.as_object_mut().expect("an object");
        if let Some(ip) = e.src_ip {
            m.insert("src_ip".into(), json!(ip.to_string()));
        }
        if let Some(p) = e.src_port {
            m.insert("src_port".into(), json!(p));
        }
        if let Some(ip) = e.dest_ip {
            m.insert("dest_ip".into(), json!(ip.to_string()));
        }
        if let Some(p) = e.dest_port {
            m.insert("dest_port".into(), json!(p));
        }
        if let Some(p) = e.proto {
            m.insert("proto".into(), json!(p));
        }
        m.insert("directional".into(), json!(e.directional));
    }
    msg.to_string()
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
    fn write(&mut self, anomaly: &AnomalyRecord<'_>) {
        let payload = build_message(anomaly);
        // Key the message by anomaly kind for partition affinity.
        let record = BaseRecord::to(&self.topic)
            .payload(&payload)
            .key(anomaly.kind);
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
    use std::borrow::Cow;

    use netring::Timestamp;
    use netring::anomaly::Severity;
    use netring::anomaly::sink::Endpoints;

    use super::*;

    #[test]
    fn message_has_core_fields() {
        let msg = build_message(
            &AnomalyRecord::new(
                "BeaconDetected",
                Severity::Error,
                Timestamp::new(1_700_000_000, 0),
            )
            .with_observations(&[("host", Cow::Borrowed("c2.example"))])
            .with_metrics(&[("interval_s", 60.0)]),
        );
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(v["kind"], "BeaconDetected");
        assert_eq!(v["severity"], "Error");
        assert_eq!(v["observations"]["host"], "c2.example");
        assert_eq!(v["metrics"]["interval_s"], 60.0);
        // No endpoints → no 5-tuple fields.
        assert!(v.get("src_ip").is_none());
    }

    /// netring 0.32 (#215): the endpoints, initiator first.
    #[test]
    fn message_carries_the_endpoints() {
        let key = netring::flow::extract::FiveTupleKey::new(
            netring::flow::L4Proto::Tcp,
            "10.0.0.1:80".parse().unwrap(),
            "10.0.0.2:40000".parse().unwrap(),
        );
        let msg = build_message(
            &AnomalyRecord::new("X", Severity::Info, Timestamp::new(0, 0))
                .with_endpoints(Endpoints::from_flow(
                    &key,
                    netring::flow::Orientation::Reverse,
                ))
                .with_key(&key),
        );
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(v["src_ip"], "10.0.0.2");
        assert_eq!(v["src_port"], 40000);
        assert_eq!(v["dest_ip"], "10.0.0.1");
        assert_eq!(v["dest_port"], 80);
        assert_eq!(v["proto"], "TCP");
        assert_eq!(v["directional"], true);
    }
}
