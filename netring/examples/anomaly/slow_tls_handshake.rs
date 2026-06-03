//! Anomaly: TLS `ClientHello` not followed by a `ServerHello`
//! within `threshold` — a slow handshake.
//!
//! Hints at: server overload, MITM box doing TLS inspection,
//! middlebox bug, or a deliberately stalled handshake to evade
//! short-lived detectors.
//!
//! Architecture:
//!
//! ```text
//! ProtocolMonitor (.flow().tls())
//!       │
//!       ▼  Message{kind:"tls", TlsMessage::ClientHello} @ ts1
//! KeyIndexed<FiveTupleKey, Timestamp>::insert(key, ts1)
//!
//!       │  Message{kind:"tls", TlsMessage::ServerHello} @ ts2
//!       ▼  pending.remove(key) → emit "ok latency=ts2-ts1"
//!
//! Sweep tick (every 1s)
//!       │
//!       ▼  pending.drain_expired(now) → unfulfilled ClientHellos
//! emit ANOMALY SlowTlsHandshake for each
//! ```
//!
//! Builds on the `AnomalyRule` trait from
//! [`netring::anomaly`] and the `KeyIndexed` primitive from
//! [`netring::correlate`].
//!
//! Usage:
//!     cargo run -p netring --example slow_tls_handshake \
//!         --features tokio,tls -- [interface] [seconds] [threshold_ms]
//!
//! Defaults: lo, 60s, 500ms threshold.
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "tls"))]
use std::time::Duration;

#[cfg(all(feature = "tokio", feature = "tls"))]
use flowscope::Timestamp;
#[cfg(all(feature = "tokio", feature = "tls"))]
use flowscope::tls::TlsMessage;
#[cfg(all(feature = "tokio", feature = "tls"))]
use netring::anomaly::{Anomaly, AnomalyRule, Severity};
#[cfg(all(feature = "tokio", feature = "tls"))]
use netring::correlate::KeyIndexed;
#[cfg(all(feature = "tokio", feature = "tls"))]
use netring::flow::extract::FiveTupleKey;
#[cfg(all(feature = "tokio", feature = "tls"))]
use netring::protocol::{ProtocolEvent, ProtocolMessage};

/// A `ClientHello` not followed by a `ServerHello` within
/// `threshold` is anomalous.
#[cfg(all(feature = "tokio", feature = "tls"))]
struct SlowTlsHandshakeRule {
    pending: KeyIndexed<FiveTupleKey, Timestamp>,
    threshold: Duration,
}

#[cfg(all(feature = "tokio", feature = "tls"))]
impl SlowTlsHandshakeRule {
    fn new(threshold: Duration) -> Self {
        Self {
            pending: KeyIndexed::new(threshold),
            threshold,
        }
    }
}

#[cfg(all(feature = "tokio", feature = "tls"))]
impl AnomalyRule<FiveTupleKey> for SlowTlsHandshakeRule {
    fn name(&self) -> &'static str {
        "SlowTlsHandshake"
    }

    fn observe(&mut self, evt: &ProtocolEvent<FiveTupleKey>, _: &mut Vec<Anomaly<FiveTupleKey>>) {
        let ProtocolEvent::Message {
            kind: "tls",
            key,
            message: ProtocolMessage::Tls(msg),
            ts,
            ..
        } = evt
        else {
            return;
        };
        match msg {
            TlsMessage::ClientHello(_) => {
                self.pending.insert(*key, *ts, *ts);
            }
            TlsMessage::ServerHello(_) => {
                // Within-TTL ServerHello → handshake completed fast
                // enough. Slow handshakes are caught by drain_expired
                // in on_tick. Just clear the pending entry.
                if let Some(client_ts) = self.pending.remove(key) {
                    let rtt = ts.saturating_sub(client_ts);
                    eprintln!("[OK ] tls handshake completed in {rtt:?} (key={key:?})");
                }
            }
            _ => {}
        }
    }

    fn on_tick(&mut self, now: Timestamp, emit: &mut Vec<Anomaly<FiveTupleKey>>) {
        for (key, client_ts) in self.pending.drain_expired(now) {
            let waited = now.saturating_sub(client_ts);
            emit.push(
                Anomaly::new(self.name(), Severity::Warning, now)
                    .with_key(key)
                    .with_observation("a", key.a.to_string())
                    .with_observation("b", key.b.to_string())
                    .with_metric("waited_ms", waited.as_secs_f64() * 1000.0)
                    .with_metric("threshold_ms", self.threshold.as_secs_f64() * 1000.0),
            );
        }
    }
}

#[cfg(all(feature = "tokio", feature = "tls"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;

    use futures::StreamExt;
    use netring::AnomalyMonitor;
    use netring::flow::extract::FiveTuple;
    use netring::protocol::ProtocolMonitorBuilder;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let threshold_ms: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let threshold = Duration::from_millis(threshold_ms);

    eprintln!(
        "[slow-tls] watching {iface} for {seconds}s; \
         alert if ClientHello not followed by ServerHello within {threshold_ms}ms"
    );

    let mut monitor = ProtocolMonitorBuilder::new()
        .interface(&iface)
        .flow()
        .tls()
        .build(FiveTuple::bidirectional())?;

    let mut rules =
        AnomalyMonitor::<FiveTupleKey>::new().with_rule(SlowTlsHandshakeRule::new(threshold));

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut sweep = tokio::time::interval(Duration::from_secs(1));
    let mut last_seen = Timestamp::default();
    let mut alerts = 0u64;

    while Instant::now() < deadline {
        tokio::select! {
            biased;
            Some(evt) = monitor.next() => {
                let evt = evt?;
                last_seen = evt.timestamp();
                for a in rules.observe(&evt) {
                    println!("{a}");
                    alerts += 1;
                }
            }
            _ = sweep.tick() => {
                let now = wall_clock_ts().max(last_seen);
                for a in rules.on_tick(now) {
                    println!("{a}");
                    alerts += 1;
                }
            }
        }
    }

    eprintln!("[done] {alerts} slow TLS handshakes raised");
    Ok(())
}

#[cfg(all(feature = "tokio", feature = "tls"))]
fn wall_clock_ts() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp::new(now.as_secs() as u32, now.subsec_nanos())
}

#[cfg(not(all(feature = "tokio", feature = "tls")))]
fn main() {
    eprintln!("Build with --features tokio,tls");
}
