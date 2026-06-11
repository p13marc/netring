#![allow(deprecated)]
// 0.21 H.3: this file uses the legacy ProtocolMonitor / AnomalyMonitor / AnomalyRule API; remove with the legacy types in 0.22.

//! Anomaly: DNS query whose label payload has high Shannon entropy
//! and a base64-shaped charset — the canonical DNS-tunnel exfil
//! fingerprint.
//!
//! Real production signal — MITRE ATT&CK T1071.004 (DNS) +
//! T1041 (Exfiltration over C2). Tunneling tools (iodine,
//! dnscat2) pack data into long subdomain labels under an
//! attacker-controlled zone. The label payload is high-entropy
//! (random or compressed/encrypted) and constrained to a
//! base32/base64-like alphabet because DNS labels can only use
//! a limited charset.
//!
//! Detector shape (single-protocol — no correlation needed):
//!
//! ```text
//! ProtocolMonitor (.dns())
//!       │
//!       ▼  Event::Message { DnsMessage::Query, parser_kind: "dns-udp" }
//! for each question.name.split('.'):
//!     if label.len() >= MIN_LEN
//!        && shannon_entropy(label) > THRESHOLD_BITS
//!        && is_base64ish(label)
//!     →  ANOMALY (Warning)
//! ```
//!
//! False-positive caveats (documented for production tuning):
//!
//! - Some CDNs (Akamai, Cloudfront, Cloudflare workers) and DKIM
//!   selectors use long randomized labels. Allowlist the apex
//!   domain before alerting.
//! - Compressed or otherwise high-entropy short labels won't
//!   trigger; the 16-byte minimum tunes for "looks like a payload,"
//!   not just "looks random."
//!
//! Usage:
//!     cargo run -p netring --example dns_tunnel_detect \
//!         --features tokio,dns -- [interface] [seconds] [entropy_threshold]
//!
//! Defaults: lo, 60s, 4.0 bits/byte (high — random data is ~7.5).
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "dns"))]
use flowscope::Timestamp;
#[cfg(all(feature = "tokio", feature = "dns"))]
use flowscope::dns::DnsMessage;
#[cfg(all(feature = "tokio", feature = "dns"))]
use netring::anomaly::{Anomaly, AnomalyRule, Severity};
#[cfg(all(feature = "tokio", feature = "dns"))]
use netring::flow::extract::FiveTupleKey;
#[cfg(all(feature = "tokio", feature = "dns"))]
use netring::protocol::{ProtocolEvent, ProtocolMessage};

/// Shortest label that gets entropy-scored. Below this length
/// the signal is too noisy.
#[cfg(all(feature = "tokio", feature = "dns"))]
const MIN_LABEL_LEN: usize = 16;

#[cfg(all(feature = "tokio", feature = "dns"))]
pub struct DnsTunnelRule {
    threshold_bits: f64,
}

#[cfg(all(feature = "tokio", feature = "dns"))]
impl DnsTunnelRule {
    pub fn new(threshold_bits: f64) -> Self {
        Self { threshold_bits }
    }
}

#[cfg(all(feature = "tokio", feature = "dns"))]
impl AnomalyRule<FiveTupleKey> for DnsTunnelRule {
    fn name(&self) -> &'static str {
        "DnsTunnel"
    }

    fn observe(
        &mut self,
        evt: &ProtocolEvent<FiveTupleKey>,
        emit: &mut Vec<Anomaly<FiveTupleKey>>,
    ) {
        let ProtocolEvent::Message {
            parser_kind: "dns-udp",
            message: ProtocolMessage::Dns(DnsMessage::Query(q)),
            key,
            ts,
            ..
        } = evt
        else {
            return;
        };
        for question in &q.questions {
            for label in question.name.split('.') {
                if label.len() < MIN_LABEL_LEN {
                    continue;
                }
                let h = flowscope::detect::shannon_entropy(label.as_bytes());
                if h > self.threshold_bits && flowscope::detect::is_base64ish(label) {
                    emit.push(
                        Anomaly::new(self.name(), Severity::Warning, *ts)
                            .with_key(*key)
                            .with_observation("qname", question.name.clone())
                            .with_observation("label", label.to_string())
                            .with_metric("entropy_bits", h)
                            .with_metric("label_len", label.len() as f64),
                    );
                    // One alert per question is plenty.
                    return;
                }
            }
        }
    }

    fn on_tick(&mut self, _: Timestamp, _: &mut Vec<Anomaly<FiveTupleKey>>) {
        // Stateless rule — no sweep work.
    }
}

#[cfg(all(feature = "tokio", feature = "dns"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    use futures::StreamExt;
    use netring::AnomalyMonitor;
    use netring::flow::extract::FiveTuple;
    use netring::protocol::ProtocolMonitorBuilder;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let threshold: f64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4.0);

    eprintln!(
        "[dns-tunnel] watching {iface} for {seconds}s; \
         alert on DNS labels ≥{MIN_LABEL_LEN}B with entropy >{threshold:.1} bits + base64-ish charset",
    );

    let mut monitor = ProtocolMonitorBuilder::new()
        .interface(&iface)
        .flow()
        .dns()
        .build(FiveTuple::bidirectional())?;

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new().with_rule(DnsTunnelRule::new(threshold));

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut alerts = 0u64;

    while Instant::now() < deadline
        && let Some(evt) = monitor.next().await
    {
        let evt = evt?;
        for a in rules.observe(&evt) {
            println!("{a}");
            alerts += 1;
        }
    }

    eprintln!("[done] {alerts} DNS-tunnel candidate labels raised");
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "dns")))]
fn main() {
    eprintln!("Build with --features tokio,dns");
}
