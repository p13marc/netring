#![allow(deprecated)]
// 0.21 H.3: this file uses the legacy ProtocolMonitor / AnomalyMonitor / AnomalyRule API; remove with the legacy types in 0.22.

//! Anomaly: > N flow-starts from one source within a short
//! window — the canonical SYN-flood / DoS fingerprint.
//!
//! MITRE ATT&CK T1498.001 (Network Denial of Service: Direct).
//! At line-rate SYN flood you'll see thousands of new flows per
//! second from a single attacker IP (or from spoofed addresses
//! within a subnet); the kernel never establishes most of them
//! because the SYN-ACK never gets ack'd.
//!
//! Architecture:
//!
//! ```text
//! ProtocolMonitor (.flow())
//!       │
//!       ▼  Event::FlowStarted { l4: Tcp, key, ts, .. }
//! BurstDetector<IpAddr, ()>::observe(src, (), ts)
//!       │  → returns Some(BurstHit) iff threshold hit within window
//!       ▼
//! ANOMALY (Critical — page immediately)
//! ```
//!
//! Severity is Critical because:
//! 1. DoS impact is operational (services degrade/page now).
//! 2. False positives are low — legit clients don't open 100s
//!    of TCP flows per second from one IP. Aggregate proxies
//!    (HAProxy, Envoy egress) are the practical exception;
//!    allowlist their IPs.
//!
//! Tunables:
//! - `threshold` (--arg 3) — flows per window before alert.
//! - `window` (--arg 4) — sliding window in seconds.
//!
//! Usage:
//!     cargo run -p netring --example syn_flood_burst \
//!         --features tokio,flow,parse -- \
//!         [interface] [seconds] [threshold] [window_s]
//!
//! Defaults: lo, 60s, threshold=100 flows / 1s window.
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use std::net::IpAddr;
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use std::time::Duration;

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use flowscope::correlate::BurstDetector;
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use flowscope::{L4Proto, Timestamp};
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use netring::anomaly::{Anomaly, AnomalyRule, Severity};
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use netring::flow::extract::FiveTupleKey;
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use netring::protocol::ProtocolEvent;

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
pub struct SynFloodRule {
    bursts: BurstDetector<IpAddr, ()>,
}

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
impl SynFloodRule {
    pub fn new(threshold: u32, window: Duration) -> Self {
        Self {
            bursts: BurstDetector::new((), threshold, window, None),
        }
    }
}

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
impl AnomalyRule<FiveTupleKey> for SynFloodRule {
    fn name(&self) -> &'static str {
        "SynFlood"
    }

    fn observe(
        &mut self,
        evt: &ProtocolEvent<FiveTupleKey>,
        emit: &mut Vec<Anomaly<FiveTupleKey>>,
    ) {
        let ProtocolEvent::FlowStarted {
            key,
            l4: Some(L4Proto::Tcp),
            ts,
        } = evt
        else {
            return;
        };
        let src = key.a.ip();
        if let Some(hit) = self.bursts.observe(&src, &(), *ts) {
            emit.push(
                Anomaly::new(self.name(), Severity::Critical, *ts)
                    .with_observation("src_ip", src.to_string())
                    .with_observation("recent_dst", key.b.to_string())
                    .with_metric("flow_starts_in_window", hit.burst_count as f64),
            );
        }
    }

    fn on_tick(&mut self, now: Timestamp, _: &mut Vec<Anomaly<FiveTupleKey>>) {
        self.bursts.evict_expired(now);
    }
}

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
fn wall_clock_ts() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp::new(now.as_secs() as u32, now.subsec_nanos())
}

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
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
    let threshold: u32 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let window_s: u64 = std::env::args()
        .nth(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    eprintln!(
        "[syn-flood] watching {iface} for {seconds}s; \
         alert if any source IP opens >{threshold} TCP flows in {window_s}s"
    );

    let mut monitor = ProtocolMonitorBuilder::new()
        .interface(&iface)
        .flow()
        .build(FiveTuple::bidirectional())?;

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new()
        .with_rule(SynFloodRule::new(threshold, Duration::from_secs(window_s)));

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
                let _ = rules.on_tick(now);
            }
        }
    }

    eprintln!("[done] {alerts} SYN-flood alerts raised");
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "flow", feature = "parse")))]
fn main() {
    eprintln!("Build with --features tokio,flow,parse");
}
