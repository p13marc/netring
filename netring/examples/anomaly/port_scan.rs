#![allow(deprecated)]
// 0.21 H.3: this file uses the legacy ProtocolMonitor / AnomalyMonitor / AnomalyRule API; remove with the legacy types in 0.22.

//! Anomaly: one source IP touches > N distinct destination TCP
//! ports inside a sliding window — the canonical horizontal-scan
//! signature.
//!
//! MITRE ATT&CK T1046 (Network Service Discovery). Internal
//! scans precede most lateral-movement playbooks and almost
//! every external recon round.
//!
//! Architecture:
//!
//! ```text
//! ProtocolMonitor (.flow())
//!       │
//!       ▼  Event::FlowStarted { l4: Tcp, key, ts, .. }
//! TimeBucketedSet<IpAddr, u16> per src_ip → set of dst ports seen
//!       │
//!       ▼ cardinality(src, now) > threshold && first time
//! ANOMALY (Warning)
//! ```
//!
//! Notes:
//!
//! - Counts distinct *destination ports*, not packets. A bot
//!   reconnecting to one port a hundred times stays at
//!   `cardinality == 1`.
//! - Per-source-IP `alerted` set rearm rule: once a source falls
//!   back below `threshold/2` distinct ports, the next jump
//!   above `threshold` can alert again.
//! - Internal-only mode (default off): set `INTERNAL_ONLY=1`
//!   to skip alerts whose source is not in RFC 1918 space.
//!   Useful in datacenter deployments where external scan
//!   traffic dominates the perimeter.
//!
//! Usage:
//!     cargo run -p netring --example port_scan \
//!         --features tokio,flow,parse -- \
//!         [interface] [seconds] [threshold] [window_s]
//!
//! Defaults: lo, 60s, threshold=30 distinct dst ports / 30s window.
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use std::collections::HashSet;
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use std::net::IpAddr;
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use std::time::Duration;

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use flowscope::correlate::TimeBucketedSet;
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use flowscope::{L4Proto, Timestamp};
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use netring::anomaly::{Anomaly, AnomalyRule, Severity};
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use netring::flow::extract::FiveTupleKey;
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use netring::protocol::ProtocolEvent;

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
pub struct PortScanRule {
    by_src: TimeBucketedSet<IpAddr, u16>,
    threshold: usize,
    alerted: HashSet<IpAddr>,
}

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
impl PortScanRule {
    pub fn new(threshold: usize, window: Duration) -> Self {
        // Bucket width 1s, generous capacity (the set is per-src,
        // so 1024 distinct ports per host is plenty).
        let bucket_width = Duration::from_secs(1);
        Self {
            by_src: TimeBucketedSet::new(window, bucket_width, 1024),
            threshold,
            alerted: HashSet::new(),
        }
    }
}

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
impl AnomalyRule<FiveTupleKey> for PortScanRule {
    fn name(&self) -> &'static str {
        "PortScan"
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
        let dst_port = key.b.port();
        self.by_src.insert(src, dst_port, *ts);

        let distinct = self.by_src.cardinality(&src, *ts);
        if distinct > self.threshold && self.alerted.insert(src) {
            emit.push(
                Anomaly::new(self.name(), Severity::Warning, *ts)
                    .with_observation("src_ip", src.to_string())
                    .with_observation("recent_dst", key.b.to_string())
                    .with_metric("distinct_dst_ports", distinct as f64)
                    .with_metric("threshold", self.threshold as f64),
            );
        }
    }

    fn on_tick(&mut self, now: Timestamp, _: &mut Vec<Anomaly<FiveTupleKey>>) {
        self.by_src.evict_expired(now);
        // Rearm: hosts below half-threshold get another alert shot
        // when they spin back up.
        let half = self.threshold / 2;
        self.alerted
            .retain(|src| self.by_src.cardinality(src, now) > half);
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
    let threshold: usize = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let window_s: u64 = std::env::args()
        .nth(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    eprintln!(
        "[port-scan] watching {iface} for {seconds}s; \
         alert if any source IP opens TCP to >{threshold} distinct dst ports in {window_s}s"
    );

    let mut monitor = ProtocolMonitorBuilder::new()
        .interface(&iface)
        .flow()
        .build(FiveTuple::bidirectional())?;

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new()
        .with_rule(PortScanRule::new(threshold, Duration::from_secs(window_s)));

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut sweep = tokio::time::interval(Duration::from_secs(5));
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

    eprintln!("[done] {alerts} port-scan alerts raised");
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "flow", feature = "parse")))]
fn main() {
    eprintln!("Build with --features tokio,flow,parse");
}
