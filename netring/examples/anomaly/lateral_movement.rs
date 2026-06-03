//! Anomaly: a single source IP contacts an unusually high number
//! of **distinct** internal destination IPs within a sliding
//! window — classic lateral-movement signal.
//!
//! Real-world incident shape: an attacker lands on one host, then
//! probes the internal subnet to find more. The fingerprint is
//! "one IP, many fan-out connections to peers." A noisy file-share
//! or k8s leader-election pattern can be a false positive — tune
//! `threshold` and `window` per environment.
//!
//! Architecture:
//!
//! ```text
//! ProtocolMonitor (.flow())
//!       │
//!       ▼  FlowEvent::Started { key, ts, .. }
//! filter: key.a internal && key.b internal
//!       │
//!       ▼ for each src_ip:
//! fan_out: HashMap<IpAddr, KeyIndexed<IpAddr, ()>>::insert(dst_ip)
//! distinct = fan_out[src_ip].len_alive(now)
//!       │
//!       ▼ if distinct > threshold && first time → ANOMALY
//! ```
//!
//! Uses [`KeyIndexed::drain_expired`] on a sweep tick to keep
//! per-source-IP state bounded.
//!
//! Usage:
//!     cargo run -p netring --example lateral_movement \
//!         --features tokio,flow,parse -- \
//!         [interface] [seconds] [threshold] [window_s]
//!
//! Defaults: lo, 60s, threshold=10 distinct dst IPs / 60s window.
//!
//! Internal-subnet allow-list is hard-coded to the canonical
//! RFC 1918 octets; in a real deployment you'd pass an `IpNet`
//! list from config.
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use std::collections::{HashMap, HashSet};
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use std::net::IpAddr;
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use std::time::Duration;

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use flowscope::Timestamp;
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use netring::anomaly::{Anomaly, AnomalyRule, Severity};
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use netring::correlate::KeyIndexed;
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use netring::flow::FlowEvent;
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use netring::flow::extract::FiveTupleKey;
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
use netring::protocol::ProtocolEvent;

/// RFC 1918 + link-local: the "internal" address space for the
/// purpose of this detector.
#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 127)
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            segs[0] & 0xfe00 == 0xfc00  // fc00::/7  (ULA)
                || segs[0] & 0xffc0 == 0xfe80   // fe80::/10 (link-local)
                || v6.is_loopback()
        }
    }
}

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
struct LateralMovementRule {
    /// src_ip → set of distinct dst IPs seen in window.
    fan_out: HashMap<IpAddr, KeyIndexed<IpAddr, ()>>,
    threshold: u64,
    window: Duration,
    alerted: HashSet<IpAddr>,
}

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
impl LateralMovementRule {
    fn new(threshold: u64, window: Duration) -> Self {
        Self {
            fan_out: HashMap::new(),
            threshold,
            window,
            alerted: HashSet::new(),
        }
    }
}

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
impl AnomalyRule<FiveTupleKey> for LateralMovementRule {
    fn name(&self) -> &'static str {
        "LateralMovement"
    }

    fn observe(
        &mut self,
        evt: &ProtocolEvent<FiveTupleKey>,
        emit: &mut Vec<Anomaly<FiveTupleKey>>,
    ) {
        let ProtocolEvent::Flow(FlowEvent::Started { key, ts, .. }) = evt else {
            return;
        };
        let src = key.a.ip();
        let dst = key.b.ip();
        if !is_internal(src) || !is_internal(dst) || src == dst {
            return;
        }

        let bucket = self
            .fan_out
            .entry(src)
            .or_insert_with(|| KeyIndexed::new(self.window));
        bucket.insert(dst, (), *ts);

        // Count live entries (within window): evict stale, then `.len()`.
        bucket.evict_expired(*ts);
        let distinct = bucket.len() as u64;
        if distinct > self.threshold && self.alerted.insert(src) {
            emit.push(
                Anomaly::new(self.name(), Severity::Critical, *ts)
                    .with_observation("src_ip", src.to_string())
                    .with_observation("recent_dst", dst.to_string())
                    .with_metric("distinct_dst", distinct as f64)
                    .with_metric("threshold", self.threshold as f64)
                    .with_metric("window_s", self.window.as_secs_f64()),
            );
        }
    }

    fn on_tick(&mut self, now: Timestamp, _: &mut Vec<Anomaly<FiveTupleKey>>) {
        // Drain expired per-src buckets so the map doesn't grow
        // unboundedly. Also rearm alerts for sources that fell back
        // below half-threshold.
        let half = self.threshold / 2;
        self.fan_out.retain(|src, bucket| {
            bucket.evict_expired(now);
            let alive = bucket.len() as u64;
            if alive <= half {
                self.alerted.remove(src);
            }
            alive > 0
        });
    }
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
    let threshold: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let window_s: u64 = std::env::args()
        .nth(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    eprintln!(
        "[lat-move] watching {iface} for {seconds}s; \
         alert if any internal IP contacts >{threshold} distinct internal IPs in {window_s}s"
    );

    let mut monitor = ProtocolMonitorBuilder::new()
        .interface(&iface)
        .flow()
        .build(FiveTuple::bidirectional())?;

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new().with_rule(LateralMovementRule::new(
        threshold,
        Duration::from_secs(window_s),
    ));

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
                for a in rules.on_tick(now) {
                    println!("{a}");
                    alerts += 1;
                }
            }
        }
    }

    eprintln!("[done] {alerts} lateral-movement alerts raised");
    Ok(())
}

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
fn wall_clock_ts() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp::new(now.as_secs() as u32, now.subsec_nanos())
}

#[cfg(not(all(feature = "tokio", feature = "flow", feature = "parse")))]
fn main() {
    eprintln!("Build with --features tokio,flow,parse");
}
