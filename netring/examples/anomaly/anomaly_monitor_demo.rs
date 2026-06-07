//! End-to-end anomaly correlator using [`ProtocolMonitor`] +
//! [`AnomalyMonitor`].
//!
//! This is the "easy to write" recipe the 0.16 roadmap aimed at.
//! Two detectors live side-by-side in the same event loop:
//!
//! 1. **`DnsBurstRule`** — per-source-IP rate counter.
//!    Uses [`TimeBucketedCounter`](netring::correlate::TimeBucketedCounter)
//!    to flag any host issuing > N DNS queries in a 10s window.
//!
//! 2. **`DnsNoConnectionRule`** — cross-protocol correlator.
//!    Uses [`KeyIndexed`](netring::correlate::KeyIndexed) to
//!    remember which IPs were just resolved; raises an anomaly
//!    if the IP isn't connected to within `timeout`.
//!
//! Both rules implement the [`AnomalyRule`] trait. The
//! [`AnomalyMonitor`] fans each event into both, returning a flat
//! `Vec<Anomaly<FiveTupleKey>>`.
//!
//! Compare against:
//! - `dns_query_burst.rs` — same first detector, raw primitives
//!   only. ~80 LoC.
//! - `dns_resolved_no_connection.rs` — same second detector with
//!   a hand-rolled `tokio::select!` over two `AsyncCapture`s.
//!   ~130 LoC.
//!
//! This example does both in ~180 LoC using one builder and one
//! event loop. The win scales linearly with the number of rules.
//!
//! Usage:
//!     cargo run -p netring --example anomaly_monitor_demo \
//!         --features tokio,dns -- [interface] [seconds]
//!
//! Defaults: lo, 60s.
//!
//! Output format: human-readable by default. Set `NETRING_JSON=1`
//! for one-line-JSON output (pipe into Vector / Fluentd / jq):
//!
//!     NETRING_JSON=1 cargo run --example anomaly_monitor_demo \
//!         --features tokio,dns -- lo 30 | jq .
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "dns"))]
use std::collections::HashSet;
#[cfg(all(feature = "tokio", feature = "dns"))]
use std::net::IpAddr;
#[cfg(all(feature = "tokio", feature = "dns"))]
use std::time::Duration;

#[cfg(all(feature = "tokio", feature = "dns"))]
use flowscope::Timestamp;
#[cfg(all(feature = "tokio", feature = "dns"))]
use flowscope::dns::{DnsMessage, DnsRdata};
#[cfg(all(feature = "tokio", feature = "dns"))]
use netring::anomaly::{Anomaly, AnomalyRule, Severity};
#[cfg(all(feature = "tokio", feature = "dns"))]
use netring::correlate::{KeyIndexed, TimeBucketedCounter};
#[cfg(all(feature = "tokio", feature = "dns"))]
use netring::flow::extract::FiveTupleKey;
#[cfg(all(feature = "tokio", feature = "dns"))]
use netring::protocol::{ProtocolEvent, ProtocolMessage};

/// Per-source-IP DNS query rate. Anomaly the first time each
/// host exceeds `threshold` in the rolling window.
#[cfg(all(feature = "tokio", feature = "dns"))]
struct DnsBurstRule {
    counts: TimeBucketedCounter<IpAddr>,
    threshold: u64,
    alerted: HashSet<IpAddr>,
}

#[cfg(all(feature = "tokio", feature = "dns"))]
impl DnsBurstRule {
    fn new(threshold: u64, window: Duration) -> Self {
        Self {
            counts: TimeBucketedCounter::new(window, Duration::from_secs(1)),
            threshold,
            alerted: HashSet::new(),
        }
    }
}

#[cfg(all(feature = "tokio", feature = "dns"))]
impl AnomalyRule<FiveTupleKey> for DnsBurstRule {
    fn name(&self) -> &'static str {
        "DnsQueryBurst"
    }

    fn observe(
        &mut self,
        evt: &ProtocolEvent<FiveTupleKey>,
        emit: &mut Vec<Anomaly<FiveTupleKey>>,
    ) {
        let ProtocolEvent::Message {
            parser_kind: flowscope::parser_kinds::DNS_UDP,
            message: ProtocolMessage::Dns(DnsMessage::Query(_)),
            key,
            ts,
            ..
        } = evt
        else {
            return;
        };
        let src = key.a.ip();
        self.counts.bump(src, *ts);
        let n = self.counts.count(&src, *ts);
        if n > self.threshold && self.alerted.insert(src) {
            emit.push(
                Anomaly::new(self.name(), Severity::Warning, *ts)
                    .with_key(*key)
                    .with_observation("src_ip", src.to_string())
                    .with_metric("count", n as f64)
                    .with_metric("threshold", self.threshold as f64),
            );
        } else if n <= self.threshold / 2 {
            self.alerted.remove(&src);
        }
    }
}

/// Cross-protocol: DNS resolves a name → IP, but no subsequent
/// flow opens to that IP within `timeout`. Drains the IP-cache
/// on each sweep tick.
#[cfg(all(feature = "tokio", feature = "dns"))]
struct DnsNoConnectionRule {
    pending: KeyIndexed<IpAddr, (String, Timestamp)>,
    timeout: Duration,
}

#[cfg(all(feature = "tokio", feature = "dns"))]
impl DnsNoConnectionRule {
    fn new(timeout: Duration) -> Self {
        Self {
            pending: KeyIndexed::new(timeout),
            timeout,
        }
    }
}

#[cfg(all(feature = "tokio", feature = "dns"))]
impl AnomalyRule<FiveTupleKey> for DnsNoConnectionRule {
    fn name(&self) -> &'static str {
        "DnsResolvedNoConnection"
    }

    fn observe(&mut self, evt: &ProtocolEvent<FiveTupleKey>, _: &mut Vec<Anomaly<FiveTupleKey>>) {
        match evt {
            ProtocolEvent::Message {
                parser_kind: flowscope::parser_kinds::DNS_UDP,
                message: ProtocolMessage::Dns(DnsMessage::Response(r)),
                ts,
                ..
            } => {
                let qname = r
                    .questions
                    .first()
                    .map(|q| q.name.clone())
                    .unwrap_or_default();
                for ans in &r.answers {
                    let ip = match &ans.data {
                        DnsRdata::A(v4) => IpAddr::V4(*v4),
                        DnsRdata::AAAA(v6) => IpAddr::V6(*v6),
                        _ => continue,
                    };
                    self.pending.insert(ip, (qname.clone(), *ts), *ts);
                }
            }
            ProtocolEvent::FlowStarted { key, .. } => {
                self.pending.remove(&key.b.ip());
            }
            _ => {}
        }
    }

    fn on_tick(&mut self, now: Timestamp, emit: &mut Vec<Anomaly<FiveTupleKey>>) {
        for (ip, (qname, _)) in self.pending.drain_expired(now) {
            emit.push(
                Anomaly::new(self.name(), Severity::Error, now)
                    .with_observation("qname", qname)
                    .with_observation("resolved_ip", ip.to_string())
                    .with_metric("timeout_s", self.timeout.as_secs_f64()),
            );
        }
    }
}

#[cfg(all(feature = "tokio", feature = "dns"))]
fn wall_clock_ts() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp::new(now.as_secs() as u32, now.subsec_nanos())
}

#[cfg(all(feature = "tokio", feature = "dns"))]
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

    // `NETRING_JSON=1` toggles structured one-line JSON output —
    // pipe straight into Vector / Fluentd / Loki / jq. Default is
    // the human-readable `Display` rendering on `Anomaly<K>`.
    let json_output = std::env::var_os("NETRING_JSON").is_some();
    let format: fn(&Anomaly<FiveTupleKey>) -> String = if json_output {
        |a| a.to_json_line()
    } else {
        |a| format!("{a}")
    };

    eprintln!(
        "[anomaly] watching {iface} for {seconds}s; rules: DnsBurst + DnsNoConnection ({})",
        if json_output {
            "JSON output"
        } else {
            "text output"
        }
    );

    let mut monitor = ProtocolMonitorBuilder::new()
        .interface(&iface)
        .flow()
        .dns()
        .build(FiveTuple::bidirectional())?;

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new()
        .with_rule(DnsBurstRule::new(50, Duration::from_secs(10)))
        .with_rule(DnsNoConnectionRule::new(Duration::from_secs(5)));

    eprintln!(
        "[anomaly] {} rules: {:?}",
        rules.rule_count(),
        rules.rule_names().collect::<Vec<_>>()
    );

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut sweep = tokio::time::interval(Duration::from_secs(1));
    let mut last_seen_ts = Timestamp::default();
    let mut total = 0u64;

    while Instant::now() < deadline {
        tokio::select! {
            biased;
            Some(evt) = monitor.next() => {
                let evt = evt?;
                last_seen_ts = evt.timestamp();
                for a in rules.observe(&evt) {
                    println!("{}", format(&a));
                    total += 1;
                }
            }
            _ = sweep.tick() => {
                let now = wall_clock_ts();
                let now = if last_seen_ts > now { last_seen_ts } else { now };
                for a in rules.on_tick(now) {
                    println!("{}", format(&a));
                    total += 1;
                }
            }
        }
    }

    eprintln!("[done] {total} anomalies raised");
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "dns")))]
fn main() {
    eprintln!("Build with --features tokio,dns");
}
