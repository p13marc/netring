//! Replay a pcap trace through an [`AnomalyMonitor`].
//!
//! Production use case: an incident pcap is captured, a new
//! detector ships, and you want to know how many anomalies it
//! would have raised against last week's traffic *before*
//! deploying it. Same detector code as live capture; just
//! drives it from [`AsyncPcapSource`] instead of an `AsyncCapture`.
//!
//! This replays UDP/53 traffic and runs the same `DnsBurstRule`
//! that lives in `examples/anomaly/anomaly_monitor_demo.rs` —
//! one host issuing > N DNS queries in a sliding window. Extend
//! the parser + rule set to cover more protocols on top.
//!
//! Why one parser per replay: `AsyncPcapSource` consumes itself
//! on `.datagrams(...)` / `.sessions(...)`, so a single pcap
//! file → one L7 protocol stream. For multi-protocol replay,
//! open the pcap twice or write your own packet-level loop.
//!
//! Usage:
//!     cargo run -p netring --example pcap_replay_anomaly \
//!         --features tokio,flow,parse,pcap,dns -- \
//!         <pcap-file> [threshold] [window_s]
//!
//! Defaults: threshold=50, window=10s (matches the live demo).
//!
//! No privileges required — pure file I/O.

#[cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap",
    feature = "dns"
))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashSet;
    use std::env;
    use std::net::IpAddr;
    use std::time::Duration;

    use flowscope::SessionEvent;
    use flowscope::dns::{DnsMessage, DnsUdpParser};
    use futures::StreamExt;
    use netring::AsyncPcapSource;
    use netring::anomaly::{Anomaly, AnomalyMonitor, AnomalyRule, Severity};
    use netring::correlate::TimeBucketedCounter;
    use netring::flow::extract::{FiveTuple, FiveTupleKey};
    use netring::protocol::{ProtocolEvent, ProtocolMessage};

    let mut args = env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: pcap_replay_anomaly <pcap-file> [threshold] [window_s]")?;
    let threshold: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(50);
    let window_s: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(10);

    eprintln!("[replay] {path}: DnsBurstRule threshold={threshold} window={window_s}s",);

    // ── The rule (mirrors `anomaly_monitor_demo.rs`'s DnsBurstRule) ──
    struct DnsBurstRule {
        counts: TimeBucketedCounter<IpAddr>,
        threshold: u64,
        alerted: HashSet<IpAddr>,
    }

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
                kind: flowscope::parser_kinds::DNS_UDP,
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

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new().with_rule(DnsBurstRule {
        counts: TimeBucketedCounter::new(Duration::from_secs(window_s), Duration::from_secs(1)),
        threshold,
        alerted: HashSet::new(),
    });

    // ── Drive: pcap → datagram stream → ProtocolEvent → rules ──
    let source = AsyncPcapSource::open(&path).await?;
    let mut stream = source.datagrams(FiveTuple::bidirectional(), DnsUdpParser::with_correlation());

    let mut total_alerts = 0u64;
    let mut total_dns = 0u64;

    while let Some(evt) = stream.next().await {
        match evt? {
            // Re-shape the underlying `SessionEvent::Application`
            // into the same `ProtocolEvent::Message` the live
            // `ProtocolMonitor` produces. The struct fields are
            // public — no helper needed.
            SessionEvent::Application {
                key,
                side,
                message,
                ts,
                parser_kind,
            } => {
                total_dns += 1;
                let pe = ProtocolEvent::Message {
                    key,
                    side,
                    kind: parser_kind,
                    message: ProtocolMessage::Dns(message),
                    ts,
                };
                for a in rules.observe(&pe) {
                    println!("{a}");
                    total_alerts += 1;
                }
            }
            // Pcap timing is monotonic per-packet; for time-bound
            // rules (drain_expired etc.) we could synthesise an
            // on_tick from the last-seen ts. The burst rule
            // doesn't need it.
            SessionEvent::Closed { .. }
            | SessionEvent::Started { .. }
            | SessionEvent::FlowAnomaly { .. }
            | SessionEvent::TrackerAnomaly { .. } => {}
            _ => {}
        }
    }

    eprintln!(
        "[done] processed {total_dns} DNS messages, {total_alerts} anomalies raised, \
         {} packets",
        stream.packets_read()
    );
    Ok(())
}

#[cfg(not(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap",
    feature = "dns"
)))]
fn main() {
    eprintln!("Build with --features tokio,flow,parse,pcap,dns");
}
