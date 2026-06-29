//! Anomaly: source IP issued >N DNS queries in a sliding window.
//!
//! Classic rate-anomaly detector — a single host doing hundreds of
//! DNS queries per second is a bot, DNS-exfiltration tunnel, or a
//! misconfigured service. This example uses the `TimeBucketedCounter`
//! primitive from `netring::correlate` to track per-source-IP query
//! rates and emit an anomaly the first time each host crosses a
//! threshold.
//!
//! Architecture:
//!
//! ```text
//! AsyncCapture (BPF: UDP/53)
//!       │
//!       ▼
//! .flow_stream(...)
//! .datagram_stream(DnsUdpParser::new())
//!       │
//!       ▼  for each Application(DnsMessage::Query)
//! TimeBucketedCounter<IpAddr>::bump(src_ip, ts)
//!       │
//!       ▼  count > threshold && first time
//! emit ANOMALY
//! ```
//!
//! Usage:
//!     cargo run -p netring --example dns_query_burst \
//!         --features tokio,dns -- [interface] [seconds] [threshold]
//!
//! Defaults: lo, 60s, 50 queries / 10s window.
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "dns"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashSet;
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    use flowscope::dns::{DnsMessage, DnsUdpParser};
    use futures::StreamExt;
    use netring::correlate::TimeBucketedCounter;
    use netring::flow::SessionEvent;
    use netring::flow::extract::FiveTuple;
    use netring::{AsyncCapture, BpfFilter};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let threshold: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    eprintln!(
        "[dns-burst] watching {iface} for {seconds}s; \
         alert if any source IP issues >{threshold} DNS queries in 10s"
    );

    let filter = BpfFilter::builder().udp().port(53).build()?;
    let cap = AsyncCapture::open_with_filter(&iface, filter)?;
    let mut stream = cap
        .flow_stream(FiveTuple::bidirectional())
        .datagram_stream(DnsUdpParser::new());

    // The anomaly primitive: 10-second window in 1-second buckets.
    let mut burst = TimeBucketedCounter::<IpAddr>::new_unbounded(
        Duration::from_secs(10),
        Duration::from_secs(1),
    );

    // Avoid spamming the same host's alert every query above threshold.
    // Re-arm once the host falls back below the threshold for a tick.
    let mut alerted: HashSet<IpAddr> = HashSet::new();

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut total_queries: u64 = 0;
    let mut total_anomalies: u64 = 0;

    while Instant::now() < deadline
        && let Some(evt) = stream.next().await
    {
        let SessionEvent::Application {
            key, message, ts, ..
        } = evt?
        else {
            continue;
        };
        let DnsMessage::Query(_) = message else {
            continue;
        };

        total_queries += 1;
        let src_ip = key.a.ip();
        burst.bump(src_ip, ts);

        let count = burst.count(&src_ip, ts);
        if count > threshold && alerted.insert(src_ip) {
            total_anomalies += 1;
            println!(
                "! ANOMALY DnsQueryBurst src={src_ip} \
                 count={count} over 10s window (threshold={threshold}) ts={ts}",
            );
        } else if count <= threshold / 2 {
            // Re-arm: host cooled off, allow a fresh alert later.
            alerted.remove(&src_ip);
        }
    }

    eprintln!("[done] {total_queries} DNS queries observed; {total_anomalies} anomalies raised",);
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "dns")))]
fn main() {
    eprintln!("Build with --features tokio,dns");
}
