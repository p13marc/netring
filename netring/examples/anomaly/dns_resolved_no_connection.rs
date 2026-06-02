//! Anomaly: DNS resolved successfully but no subsequent TCP/UDP
//! connection to the answer IP within a timeout.
//!
//! Classic cross-protocol correlator. Catches:
//!
//! - Stale DNS cache returning IPs that aren't actually used.
//! - DNS-tunnel exfiltration patterns (lots of A queries, no
//!   matching outbound TCP/UDP).
//! - Misconfigured services querying names they don't connect to.
//! - DPI middleboxes silently dropping connections after DNS
//!   completes.
//!
//! Architecture:
//!
//! ```text
//! Capture A — UDP/53 (DNS)
//!       │
//!       ▼  DnsMessage::Response(r) — for each A/AAAA answer:
//! KeyIndexed<IpAddr, (qname, query_ts)>::insert(ip, ..., now)
//!
//! Capture B — any TCP/UDP
//!       │
//!       ▼  Flow::Started → look up dest IP in cache
//! cache.remove(dst_ip) → "fulfilled" (print latency)
//!
//! Periodic sweep (every 1s)
//!       │
//!       ▼  cache.drain_expired(now) → unfulfilled entries
//! emit ANOMALY for each drained (ip, qname) pair
//! ```
//!
//! Demonstrates both `netring::correlate` primitives interlocking
//! across two `AsyncCapture` streams + `tokio::select!`.
//!
//! Usage:
//!     cargo run -p netring --example dns_resolved_no_connection \
//!         --features tokio,dns -- [interface] [seconds] [timeout_s]
//!
//! Defaults: lo, 60s, 5s timeout (DNS-to-connection window).
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "dns"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    use flowscope::SessionEvent;
    use flowscope::dns::{DnsMessage, DnsRdata, DnsUdpParser};
    use flowscope::{FlowEvent, Timestamp};
    use futures::StreamExt;
    use netring::correlate::KeyIndexed;
    use netring::flow::extract::FiveTuple;
    use netring::{AsyncCapture, BpfFilter};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let timeout_s: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let timeout = Duration::from_secs(timeout_s);

    eprintln!(
        "[dns-no-conn] watching {iface} for {seconds}s; \
         alert if DNS resolution not followed by TCP/UDP within {timeout_s}s"
    );

    // Stream 1: DNS observations.
    let dns_filter = BpfFilter::builder().udp().port(53).build()?;
    let cap_dns = AsyncCapture::open_with_filter(&iface, dns_filter)?;
    let mut dns = cap_dns
        .flow_stream(FiveTuple::bidirectional())
        .datagram_stream(DnsUdpParser::new());

    // Stream 2: TCP/UDP flow lifecycle (everything except UDP/53 to
    // avoid double-counting DNS itself).
    let flow_filter = BpfFilter::builder()
        .tcp()
        .or(|b| b.udp().port(53).negate().udp())
        .build()?;
    let cap_flow = AsyncCapture::open_with_filter(&iface, flow_filter)?;
    let mut flow = cap_flow.flow_stream(FiveTuple::bidirectional());

    // The correlation primitive: IP → (qname, query_ts) with timeout TTL.
    // Entries that age out without being removed via `.remove(ip)` are
    // anomalies — DNS resolved but nothing connected.
    let mut pending = KeyIndexed::<IpAddr, (String, Timestamp)>::new(timeout);

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut sweep_tick = tokio::time::interval(Duration::from_secs(1));

    let mut total_resolutions = 0u64;
    let mut total_fulfilled = 0u64;
    let mut total_anomalies = 0u64;

    while Instant::now() < deadline {
        tokio::select! {
            biased;

            // DNS responses → populate the pending map.
            evt = dns.next() => match evt {
                Some(Ok(SessionEvent::Application { message: DnsMessage::Response(r), ts, .. })) => {
                    let qname = r.questions.first().map(|q| q.name.clone()).unwrap_or_default();
                    for ans in &r.answers {
                        let ip = match &ans.data {
                            DnsRdata::A(v4) => IpAddr::V4(*v4),
                            DnsRdata::AAAA(v6) => IpAddr::V6(*v6),
                            _ => continue,  // skip CNAME/MX/TXT — they aren't connection targets
                        };
                        pending.insert(ip, (qname.clone(), ts), ts);
                        total_resolutions += 1;
                    }
                }
                Some(Ok(_)) => {}  // Query / Unanswered / Started / Closed: skip
                Some(Err(e)) => { eprintln!("[dns] err: {e}"); break; }
                None => break,
            },

            // TCP/UDP flow starts → check if destination IP was just resolved.
            evt = flow.next() => match evt {
                Some(Ok(FlowEvent::Started { key, ts, .. })) => {
                    let dst = key.b.ip();
                    if let Some((qname, query_ts)) = pending.remove(&dst) {
                        let latency = ts.saturating_sub(query_ts);
                        println!(
                            "[OK ] {qname} → {dst} (flow started {latency:?} after DNS)"
                        );
                        total_fulfilled += 1;
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => { eprintln!("[flow] err: {e}"); break; }
                None => break,
            },

            // Periodic sweep → drain expired entries as anomalies.
            _ = sweep_tick.tick() => {
                let now = Timestamp::new(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or(Duration::ZERO)
                        .as_secs() as u32,
                    0,
                );
                for (ip, (qname, query_ts)) in pending.drain_expired(now) {
                    let age = now.saturating_sub(query_ts);
                    println!(
                        "! ANOMALY DnsResolvedNoConnection name={qname} ip={ip} \
                         age={age:?} (no connection within {timeout:?})"
                    );
                    total_anomalies += 1;
                }
            }
        }
    }

    eprintln!(
        "[done] {total_resolutions} A/AAAA answers cached, \
         {total_fulfilled} followed by a connection, \
         {total_anomalies} raised as anomalies"
    );
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "dns")))]
fn main() {
    eprintln!("Build with --features tokio,dns");
}
