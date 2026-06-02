//! DNS query/response observation with RTT correlation.
//!
//! Real-life pattern: kernel-side BPF filter narrows to UDP/53,
//! `datagram_stream(DnsUdpParser::with_correlation())` parses each
//! datagram AND correlates request → response by transaction ID,
//! reporting RTT on every response. The new `on_tick` hook
//! (flowscope 0.4 / netring 0.14) emits `DnsMessage::Unanswered`
//! events for queries that timed out without a reply — useful for
//! flagging upstream-DNS issues without polling.
//!
//! Output:
//!
//! ```text
//! ?  example.com               A   (txid=0x1234)
//! ←  example.com               A   93.184.216.34   in 2.3ms
//! ?  malformed.invalid         A   (txid=0x5678)
//! ⏱  malformed.invalid         A   UNANSWERED after 5.0s
//! ```
//!
//! Usage:
//!     cargo run -p netring --example dns_lookups \
//!         --features tokio,dns -- [interface] [seconds]
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "dns"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use flowscope::SessionEvent;
    use flowscope::dns::{DnsMessage, DnsUdpParser};
    use futures::StreamExt;
    use netring::flow::extract::FiveTuple;
    use netring::{AsyncCapture, BpfFilter};
    use std::time::{Duration, Instant};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    // Kernel-side filter: UDP/53 only (src OR dst).
    let filter = BpfFilter::builder().udp().port(53).build()?;

    eprintln!(
        "[dns] watching {iface} for {seconds}s (UDP/53)\n\
         BPF filter: {} instructions",
        filter.len()
    );

    let cap = AsyncCapture::open_with_filter(&iface, filter)?;
    let mut stream = cap
        .flow_stream(FiveTuple::bidirectional())
        .datagram_stream(DnsUdpParser::with_correlation());

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut queries = 0u64;
    let mut responses = 0u64;
    let mut unanswered = 0u64;

    while Instant::now() < deadline
        && let Some(evt) = stream.next().await
    {
        match evt? {
            SessionEvent::Application { message, .. } => match message {
                DnsMessage::Query(q) => {
                    queries += 1;
                    let qname = q.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
                    println!(
                        "?  {qname:<32} (txid=0x{txid:04x})",
                        txid = q.transaction_id
                    );
                }
                DnsMessage::Response(r) => {
                    responses += 1;
                    let qname = r.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
                    let rtt = r
                        .elapsed
                        .map(|d| format!("{:.1}ms", d.as_secs_f64() * 1000.0))
                        .unwrap_or_else(|| "?".into());
                    println!(
                        "←  {qname:<32} rcode={rcode:?} answers={n} in {rtt}",
                        rcode = r.rcode,
                        n = r.answers.len(),
                    );
                }
                DnsMessage::Unanswered(q) => {
                    unanswered += 1;
                    let qname = q.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
                    println!(
                        "⏱  {qname:<32} UNANSWERED (txid=0x{txid:04x})",
                        txid = q.transaction_id
                    );
                }
                _ => {}
            },
            SessionEvent::FlowAnomaly { kind, .. } => {
                eprintln!("! flow anomaly: {kind:?}");
            }
            SessionEvent::TrackerAnomaly { kind, .. } => {
                eprintln!("! tracker anomaly: {kind:?}");
            }
            _ => {}
        }
    }

    eprintln!("[done] {queries} queries, {responses} responses, {unanswered} unanswered");
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "dns")))]
fn main() {
    eprintln!("Build with --features tokio,dns");
}
