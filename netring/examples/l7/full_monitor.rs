//! Full L4 + L7 monitor — all at once.
//!
//! Three concurrent async streams over the same interface, joined
//! with `tokio::select!`:
//!
//! 1. **Flow tracker** (`flow_stream`) — every TCP / UDP / ICMP flow,
//!    lifecycle events with per-protocol summary.
//! 2. **HTTP session** (`session_stream<HttpParser>`, BPF-filtered to
//!    TCP/80 + TCP/8080) — request/response pairs.
//! 3. **DNS** (`datagram_stream<DnsUdpParser::with_correlation()>`,
//!    BPF-filtered to UDP/53) — queries, responses with RTT,
//!    unanswered queries via `on_tick`.
//!
//! Each stream runs on its own `AsyncCapture` with its own BPF
//! filter, so the kernel side only delivers the packets each
//! stream actually cares about. On a busy interface this typically
//! drops CPU by an order of magnitude vs filter-in-userspace.
//!
//! Output is tagged so you can `grep` for one protocol:
//!
//! ```text
//! [FLOW] + TCP   10.0.0.5:54321 <-> 10.0.0.10:80
//! [HTTP] →  GET / HTTP/1.1
//! [HTTP] ←  200 OK 1284 bytes
//! [FLOW] - TCP   10.0.0.5:54321 <-> 10.0.0.10:80  Fin pkts=12
//! [DNS ] ?  example.com (txid=0x1234)
//! [DNS ] ←  example.com → 93.184.216.34 in 2.3ms
//! [FLOW] + ICMP  10.0.0.1 <-> 10.0.0.2
//! ```
//!
//! Usage:
//!     cargo run -p netring --example full_monitor \
//!         --features tokio,http,dns -- [interface] [seconds]
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.
//!
//! ## Scaling note
//!
//! Three captures = three kernel rings = ~3× memory. That's fine
//! for the demo. For higher-throughput production use cases,
//! consider running all three streams off a single `AsyncCapture`
//! and dispatching in user-space — or, better, use
//! `AsyncMultiCapture::open_workers` to fan out across CPU cores
//! and run this monitor per worker.

#[cfg(all(feature = "tokio", feature = "http", feature = "dns"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    use flowscope::SessionEvent;
    use flowscope::dns::{DnsMessage, DnsUdpParser};
    use flowscope::http::{HttpMessage, HttpParser};
    use futures::StreamExt;
    use netring::flow::extract::{FiveTuple, FiveTupleKey};
    use netring::flow::{EndReason, FlowEvent, L4Proto};
    use netring::{AsyncCapture, BpfFilter};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    // ── Flow stream — every ICMP/TCP/UDP flow (no L7) ───────────
    let cap_flow = AsyncCapture::open(&iface)?;
    let mut flow = cap_flow.flow_stream(FiveTuple::bidirectional());

    // ── HTTP stream — TCP/80 + TCP/8080 only ────────────────────
    let http_filter = BpfFilter::builder()
        .tcp()
        .dst_port(80)
        .or(|b| b.tcp().src_port(80))
        .or(|b| b.tcp().dst_port(8080))
        .or(|b| b.tcp().src_port(8080))
        .build()?;
    let cap_http = AsyncCapture::open_with_filter(&iface, http_filter)?;
    let mut http = cap_http
        .flow_stream(FiveTuple::bidirectional())
        .session_stream(HttpParser::default());

    // ── DNS stream — UDP/53 only ────────────────────────────────
    let dns_filter = BpfFilter::builder()
        .udp()
        .dst_port(53)
        .or(|b| b.udp().src_port(53))
        .build()?;
    let cap_dns = AsyncCapture::open_with_filter(&iface, dns_filter)?;
    let mut dns = cap_dns
        .flow_stream(FiveTuple::bidirectional())
        .datagram_stream(DnsUdpParser::with_correlation());

    eprintln!(
        "[full-monitor] watching {iface} for {seconds}s\n\
         streams: flow (all L4)  +  HTTP (TCP/80,8080)  +  DNS (UDP/53)\n"
    );

    // FlowEvent::Ended doesn't carry l4; remember it from Started.
    let mut l4_by_key: HashMap<FiveTupleKey, L4Proto> = HashMap::new();

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut totals = Totals::default();

    while Instant::now() < deadline {
        tokio::select! {
            biased;  // give flow events priority so lifecycle prints first

            evt = flow.next() => match evt {
                Some(Ok(FlowEvent::Started { key, l4, .. })) => {
                    if let Some(p) = l4 { l4_by_key.insert(key, p); }
                    println!(
                        "[FLOW] + {tag:<5} {a} <-> {b}",
                        tag = l4_tag(l4),
                        a = key.a,
                        b = key.b
                    );
                    totals.flow_started += 1;
                }
                Some(Ok(FlowEvent::Ended { key, reason, stats, .. })) => {
                    let l4 = l4_by_key.remove(&key);
                    println!(
                        "[FLOW] - {tag:<5} {a} <-> {b}  {reason:?} pkts={p}",
                        tag = l4_tag(l4),
                        a = key.a,
                        b = key.b,
                        p = stats.packets_initiator + stats.packets_responder,
                    );
                    totals.flow_ended += 1;
                    if matches!(reason, EndReason::Rst) {
                        totals.flow_rst += 1;
                    }
                }
                Some(Ok(_)) => {}  // Packet/Established/StateChange/Anomaly: skip
                Some(Err(e)) => { eprintln!("[FLOW] err: {e}"); break; }
                None => break,
            },

            evt = http.next() => match evt {
                Some(Ok(SessionEvent::Application { message, .. })) => match message {
                    HttpMessage::Request(req) => {
                        totals.http_req += 1;
                        println!(
                            "[HTTP] →  {method} {path} {ver:?}",
                            method = req.method,
                            path = req.path,
                            ver = req.version
                        );
                    }
                    HttpMessage::Response(resp) => {
                        totals.http_resp += 1;
                        println!(
                            "[HTTP] ←  {status} {reason}  {len} bytes",
                            status = resp.status,
                            reason = resp.reason,
                            len = resp.body.len()
                        );
                    }
                },
                Some(Ok(_)) => {}
                Some(Err(e)) => { eprintln!("[HTTP] err: {e}"); break; }
                None => break,
            },

            evt = dns.next() => match evt {
                Some(Ok(SessionEvent::Application { message, .. })) => match message {
                    DnsMessage::Query(q) => {
                        totals.dns_query += 1;
                        let qname = q.questions.first()
                            .map(|q| q.name.as_str()).unwrap_or("?");
                        println!(
                            "[DNS ] ?  {qname} (txid=0x{txid:04x})",
                            txid = q.transaction_id
                        );
                    }
                    DnsMessage::Response(r) => {
                        totals.dns_resp += 1;
                        let qname = r.questions.first()
                            .map(|q| q.name.as_str()).unwrap_or("?");
                        let rtt = r.elapsed
                            .map(|d| format!("{:.1}ms", d.as_secs_f64() * 1000.0))
                            .unwrap_or_else(|| "?".into());
                        println!(
                            "[DNS ] ←  {qname} rcode={rcode:?} ans={n} in {rtt}",
                            rcode = r.rcode,
                            n = r.answers.len()
                        );
                    }
                    DnsMessage::Unanswered(q) => {
                        totals.dns_unanswered += 1;
                        let qname = q.questions.first()
                            .map(|q| q.name.as_str()).unwrap_or("?");
                        println!(
                            "[DNS ] ⏱  {qname} UNANSWERED (txid=0x{txid:04x})",
                            txid = q.transaction_id
                        );
                    }
                    _ => {}
                },
                Some(Ok(_)) => {}
                Some(Err(e)) => { eprintln!("[DNS ] err: {e}"); break; }
                None => break,
            },
        }
    }

    eprintln!(
        "\n[done] flows started/ended/rst = {}/{}/{} | http req/resp = {}/{} | \
         dns query/resp/unanswered = {}/{}/{}",
        totals.flow_started,
        totals.flow_ended,
        totals.flow_rst,
        totals.http_req,
        totals.http_resp,
        totals.dns_query,
        totals.dns_resp,
        totals.dns_unanswered,
    );
    Ok(())
}

#[cfg(all(feature = "tokio", feature = "http", feature = "dns"))]
#[derive(Default)]
struct Totals {
    flow_started: u64,
    flow_ended: u64,
    flow_rst: u64,
    http_req: u64,
    http_resp: u64,
    dns_query: u64,
    dns_resp: u64,
    dns_unanswered: u64,
}

#[cfg(all(feature = "tokio", feature = "http", feature = "dns"))]
fn l4_tag(l4: Option<netring::flow::L4Proto>) -> &'static str {
    use netring::flow::L4Proto;
    match l4 {
        Some(L4Proto::Tcp) => "TCP",
        Some(L4Proto::Udp) => "UDP",
        Some(L4Proto::Icmp) => "ICMP",
        Some(L4Proto::IcmpV6) => "ICMP6",
        Some(L4Proto::Sctp) => "SCTP",
        Some(L4Proto::Other(_)) => "L4?",
        None => "?",
    }
}

#[cfg(not(all(feature = "tokio", feature = "http", feature = "dns")))]
fn main() {
    eprintln!("Build with --features tokio,http,dns");
}
