#![allow(deprecated)]
// 0.21 H.3: this file uses the legacy ProtocolMonitor / AnomalyMonitor / AnomalyRule API; remove with the legacy types in 0.22.

//! Full L4 + L7 monitor — flow lifecycle + HTTP + DNS in one stream.
//!
//! Demonstrates [`ProtocolMonitor`] (new in netring 0.16): one
//! builder call replaces three `AsyncCapture`s + a hand-rolled
//! `tokio::select!`. The monitor orchestrates a kernel-side BPF
//! filter per enabled protocol and yields a unified
//! [`ProtocolEvent<K>`] sum-type across all of them.
//!
//! ```text
//! ProtocolMonitorBuilder::new()
//!     .interface(iface)
//!     .flow()         // ICMP/TCP/UDP lifecycle (no filter)
//!     .http()         // TCP/80,8080 → HttpParser
//!     .dns()          // UDP/53 → DnsUdpParser::with_correlation()
//!     .build(FiveTuple::bidirectional())?
//! ```
//!
//! Output is tagged so each line is greppable:
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
//! Compare against `examples/l7/multi_protocol_monitor.rs` (single
//! `flow_stream`, no L7) and `examples/anomaly/dns_*` (anomaly
//! correlators on top of single streams).
//!
//! Usage:
//!     cargo run -p netring --example full_monitor \
//!         --features tokio,http,dns -- [interface] [seconds]
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "http", feature = "dns"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    use flowscope::dns::DnsMessage;
    use flowscope::http::HttpMessage;
    use futures::StreamExt;
    use netring::ProtocolMonitorBuilder;
    use netring::flow::EndReason;
    use netring::flow::extract::FiveTuple;
    use netring::protocol::{ProtocolEvent, ProtocolMessage};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    eprintln!(
        "[full-monitor] watching {iface} for {seconds}s\n\
         protocols: flow + HTTP (TCP/80,8080) + DNS (UDP/53)\n"
    );

    // One builder call. Internally opens 3 AsyncCaptures with
    // distinct BPF filters and joins them via round-robin select.
    let mut monitor = ProtocolMonitorBuilder::new()
        .interface(&iface)
        .flow()
        .http()
        .dns()
        .build(FiveTuple::bidirectional())?;

    eprintln!("[full-monitor] {} sources active\n", monitor.source_count());

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut totals = Totals::default();

    while Instant::now() < deadline
        && let Some(evt) = monitor.next().await
    {
        match evt? {
            ProtocolEvent::FlowStarted { key, l4, .. } => {
                println!(
                    "[FLOW] + {tag:<5} {a} <-> {b}",
                    tag = l4_label(l4),
                    a = key.a,
                    b = key.b
                );
                totals.flow_started += 1;
            }
            ProtocolEvent::FlowEnded {
                key,
                reason,
                stats,
                l4,
                ..
            } => {
                println!(
                    "[FLOW] - {tag:<5} {a} <-> {b}  {reason:?} pkts={p}",
                    tag = l4_label(l4),
                    a = key.a,
                    b = key.b,
                    p = stats.total_packets(),
                );
                totals.flow_ended += 1;
                if matches!(reason, EndReason::Rst) {
                    totals.flow_rst += 1;
                }
            }
            ProtocolEvent::FlowEstablished { .. }
            | ProtocolEvent::FlowPacket { .. }
            | ProtocolEvent::FlowTick { .. }
            | ProtocolEvent::FlowAnomaly { .. }
            | ProtocolEvent::TrackerAnomaly { .. }
            | ProtocolEvent::ParserClosed { .. } => {} // skipped
            ProtocolEvent::Message {
                message: ProtocolMessage::Http(http),
                ..
            } => match http {
                HttpMessage::Request(req) => {
                    totals.http_req += 1;
                    println!(
                        "[HTTP] →  {method} {path} {ver:?}",
                        method = String::from_utf8_lossy(&req.method),
                        path = String::from_utf8_lossy(&req.path),
                        ver = req.version
                    );
                }
                HttpMessage::Response(resp) => {
                    totals.http_resp += 1;
                    println!(
                        "[HTTP] ←  {status} {reason}  {len} bytes",
                        status = resp.status,
                        reason = String::from_utf8_lossy(&resp.reason),
                        len = resp.body.len()
                    );
                }
            },
            ProtocolEvent::Message {
                message: ProtocolMessage::Dns(dns),
                ..
            } => match dns {
                DnsMessage::Query(q) => {
                    totals.dns_query += 1;
                    let qname = q.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
                    println!(
                        "[DNS ] ?  {qname} (txid=0x{txid:04x})",
                        txid = q.transaction_id
                    );
                }
                DnsMessage::Response(r) => {
                    totals.dns_resp += 1;
                    let qname = r.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
                    let rtt = r
                        .elapsed
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
                    let qname = q.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
                    println!(
                        "[DNS ] ⏱  {qname} UNANSWERED (txid=0x{txid:04x})",
                        txid = q.transaction_id
                    );
                }
                _ => {}
            },
            ProtocolEvent::Message { .. } => {}
            _ => {} // `ProtocolEvent` is `#[non_exhaustive]` for future variants
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
fn l4_label(l4: Option<netring::flow::L4Proto>) -> String {
    // `L4Proto: Display` since flowscope 0.7 (plan 77). Renders the
    // metric-vocabulary token directly — `"tcp"`, `"udp"`, …
    l4.map(|p| p.to_string()).unwrap_or_else(|| "?".into())
}

#[cfg(not(all(feature = "tokio", feature = "http", feature = "dns")))]
fn main() {
    eprintln!("Build with --features tokio,http,dns");
}
