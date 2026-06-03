//! Demultiplex ICMP / TCP / UDP from a single `flow_stream`.
//!
//! Real-life pattern: one `AsyncCapture` feeds one `FlowStream`,
//! and the consumer routes each event by L4 protocol. No L7
//! parsing here — that's `http_session`, `dns_lookups`, and
//! `full_monitor`. This example shows how to get a clean
//! per-protocol overview of an interface in ~80 lines.
//!
//! Output looks like:
//!
//! ```text
//! [ICMP ] + 10.0.0.1     <-> 10.0.0.2
//! [TCP  ] + 10.0.0.5:54321 <-> 10.0.0.10:443
//! [HTTP] (port hint)  10.0.0.5:54322 <-> 10.0.0.10:80
//! [UDP  ] + 10.0.0.5:53210 <-> 8.8.8.8:53        (DNS port)
//! [TCP  ] - 10.0.0.5:54321 <-> 10.0.0.10:443  Fin pkts=42
//! ```
//!
//! Usage:
//!     cargo run -p netring --example multi_protocol_monitor \
//!         --features tokio,flow,parse -- [interface] [seconds]
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "flow"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use futures::StreamExt;
    use netring::AsyncCapture;
    use netring::flow::extract::FiveTuple;
    use netring::flow::{EndReason, FlowEvent};
    use std::time::{Duration, Instant};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);

    eprintln!("[multi-proto] watching {iface} for {seconds}s (ICMP / TCP / UDP)");

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap.flow_stream(FiveTuple::bidirectional());

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut stats_icmp: (u64, u64) = (0, 0); // (started, ended)
    let mut stats_tcp: (u64, u64) = (0, 0);
    let mut stats_udp: (u64, u64) = (0, 0);

    while Instant::now() < deadline
        && let Some(evt) = stream.next().await
    {
        match evt? {
            FlowEvent::Started { key, l4, .. } => {
                let (tag, port_hint) = describe(&key, l4);
                println!("[{tag:<5}] + {a} <-> {b}{port_hint}", a = key.a, b = key.b);
                bump_started(l4, &mut stats_icmp, &mut stats_tcp, &mut stats_udp);
            }
            FlowEvent::Ended {
                key,
                reason,
                stats,
                l4,
                ..
            } => {
                let (tag, _) = describe(&key, l4);
                println!(
                    "[{tag:<5}] - {a} <-> {b}  {reason:?} pkts={p}",
                    a = key.a,
                    b = key.b,
                    p = stats.packets_initiator + stats.packets_responder,
                );
                if matches!(reason, EndReason::Rst | EndReason::BufferOverflow) {
                    eprintln!("  (note: aborted flow — {reason:?})");
                }
                bump_ended(l4, &mut stats_icmp, &mut stats_tcp, &mut stats_udp);
            }
            // FlowEvent::Packet, Established, StateChange, Anomaly — skipped
            // for this overview. Plug them in for richer monitoring.
            _ => {}
        }
    }

    eprintln!(
        "[done] ICMP: {}/{}, TCP: {}/{}, UDP: {}/{}  (started/ended)",
        stats_icmp.0, stats_icmp.1, stats_tcp.0, stats_tcp.1, stats_udp.0, stats_udp.1
    );
    Ok(())
}

/// Map `(key, l4)` to a short tag plus an optional port-hint suffix
/// for protocols that commonly use a well-known port.
#[cfg(all(feature = "tokio", feature = "flow"))]
fn describe(
    key: &netring::flow::extract::FiveTupleKey,
    l4: Option<netring::flow::L4Proto>,
) -> (&'static str, String) {
    use netring::flow::L4Proto;
    match l4 {
        Some(L4Proto::Icmp) | Some(L4Proto::IcmpV6) => ("ICMP", String::new()),
        Some(L4Proto::Tcp) => {
            let hint = if key.either_port(80) || key.either_port(8080) {
                "  (HTTP port)"
            } else if key.either_port(443) {
                "  (TLS port)"
            } else if key.either_port(22) {
                "  (SSH port)"
            } else {
                ""
            };
            ("TCP", hint.to_string())
        }
        Some(L4Proto::Udp) => {
            let hint = if key.either_port(53) {
                "  (DNS port)"
            } else if key.either_port(123) {
                "  (NTP port)"
            } else if key.either_port(443) {
                "  (QUIC port)"
            } else {
                ""
            };
            ("UDP", hint.to_string())
        }
        Some(other) => {
            // Other L4 (GRE, SCTP, ESP, …) — flowscope's L4Proto covers them.
            let _ = other;
            ("L4", String::new())
        }
        None => ("?", String::new()),
    }
}

#[cfg(all(feature = "tokio", feature = "flow"))]
fn bump_started(
    l4: Option<netring::flow::L4Proto>,
    icmp: &mut (u64, u64),
    tcp: &mut (u64, u64),
    udp: &mut (u64, u64),
) {
    use netring::flow::L4Proto;
    match l4 {
        Some(L4Proto::Icmp) | Some(L4Proto::IcmpV6) => icmp.0 += 1,
        Some(L4Proto::Tcp) => tcp.0 += 1,
        Some(L4Proto::Udp) => udp.0 += 1,
        _ => {}
    }
}

#[cfg(all(feature = "tokio", feature = "flow"))]
fn bump_ended(
    l4: Option<netring::flow::L4Proto>,
    icmp: &mut (u64, u64),
    tcp: &mut (u64, u64),
    udp: &mut (u64, u64),
) {
    use netring::flow::L4Proto;
    match l4 {
        Some(L4Proto::Icmp) | Some(L4Proto::IcmpV6) => icmp.1 += 1,
        Some(L4Proto::Tcp) => tcp.1 += 1,
        Some(L4Proto::Udp) => udp.1 += 1,
        _ => {}
    }
}

#[cfg(not(all(feature = "tokio", feature = "flow")))]
fn main() {
    eprintln!("Build with --features tokio,flow");
}
