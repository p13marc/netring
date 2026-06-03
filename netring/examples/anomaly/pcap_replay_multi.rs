//! Multi-protocol pcap replay through an [`AnomalyMonitor`].
//!
//! Sibling to `pcap_replay.rs` (which drives a single-protocol
//! detector). This one demonstrates the **multi-protocol** case
//! — a detector like
//! [`TlsToUnresolvedIpRule`](../l7/tls_to_unresolved_ip) that
//! needs DNS responses to precede TLS handshakes timestamp-wise.
//!
//! ## Why this pattern exists
//!
//! `AsyncPcapSource::sessions(...)` and `.datagrams(...)`
//! consume the source, so one source = one parser. Multi-protocol
//! replay needs either:
//!
//! 1. **A custom packet-level loop** that hand-routes each packet
//!    to multiple parsers — ~300 LoC, reimplements what
//!    [`ProtocolMonitor`](netring::protocol::ProtocolMonitor) does
//!    internally.
//!
//! 2. **Open the pcap N times** (once per protocol), collect each
//!    pass into a `Vec<(Timestamp, ProtocolEvent)>`, then merge
//!    them by timestamp before feeding to `AnomalyMonitor`.
//!    Simpler to read; loads the pcap N× from disk; OK for replay
//!    (no real-time constraint).
//!
//! This example uses **approach 2**. The merge-by-timestamp gives
//! the rules the same event order they'd see on a live wire.
//!
//! `AsyncPcapSource` consuming-on-entry is flagged in
//! [`flowscope-0.8-feedback`](../../plans/flowscope-0.8-feedback-2026-06-03.md)
//! G4 for a structural fix. Once that lands, this approach
//! collapses to a one-pass loop and the example can be retired.
//!
//! Usage:
//!     cargo run -p netring --example pcap_replay_multi \
//!         --features tokio,flow,parse,pcap,dns,tls -- <pcap> [ttl_s]
//!
//! Defaults: ttl_s=300 (matches `tls_to_unresolved_ip.rs`).
//!
//! No privileges required — pure file I/O.

#[cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap",
    feature = "dns",
    feature = "tls"
))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap;
    use std::env;
    use std::net::IpAddr;
    use std::time::Duration;

    use flowscope::SessionEvent;
    use flowscope::dns::{DnsMessage, DnsRdata, DnsUdpParser};
    use flowscope::tls::{TlsMessage, TlsParser};
    use futures::StreamExt;
    use netring::AsyncPcapSource;
    use netring::anomaly::{Anomaly, AnomalyMonitor, AnomalyRule, Severity};
    use netring::correlate::KeyIndexed;
    use netring::flow::extract::{FiveTuple, FiveTupleKey};
    use netring::protocol::{ProtocolEvent, ProtocolMessage};

    let mut args = env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: pcap_replay_multi <pcap> [ttl_s]")?;
    let ttl_s: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(300);

    eprintln!("[replay-multi] {path}: DNS + TLS streams, TTL {ttl_s}s");

    // ── Pass 1: read DNS messages from the pcap ────────────────────
    let dns_src = AsyncPcapSource::open(&path).await?;
    let mut dns_stream =
        dns_src.datagrams(FiveTuple::bidirectional(), DnsUdpParser::with_correlation());

    let mut events: Vec<ProtocolEvent<FiveTupleKey>> = Vec::new();
    while let Some(evt) = dns_stream.next().await {
        if let SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind,
        } = evt?
        {
            events.push(ProtocolEvent::Message {
                key,
                side,
                kind: parser_kind,
                message: ProtocolMessage::Dns(message),
                ts,
            });
        }
    }
    eprintln!("[pass 1] DNS: {} events collected", events.len());
    let dns_count = events.len();

    // ── Pass 2: read TLS handshake messages ────────────────────────
    let tls_src = AsyncPcapSource::open(&path).await?;
    let mut tls_stream = tls_src.sessions(FiveTuple::bidirectional(), TlsParser::default());

    while let Some(evt) = tls_stream.next().await {
        if let SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind,
        } = evt?
        {
            events.push(ProtocolEvent::Message {
                key,
                side,
                kind: parser_kind,
                message: ProtocolMessage::Tls(message),
                ts,
            });
        }
    }
    eprintln!(
        "[pass 2] TLS: {} events collected",
        events.len() - dns_count
    );

    // ── Merge by timestamp ─────────────────────────────────────────
    events.sort_by_key(|e| e.timestamp());
    eprintln!("[merge] {} events total, sorted", events.len());

    // ── Build the AnomalyMonitor + the 3-protocol rule ─────────────
    struct TlsToUnresolvedIpRule {
        resolved_by_host: HashMap<IpAddr, KeyIndexed<IpAddr, ()>>,
        ttl: Duration,
    }
    impl AnomalyRule<FiveTupleKey> for TlsToUnresolvedIpRule {
        fn name(&self) -> &'static str {
            "TlsToUnresolvedIp"
        }
        fn observe(
            &mut self,
            evt: &ProtocolEvent<FiveTupleKey>,
            emit: &mut Vec<Anomaly<FiveTupleKey>>,
        ) {
            match evt {
                ProtocolEvent::Message {
                    kind: "dns-udp",
                    message: ProtocolMessage::Dns(DnsMessage::Response(r)),
                    key,
                    ts,
                    ..
                } => {
                    let host = key.b.ip();
                    let cache = self
                        .resolved_by_host
                        .entry(host)
                        .or_insert_with(|| KeyIndexed::new(self.ttl));
                    for ans in &r.answers {
                        let ip = match &ans.data {
                            DnsRdata::A(v4) => IpAddr::V4(*v4),
                            DnsRdata::AAAA(v6) => IpAddr::V6(*v6),
                            _ => continue,
                        };
                        cache.insert(ip, (), *ts);
                    }
                }
                ProtocolEvent::Message {
                    kind: "tls",
                    message: ProtocolMessage::Tls(TlsMessage::ClientHello(ch)),
                    key,
                    ts,
                    ..
                } => {
                    let src = key.a.ip();
                    let dst = key.b.ip();
                    let resolved = self
                        .resolved_by_host
                        .get(&src)
                        .map(|c| c.contains_fresh(&dst, *ts))
                        .unwrap_or(false);
                    if !resolved {
                        let sni = ch.sni.as_deref().unwrap_or("<none>");
                        emit.push(
                            Anomaly::new(self.name(), Severity::Warning, *ts)
                                .with_key(*key)
                                .with_observation("src_ip", src.to_string())
                                .with_observation("dst_ip", dst.to_string())
                                .with_observation("sni", sni)
                                .with_observation("source", "pcap-replay"),
                        );
                    }
                }
                _ => {}
            }
        }
    }

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new().with_rule(TlsToUnresolvedIpRule {
        resolved_by_host: HashMap::new(),
        ttl: Duration::from_secs(ttl_s),
    });

    // ── Replay: feed merged stream to AnomalyMonitor ───────────────
    let mut alerts = 0u64;
    for evt in &events {
        for a in rules.observe(evt) {
            println!("{a}");
            alerts += 1;
        }
    }

    eprintln!("[done] {alerts} alerts raised");
    Ok(())
}

#[cfg(not(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap",
    feature = "dns",
    feature = "tls"
)))]
fn main() {
    eprintln!("Build with --features tokio,flow,parse,pcap,dns,tls");
}
