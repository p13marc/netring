#![allow(deprecated)]
// 0.21 H.3: this file uses the legacy ProtocolMonitor / AnomalyMonitor / AnomalyRule API; remove with the legacy types in 0.22.

//! Integration tests for the three new 0.18 anomaly detectors:
//!
//! - **DnsTunnel** (D1) — high-entropy + base64-shaped DNS labels
//! - **PortScan** (D2) — distinct dst-port cardinality per source
//! - **SynFlood** (D3) — burst flow-starts per source
//!
//! Each test:
//! 1. Defines the rule inline (mirrors `examples/anomaly/<name>.rs`).
//! 2. Synthesizes a small `Vec<ProtocolEvent<K>>` exhibiting the
//!    pattern.
//! 3. Asserts the expected alert count.
//!
//! No pcap, no kernel rings — pure synthetic streams.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "dns"
))]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use flowscope::correlate::{BurstDetector, TimeBucketedSet};
use flowscope::dns::{DnsFlags, DnsMessage, DnsQuery, DnsQuestion};
use flowscope::{FlowSide, L4Proto, Timestamp};
use netring::anomaly::{Anomaly, AnomalyMonitor, AnomalyRule, Severity};
use netring::flow::extract::FiveTupleKey;
use netring::protocol::{ProtocolEvent, ProtocolMessage};

// ── Shared helpers ──────────────────────────────────────────────

fn sock(o4: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, o4)), port)
}

fn tcp_key(src_o4: u8, src_port: u16, dst_o4: u8, dst_port: u16) -> FiveTupleKey {
    FiveTupleKey {
        a: sock(src_o4, src_port),
        b: sock(dst_o4, dst_port),
        proto: L4Proto::Tcp,
    }
}

fn flow_started_tcp(key: FiveTupleKey, ts_s: u32) -> ProtocolEvent<FiveTupleKey> {
    ProtocolEvent::FlowStarted {
        key,
        l4: Some(L4Proto::Tcp),
        ts: Timestamp::new(ts_s, 0),
    }
}

fn dns_query(src_o4: u8, ts_s: u32, qname: &str) -> ProtocolEvent<FiveTupleKey> {
    let k = FiveTupleKey {
        a: sock(src_o4, 5353),
        b: sock(1, 53),
        proto: L4Proto::Udp,
    };
    let q = DnsQuery {
        transaction_id: 0x1234,
        flags: DnsFlags(0),
        questions: vec![DnsQuestion {
            name: qname.into(),
            qtype: 1,
            qclass: 1,
        }],
        timestamp: Timestamp::new(ts_s, 0),
    };
    ProtocolEvent::Message {
        key: k,
        side: FlowSide::Initiator,
        parser_kind: flowscope::parser_kinds::DNS_UDP,
        message: ProtocolMessage::Dns(DnsMessage::Query(q)),
        ts: Timestamp::new(ts_s, 0),
    }
}

// ── D1. DnsTunnelRule ───────────────────────────────────────────

struct DnsTunnelRule {
    threshold_bits: f64,
}

impl AnomalyRule<FiveTupleKey> for DnsTunnelRule {
    fn name(&self) -> &'static str {
        "DnsTunnel"
    }
    fn observe(
        &mut self,
        evt: &ProtocolEvent<FiveTupleKey>,
        emit: &mut Vec<Anomaly<FiveTupleKey>>,
    ) {
        let ProtocolEvent::Message {
            parser_kind: "dns-udp",
            message: ProtocolMessage::Dns(DnsMessage::Query(q)),
            key,
            ts,
            ..
        } = evt
        else {
            return;
        };
        for question in &q.questions {
            for label in question.name.split('.') {
                if label.len() < 16 {
                    continue;
                }
                let h = flowscope::detect::shannon_entropy(label.as_bytes());
                if h > self.threshold_bits && flowscope::detect::is_base64ish(label) {
                    emit.push(
                        Anomaly::new(self.name(), Severity::Warning, *ts)
                            .with_key(*key)
                            .with_observation("label", label.to_string())
                            .with_metric("entropy_bits", h),
                    );
                    return;
                }
            }
        }
    }
}

#[test]
fn dns_tunnel_fires_on_high_entropy_base64_label() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new().with_rule(DnsTunnelRule {
        threshold_bits: 4.0,
    });
    // Real exfil-style label: 32 random base32-shaped bytes.
    let tunnel_label = "qm5n3z7gv4xkc2bv9w8x6r5tn4smfdpa";
    let qname = format!("{tunnel_label}.evil.example.com");
    let alarms = monitor.observe(&dns_query(7, 100, &qname));
    assert_eq!(alarms.len(), 1, "expected 1 tunnel alert");
    assert_eq!(alarms[0].kind, "DnsTunnel");
}

#[test]
fn dns_tunnel_ignores_normal_dns_queries() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new().with_rule(DnsTunnelRule {
        threshold_bits: 4.0,
    });
    for q in [
        "www.example.com",
        "api.github.com",
        "cdn.cloudflare.net",
        "_dmarc.example.com",
    ] {
        let alarms = monitor.observe(&dns_query(7, 100, q));
        assert!(
            alarms.is_empty(),
            "normal qname {q} should not fire DnsTunnel"
        );
    }
}

#[test]
fn dns_tunnel_ignores_short_labels_even_if_random() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new().with_rule(DnsTunnelRule {
        threshold_bits: 4.0,
    });
    // 8-byte random label — below MIN_LABEL_LEN.
    let alarms = monitor.observe(&dns_query(7, 100, "q5z8n3v2.example.com"));
    assert!(
        alarms.is_empty(),
        "short labels must not trigger the tunnel rule"
    );
}

// ── D2. PortScanRule ────────────────────────────────────────────

struct PortScanRule {
    by_src: TimeBucketedSet<IpAddr, u16>,
    threshold: usize,
    alerted: HashSet<IpAddr>,
}

impl AnomalyRule<FiveTupleKey> for PortScanRule {
    fn name(&self) -> &'static str {
        "PortScan"
    }
    fn observe(
        &mut self,
        evt: &ProtocolEvent<FiveTupleKey>,
        emit: &mut Vec<Anomaly<FiveTupleKey>>,
    ) {
        let ProtocolEvent::FlowStarted {
            key,
            l4: Some(L4Proto::Tcp),
            ts,
        } = evt
        else {
            return;
        };
        let src = key.a.ip();
        self.by_src.insert(src, key.b.port(), *ts);
        let distinct = self.by_src.cardinality(&src, *ts);
        if distinct > self.threshold && self.alerted.insert(src) {
            emit.push(
                Anomaly::new(self.name(), Severity::Warning, *ts)
                    .with_observation("src_ip", src.to_string())
                    .with_metric("distinct_dst_ports", distinct as f64),
            );
        }
    }
}

#[test]
fn port_scan_fires_above_threshold() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new().with_rule(PortScanRule {
        by_src: TimeBucketedSet::new(Duration::from_secs(30), Duration::from_secs(1), 256),
        threshold: 10,
        alerted: HashSet::new(),
    });
    // One attacker → 11 distinct ports on one target.
    let mut alerts = 0;
    for port in 1..=11 {
        let evt = flow_started_tcp(tcp_key(99, 40000 + port, 1, port), 100);
        alerts += monitor.observe(&evt).len();
    }
    assert_eq!(alerts, 1, "exactly one alert at the 11th distinct port");
}

#[test]
fn port_scan_ignores_repeat_connections_to_same_port() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new().with_rule(PortScanRule {
        by_src: TimeBucketedSet::new(Duration::from_secs(30), Duration::from_secs(1), 256),
        threshold: 5,
        alerted: HashSet::new(),
    });
    // Same port → cardinality stays 1.
    for src_port in 40000..40050 {
        let evt = flow_started_tcp(tcp_key(99, src_port, 1, 80), 100);
        assert!(monitor.observe(&evt).is_empty());
    }
}

#[test]
fn port_scan_ignores_udp() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new().with_rule(PortScanRule {
        by_src: TimeBucketedSet::new(Duration::from_secs(30), Duration::from_secs(1), 256),
        threshold: 5,
        alerted: HashSet::new(),
    });
    let k_udp = FiveTupleKey {
        a: sock(99, 1024),
        b: sock(1, 53),
        proto: L4Proto::Udp,
    };
    for _ in 0..100 {
        let evt = ProtocolEvent::FlowStarted {
            key: k_udp,
            l4: Some(L4Proto::Udp),
            ts: Timestamp::new(100, 0),
        };
        assert!(monitor.observe(&evt).is_empty());
    }
}

// ── D3. SynFloodRule ────────────────────────────────────────────

struct SynFloodRule {
    bursts: BurstDetector<IpAddr, ()>,
}

impl AnomalyRule<FiveTupleKey> for SynFloodRule {
    fn name(&self) -> &'static str {
        "SynFlood"
    }
    fn observe(
        &mut self,
        evt: &ProtocolEvent<FiveTupleKey>,
        emit: &mut Vec<Anomaly<FiveTupleKey>>,
    ) {
        let ProtocolEvent::FlowStarted {
            key,
            l4: Some(L4Proto::Tcp),
            ts,
        } = evt
        else {
            return;
        };
        let src = key.a.ip();
        if let Some(hit) = self.bursts.observe(&src, &(), *ts) {
            emit.push(
                Anomaly::new(self.name(), Severity::Critical, *ts)
                    .with_observation("src_ip", src.to_string())
                    .with_metric("flow_starts_in_window", hit.burst_count as f64),
            );
        }
    }
}

#[test]
fn syn_flood_fires_at_threshold() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new().with_rule(SynFloodRule {
        bursts: BurstDetector::new((), 50, Duration::from_secs(1), None),
    });
    let mut alerts = 0;
    for i in 0..50 {
        // Same-second timestamp; varying dst port to keep keys distinct.
        let evt = flow_started_tcp(tcp_key(99, 40000 + i, 1, 80 + (i % 10)), 100);
        alerts += monitor.observe(&evt).len();
    }
    assert_eq!(alerts, 1, "burst threshold of 50 fires exactly once");
}

#[test]
fn syn_flood_does_not_fire_below_threshold() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new().with_rule(SynFloodRule {
        bursts: BurstDetector::new((), 1000, Duration::from_secs(1), None),
    });
    for i in 0..500 {
        let evt = flow_started_tcp(tcp_key(99, 40000 + i, 1, 80), 100);
        assert!(monitor.observe(&evt).is_empty());
    }
}

#[test]
fn syn_flood_isolates_per_source() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new().with_rule(SynFloodRule {
        bursts: BurstDetector::new((), 10, Duration::from_secs(1), None),
    });
    // 5 from src=99, 10 from src=88 — only src=88 should fire.
    let mut alerts = 0;
    for i in 0..5 {
        let evt = flow_started_tcp(tcp_key(99, 40000 + i, 1, 80), 100);
        alerts += monitor.observe(&evt).len();
    }
    for i in 0..10 {
        let evt = flow_started_tcp(tcp_key(88, 40000 + i, 1, 80), 100);
        alerts += monitor.observe(&evt).len();
    }
    assert_eq!(alerts, 1);
}
