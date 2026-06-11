//! Smoke tests for the [`AnomalyMonitor`] + [`AnomalyRule`] harness.
//!
//! Build a synthetic `ProtocolEvent` stream and drive the same rule
//! shapes the reference examples in `examples/anomaly/` use —
//! ensures the public surface used by users keeps working across
//! flowscope/netring version bumps.
//!
//! Run with:
//!   cargo test --features tokio,flow,parse,dns,tls --test anomaly_monitor_smoke

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "dns",
    feature = "tls"
))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use flowscope::dns::{DnsFlags, DnsMessage, DnsQuery, DnsQuestion};
use flowscope::tls::{TlsClientHello, TlsMessage, TlsVersion};
use flowscope::{FlowSide, L4Proto, Timestamp};
use netring::anomaly::{Anomaly, AnomalyMonitor, AnomalyRule, Severity};
use netring::correlate::{KeyIndexed, TimeBucketedCounter};
use netring::flow::extract::FiveTupleKey;
use netring::protocol::{ProtocolEvent, ProtocolMessage};

fn sock(ip: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
}

fn key(a: SocketAddr, b: SocketAddr) -> FiveTupleKey {
    FiveTupleKey {
        a,
        b,
        proto: L4Proto::Udp,
    }
}

fn fake_flow_started(k: FiveTupleKey, ts_s: u32) -> ProtocolEvent<FiveTupleKey> {
    ProtocolEvent::FlowStarted {
        key: k,
        l4: Some(L4Proto::Udp),
        ts: Timestamp::new(ts_s, 0),
    }
}

fn fake_dns_query(k: FiveTupleKey, ts_s: u32, qname: &str) -> ProtocolEvent<FiveTupleKey> {
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

fn fake_tls_client_hello(k: FiveTupleKey, ts_s: u32) -> ProtocolEvent<FiveTupleKey> {
    // flowscope 0.13 made `TlsClientHello` `#[non_exhaustive]` (plan 144 — ECH).
    // Default initializer + selective field overrides so future field additions
    // don't break this fixture.
    let mut ch = TlsClientHello::default();
    ch.record_version = TlsVersion::Tls1_0;
    ch.legacy_version = TlsVersion::Tls1_2;
    ch.random = [0u8; 32];
    ch.sni = Some("example.com".into());
    ProtocolEvent::Message {
        key: k,
        side: FlowSide::Initiator,
        parser_kind: flowscope::parser_kinds::TLS,
        message: ProtocolMessage::Tls(TlsMessage::ClientHello(Box::new(ch))),
        ts: Timestamp::new(ts_s, 0),
    }
}

// ── DnsBurstRule (mirror of examples/anomaly/anomaly_monitor_demo.rs) ──

struct DnsBurstRule {
    counts: TimeBucketedCounter<IpAddr>,
    threshold: u64,
}

impl DnsBurstRule {
    fn new(threshold: u64, window: Duration) -> Self {
        Self {
            counts: TimeBucketedCounter::new(window, Duration::from_secs(1)),
            threshold,
        }
    }
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
        if n > self.threshold {
            emit.push(
                Anomaly::new(self.name(), Severity::Warning, *ts)
                    .with_observation("src_ip", src.to_string())
                    .with_metric("count", n as f64),
            );
        }
    }
}

#[test]
fn dns_burst_rule_fires_above_threshold() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new()
        .with_rule(DnsBurstRule::new(2, Duration::from_secs(10)));
    let k = key(sock([10, 0, 0, 1], 5353), sock([8, 8, 8, 8], 53));
    // First two queries: below threshold (n=1, n=2; threshold is 2, so > 2 means n=3 fires).
    assert!(monitor.observe(&fake_dns_query(k, 1, "a.test")).is_empty());
    assert!(monitor.observe(&fake_dns_query(k, 1, "b.test")).is_empty());
    // Third query — count=3 > threshold=2 → fires.
    let alarms = monitor.observe(&fake_dns_query(k, 1, "c.test"));
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].kind, "DnsQueryBurst");
    assert_eq!(alarms[0].severity, Severity::Warning);
}

#[test]
fn dns_burst_rule_ignores_non_dns_events() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new()
        .with_rule(DnsBurstRule::new(1, Duration::from_secs(10)));
    let k = key(sock([10, 0, 0, 1], 1234), sock([10, 0, 0, 2], 80));
    // Even 100 flow-started events shouldn't trip a DNS rule.
    for _ in 0..100 {
        assert!(monitor.observe(&fake_flow_started(k, 1)).is_empty());
    }
}

// ── SlowTlsHandshakeRule (mirror of examples/anomaly/slow_tls_handshake.rs) ──

struct SlowTlsHandshakeRule {
    pending: KeyIndexed<FiveTupleKey, Timestamp>,
    threshold: Duration,
}

impl SlowTlsHandshakeRule {
    fn new(threshold: Duration) -> Self {
        Self {
            pending: KeyIndexed::new(threshold),
            threshold,
        }
    }
}

impl AnomalyRule<FiveTupleKey> for SlowTlsHandshakeRule {
    fn name(&self) -> &'static str {
        "SlowTlsHandshake"
    }
    fn observe(&mut self, evt: &ProtocolEvent<FiveTupleKey>, _: &mut Vec<Anomaly<FiveTupleKey>>) {
        let ProtocolEvent::Message {
            parser_kind: flowscope::parser_kinds::TLS,
            message: ProtocolMessage::Tls(TlsMessage::ClientHello(_)),
            key,
            ts,
            ..
        } = evt
        else {
            return;
        };
        self.pending.insert(*key, *ts, *ts);
    }
    fn on_tick(&mut self, now: Timestamp, emit: &mut Vec<Anomaly<FiveTupleKey>>) {
        for (key, client_ts) in self.pending.drain_expired(now) {
            let waited = now.saturating_sub(client_ts);
            emit.push(
                Anomaly::new(self.name(), Severity::Warning, now)
                    .with_key(key)
                    .with_metric("waited_ms", waited.as_secs_f64() * 1000.0)
                    .with_metric("threshold_ms", self.threshold.as_secs_f64() * 1000.0),
            );
        }
    }
}

#[test]
fn slow_tls_rule_drain_expired_emits_anomaly() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new()
        .with_rule(SlowTlsHandshakeRule::new(Duration::from_secs(1)));
    let k = key(sock([10, 0, 0, 1], 55555), sock([93, 184, 216, 34], 443));
    // ClientHello at t=10; no ServerHello.
    assert!(monitor.observe(&fake_tls_client_hello(k, 10)).is_empty());
    // Within TTL: drain finds nothing.
    assert!(monitor.on_tick(Timestamp::new(10, 0)).is_empty());
    // Past TTL: drain returns the unfulfilled ClientHello.
    let alarms = monitor.on_tick(Timestamp::new(12, 0));
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].kind, "SlowTlsHandshake");
    assert_eq!(alarms[0].key, Some(k));
}

// ── Multi-rule monitor + scratch isolation ──

#[test]
fn monitor_with_multiple_rules_fans_out() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new()
        .with_rule(DnsBurstRule::new(0, Duration::from_secs(10))) // fires immediately
        .with_rule(SlowTlsHandshakeRule::new(Duration::from_secs(1)));
    assert_eq!(monitor.rule_count(), 2);
    let k = key(sock([10, 0, 0, 1], 5353), sock([8, 8, 8, 8], 53));
    let alarms = monitor.observe(&fake_dns_query(k, 1, "x.test"));
    // Only the burst rule reacts to a DNS query.
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].kind, "DnsQueryBurst");
}

#[test]
fn monitor_returns_fresh_vec_each_call() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new()
        .with_rule(DnsBurstRule::new(0, Duration::from_secs(10)));
    let k = key(sock([10, 0, 0, 1], 1), sock([10, 0, 0, 2], 53));
    let a = monitor.observe(&fake_dns_query(k, 1, "a"));
    let b = monitor.observe(&fake_dns_query(k, 1, "b"));
    // Both calls must produce independently owned Vecs — second
    // call must not drain the first.
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
}
