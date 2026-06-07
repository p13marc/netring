//! Anomaly-path benchmarks — characterize the `AnomalyMonitor`
//! + `AnomalyRule` cost at the granularity actual detectors hit.
//!
//! Why these benches exist: the 0.16 anomaly toolkit shipped
//! without perf measurement. These answer the four questions the
//! 0.18 roadmap (O6) flagged:
//!
//! 1. **Per-event overhead** with a no-op rule (what does the
//!    harness itself cost?).
//! 2. **Rule-count scaling** — linear in N? what's the constant?
//! 3. **Allocation cost** when a rule actually fires (the scratch
//!    `Vec<Anomaly<K>>` is taken on each emit).
//! 4. **JSON serialization** — `to_json_line()` cost per anomaly.
//!
//! Plus a full-pipeline `DnsBurstRule` bench that exercises the
//! `TimeBucketedCounter` primitive at observe time.
//!
//! All benches use synthesized events; no kernel rings, no
//! `CAP_NET_RAW`.
//!
//! Run:
//!     cargo bench --bench anomaly --features tokio,flow,parse,dns,tls
//!
//! Compare against `master` after a refactor:
//!     cargo bench --bench anomaly --features ... -- --save-baseline master
//!     # … make changes …
//!     cargo bench --bench anomaly --features ... -- --baseline master

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "dns",
    feature = "tls"
))]

use std::collections::HashSet;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use flowscope::dns::{DnsFlags, DnsMessage, DnsQuery, DnsQuestion};
use flowscope::{FlowSide, L4Proto, Timestamp};
use netring::anomaly::{Anomaly, AnomalyMonitor, AnomalyRule, Severity};
use netring::correlate::{KeyIndexed, TimeBucketedCounter};
use netring::flow::extract::FiveTupleKey;
use netring::protocol::{ProtocolEvent, ProtocolMessage};

// ── Helpers ──────────────────────────────────────────────────────

fn sock(o4: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, o4)), port)
}

fn make_key(o4: u8) -> FiveTupleKey {
    FiveTupleKey {
        a: sock(o4, 5353),
        b: sock(1, 53),
        proto: L4Proto::Udp,
    }
}

fn dns_query_event(o4: u8, ts: u32) -> ProtocolEvent<FiveTupleKey> {
    let q = DnsQuery {
        transaction_id: 0x1234,
        flags: DnsFlags(0),
        questions: vec![DnsQuestion {
            name: "example.com".into(),
            qtype: 1,
            qclass: 1,
        }],
        timestamp: Timestamp::new(ts, 0),
    };
    ProtocolEvent::Message {
        key: make_key(o4),
        side: FlowSide::Initiator,
        parser_kind: flowscope::parser_kinds::DNS_UDP,
        message: ProtocolMessage::Dns(DnsMessage::Query(q)),
        ts: Timestamp::new(ts, 0),
    }
}

fn flow_started_event(o4: u8, ts: u32) -> ProtocolEvent<FiveTupleKey> {
    ProtocolEvent::FlowStarted {
        key: make_key(o4),
        l4: Some(L4Proto::Udp),
        ts: Timestamp::new(ts, 0),
    }
}

// ── Rules used across benches ────────────────────────────────────

/// Cheapest possible rule: matches nothing, emits nothing.
/// Establishes the harness overhead floor.
struct NoOpRule;
impl AnomalyRule<FiveTupleKey> for NoOpRule {
    fn name(&self) -> &'static str {
        "NoOp"
    }
    fn observe(&mut self, _: &ProtocolEvent<FiveTupleKey>, _: &mut Vec<Anomaly<FiveTupleKey>>) {}
}

/// Always fires; measures the allocation cost on the hot path.
struct AlwaysFireRule;
impl AnomalyRule<FiveTupleKey> for AlwaysFireRule {
    fn name(&self) -> &'static str {
        "AlwaysFire"
    }
    fn observe(
        &mut self,
        evt: &ProtocolEvent<FiveTupleKey>,
        emit: &mut Vec<Anomaly<FiveTupleKey>>,
    ) {
        emit.push(
            Anomaly::new(self.name(), Severity::Info, evt.timestamp())
                .with_key_opt(evt.key().cloned()),
        );
    }
}

/// Per-source DNS query rate, mirroring `dns_query_burst.rs` /
/// `anomaly_monitor_demo.rs`. The realistic shape.
struct DnsBurstRule {
    counts: TimeBucketedCounter<IpAddr>,
    threshold: u64,
    alerted: HashSet<IpAddr>,
}
impl DnsBurstRule {
    fn new(threshold: u64) -> Self {
        Self {
            counts: TimeBucketedCounter::new(Duration::from_secs(10), Duration::from_secs(1)),
            threshold,
            alerted: HashSet::new(),
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
        if n > self.threshold && self.alerted.insert(src) {
            emit.push(
                Anomaly::new(self.name(), Severity::Warning, *ts)
                    .with_key(*key)
                    .with_metric("count", n as f64),
            );
        }
    }
}

// ── Benches ──────────────────────────────────────────────────────

/// **Q: What does the harness itself cost?** Single rule, never
/// fires. The cost per event is the dispatch + the rule's own
/// `observe` body, which here is empty. Establishes the floor.
fn bench_observe_no_op_rule(c: &mut Criterion) {
    let mut group = c.benchmark_group("anomaly/observe");
    group.throughput(Throughput::Elements(1));

    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new().with_rule(NoOpRule);
    let evt = dns_query_event(7, 100);

    group.bench_function("no_op_rule", |b| {
        b.iter(|| {
            let alerts = monitor.observe(black_box(&evt));
            black_box(alerts);
        })
    });
    group.finish();
}

/// **Q: Does rule count scale linearly?** N no-op rules; observe
/// the same event. Slope = per-rule dispatch cost.
fn bench_observe_n_rules(c: &mut Criterion) {
    let mut group = c.benchmark_group("anomaly/observe_n_rules");
    group.throughput(Throughput::Elements(1));

    for n in [1usize, 4, 16, 64] {
        let mut monitor = AnomalyMonitor::<FiveTupleKey>::new();
        for _ in 0..n {
            monitor.add_rule(NoOpRule);
        }
        let evt = dns_query_event(7, 100);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let alerts = monitor.observe(black_box(&evt));
                black_box(alerts);
            })
        });
    }
    group.finish();
}

/// **Q: What's the cost when a rule actually fires?** Includes
/// `Anomaly::new` + `with_key_opt` + the scratch `Vec` realloc.
fn bench_observe_always_fire(c: &mut Criterion) {
    let mut group = c.benchmark_group("anomaly/observe");
    group.throughput(Throughput::Elements(1));

    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new().with_rule(AlwaysFireRule);
    let evt = dns_query_event(7, 100);

    group.bench_function("always_fire_rule", |b| {
        b.iter(|| {
            let alerts = monitor.observe(black_box(&evt));
            black_box(alerts);
        })
    });
    group.finish();
}

/// **Q: How fast does the realistic burst rule run?** DnsBurst
/// over a stream of varying source IPs to keep the counter +
/// HashSet realistic.
fn bench_full_pipeline_dns_burst(c: &mut Criterion) {
    let mut group = c.benchmark_group("anomaly/full_pipeline");
    group.throughput(Throughput::Elements(1));

    // 256 events from 16 distinct sources, in a stable order.
    let events: Vec<_> = (0..256u32)
        .map(|i| dns_query_event((i % 16) as u8 + 1, 100 + i / 50))
        .collect();

    group.bench_function("dns_burst_threshold_50", |b| {
        b.iter(|| {
            let mut monitor =
                AnomalyMonitor::<FiveTupleKey>::new().with_rule(DnsBurstRule::new(50));
            for evt in &events {
                let alerts = monitor.observe(black_box(evt));
                black_box(alerts);
            }
        })
    });
    group.finish();
}

/// **Q: What's `KeyIndexed::drain_expired` cost at scale?** The
/// drain-on-expiry pattern is the most common `on_tick` workload.
fn bench_on_tick_drain_expired(c: &mut Criterion) {
    let mut group = c.benchmark_group("anomaly/on_tick");

    for n in [10usize, 100, 1000] {
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("drain_expired", n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let mut ki: KeyIndexed<u32, ()> = KeyIndexed::new(Duration::from_secs(5));
                    let insert_ts = Timestamp::new(100, 0);
                    for i in 0..n {
                        ki.insert(i as u32, (), insert_ts);
                    }
                    ki
                },
                |mut ki| {
                    let drained = ki.drain_expired(Timestamp::new(200, 0));
                    black_box(drained);
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// **Q: What does `to_json_line()` cost per anomaly?** Compared
/// against `Display` (for reference) to know whether JSON output
/// is a worthwhile bottleneck.
fn bench_to_json_line(c: &mut Criterion) {
    let mut group = c.benchmark_group("anomaly/render");
    group.throughput(Throughput::Elements(1));

    let a: Anomaly<FiveTupleKey> =
        Anomaly::new("DnsBurst", Severity::Warning, Timestamp::new(42, 0))
            .with_key(make_key(7))
            .with_observation("src_ip", "10.0.0.7")
            .with_metric("count", 123.4)
            .with_metric("threshold", 50.0);

    group.bench_function("display", |b| {
        b.iter(|| {
            let s = format!("{}", black_box(&a));
            black_box(s);
        })
    });

    group.bench_function("to_json_line", |b| {
        b.iter(|| {
            let s = black_box(&a).to_json_line();
            black_box(s);
        })
    });

    group.finish();
}

/// **Q: What's the `TimeBucketedCounter` bump cost?** Single key,
/// stable bucket. The most common observe-time op.
fn bench_time_bucketed_counter_bump(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlate/time_bucketed_counter");
    group.throughput(Throughput::Elements(1));

    group.bench_function("bump_same_key", |b| {
        let mut counter: TimeBucketedCounter<u32> =
            TimeBucketedCounter::new(Duration::from_secs(10), Duration::from_secs(1));
        let key = 42u32;
        let ts = Timestamp::new(100, 0);
        b.iter(|| {
            counter.bump(black_box(key), black_box(ts));
        })
    });

    group.bench_function("count_same_key", |b| {
        let mut counter: TimeBucketedCounter<u32> =
            TimeBucketedCounter::new(Duration::from_secs(10), Duration::from_secs(1));
        let key = 42u32;
        let ts = Timestamp::new(100, 0);
        for _ in 0..100 {
            counter.bump(key, ts);
        }
        b.iter(|| {
            let n = counter.count(black_box(&key), black_box(ts));
            black_box(n);
        })
    });

    group.finish();
}

/// Quick reference: observing a flow event (not a Message) —
/// most rules filter on `kind` early and bail. This measures the
/// "fast pass-through" cost.
fn bench_observe_irrelevant_event(c: &mut Criterion) {
    let mut group = c.benchmark_group("anomaly/observe");
    group.throughput(Throughput::Elements(1));

    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new().with_rule(DnsBurstRule::new(50)); // only matches DNS Query
    let evt = flow_started_event(7, 100);

    group.bench_function("dns_rule_sees_flow_event", |b| {
        b.iter(|| {
            let alerts = monitor.observe(black_box(&evt));
            black_box(alerts);
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_observe_no_op_rule,
    bench_observe_n_rules,
    bench_observe_always_fire,
    bench_observe_irrelevant_event,
    bench_full_pipeline_dns_burst,
    bench_on_tick_drain_expired,
    bench_to_json_line,
    bench_time_bucketed_counter_bump,
);
criterion_main!(benches);
