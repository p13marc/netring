# Writing your own anomaly detector

A practical guide to the `AnomalyRule` trait and the
`AnomalyMonitor` harness — how to compose a new detector, what
the state primitives are good for, and how to debug a rule that
doesn't fire when you expect it to.

Companion to:

- The 7 reference detectors under `examples/anomaly/` — working
  examples for every pattern this guide describes.
- The crate-level API reference (`cargo doc -p netring --open`).
- The roadmap doc
  [`plans/netring-0.16-roadmap-2026-05-29.md`](../../plans/netring-0.16-roadmap-2026-05-29.md)
  for the architecture rationale.

---

## 1. The anatomy of an `AnomalyRule`

A detector is a struct + an `impl AnomalyRule<K>`. The trait has
two required methods and one optional, all small:

```rust
use flowscope::Timestamp;
use netring::anomaly::{Anomaly, AnomalyRule};
use netring::protocol::ProtocolEvent;

struct MyRule {
    /* whatever state you need */
}

impl<K> AnomalyRule<K> for MyRule {
    /// Stable detector identifier — also the default kind slug
    /// on emitted Anomalies. Use a short PascalCase name.
    fn name(&self) -> &'static str { "MyDetector" }

    /// Inspect each event, push any findings into `emit`.
    fn observe(&mut self, evt: &ProtocolEvent<K>, emit: &mut Vec<Anomaly<K>>) {
        /* the per-event hot path */
    }

    /// Optional: sweep-driven detection. Called from
    /// `AnomalyMonitor::on_tick(now)` once per sweep tick.
    /// Default: no-op.
    fn on_tick(&mut self, _now: Timestamp, _emit: &mut Vec<Anomaly<K>>) {}
}
```

Wire it into a monitor:

```rust
use netring::anomaly::AnomalyMonitor;
use netring::flow::extract::FiveTupleKey;

let mut rules = AnomalyMonitor::<FiveTupleKey>::new()
    .with_rule(MyRule { /* ... */ });

// Each event:
for anomaly in rules.observe(&evt) { /* emit */ }

// On a periodic sweep (e.g. every 1s):
for anomaly in rules.on_tick(now) { /* emit */ }
```

That's the whole API. Most rules are 30–80 LoC of state + match.

---

## 2. State primitives — `KeyIndexed` vs `TimeBucketedCounter`

`netring::correlate` ships two primitives. The choice between
them is the most consequential design decision in a detector.

### `TimeBucketedCounter<K>` — "is this rate too high?"

Per-key counter with a sliding window of fixed-width buckets.
O(1) bump + O(buckets) count.

Use when the question is **how often** something happens:

- DNS queries per source IP per 10s
- Failed-login attempts per username per minute
- HTTP errors per backend per 5s
- Bytes per flow per second (with a smoothed window)

```rust
use std::time::Duration;
use netring::correlate::TimeBucketedCounter;

let mut rate: TimeBucketedCounter<IpAddr> =
    TimeBucketedCounter::new(Duration::from_secs(10), Duration::from_secs(1));

rate.bump(src_ip, ts);
if rate.count(&src_ip, ts) > threshold { /* fire */ }
```

See `examples/anomaly/dns_query_burst.rs` for the canonical use.

### `KeyIndexed<K, V>` — "did X happen recently?"

TTL'd key-value cache. Entries expire after the TTL. The
`drain_expired(now)` method is the killer feature for
"expected B-after-A didn't happen" detectors.

Use when the question is **whether/when** something happened:

- Was this destination IP recently DNS-resolved? (presence check)
- Which IP did this DNS query resolve to? (value lookup)
- Did the ClientHello finish handshaking? (drain-on-expiry)

```rust
use netring::correlate::KeyIndexed;

let mut cache: KeyIndexed<IpAddr, String> =
    KeyIndexed::new(Duration::from_secs(30));

cache.insert(ip, hostname, ts);
if cache.contains_fresh(&ip, now) { /* fine */ }

// Or — drain anything that aged out without being explicitly removed:
for (ip, hostname) in cache.drain_expired(now) {
    // these are anomalies: B never followed A within the TTL
}
```

See `examples/anomaly/dns_resolved_no_connection.rs` for the
drain pattern, `examples/anomaly/tls_to_unresolved_ip.rs` for
the presence-check pattern.

### Decision rule

| Question shape | Primitive |
|---|---|
| "More than N events in T?" | `TimeBucketedCounter` |
| "Was X seen recently?" | `KeyIndexed::contains_fresh` |
| "What value did we cache for X?" | `KeyIndexed::get` |
| "Which expected events didn't happen?" | `KeyIndexed::drain_expired` |
| "Fan-out: distinct keys seen per source?" | `HashMap<Src, KeyIndexed<Dst, ()>>` (see `lateral_movement.rs`) |

---

## 3. Severity tiers — `Info` / `Warning` / `Error` / `Critical`

Pick a tier per anomaly. The harness is policy-neutral; the
tier informs the *consumer* (your logging / paging / dashboard
layer) what to do. Conventions:

| Tier | What it means | Example detector |
|---|---|---|
| `Info` | Pattern of interest, no immediate action. High-volume; log-only. | `IcmpExplainedDrop` (explained arm — normal network behaviour) |
| `Warning` | Worth surfacing in dashboards. Cumulative trends matter. | `DnsQueryBurst`, `SlowTlsHandshake`, `TlsToUnresolvedIp` (default tier for most detectors) |
| `Error` | Indicates a real problem. Operator should investigate. | `DnsResolvedNoConnection` (consistently elevated indicates DNS / firewall issues) |
| `Critical` | Page someone. Reserved for high-confidence, high-impact signals. | `LateralMovement` (one host hitting many internal peers fast) |

Match flowscope's `AnomalyKind::severity()` mapping for
consistency when your rule lifts a flowscope-side anomaly — the
`From<flowscope::event::Severity> for netring::anomaly::Severity`
impl already does this 1:1, so just pipe it through.

---

## 4. The `observe` / `on_tick` split

Two hooks, two roles. Get this wrong and your detector either
misses anomalies or fires spuriously.

### `observe(&mut self, evt, emit)` — synchronous

Called for every event. Fast path. State updates + immediate
decisions belong here.

What you do here:
- Bump counters / caches based on the event content.
- Check thresholds that are crossable on a single event
  (rate-class anomalies).
- Emit anomalies that are tied to a specific input event.

What you don't do here:
- Long sweeps over collected state.
- Wall-clock-driven checks (use the event's `ts` instead).

### `on_tick(&mut self, now, emit)` — sweep-driven

Called once per `AnomalyMonitor::on_tick(now)` invocation —
typically from a `tokio::time::interval` in the consumer's event
loop. Default no-op; opt in by overriding.

What belongs here:
- `KeyIndexed::drain_expired(now)` — surface entries that didn't
  get their expected follow-up event.
- Memory trimming: evict aged-out entries from caches that
  observers don't actively drain.
- Periodic summary anomalies (e.g. "5-minute rollup: top 10
  noisiest sources").

The sweep cadence is the consumer's choice — typically 1–5
seconds. Don't depend on a specific cadence in your rule;
write it to work with any.

### Example: drain-on-expiry pattern

`SlowTlsHandshakeRule` (`slow_tls_handshake.rs`) shows the
pattern at its purest:

```rust
fn observe(&mut self, evt, _emit) {
    if let ProtocolEvent::Message { /* ClientHello */, key, ts, .. } = evt {
        self.pending.insert(*key, *ts, *ts);  // → cache for `threshold` TTL
    }
    if let ProtocolEvent::Message { /* ServerHello */, key, .. } = evt {
        self.pending.remove(key);  // matched: fast handshake, no anomaly
    }
}

fn on_tick(&mut self, now, emit) {
    for (key, client_ts) in self.pending.drain_expired(now) {
        // ClientHellos that didn't get a ServerHello within TTL
        emit.push(Anomaly::new(self.name(), Severity::Warning, now)
            .with_key(key));
    }
}
```

The TTL itself is the threshold. No explicit timeout check.

---

## 5. Cross-protocol detectors

The harness's central promise is "writing a multi-protocol
correlator is easy." The canonical pattern joins ≥2 protocols
in a single rule via state shared between observe arms.

### Two-protocol: DNS → TCP/UDP flow

`DnsResolvedNoConnectionRule` (in `anomaly_monitor_demo.rs`):

```rust
fn observe(&mut self, evt, _emit) {
    match evt {
        // DNS Response: cache the resolution
        ProtocolEvent::Message { kind: "dns-udp",
            message: ProtocolMessage::Dns(DnsMessage::Response(r)), ts, .. } => {
            for ans in &r.answers {
                if let DnsRdata::A(v4) = &ans.data {
                    self.pending.insert(IpAddr::V4(*v4), (qname, *ts), *ts);
                }
            }
        }
        // Any flow Started: check if dst was just resolved
        ProtocolEvent::Flow(FlowEvent::Started { key, .. }) => {
            self.pending.remove(&key.b.ip());  // resolved + connected: OK
        }
        _ => {}
    }
}

fn on_tick(&mut self, now, emit) {
    for (ip, (qname, _)) in self.pending.drain_expired(now) {
        // Resolved but no connection followed within TTL — anomalous
        emit.push(...);
    }
}
```

### Three-protocol: Flow + DNS + TLS

`TlsToUnresolvedIpRule` (`tls_to_unresolved_ip.rs`) joins three
protocols to catch hardcoded-IP TLS (MITRE T1571 / T1090):

```rust
fn observe(&mut self, evt, emit) {
    match evt {
        // DNS Response → per-host resolution cache
        ProtocolEvent::Message { kind: "dns-udp",
            message: ProtocolMessage::Dns(DnsMessage::Response(r)), key, ts, .. } => {
            let host = key.b.ip();
            let cache = self.resolved_by_host.entry(host)
                .or_insert_with(|| KeyIndexed::new(self.ttl));
            for ans in &r.answers {
                if let DnsRdata::A(v4) = &ans.data {
                    cache.insert(IpAddr::V4(*v4), (), *ts);
                }
            }
        }
        // TLS ClientHello → look up dst in source's cache
        ProtocolEvent::Message { kind: "tls",
            message: ProtocolMessage::Tls(TlsMessage::ClientHello(ch)), key, ts, .. } => {
            let resolved = self.resolved_by_host.get(&key.a.ip())
                .map(|c| c.contains_fresh(&key.b.ip(), *ts))
                .unwrap_or(false);
            if !resolved {
                emit.push(Anomaly::new(self.name(), Severity::Warning, *ts)
                    .with_key(*key)
                    .with_observation("sni", ch.sni.as_deref().unwrap_or("")));
            }
        }
        _ => {}
    }
}
```

Notice the pattern: each protocol contributes a different role
(DNS = source of truth, TLS = trigger, Flow = scope). State is
per-source-IP because we're asking a per-host question.

Build the monitor matching the rule's protocol set:

```rust
let mut monitor = ProtocolMonitorBuilder::new()
    .interface("eth0")
    .flow()      // even if you don't read FlowEvent — it scopes the tracker
    .dns()       // for the resolution cache
    .tls()       // for the trigger
    .build(FiveTuple::bidirectional())?;
```

---

## 6. Composing with `FlowAnomalyRule`

flowscope's own anomalies (TCP out-of-order, reassembler
watermark, eviction pressure, parser poison) are first-class.
The shipped `FlowAnomalyRule` lifts them through the same
pipeline as your detectors:

```rust
use netring::anomaly::{AnomalyMonitor, FlowAnomalyRule, Severity};

let mut rules = AnomalyMonitor::<FiveTupleKey>::new()
    // Lift every FlowEvent::FlowAnomaly / TrackerAnomaly:
    .with_rule(FlowAnomalyRule::default())
    // Your own detectors:
    .with_rule(MyDnsBurstRule { ... })
    .with_rule(MyLateralMovementRule { ... });
```

Severity comes from `AnomalyKind::severity()` (flowscope side).
Filter floor: `FlowAnomalyRule::with_min_severity(Severity::Warning)`
suppresses `Info`-tier flowscope anomalies (out-of-order
segments are routine on lossy networks; you probably don't want
those in your alert stream).

The `From<flowscope::event::Severity> for Severity` impl means
threshold filters port across the boundary unchanged.

---

## 7. Testing a detector

Two pragmatic tools:

### Smoke test against synthesized events

Construct `ProtocolEvent`s by hand (the variants are public
structs) and drive your rule directly:

```rust
#[test]
fn my_rule_fires_above_threshold() {
    let mut monitor = AnomalyMonitor::<FiveTupleKey>::new()
        .with_rule(MyRule::new(threshold: 10));

    // Synthesize 11 events; expect 1 anomaly
    let key = FiveTupleKey { /* ... */ };
    for _ in 0..11 {
        let evt = ProtocolEvent::Message { /* ... */ };
        let _ = monitor.observe(&evt);
    }
    // Or: collect alerts inline:
    let alerts: Vec<_> = (0..11).flat_map(|_| monitor.observe(&evt)).collect();
    assert_eq!(alerts.len(), 1);
}
```

See `tests/anomaly_monitor_smoke.rs` for the canonical pattern.

### Pcap-replay against real traffic

For protocol-shape coverage, write a pcap and replay it:

```rust
#[test]
fn my_rule_fires_on_realistic_dns_burst() {
    let frames = build_dns_burst_pcap(60);  // 60 DNS queries
    let pcap = write_pcap(&frames);

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new()
        .with_rule(MyRule::new(...));

    let source = AsyncPcapSource::open(pcap.path()).await.unwrap();
    let mut stream = source.datagrams(FiveTuple::bidirectional(), DnsUdpParser::with_correlation());

    let mut alerts = 0;
    while let Some(evt) = stream.next().await {
        if let SessionEvent::Application { key, side, message, ts, parser_kind } = evt.unwrap() {
            let pe = ProtocolEvent::Message {
                key, side, kind: parser_kind,
                message: ProtocolMessage::Dns(message), ts
            };
            alerts += rules.observe(&pe).len();
        }
    }
    assert!(alerts > 0);
}
```

See `tests/anomaly_pcap_replay.rs` for the working pair.

### Debug a rule that doesn't fire

Three usual suspects:

1. **`kind` mismatch.** Your `let ProtocolEvent::Message { kind: "dns-udp", … }` only matches events with that exact kind. Run with extra logging: `eprintln!("kind={kind}")` inside `observe` to see what's actually flowing.
2. **Timestamp clock skew.** `TimeBucketedCounter::count(&k, now)` checks "now vs bucket start." If `now` is earlier than the event timestamps, you're querying a future bucket. Use `evt.timestamp()` consistently.
3. **`alerted` set sticking.** Many examples use a `HashSet` to alert-once-per-source. Forgetting to re-arm (`alerted.remove(&src)`) means the rule fires once and never again — easy to mis-attribute as "rule broken."

---

## 8. Production deployment

### Output format

Two built-in renderers on `Anomaly<K>`:

```rust
// Human-readable, one line, greppable:
println!("{a}");
// [warning] DnsBurst ts=1234.567 key=FiveTupleKey { ... } src_ip=10.0.0.1 count=42.00

// One-line JSON, pipe into Vector / Fluentd / Loki / jq:
println!("{}", a.to_json_line());
// {"severity":"warning","kind":"DnsBurst","ts_secs":1234,"ts_nanos":567000000,"key":"...","observations":{"src_ip":"10.0.0.1"},"metrics":{"count":42.0}}
```

`Anomaly::to_json_line()` is RFC 8259-compliant (escapes
quotes, backslashes, the C0 control set; NaN/±Inf → null).
No `serde` dependency.

Reference example: `anomaly_monitor_demo.rs` reads
`NETRING_JSON=1` to switch between the two:

```bash
NETRING_JSON=1 cargo run --example anomaly_monitor_demo \
    --features tokio,dns -- eth0 60 | jq .
```

### Pipeline integration

A typical production wiring:

```
netring detector → stdout (JSON) → Vector → Loki + Prometheus + alertmanager
```

- `Vector` ingests the JSON lines (`source.type = "stdin"`,
  `decode_format = "json"`).
- `severity` field drives routing: `info` → Loki only,
  `warning` → Loki + Grafana dashboard, `error/critical` →
  alertmanager.
- `kind` field drives label cardinality in Prometheus — keep
  it stable across detector versions.

### Tracing integration

If your service already uses [`tracing`](https://docs.rs/tracing/),
`Anomaly::emit_tracing()` routes anomalies through the standard
subscriber instead of stdout:

```rust
for a in rules.observe(&evt)? {
    a.emit_tracing();
}
```

| `Severity` | tracing `Level` | Extra field |
|---|---|---|
| `Info` | `INFO` | — |
| `Warning` | `WARN` | — |
| `Error` | `ERROR` | — |
| `Critical` | `ERROR` | `critical = true` |

Target: `"netring.anomaly"` — filter independently of the rest of
your logs (`RUST_LOG=netring.anomaly=warn`).

Fields on every event: `kind`, `severity`, `ts_secs`, `ts_nanos`,
`key` (Debug-formatted), plus `payload` carrying the full JSON
line (same shape as `to_json_line()`). Subscribers that want the
dynamic observations / metrics parse the `payload`; subscribers
that just want kind + severity routing read the fixed fields
directly.

### Backpressure

`AnomalyMonitor::observe` returns a `Vec<Anomaly<K>>` per call
— freshly allocated, no scratch sharing across calls. If you
emit at a rate faster than your sink can drain, the bottleneck
is your `println!` / mpsc send, not the harness. The harness
itself is non-blocking.

If your sink is genuinely slow (network alert, DB insert),
buffer into a bounded channel and drop on full with a metric
("anomalies_dropped_total"). Don't block the event loop.

---

## 9. Common false-positive patterns

Every detector has a "looks anomalous, isn't" case. Document
yours; allow-list when appropriate.

| Detector | Common FP |
|---|---|
| `DnsQueryBurst` | Multicast DNS / mDNS clients legitimately query at high rates on subnet broadcast |
| `DnsResolvedNoConnection` | DNS prefetch (browser look-ahead resolution) — resolved-but-never-connected is normal |
| `SlowTlsHandshake` | Captive portals / probe traffic — the ClientHello goes nowhere by design |
| `LateralMovement` | k8s leader-election, file-share / SMB browsing, broadcast services (mDNS, SSDP) |
| `IcmpExplainedDrop` (unexplained arm) | Peer-side RSTs are normal at the end of long-lived flows; alert only on sustained patterns |
| `TlsToUnresolvedIp` | Hostsfile / `/etc/hosts` entries bypass DNS-over-the-wire entirely — pre-populate the cache from config |

The pattern: surface the anomaly, but pair it with operator-side
allowlists (CIDR exclusions, hostname patterns, known-internal
service registries). The detector raises signal; the operator
decides what's actionable.

---

## 10. Mapping to MITRE ATT&CK

For SOC / detection-engineering teams, label each detector
with the technique(s) it covers. The shipped detectors map as
follows:

| Detector | MITRE technique |
|---|---|
| `DnsQueryBurst` | T1071.004 (Application Layer Protocol: DNS), T1568.002 (Dynamic Resolution: Domain Generation Algorithms — at high cardinality) |
| `DnsResolvedNoConnection` | T1041 (Exfiltration Over C2 Channel — possible exfil via DNS tunneling), T1071.004 |
| `SlowTlsHandshake` | T1573.002 (Encrypted Channel: Asymmetric Cryptography — possible MITM / DPI) |
| `LateralMovement` | T1021 (Remote Services), T1018 (Remote System Discovery) |
| `IcmpExplainedDrop` | T1571 (Non-Standard Port — explained arm baselines normal RST patterns; unexplained arm flags candidates) |
| `TlsToUnresolvedIp` | T1571 (Non-Standard Port), T1090 (Proxy) — hardcoded-IP C2 |

Add the technique ID as an observation on every anomaly so it
flows through to SIEMs:

```rust
emit.push(Anomaly::new(self.name(), Severity::Warning, *ts)
    .with_key(*key)
    .with_observation("mitre", "T1071.004"));
```

This makes SOC-side automation (auto-creating tickets, mapping
to playbooks) much easier than after-the-fact tagging.

---

## Further reading

- **The 7 reference detectors** under `netring/examples/anomaly/`
  — every pattern in this guide is implemented in working code.
- **The roadmap** —
  [`plans/netring-0.16-roadmap-2026-05-29.md`](../../plans/netring-0.16-roadmap-2026-05-29.md)
  documents the design rationale; the bonus items
  (`Display`/`to_json_line`/`FlowAnomalyRule`) are documented
  alongside.
- **flowscope**'s docs — the `SessionEvent` /
  `DatagramParser` types this layer composes over.
- **`docs/ASYNC_GUIDE.md`** for the runtime-side patterns
  underneath (`AsyncCapture`, `Stream`, backpressure).

If you write a detector that surfaces a useful pattern, please
contribute it back — `examples/anomaly/` is the canonical place.
