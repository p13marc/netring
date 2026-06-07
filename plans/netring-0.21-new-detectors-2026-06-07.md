# netring 0.21 — new detectors + flowscope 0.10 tooling adoption

**Date:** 2026-06-07
**Author:** netring maintainer
**Status:** 📝 drafted; depends on 0.17 + 0.18 (= the 0.19 + 0.20 plan files)
**Predecessor:** [`netring-0.20-unified-driver-refactor-2026-06-07.md`](./netring-0.20-unified-driver-refactor-2026-06-07.md)

**Driven by:** flowscope 0.10 shipped seven new tooling modules
that netring detectors can build on:

- `flowscope::correlate` extensions (plan 102 sub-A): `TimeBucketedSet<K, V>`, `BurstDetector<K, E>`, `TopK<K>`, `Ewma<K>`.
- `flowscope::detect` (plan 102 sub-C): `shannon_entropy`, `is_high_entropy`, `ngram_distribution`, `is_base64ish`, `is_hex_string`, `hamming_distance`.
- `flowscope::detect::signatures` (plan 113 sub-A): magic-byte recognizers for 10+ protocols.
- `flowscope::aggregate` (plan 102 sub-B): `Histogram`, `Percentile`.
- `flowscope::emit` (plan 101): `FlowEventCsvWriter`, `FlowEventNdjsonWriter`, `ZeekConnLogWriter`.
- `flowscope::well_known` (plan 102 sub-D): `(L4Proto, port) → label` table.
- Plan 110 sub-B helper sweep: `Timestamp` / `FlowStats` / `EndReason::as_str` / `LayerKind` / `Layer<'_>::Display` / `LayerStack` / `KeyIndexed::peek`.

Plus 2 new aggregator parsers (`HttpExchangeParser`,
`DnsExchangeParser`) and parser ergonomics
(`BufferedFrameDrain`, `AccumulatingSessionParser`,
`PerDatagramParser`).

**Scope rule:** additive; new examples + helper-sweep adoption.
No further breaking changes to netring's public API.

---

## At a glance — work items

| # | Item | Tier | Source |
|---|---|---|---|
| **D1** | `examples/anomaly/dns_tunnel_detect.rs` — Shannon-entropy + n-gram on DNS qnames | **High** | `flowscope::detect::shannon_entropy` + `ngram_distribution` |
| **D2** | `examples/anomaly/port_scan.rs` — distinct-port-set fan-out per source | **High** | `flowscope::correlate::TimeBucketedSet` |
| **D3** | `examples/anomaly/syn_flood_burst.rs` — burst detector on SYN floods | **High** | `flowscope::correlate::BurstDetector` |
| **D4** | `examples/flow/top_n_flows.rs` — top-K flows by bytes (Misra-Gries) | **Med** | `flowscope::correlate::TopK` |
| **D5** | `examples/flow/ewma_rate.rs` — per-flow EWMA throughput | **Med** | `flowscope::correlate::Ewma` |
| **D6** | `examples/flow/active_flows_snapshot.rs` — periodic active-flow snapshot | **Med** | `FlowTracker::iter_active` (already shipped in 0.8) |
| **D7** | `examples/flow/zeek_export.rs` — Zeek conn.log writer | **Med** | `flowscope::emit::ZeekConnLogWriter` |
| **D8** | `examples/anomaly/http_exchange_correlator.rs` — request/response pair detector | **Med** | `flowscope::http::HttpExchangeParser` |
| **D9** | `examples/anomaly/dns_exchange_correlator.rs` — query/response pair detector with elapsed time | **Med** | `flowscope::dns::DnsExchangeParser` |
| **D10** | Adopt `flowscope::well_known::protocol_label` in `multi_protocol_monitor.rs` | Polish | `multi_protocol_monitor.rs` |
| **D11** | Adopt helper sweep: `EndReason::as_str` in formatters; `KeyIndexed::peek` where applicable | Polish | per-file |
| **D12** | Adopt `FlowStats` helpers (`total_bytes` / `duration` / `retransmit_rate`) in flow/* examples | Polish | per-file |
| **D13** | Update `WRITING_DETECTORS.md` with a "More flowscope primitives" subsection covering correlate-extensions + detect + aggregate | Polish | `docs/WRITING_DETECTORS.md` |
| **D14** | Sweep + version bump 0.18 → 0.19 + CHANGELOG | **High** | release artifacts |

---

## D1. `dns_tunnel_detect.rs` — high-entropy DNS labels

DNS tunneling is a canonical exfil pattern: queries to
attacker-controlled domain encode data in subdomains
(`base32-encoded-payload.evil.com`). The signal is high
**Shannon entropy** on the label values, plus characteristic
n-gram distributions.

### Detector shape

```rust
struct DnsTunnelRule {
    /// Sliding-window per-source-IP entropy histogram.
    by_src: HashMap<IpAddr, EntropyState>,
    threshold: f64,           // typical: 4.0 bits per byte
}

impl AnomalyRule<FiveTupleKey> for DnsTunnelRule {
    fn observe(&mut self, evt, emit) {
        let Event::Message {
            parser_kind: DNS_UDP,
            message: ProtocolMessage::Dns(DnsMessage::Query(q)),
            key, ts, ..
        } = evt else { return };
        for question in &q.questions {
            for label in question.name.split('.') {
                if label.len() < 16 { continue; }  // skip short labels
                let h = flowscope::detect::shannon_entropy(label.as_bytes());
                if h > self.threshold && flowscope::detect::is_base64ish(label) {
                    emit.push(Anomaly::new("DnsTunnel", Severity::Warning, *ts)
                        .with_key(*key)
                        .with_observation("qname", &question.name)
                        .with_observation("label", label)
                        .with_metric("entropy", h));
                }
            }
        }
    }
}
```

**Severity tier:** Warning (high-confidence pattern but
operator should investigate; not every base64-shaped label is
malicious).

**MITRE mapping:** T1071.004 (DNS), T1041 (Exfiltration over C2).

### Tradeoff doc

The example header documents the false-positive caveat: some
legitimate CDNs (Akamai, Cloudflare workers) use long
randomized hostnames. Pair with a domain-allowlist.

## D2. `port_scan.rs` — distinct-port-set per source

Detector: one source IP touching > N distinct destination ports
in a window. The classic horizontal scan signature.

```rust
struct PortScanRule {
    by_src: TimeBucketedSet<IpAddr, u16>,   // ports per source
    threshold: usize,
}

impl AnomalyRule<FiveTupleKey> for PortScanRule {
    fn observe(&mut self, evt, emit) {
        let Event::FlowStarted { key, l4: Some(L4Proto::Tcp), ts, .. } = evt
        else { return };
        let src = key.a.ip();
        let dst_port = key.b.port();
        self.by_src.insert(src, dst_port, *ts);
        if self.by_src.cardinality(&src, *ts) > self.threshold {
            emit.push(Anomaly::new("PortScan", Severity::Warning, *ts)
                .with_observation("src_ip", src.to_string())
                .with_metric("distinct_dst_ports", self.by_src.cardinality(&src, *ts) as f64));
        }
    }
}
```

**MITRE:** T1046 (Network Service Discovery).

## D3. `syn_flood_burst.rs` — burst detector

Detector: > N SYN packets from one source in window without
matching established flows. Classic DoS pattern.

```rust
struct SynFloodRule {
    bursts: BurstDetector<IpAddr, SynEvent>,
    threshold: u64,
    window: Duration,
}

impl AnomalyRule<FiveTupleKey> for SynFloodRule {
    fn observe(&mut self, evt, emit) {
        match evt {
            Event::FlowStarted { key, l4: Some(L4Proto::Tcp), ts, .. } => {
                let src = key.a.ip();
                if let Some(hit) = self.bursts.observe(src, SynEvent::Started, *ts) {
                    emit.push(Anomaly::new("SynFlood", Severity::Critical, *ts)
                        .with_observation("src_ip", src.to_string())
                        .with_metric("syn_count", hit.count as f64));
                }
            }
            Event::FlowEstablished { key, .. } => {
                // Established flows clear "burst" pressure on this source.
                self.bursts.observe(key.a.ip(), SynEvent::Established, /* ts */ );
            }
            _ => {}
        }
    }
}
```

**MITRE:** T1498.001 (Network Denial of Service: Direct).

Severity Critical (DoS — page immediately).

## D4. `top_n_flows.rs` — top-K by bytes

A streaming top-K tracker (`Misra-Gries`). Useful for "biggest
flow last 5 minutes" dashboards without keeping per-flow state
indefinitely.

```rust
let mut topk: TopK<FiveTupleKey> = TopK::new(10);

while let Some(evt) = stream.next().await {
    if let Event::FlowEnded { key, stats, .. } = evt? {
        topk.observe_n(key, stats.total_bytes());
    }
}

eprintln!("Top 10 flows by bytes:");
for (key, est) in topk.top() {
    println!("  {key:?}: ~{est} bytes");
}
```

Bonus: snapshot via tokio interval to publish to a metric sink.

## D5. `ewma_rate.rs` — per-flow EWMA throughput

Smoothed-rate detector. Each flow's per-side byte rate, EWMA'd,
exposed as a metric. Detects sustained-high-throughput flows
(potential bulk exfil).

```rust
let mut rate: Ewma<FiveTupleKey> = Ewma::new(alpha: 0.1);

while let Some(evt) = stream.next().await {
    match evt? {
        Event::FlowPacket { key, ts, length, .. } => {
            // Discrete sample; Ewma smooths.
            rate.observe(key, length as f64, ts);
        }
        Event::FlowEnded { key, .. } => {
            rate.evict(&key);
        }
        _ => {}
    }
}
```

Bonus: a periodic snapshot publishes the top-N flows by
smoothed-rate to Prometheus / Loki / your sink.

## D6. `active_flows_snapshot.rs` — periodic snapshot

`FlowTracker::iter_active` (flowscope 0.8, plan 90) was
deferred from the netring 0.17 wishlist absorption (in
[`netring-0.19-flowscope-0.10-bump`](./netring-0.19-flowscope-0.10-bump-2026-06-07.md))
as "optional — ship an example in 0.21". This is that
example.

```rust
let mut tick = tokio::time::interval(Duration::from_secs(5));
loop {
    tokio::select! {
        Some(evt) = stream.next() => { /* normal loop */ }
        _ = tick.tick() => {
            let mut by_bytes: Vec<_> = stream
                .tracker()
                .iter_active()
                .map(|f| (f.key.clone(), f.stats.total_bytes(), f.tcp_state))
                .collect();
            by_bytes.sort_by_key(|(_, bytes, _)| std::cmp::Reverse(*bytes));
            for (key, bytes, state) in by_bytes.into_iter().take(10) {
                println!("active: {key:?} bytes={bytes} state={state:?}");
            }
        }
    }
}
```

## D7. `zeek_export.rs` — Zeek conn.log writer

flowscope's `ZeekConnLogWriter` (plan 101) drops a hand-rolled
30-LoC example into a 5-line `writer.write(&flow_end_event)`.

```rust
use flowscope::emit::ZeekConnLogWriter;

let mut zeek = ZeekConnLogWriter::new(File::create("conn.log")?);
while let Some(evt) = stream.next().await {
    if let Event::FlowEnded { key, reason, stats, l4, .. } = evt? {
        zeek.write(&FlowEvent::Ended { /* … */ })?;
    }
}
```

Useful pivot: dump a live capture into a Zeek-compatible log
file for `zeek-cut` post-processing.

## D8. `http_exchange_correlator.rs` — request/response pair detector

flowscope's `HttpExchangeParser` (plan 107) emits one
`HttpExchange` per req/resp pair instead of decomposing into
two `HttpMessage` events. Detector: high error-rate
(`is_error()`) or slow-response (long elapsed) per origin.

```rust
let monitor = cap.protocol_monitor()
    .flow()
    .http_exchanges()   // → HttpExchangeParser
    .build();

struct HttpErrorRateRule {
    by_origin: TimeBucketedSet<String, ExchangeOutcome>,
    threshold: f64,
}

// Outcome::Failed when status_class() == 5
// Periodic sweep: fraction of Failed / total > threshold → alert
```

**MITRE:** T1190 (Public-Facing Application failures).

## D9. `dns_exchange_correlator.rs` — query/response pair detector

flowscope's `DnsExchangeParser` (plan 107). Detector:
unresponsive resolver (sustained `NoResponse` outcomes).

```rust
let monitor = cap.protocol_monitor()
    .flow()
    .dns_exchanges()    // → DnsExchangeParser
    .build();

// Outcome::NoResponse / Outcome::Failed { rcode } → alert
```

Also exposes `elapsed` directly (RTT per query/response pair)
— easy to feed into Histogram (D8) for resolver-latency
distributions.

## D10. `well_known::protocol_label` adoption

`multi_protocol_monitor.rs`'s `describe()` function today has
a ~40-LoC port-disambiguation block:

```rust
match key.either_port(80) {
    true => "HTTP",
    false => match key.either_port(443) {
        true => "TLS",
        ...
    }
}
```

`flowscope::well_known::protocol_label(proto, src_port, dst_port)`
returns the same answer with ~70 IANA + cloud-native services
covered:

```rust
let label = key.protocol_label().unwrap_or("");
// or
let label = flowscope::well_known::protocol_label(l4, key.a.port(), key.b.port()).unwrap_or("");
```

Net: ~40 LoC deleted from `multi_protocol_monitor.rs`.

## D11. Helper sweep — `EndReason::as_str` + `KeyIndexed::peek`

`EndReason::as_str()` (plan 110 sub-B) returns the same
snake-case slug as `Display`. Use it directly:

```rust
- let reason_slug = format!("{reason}");
+ let reason_slug = reason.as_str();
```

Saves an alloc.

`KeyIndexed::peek(key, now)` — read-only get that doesn't
bump LRU recency. Use in metrics / logging contexts that
shouldn't disturb the eviction order.

## D12. `FlowStats` helpers

`FlowStats::total_bytes()` / `total_packets()` /
`total_retransmits()` / `retransmit_rate()` / `duration()` /
`duration_secs()` collapse the per-side aggregation across
the existing flow examples:

```diff
- let total = stats.bytes_initiator + stats.bytes_responder;
+ let total = stats.total_bytes();

- let duration = stats.last_seen.saturating_sub(stats.first_seen);
+ let duration = stats.duration();
```

Each example shrinks 2-4 LoC; aggregate ~30 LoC across the
flow/ examples.

## D13. `WRITING_DETECTORS.md` — new section

Add **Section 2.5: More flowscope primitives** between section
2 (current state-primitive decision matrix) and section 3
(severity tiers):

```
## 2.5. Beyond KeyIndexed + TimeBucketedCounter

flowscope 0.10 ships richer primitives for common detection
shapes:

| Shape | Primitive | Use case |
|---|---|---|
| "Distinct entries per key in window" | TimeBucketedSet | Port scan (D2) |
| "N events of kind X within window" | BurstDetector | SYN flood (D3), failed-login bursts |
| "Top K by count" | TopK | Top-N hosts by traffic |
| "Smoothed per-key rate" | Ewma | Throughput baselines |
| "Histogram / quantile" | Histogram / Percentile | Latency distributions |
| "Magic-byte signature match" | flowscope::detect::signatures | Port-randomized protocol detection |
| "Shannon entropy + n-gram" | flowscope::detect | DNS tunneling (D1), encoded payloads |
```

## D14. CHANGELOG + version 0.18 → 0.19

netring 0.19. CHANGELOG entry:

- Added: 9 new example detectors covering port scan, SYN flood,
  DNS tunneling, HTTP exchange correlation, DNS exchange
  correlation, top-K flows, EWMA rates, active-flow snapshot,
  Zeek conn.log export
- Polish: well_known protocol-label adoption in multi_protocol_monitor;
  helper-sweep adoption in 6 flow/* examples
- WRITING_DETECTORS.md gains a "More flowscope primitives" section

---

## Effort summary

| # | LoC | Days | Risk |
|---|---|---|---|
| D1 (DNS tunnel) | ~150 | 0.5 | None |
| D2 (port scan) | ~120 | 0.3 | None |
| D3 (SYN flood) | ~150 | 0.4 | None |
| D4 (top-K) | ~80 | 0.2 | None |
| D5 (EWMA rate) | ~100 | 0.3 | None |
| D6 (iter_active snapshot) | ~80 | 0.2 | None |
| D7 (Zeek export) | ~60 | 0.2 | None |
| D8 (HttpExchange) | ~120 | 0.3 | None |
| D9 (DnsExchange) | ~100 | 0.3 | None |
| D10 (well_known adoption) | -40 / +5 | 0.1 | None |
| D11 (helper sweep) | ~10 sites | 0.2 | None |
| D12 (FlowStats helpers) | ~10 sites | 0.2 | None |
| D13 (doc update) | +60 prose | 0.2 | None |
| D14 (release + CHANGELOG) | ~100 doc | 0.2 | None |

**Total: ~3.5 days.** Ship as **2 ship-commits**:

- **Commit A** — D1 + D2 + D3 + D8 + D9 (anomaly detectors)
- **Commit B** — D4 + D5 + D6 + D7 (flow examples) + D10 + D11 + D12 + D13 + D14 (polish + release)

---

## What 0.19 success looks like

After this plan lands:

1. **17 example detectors** under `examples/anomaly/` (was 8 in
   0.17). Coverage spans:
   - Rate-class: DnsQueryBurst, SynFlood
   - Cross-protocol: DnsResolvedNoConnection,
     IcmpExplainedDrop, TlsToUnresolvedIp
   - Threshold: SlowTlsHandshake
   - Persistent-state: LateralMovement, PortScan
   - Entropy: DnsTunnel
   - Exchange-pair: HttpExchange, DnsExchange
   - Replay: PcapReplayAnomaly, PcapReplayMulti
   - Harness demo: AnomalyMonitorDemo
2. **6 flow examples** updated to use flowscope helpers, ~50
   LoC simpler.
3. WRITING_DETECTORS.md gains a primitive-decision table
   covering `TimeBucketedSet` / `BurstDetector` / `TopK` /
   `Ewma` / `Histogram` / `signatures` / `shannon_entropy`.
4. The "writing a real-world detector takes ~30 LoC" promise
   of the harness is reinforced by 9 more proof points.

---

## Out of scope (deferred to 0.20+)

- **`flowscope::layers` adoption** for richer per-packet
  introspection (VLAN walk, ARP slices, tunnel walking). Not a
  current pain point; defer until a use case materializes.
- **Pipeline-level emit integration** — feeding events directly
  through `FlowEventNdjsonWriter` from inside `ProtocolMonitor`
  instead of in the example main(). Possible but would couple
  netring tighter to one format; skip.
- **eBPF correlator front-end.** Still out of scope.
- **Suricata DSL.** Still out of scope.
- **Tracing-side richer integration.** `emit_tracing()` is
  enough.

---

## Open design questions

### Q1. Should `port_scan.rs` / `dns_tunnel_detect.rs` ship as **integration tests** too?

Yes — each detector should get a `tests/anomaly_<name>.rs`
parallel to `tests/anomaly_pcap_replay.rs` that synthesizes a
pcap exhibiting the pattern, replays through the detector, and
asserts the alert count.

The harness from `tests/anomaly_monitor_smoke.rs` is the model;
each new detector adds ~80 LoC of test. Roll into the plan or
defer? **Recommend: roll in.** Same commit as the example.

### Q2. Should we ship `flowscope::aggregate::Histogram` in a new flow example or fold into the EWMA one?

Standalone example (`examples/flow/flow_duration_histogram.rs`)
— mirrors flowscope's own example of the same name. ~80 LoC.
Add as **D5.5** if light.

### Q3. Heuristic-routing example?

flowscope's signature recognizers (plan 113) deserve their own
example showing port-randomized protocol detection:
`examples/anomaly/protocol_misuse.rs` — HTTP on non-:80, TLS on
non-:443, DNS on non-:53. Indicates port-evasion. Could ship as
D2.5.

Decide after the others land; ~120 LoC.

---

## Cumulative plan: 0.17 → 0.18 → 0.19 quarter view

| netring version | flowscope adoption | Examples shipped (cum.) | Tests (cum.) | Days |
|---|---|---|---|---|
| 0.17 | dep bump 0.7 → 0.10; wishlist absorption | 57 (unchanged) | ~330 | 2 |
| 0.18 | unified Driver collapses ProtocolMonitor | 57 (variant renames) | ~325 | 4 |
| 0.19 | new detectors + helper sweep | 66 (+9) | ~410 (+85 incl. detector smoke tests) | 3.5 |
| **Total** | flowscope 0.10 fully absorbed | +9 examples | +90 tests | **~9.5** |

After the three releases, every actionable item from the
[`flowscope-wishlist-2026-06-06`](./flowscope-wishlist-2026-06-06.md)
plus the absorbed 0.9 and 0.10 cycles are integrated. netring
becomes the showcase for what flowscope 0.10 enables —
13 reference detectors covering the full anomaly-correlation
pattern space.
