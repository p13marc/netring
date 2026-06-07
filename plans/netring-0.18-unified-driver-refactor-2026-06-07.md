# netring 0.18 — unified `Driver<E, M>` refactor + new detectors + tooling adoption

**Date:** 2026-06-07 (last revised 2026-06-09)
**Author:** netring maintainer
**Status:** 📝 drafted; await execution
**Predecessor:** netring 0.17 (shipped — `c1ec36b`).

**One big release** consolidating two formerly-separate strands.
The architectural refactor (collapse `ProtocolMonitor` onto
flowscope's unified `Driver<E, M>`) and the additive work
(9 new reference detectors + helper-sweep adoption) ship in the
same 0.18 release.

Rationale: shipping the architectural refactor solo would burn a
release without delivering visible value to anomaly-toolkit users.
Pairing it with the new detectors that exercise the new
`Event<K, M>` shape proves the refactor on real workloads and
lands the additive value at the same time. Pre-1.0 — breaking
changes on `ProtocolEvent` / `ProtocolMessage` are acceptable.

**Driven by:** flowscope 0.10's centerpiece plan 116 — unified
`Driver<E, M>` + `Event<K, M>` + `driver_unified::Pipeline` — plus
flowscope 0.10's seven new tooling modules:

- `flowscope::correlate` extensions (plan 102 sub-A):
  `TimeBucketedSet<K, V>`, `BurstDetector<K, E>`, `TopK<K>`,
  `Ewma<K>`.
- `flowscope::detect` (plan 102 sub-C): `shannon_entropy`,
  `is_high_entropy`, `ngram_distribution`, `is_base64ish`,
  `is_hex_string`, `hamming_distance`.
- `flowscope::detect::signatures` (plan 113 sub-A): magic-byte
  recognizers for 10+ protocols.
- `flowscope::aggregate` (plan 102 sub-B): `Histogram`,
  `Percentile`.
- `flowscope::emit` (plan 101): `FlowEventCsvWriter`,
  `FlowEventNdjsonWriter`, `ZeekConnLogWriter`.
- `flowscope::well_known` (plan 102 sub-D): `(L4Proto, port) →
  label` table.
- Plan 110 sub-B helper sweep: `Timestamp` / `FlowStats` /
  `EndReason::as_str` / `LayerKind` / `Layer<'_>::Display` /
  `LayerStack` / `KeyIndexed::peek`.
- Plus 2 new aggregator parsers (`HttpExchangeParser`,
  `DnsExchangeParser`) and parser ergonomics
  (`BufferedFrameDrain`, `AccumulatingSessionParser`,
  `PerDatagramParser`).

Also closes four long-deferred netring items:
- **N5** — netring's hand-rolled session/datagram stream state
  machines (originally from the 0.16 roadmap)
- **N6** — single-ring fan-out (the "ProtocolMonitor opens N
  captures" memory cost; same roadmap)
- **O1** — `AsyncCapture::broadcast(n)` (from the retired 0.18
  roadmap)
- **O2** — collapse session/datagram drivers onto flowscope's
  (same roadmap)

---

## Strand 1 (refactor) — TL;DR

| What | Before | After |
|---|---|---|
| **Ring count** for an N-protocol monitor | N `AsyncCapture`s + N kernel BPF filters | **1** `AsyncCapture` + N user-side parser slots |
| **netring's session_stream.rs** | ~880 LoC hand-rolled state machine | ~30 LoC wrapper around `flowscope::driver_unified::Driver` |
| **netring's datagram_stream.rs** | ~505 LoC hand-rolled state machine | ~30 LoC wrapper |
| **ProtocolMonitor's internal wiring** | `Vec<BoxedEventStream<K>>` + round-robin polling | One driver, one event stream |
| **netring::ProtocolEvent\<K\>** | Custom sum-type wrapping FlowEvent + ProtocolMessage | Thin alias around `flowscope::driver_unified::Event<K, ProtocolMessage>` |
| **netring::ProtocolMessage** | netring-owned enum | Kept (light); becomes the `M` parameter on the unified Driver |

**Net code change for the refactor strand:** ~1300 LoC deleted,
~400 LoC added. **Memory cost** for a 5-protocol monitor
(flow + http + dns + tls + icmp): 5× ring → 1× ring. Linux
kernel `tpacket_v3` ring is typically 16-32 MiB per capture;
5× becomes 1×.

## Strand 2 (additive) — TL;DR

| What | Delta |
|---|---|
| Reference detectors under `examples/anomaly/` | 8 → 17 (+9: dns_tunnel_detect, port_scan, syn_flood_burst, top_n_flows, ewma_rate, active_flows_snapshot, zeek_export, http_exchange_correlator, dns_exchange_correlator) |
| Examples adopting new flowscope helpers | 0 → 6 (well_known protocol_label; EndReason::as_str; FlowStats helpers) |
| `docs/WRITING_DETECTORS.md` | +60 lines (new "More flowscope primitives" section with the decision matrix for `BurstDetector` / `TopK` / `Ewma` / `shannon_entropy` / etc.) |
| Tests | +85 (new detector smoke tests, ~80 LoC each) |

---

## At a glance — work breakdown (25 items, 4 ship-commits)

### Refactor strand (U1–U11)

| # | Item | Tier | Touch points |
|---|---|---|---|
| **U1** | Adopt `flowscope::driver_unified::Driver<E, M>` internally in `ProtocolMonitor` | **High** | `protocol/monitor.rs` rewrite |
| **U2** | Migrate `netring::ProtocolEvent<K>` to wrap `flowscope::Event<K, M>` (Path A: type alias) | **High** | `protocol/event.rs` |
| **U3** | `netring::ProtocolMessage` stays as the `M` parameter; add `TlsHandshake` variant if not already present (it is, from 0.17) | **Med** | `protocol/event.rs` (no change needed) |
| **U4** | Delete `netring/src/async_adapters/session_stream.rs` (~880 LoC) | **Med** | Source deletion + acceptance tests pass |
| **U5** | Delete `netring/src/async_adapters/datagram_stream.rs` (~505 LoC) | **Med** | Same |
| **U6** | Replace netring's `flow_stream` / `session_stream` / `datagram_stream` constructors with wrappers around `flowscope::driver_unified::Driver` | **High** | `lib.rs` re-exports + `async_adapters/` glue |
| **U7** | Update `pcap_flow.rs` (`PcapFlowStream` / `PcapSessionStream` / `PcapDatagramStream`) similarly | **Med** | `pcap_flow.rs` |
| **U8** | Migrate all reference detectors (8 existing + 9 new — net 17) for the variant rename: `ProtocolEvent::Flow(FlowEvent::Started)` → `Event::FlowStarted`; `kind` → `parser_kind`; etc. | **High** | `examples/anomaly/*.rs` + `tests/*` |
| **U9** | Heuristic routing: `ProtocolMonitorBuilder::heuristic()` exposes flowscope's signature-based dispatch | **Med** | `protocol/monitor.rs` |
| **U10** | Update `WRITING_DETECTORS.md` to reflect the new shape | Polish | `docs/WRITING_DETECTORS.md` |
| **U11** | CHANGELOG entries (combined for both strands) + version bump 0.17 → 0.18 | **High** | `CHANGELOG.md` + `Cargo.toml` |

### Additive strand (D1–D14)

| # | Item | Tier | Source |
|---|---|---|---|
| **D1** | `examples/anomaly/dns_tunnel_detect.rs` — Shannon-entropy + n-gram on DNS qnames | **High** | `flowscope::detect::shannon_entropy` + `ngram_distribution` |
| **D2** | `examples/anomaly/port_scan.rs` — distinct-port-set fan-out per source | **High** | `flowscope::correlate::TimeBucketedSet` |
| **D3** | `examples/anomaly/syn_flood_burst.rs` — burst detector on SYN floods | **High** | `flowscope::correlate::BurstDetector` |
| **D4** | `examples/flow/top_n_flows.rs` — top-K flows by bytes (Misra-Gries) | **Med** | `flowscope::correlate::TopK` |
| **D5** | `examples/flow/ewma_rate.rs` — per-flow EWMA throughput | **Med** | `flowscope::correlate::Ewma` |
| **D6** | `examples/flow/active_flows_snapshot.rs` — periodic active-flow snapshot | **Med** | `FlowTracker::iter_active` |
| **D7** | `examples/flow/zeek_export.rs` — Zeek conn.log writer | **Med** | `flowscope::emit::ZeekConnLogWriter` |
| **D8** | `examples/anomaly/http_exchange_correlator.rs` — request/response pair detector | **Med** | `flowscope::http::HttpExchangeParser` |
| **D9** | `examples/anomaly/dns_exchange_correlator.rs` — query/response pair detector with elapsed time | **Med** | `flowscope::dns::DnsExchangeParser` |
| **D10** | Adopt `flowscope::well_known::protocol_label` in `multi_protocol_monitor.rs` | Polish | `multi_protocol_monitor.rs` |
| **D11** | Adopt helper sweep: `EndReason::as_str` in formatters; `KeyIndexed::peek` where applicable | Polish | per-file |
| **D12** | Adopt `FlowStats` helpers (`total_bytes` / `duration` / `retransmit_rate`) in `flow/*` examples | Polish | per-file |
| **D13** | Update `WRITING_DETECTORS.md` with a "More flowscope primitives" section | Polish | `docs/WRITING_DETECTORS.md` |
| **D14** | Integration tests for new detectors (synthetic-pcap smoke tests parallel to `tests/anomaly_pcap_replay.rs`) | **Med** | `tests/anomaly_*.rs` |

---

# Strand 1 — Refactor

## U1. Adopt `Driver<E, M>` internally

flowscope 0.10's centerpiece is:

```rust
let driver = Driver::builder(FiveTuple::bidirectional())
    .session_on_ports(HttpParser::default(), &[80, 8080], |m| MyMsg::Http(m))
    .session_on_ports(TlsParser::default(),  &[443],      |m| MyMsg::Tls(m))
    .datagram_on_ports(DnsUdpParser::with_correlation(), &[53], |m| MyMsg::Dns(m))
    .datagram_broadcast(IcmpParser::default(), |m| MyMsg::Icmp(m))
    .build();

while let Some(view) = source.next() {
    for ev in driver.track(&view)? {
        match ev {
            Event::FlowStarted { key, .. } => …,
            Event::Message { key, message, parser_kind, .. } => match message {
                MyMsg::Http(http) => …,
                MyMsg::Dns(dns) => …,
                MyMsg::Tls(tls) => …,
                MyMsg::Icmp(icmp) => …,
            },
            Event::FlowEnded { key, reason, l4, .. } => …,
            _ => {}
        }
    }
}
```

`ProtocolMonitor` becomes a tokio adapter over exactly this
shape:

```rust
pub struct ProtocolMonitor<K> {
    inner_capture: AsyncCapture,           // ONE ring, no filter
    driver: Driver<E, M>,                  // owns the per-parser slots + tracker
    pending: VecDeque<Event<K, M>>,        // batch buffer
}
```

Each `poll_next` either drains `pending` or pulls a new batch
from `inner_capture` and calls `driver.track(&view)` for each
packet.

### Acceptance gate

`tests/anomaly_monitor_smoke.rs` passes — no rule needs to
change. `tests/anomaly_pcap_replay.rs` passes — likewise. The
existing rules just iterate `Event<K, M>` instead of
`ProtocolEvent<K>` (or `ProtocolEvent<K>` becomes a type alias).

## U2 + U3. `ProtocolEvent` / `ProtocolMessage` collapse

**Path A** — type alias over flowscope's unified Event:

```rust
pub type ProtocolEvent<K> = flowscope::driver_unified::Event<K, ProtocolMessage>;
```

`ProtocolMessage` stays as a netring-owned sum-type (it already
exists and gained `TlsHandshake` in 0.17):

```rust
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum ProtocolMessage {
    #[cfg(feature = "http")]
    Http(flowscope::http::HttpMessage),
    #[cfg(feature = "dns")]
    Dns(flowscope::dns::DnsMessage),
    #[cfg(feature = "tls")]
    Tls(flowscope::tls::TlsMessage),
    #[cfg(feature = "tls")]
    TlsHandshake(flowscope::tls::TlsHandshake),
    #[cfg(feature = "icmp")]
    Icmp(flowscope::icmp::IcmpMessage),
    // Followups in strand 2: HttpExchange, DnsExchange
}
```

netring users keep writing `ProtocolEvent<K>` and
`ProtocolMessage::Dns(_)`. The match shapes change because
`Event<K, M>` has different variant names:

| Old (netring `ProtocolEvent`) | New (`Event<K, M>`) |
|---|---|
| `ProtocolEvent::Flow(FlowEvent::Started { … })` | `Event::FlowStarted { … }` |
| `ProtocolEvent::Flow(FlowEvent::Ended { … })` | `Event::FlowEnded { … }` |
| `ProtocolEvent::Flow(FlowEvent::Established { … })` | `Event::FlowEstablished { … }` |
| `ProtocolEvent::Flow(FlowEvent::Tick { … })` | `Event::FlowTick { … }` |
| `ProtocolEvent::Flow(FlowEvent::FlowAnomaly { … })` | `Event::FlowAnomaly { … }` |
| `ProtocolEvent::Flow(FlowEvent::TrackerAnomaly { … })` | `Event::TrackerAnomaly { … }` |
| `ProtocolEvent::Message { kind, … }` | `Event::Message { parser_kind, … }` |

Detector code touches change mechanically. ~30 sites across
the 8 existing reference detectors; the 9 new ones in strand 2
are authored against the new shape from the start.

### Why Path A (alias) and not Path B (rename)

Path B (`pub use flowscope::driver_unified::Event as ProtocolEvent`)
is cleaner but loses the escape hatch to add netring-side fields
later (capture metadata, etc.) without forcing another breaking
change.

Path A also keeps the existing tutorial discoverable
(`ProtocolEvent<K>` still appears in docs); only the variant
names shift.

## U4 + U5. Delete `session_stream.rs` and `datagram_stream.rs`

These are ~1400 LoC of hand-rolled state machine that duplicate
what flowscope's `FlowSessionDriver` / `FlowDatagramDriver` (and
now the unified `Driver`) handle.

### Preservation work

Lift to `tests/` any scenarios netring's tests cover that
flowscope's drivers don't:

- The FIN-with-residual-bytes drain semantics
- The RST-drops-reassembler semantics
- The BufferOverflow vs Application event ordering

flowscope's `tests/session_driver_*.rs` already cover most of
these; verify before deleting netring's.

### Public-API impact

`netring/src/lib.rs` re-exports:

```diff
- pub use async_adapters::session_stream::SessionStream;
- pub use async_adapters::datagram_stream::DatagramStream;
+ pub use protocol::ProtocolStream;  // new — wraps Driver<E, M>
```

### Backwards compat

Keep `SessionStream<S, E, F>` and `DatagramStream<S, E, P>` as
**type aliases** to `ProtocolStream` shapes for one release.
Document as deprecated. Remove in 0.19.

## U6. `flow_stream` / `session_stream` / `datagram_stream` wrappers

The user-facing entry points stay:

```rust
let stream = cap.flow_stream(FiveTuple::bidirectional());
let stream = cap.session_stream(FiveTuple::bidirectional(), HttpParser::default());
let stream = cap.datagram_stream(FiveTuple::bidirectional(), DnsUdpParser::with_correlation());
```

Internally, each constructs a `Driver` with one slot configured
and wraps it.

Multi-parser entry: `cap.protocol_monitor()` returns a
`ProtocolMonitorBuilder` that mirrors flowscope's
`Driver::builder` API but stays in netring's idiom:

```rust
let monitor = cap.protocol_monitor()
    .flow()
    .http()           // → driver.session_on_ports(HttpParser, [80, 8080], lift)
    .dns()            // → driver.datagram_on_ports(DnsUdpParser, [53], lift)
    .tls_handshake()  // → driver.session_on_ports(TlsHandshakeParser, [443], lift)
    .icmp()           // → driver.datagram_broadcast(IcmpParser, lift)
    .build();
```

The `lift` closure is internal to the builder.

## U7. Pcap stream wrappers

Same shape for the pcap-side wrappers:

```rust
let stream = source.flow_events(FiveTuple::bidirectional());
let stream = source.sessions(FiveTuple::bidirectional(), HttpParser::default());
let stream = source.datagrams(FiveTuple::bidirectional(), DnsUdpParser::with_correlation());
```

These constructors stay; internals adopt the unified driver.

`AsyncPcapSource::protocol_monitor()` ships as a new builder
entry for multi-protocol pcap replay — fulfills the deferred O9
(`ProtocolMonitorBuilder::pcap(path)`, originally from the
retired 0.18 roadmap) and supersedes the manual "open twice +
merge by timestamp" pattern in
`examples/anomaly/pcap_replay_multi.rs`.

The `pcap_replay_multi.rs` example becomes ~30 LoC: just call
`AsyncPcapSource::protocol_monitor().flow().dns().tls()…build()`.

## U8. Detector migration

Each rule body needs the variant-name shift and the
`kind` → `parser_kind` field rename. Per-example diff:

```diff
- ProtocolEvent::Flow(FlowEvent::Started { key, l4, ts, .. }) => {
+ Event::FlowStarted { key, l4, ts, .. } => {
      // … unchanged …
  }
- ProtocolEvent::Flow(FlowEvent::Ended { key, reason, stats, l4, .. }) => {
+ Event::FlowEnded { key, reason, stats, l4, .. } => {
      // … unchanged …
  }
- ProtocolEvent::Message { kind: DNS_UDP, message: ProtocolMessage::Dns(DnsMessage::Query(_)), key, ts, .. } => {
+ Event::Message { parser_kind: DNS_UDP, message: ProtocolMessage::Dns(DnsMessage::Query(_)), key, ts, .. } => {
      // … unchanged …
  }
```

`AnomalyRule<K>` signature stays unchanged (Path A means
`ProtocolEvent<K>` is still the same type, just realiased).

~30 sites across the 8 existing reference detectors. The 9
new detectors (D1–D9) are written directly against the new
shape.

## U9. Heuristic routing

flowscope 0.10 ships heuristic dispatch on the unified Driver
(plan 116 PR 2b + plan 113 sub-B). Each heuristic slot is a
signature function over the first 64 bytes per side, with
`Probing` → `Pinned` → `GaveUp` state per flow.

netring exposes it via:

```rust
let monitor = cap.protocol_monitor()
    .flow()
    .heuristic(http_request_signature, HttpParser::default(), |m| ProtocolMessage::Http(m))
    .heuristic(tls_client_hello_signature, TlsHandshakeParser::default(), |m| ProtocolMessage::TlsHandshake(m))
    .dns()
    .build();
```

Useful for port-randomized C2 detection and protocols on
non-standard ports.

`flowscope::detect::signatures::{http_request, http_response,
tls_client_hello, tls_server_hello, dns_message, ssh_banner,
smtp_banner, ftp_banner, irc_message, redis_resp, mqtt_connect,
postgres_startup}` — the curated set. Their slugs align with
`parser_kinds::*` so dispatch round-trips cleanly.

## U10. `WRITING_DETECTORS.md` update

The tutorial gets two patches in 0.18:

**First patch (from U10)** — the variant-rename reality:
- Section 1 (anatomy) — Update variant names: `Event::FlowStarted`
  vs old `ProtocolEvent::Flow(FlowEvent::Started)`. Field-rename
  `kind` → `parser_kind`.
- Section 5 (cross-protocol) — update the `tls_to_unresolved_ip`
  pattern to use `Event::Message` shape.
- Section 8 (production deployment) — mention
  `flowscope::emit::FlowEventNdjsonWriter` as an alternative to
  `to_json_line()`.

**Second patch (from D13)** — additive content; see strand 2
below.

## U11. CHANGELOG + version bump

netring 0.17 → 0.18. CHANGELOG headline:

> Centerpiece architectural refactor + flowscope-tooling adoption:
> ProtocolMonitor now collapses N captures + N kernel BPF filters
> down to ONE capture + flowscope's unified Driver<E, M>. Memory
> savings scale linearly with the protocol count. Plus 9 new
> reference detectors using flowscope::detect / correlate
> extensions / aggregate / emit / well_known.

Breaking changes section:
- `ProtocolEvent<K>` variant rename: `Flow(FlowEvent::Started)`
  → `FlowStarted`, etc. Path A — type alias to flowscope's
  `Event<K, M>`.
- `kind` field renamed to `parser_kind` on `Message` arm.
- `SessionStream` / `DatagramStream` deprecated (aliases stay
  one release; deletion in 0.19).

---

# Strand 2 — New detectors + tooling

## D1. `dns_tunnel_detect.rs` — high-entropy DNS labels

DNS tunneling is a canonical exfil pattern: queries to
attacker-controlled domain encode data in subdomains
(`base32-encoded-payload.evil.com`). The signal is high
**Shannon entropy** on the label values, plus characteristic
n-gram distributions.

### Detector shape (written against the post-U2 alias)

```rust
struct DnsTunnelRule {
    threshold: f64,           // typical: 4.0 bits per byte
}

impl AnomalyRule<FiveTupleKey> for DnsTunnelRule {
    fn observe(&mut self, evt: &ProtocolEvent<FiveTupleKey>, emit: &mut Vec<Anomaly<FiveTupleKey>>) {
        let ProtocolEvent::Message {
            parser_kind: flowscope::parser_kinds::DNS_UDP,
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
                        .with_observation("qname", question.name.clone())
                        .with_observation("label", label.to_string())
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
        let ProtocolEvent::FlowStarted { key, l4: Some(L4Proto::Tcp), ts, .. } = evt
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
            ProtocolEvent::FlowStarted { key, l4: Some(L4Proto::Tcp), ts, .. } => {
                let src = key.a.ip();
                if let Some(hit) = self.bursts.observe(src, SynEvent::Started, *ts) {
                    emit.push(Anomaly::new("SynFlood", Severity::Critical, *ts)
                        .with_observation("src_ip", src.to_string())
                        .with_metric("syn_count", hit.count as f64));
                }
            }
            ProtocolEvent::FlowEstablished { key, ts, .. } => {
                self.bursts.observe(key.a.ip(), SynEvent::Established, *ts);
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
    if let ProtocolEvent::FlowEnded { key, stats, .. } = evt? {
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
let mut rate: Ewma<FiveTupleKey> = Ewma::new(/* alpha: */ 0.1);

while let Some(evt) = stream.next().await {
    match evt? {
        ProtocolEvent::FlowPacket { key, ts, length, .. } => {
            rate.observe(key, length as f64, ts);
        }
        ProtocolEvent::FlowEnded { key, .. } => {
            rate.evict(&key);
        }
        _ => {}
    }
}
```

Bonus: a periodic snapshot publishes the top-N flows by
smoothed-rate to Prometheus / Loki.

## D6. `active_flows_snapshot.rs` — periodic snapshot

`FlowTracker::iter_active` (flowscope 0.8, plan 90) shipped in
0.17 but no example landed. This is that example.

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
    if let ProtocolEvent::FlowEnded { key, reason, stats, l4, .. } = evt? {
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
(`is_error()`) or slow-response per origin.

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

Requires `ProtocolMessage::HttpExchange(HttpExchange)` variant
+ `ProtocolMonitorBuilder::http_exchanges()` /
`.http_exchanges_on_ports()` — added in U6 / U9 work.

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
— easy to feed into Histogram for resolver-latency
distributions.

Requires `ProtocolMessage::DnsExchange(DnsExchange)` variant +
`ProtocolMonitorBuilder::dns_exchanges()` — added in U6 / U9.

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

```diff
- let reason_slug = format!("{reason}");
+ let reason_slug = reason.as_str();
```

Saves an alloc.

`KeyIndexed::peek(key, now)` — read-only `get` that doesn't
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
`flow/` examples.

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
| "Magic-byte signature match" | flowscope::detect::signatures | Port-randomized protocol detection (via .heuristic()) |
| "Shannon entropy + n-gram" | flowscope::detect | DNS tunneling (D1), encoded payloads |
```

## D14. Integration tests

Each new detector (D1–D3, D8, D9) gets a parallel integration
test under `tests/anomaly_<name>.rs`. Pattern follows
`tests/anomaly_pcap_replay.rs`:

1. Synthesize a small pcap (or just a `Vec<ProtocolEvent<K>>`)
   that exhibits the pattern.
2. Run it through the detector via `AnomalyMonitor::observe`.
3. Assert the alert count matches expectation.

~80 LoC per test.

Flow-level examples (D4–D7) don't get smoke tests — they're
infrastructure demos, not detection rules; their value is in
"do they compile, run, and produce sensible output."

---

## Effort summary

### Refactor strand

| Phase | LoC delta | Days | Risk |
|---|---|---|---|
| U1 (ProtocolMonitor adopts Driver) | +200 / -500 | 1 | Med |
| U2 + U3 (Event/ProtocolEvent alias) | +50 / -150 | 0.5 | Med (semver) |
| U4 (delete session_stream.rs) | -880 | 0.3 | Low |
| U5 (delete datagram_stream.rs) | -505 | 0.3 | Low |
| U6 (stream wrappers) | +200 / -100 | 0.5 | Low |
| U7 (pcap stream wrappers) | +100 / -50 | 0.3 | Low |
| U8 (8 detector migrations) | ~30 site touches | 0.3 | None |
| U9 (heuristic routing) | +80 + builder | 0.3 | Low |
| U10 (WRITING_DETECTORS update) | +50 prose | 0.2 | None |
| U11 (CHANGELOG + version) | +100 doc | 0.2 | None |

**Refactor subtotal: ~4 days.**

### Additive strand

| # | LoC | Days | Risk |
|---|---|---|---|
| D1 (DNS tunnel) | ~150 | 0.5 | None |
| D2 (port scan) | ~120 | 0.3 | None |
| D3 (SYN flood) | ~150 | 0.4 | None |
| D4 (top-K) | ~80 | 0.2 | None |
| D5 (EWMA rate) | ~100 | 0.3 | None |
| D6 (iter_active snapshot) | ~80 | 0.2 | None |
| D7 (Zeek export) | ~60 | 0.2 | None |
| D8 (HttpExchange) | ~120 | 0.3 | Low |
| D9 (DnsExchange) | ~100 | 0.3 | Low |
| D10 (well_known adoption) | -40 / +5 | 0.1 | None |
| D11 (helper sweep) | ~10 sites | 0.2 | None |
| D12 (FlowStats helpers) | ~10 sites | 0.2 | None |
| D13 (doc update) | +60 prose | 0.2 | None |
| D14 (integration tests, 5) | ~400 LoC | 0.5 | None |

**Additive subtotal: ~3.5 days.**

**Combined total: ~7.5 days.** Ship as **4 ship-commits**:

- **Commit A** — refactor proper. U1 + U2 + U3 + U4 + U5 + U6 +
  U7 + U8 (8 existing detectors migrated). Acceptance gate: all
  existing tests pass. ~3 days.
- **Commit B** — refactor polish. U9 (heuristic routing) +
  U10 (tutorial update for variant renames) + a benchmark
  re-pin against the pinned baseline. ~0.5 days.
- **Commit C** — new anomaly detectors. D1 + D2 + D3 + D8 + D9
  + integration tests for each (D14 partial). ~2.5 days.
- **Commit D** — flow examples + polish + release. D4 + D5 +
  D6 + D7 + D10 + D11 + D12 + D13 + U11 (CHANGELOG + version
  bump). ~1.5 days.

Each commit must pass `cargo fmt --check`, `cargo clippy
--all-targets --all-features -- -D warnings`, `cargo doc -p
netring --no-deps --all-features`, `cargo test --workspace
--features tokio,channel,flow,parse,pcap,http,dns,tls,icmp`,
`cargo build -p netring --examples --features ...`.

---

## Open design questions

### Q1. Does `ProtocolMonitor`'s constant overhead regress after the refactor?

Run `cargo bench --bench anomaly` and confirm against the
baseline in commit `fb9bdc0`:

- `bench_observe_no_op_rule`: still ≤ 10 ns/event (was 9.5)
- `bench_full_pipeline_dns_burst`: still ≤ 100 ns/event (was 91)

A 2× regression on the no-op rule would be acceptable (we're
going through one more layer); 10× would not be. If the
regression is real, profile + identify the contention point
before merging Commit A.

### Q2. Does pcap-replay throughput change?

Should improve modestly: one driver replacing the
SessionStream/DatagramStream state machine. Re-run
`tests/anomaly_pcap_replay.rs` with a 10× larger synthesized
pcap and confirm no regressions.

### Q3. Should we ship `flowscope::aggregate::Histogram` in a flow example?

Yes — fold into D5 as a bonus print. The EWMA example already
shows `flowscope::correlate::Ewma`; pairing it with a
`flowscope::aggregate::Histogram` of per-flow durations in the
same file demonstrates both at minimal extra LoC.

### Q4. Heuristic-routing example?

The U9 work makes heuristic routing available, but the
detectors that fire on heuristic-routed parsers don't change
shape from the regular ones — they're just downstream of a
different builder choice. An explicit example
(`examples/anomaly/protocol_misuse.rs` — HTTP on non-:80, TLS
on non-:443, DNS on non-:53; indicates port-evasion) would
make the feature discoverable. Add as **Commit B+** if light
(~120 LoC).

---

## What 0.18 success looks like

After this plan lands:

1. **`ProtocolMonitor` opens 1 `AsyncCapture`** regardless of
   how many parsers are enabled. Memory savings linearly
   proportional to N.
2. **`session_stream.rs` and `datagram_stream.rs` are deleted**
   (~1400 LoC removed from netring). The shape of
   `cap.session_stream(...)` / `.datagram_stream(...)` is
   unchanged for users.
3. **17 reference detectors** under `examples/anomaly/` (was 8
   in 0.17, +9 new) — coverage spans rate-class, cross-protocol,
   threshold, persistent-state, entropy, exchange-pair, replay,
   and harness-demo categories.
4. **6 flow examples** updated to use flowscope helpers
   (`well_known`, `EndReason::as_str`, `FlowStats` helpers,
   `KeyIndexed::peek`) — ~50 LoC simpler aggregate.
5. **All 17 detectors** use the unified Driver event shape via
   the `ProtocolEvent` type alias.
6. **`cap.protocol_monitor()`** exposes the unified-Driver
   builder including heuristic-routing slots.
7. **CHANGELOG** documents the breaking renames + the new
   detectors.
8. **`pcap_replay_multi.rs`** collapses to "use
   `ProtocolMonitorBuilder::pcap(path)`."
9. **Per-event overhead** in benchmarks regresses by < 2×; the
   harness floor stays ≤ 20 ns/event.
10. **`docs/WRITING_DETECTORS.md`** updated for both the
    variant-rename reality AND the new "More flowscope
    primitives" decision matrix.

netring becomes the showcase for what flowscope 0.10 enables —
17 reference detectors covering the full anomaly-correlation
pattern space, all powered by one shared driver per monitor.

---

## Out of scope (deferred to 0.19+)

- **Public `AsyncCapture::broadcast(n)` for non-`ProtocolMonitor`
  use cases.** The unified Driver gives us the multi-parser
  case; general broadcast (for fanning packets to user-defined
  sinks) is a separate motivation. Defer.
- **Async-trait `AnomalyRule`.** flowscope drivers are sync;
  netring's `AnomalyRule` stays sync. Users wanting async I/O
  fan events to a channel and process there.
- **`PacketBackend` unification** (AF_PACKET + AF_XDP).
  Tracked in `upstream-tracking.md`.
- **Removing the legacy `SessionStream` / `DatagramStream`
  aliases.** Keep in 0.18 as deprecated; delete in 0.19.
- **`flowscope::layers` adoption** for richer per-packet
  introspection. Not a current pain point.
- **Pipeline-level emit integration** — feeding events
  directly through `FlowEventNdjsonWriter` from inside
  `ProtocolMonitor`. Would couple netring to one format;
  skip.
- **eBPF correlator front-end.** Still out of scope.
- **Suricata-compatible rule DSL.** Still out of scope.
- **Tracing-side richer integration.** `emit_tracing()` is
  enough.
