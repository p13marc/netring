# Writing your own anomaly detector

A practical guide to detector design on the declarative
[`Monitor`](../src/monitor/mod.rs) API: how a detector is wired, what
the state primitives are good for, which engine events are worth
handling, how to test a detector offline, and how to debug one that
doesn't fire when you expect it to.

Working code for every pattern here lives in `examples/monitor/`
(`port_scan`, `beacon_detector`, `dga_query`, `lateral_movement`,
`net_diagnostic`, `detector_macro`, …) and `examples/anomaly/`.

> Before 0.22 detectors were `AnomalyRule` impls driven by an
> `AnomalyMonitor` over `ProtocolEvent`s. That harness is gone; see
> `docs/MIGRATING_0.21_TO_0.22.md` if you are porting one.

---

## 1. Anatomy

A detector is one or more **handlers** registered on a
`MonitorBuilder`. A handler receives a typed event — an L7 message
(`Http`, `Dns`, `Tls`, …) or a lifecycle event (`FlowStarted<Tcp>`,
`FlowEnded<Udp>`, `AnyFlowAnomaly`, `ParserClosed<Http>`, …) — and,
with `on_ctx`, a `&mut Ctx` for state and emission:

```rust
use std::time::Duration;
use netring::prelude::*;

Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()
    .protocol::<Http>()
    .on_ctx::<Http>(|msg: &flowscope::http::HttpMessage, ctx: &mut Ctx<'_>| {
        if let flowscope::http::HttpMessage::Request(req) = msg
            && req.path.starts_with(b"/.env")
        {
            ctx.emit("HttpSecretProbe", Severity::Warning)
                .with("path", String::from_utf8_lossy(&req.path).into_owned())
                .emit();
        }
        Ok(())
    })
    .sink(StdoutSink::default())
    .build()?
    .run_for(Duration::from_secs(60))
    .await?;
```

- `.on::<E>(|payload| …)` — payload only; `.on_ctx::<E>(|payload, ctx| …)`
  — with context. Registering a handler for a protocol you did not
  `.protocol::<P>()` is a `build()` error.
- `ctx.emit(kind, severity)` starts an anomaly stamped with the event's
  timestamp; `.with(label, value)` / `.with_metric(label, f64)` /
  `.with_key(&key)` add fields; `.emit()` writes it to the sink chain.
  The writer is stack-only — no allocation for up to 8 observations and
  8 metrics.
- `ctx.flow` is the event's flow key; for L7 messages `ctx.side()` /
  `ctx.orientation()` say which peer sent it (0.31).
- `netring::detector!` (match + emit on one event) and
  `netring::pattern_detector!` (feed a `DetectorScore`, emit on a
  verdict) are sugar for the common shapes — see
  `examples/monitor/detector_macro.rs` and `dga_query.rs`.

Handlers run on the capture task, in event order, and must not block.
For I/O, use `on_async` / `on_effect` (see `docs/ASYNC_GUIDE.md`).

---

## 2. State primitives

| Need | Register | Use in a handler |
|---|---|---|
| Detector-wide state | `.state::<T>()` / `.state_init(|| T::new(..))` | `ctx.state_mut::<T>()` |
| "Is this rate too high?" | `.counter::<K>(window, bucket)` | `ctx.counter_mut::<K>().bump(k, ctx.ts)` / `.count(&k, ctx.ts)` |
| Per-flow state, freed with the flow | `.flow_state::<T>(idle_timeout)` | `ctx.flow_state_mut::<T>()` |
| "Did X happen recently?" | a `KeyIndexed<K, V>` inside your `.state` | `insert(k, v, ts)` / `get(&k, ts)` / `drain_expired(now)` |

### `TimeBucketedCounter<K>` — rates

Bucketed sliding window: `bump` is O(1), `count` sums the buckets
inside the window. Pick `bucket` ≈ window / 10 — finer buckets cost
memory, coarser ones make the window edge fuzzy.

```rust
.counter::<std::net::IpAddr>(Duration::from_secs(10), Duration::from_secs(1))
.on_ctx::<Dns>(|msg: &flowscope::dns::DnsMessage, ctx: &mut Ctx<'_>| {
    let (Some(key), flowscope::dns::DnsMessage::Query(_)) = (ctx.flow, msg) else {
        return Ok(());
    };
    let src = key.a.ip(); // pick the client side for your topology
    let now = ctx.ts;
    let counter = ctx.counter_mut::<std::net::IpAddr>();
    counter.bump(src, now);
    if counter.count(&src, now) == 51 {
        ctx.emit("DnsQueryBurst", Severity::Warning)
            .with("src", src.to_string())
            .emit();
    }
    Ok(())
})
```

(Emitting on `== threshold + 1` fires once per burst without an
"already alerted" set.)

### `KeyIndexed<K, V>` — correlation with a TTL

A map whose entries expire `ttl` after insertion. Use it for "A, then
B within T": insert on A, look up on B; and for "A, and **no** B
within T": insert on A, remove on B, and `drain_expired(now)` from a
tick — what's left expired without its B.

### Per-flow state

`ctx.flow_state_mut::<T>()` lazily creates `T::default()` for the
event's flow. Since 0.31 the slot is freed when the flow ends (after
its `FlowEnded` handlers ran) and on the monitor's sweep; before, it
lived for the whole run.

### Decision rule

- Counting occurrences per key → `TimeBucketedCounter`.
- Remembering a fact about a key for a while → `KeyIndexed`.
- Accumulating over one flow → `flow_state`.
- Anything global (a scorer, a model, a baseline) → `state`.

---

## 3. Severity

| Severity | Meaning | Typical routing |
|---|---|---|
| `Info` | Observation worth recording (new SNI, first-seen host) | logs only |
| `Warning` | Suspicious, needs context (scan, burst, DGA-like name) | dashboard |
| `Error` | Likely malicious or broken (DCSync bind, cert mismatch) | alerting |
| `Critical` | Act now (known-bad IOC hit, credential dump) | paging |

Keep `kind` stable across versions — it is the join key downstream
(Prometheus labels, SIEM rules, dedupe).

---

## 4. Events, flow ends and ticks

- **Per event** — L7 message and lifecycle handlers. This is where
  most detection happens.
- **At flow end** — `FlowEnded<P>` carries the reason (`Fin`, `Rst`,
  `IdleTimeout`, `Evicted`, `ForceClosed`) and the final `FlowStats`.
  Flows end for **transport** reasons only; a parser giving up does
  not end the flow (see §5).
- **Periodically** — `.tick_ctx(period, |ctx| …)` (or `.tick` /
  `.on::<Tick>`). Use it for "absence" detectors (`drain_expired`),
  baselines, and periodic summaries. `ctx.ts` in a tick is packet
  time: live, the last packet's time plus the wall time since; on
  replay, ticks are scheduled on capture time (0.31 — they never ran
  on replay before).

The monitor sweeps its flow table on `sweep_interval`: idle flows end
(`FlowEnded { reason: IdleTimeout }`), parsers get `on_tick`, and
out-of-order reassembly holes expire. Live, that runs on a timer; on
`replay()` it runs on **packet time**, so an idle flow ends where it
went idle in the capture, not at the end of the file (0.31 — before,
the Monitor never swept).

Delivery order is the engine's: a flow's messages come before its
`FlowEnded`, including the ones a parser flushes when the connection
closes.

---

## 5. Engine events worth handling

The session engine reports what it could not do. A detector that
ignores these is blind in exactly the places an attacker (or a lossy
tap) makes interesting.

| Event | When | What it means for your detector |
|---|---|---|
| `AnyFlowAnomaly` | reassembly gaps, retransmissions with different bytes, out-of-window segments, buffer / memcap limits, eviction pressure | registering a handler turns anomaly reporting on (`MonitorBuilder::emit_anomalies` to force it either way) |
| `ParserClosed<P>` | once per (parser, flow): early when the parser stopped — malformed input (`ParseError`), finished (`ParserDone`), a gap it can't bridge (`StreamGap`) — or, at the flow's end, right before `FlowEnded` with the flow's reason | after an early close: no more `P` messages from this flow, though the flow continues |
| `ParserSideStopped<P>` | `P`'s parser stopped reading **one side** (a gap, or that side's buffer cap) | the other side is still parsed |

`ParserClosed<Http>` reaches the HTTP parser's protocol (0.31 — it
used to be routed by transport only, so it never fired for `Http`);
`ParserClosed<Tcp>` still fires for every TCP parser. Evasion-minded
detectors should treat `TcpRexmitInconsistency` anomalies (a
retransmission carrying different bytes) as a signal of their own.

---

## 6. Cross-protocol detectors

Register every protocol the detector reads and keep the correlation
state in `.state`:

```rust
#[derive(Default)]
struct Resolved(netring::correlate::KeyIndexed<std::net::IpAddr, String>);

Monitor::builder()
    .interface("eth0")
    .protocol::<Udp>()
    .protocol::<Tcp>()
    .protocol::<Dns>()
    .state_init(|| Resolved(netring::correlate::KeyIndexed::new(Duration::from_secs(300))))
    .on_ctx::<Dns>(|msg: &flowscope::dns::DnsMessage, ctx: &mut Ctx<'_>| {
        if let flowscope::dns::DnsMessage::Response(r) = msg {
            let ts = ctx.ts;
            let qname = r.questions.first().map(|q| q.name.to_string()).unwrap_or_default();
            for ip in r.answers.iter().filter_map(|a| a.ip()) {
                ctx.state_mut::<Resolved>().0.insert(ip, qname.clone(), ts);
            }
        }
        Ok(())
    })
    .on_ctx::<FlowStarted<Tcp>>(|evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
        let ts = ctx.ts;
        let dst = evt.key.b.ip(); // pick the server side for your topology
        if ctx.state_mut::<Resolved>().0.get(&dst, ts).is_none() {
            ctx.emit("TcpToUnresolvedIp", Severity::Info)
                .with("dst", dst.to_string())
                .emit();
        }
        Ok(())
    })
```

(`a.ip()` stands for however your DNS answer type exposes an
address.) For protocols on non-standard ports, markers with
`Dispatch::Signature` (e.g. `Http2`) probe every TCP flow — mind the
cost described on the marker.

---

## 7. Testing a detector

Test against **frames**, through the real engine, with pcap replay —
no privileges needed, and the Monitor runs exactly as it would live
(sweeps on packet time, same ordering, same parser events).

```rust
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
use netring::anomaly::sink::AnomalySink;
use netring::prelude::*;

/// Collects the kinds a detector emits.
struct Kinds(Arc<Mutex<Vec<&'static str>>>);

impl AnomalySink for Kinds {
    fn write(
        &mut self,
        kind: &'static str,
        _: Severity,
        _: flowscope::Timestamp,
        _: Option<&dyn netring::anomaly::Key>,
        _: &[(&'static str, std::borrow::Cow<'_, str>)],
        _: &[(&'static str, f64)],
    ) {
        self.0.lock().unwrap().push(kind);
    }
}

fn pcap(frames: &[(Duration, Vec<u8>)]) -> tempfile::NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let file = tempfile::NamedTempFile::new().unwrap();
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).unwrap();
    for (ts, f) in frames {
        w.write_packet(&PcapPacket::new_owned(*ts, f.len() as u32, f.clone())).unwrap();
    }
    file
}

#[tokio::test(flavor = "current_thread")]
async fn fires_on_a_dns_burst() {
    let frames: Vec<_> = (0..60)
        .map(|i| (
            Duration::from_millis(1_000 + i * 10),
            ipv4_udp([10, 0, 0, 1], [10, 0, 0, 53], 40_000 + i as u16, 53, &dns_query("x.test")),
        ))
        .collect();
    let file = pcap(&frames);
    let kinds = Arc::new(Mutex::new(Vec::new()));
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .protocol::<Dns>()
        // … the detector's registrations …
        .sink(Kinds(Arc::clone(&kinds)))
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(*kinds.lock().unwrap(), ["DnsQueryBurst"]);
}
```

(`dns_query` builds a DNS query payload; `test_frames` needs flowscope's
`test-helpers` feature in `[dev-dependencies]`.) Working examples of
this pattern: `tests/monitor_parser_routing.rs` (parser events, side,
anomalies), `tests/monitor_lifecycle_replay.rs` (idle ends on packet
time, per-flow state release, message-before-end ordering, sink
flush), `tests/transport_routing_replay.rs`.

To test the gap / loss paths, drop or reorder frames — the engine
reports exactly what a lossy tap would produce.

### Debug a detector that doesn't fire

1. **Not registered.** A handler for `Http` does nothing without
   `.protocol::<Http>()`, and `build()` tells you. A handler for
   `FlowStarted<Tcp>` needs `.protocol::<Tcp>()`.
2. **The parser gave up.** Add a `ParserClosed<P>` /
   `ParserSideStopped<P>` handler and an `AnyFlowAnomaly` handler:
   malformed input, a gap, or a buffer cap stops the messages you are
   waiting for.
3. **Time.** Counters and `KeyIndexed` take the *event* timestamp
   (`ctx.ts`); mixing in wall-clock time breaks replay. Ticks carry
   packet time too (live: the packet clock; replay: scheduled on
   capture time), so `ctx.ts` is the one clock to use everywhere.
4. **Alert-once state that never re-arms** — a `HashSet` of alerted
   keys with no expiry fires once per process lifetime.

---

## 8. Production deployment

- **Sinks.** `StdoutSink` (human), `StdoutJsonSink` (`serde`, one JSON
  object per line for Vector / Fluentd / Loki), `EveSink`
  (`eve-sink`, Suricata EVE), `TracingSink`, `ChannelSink` (hand
  `OwnedAnomaly` values to your own task), `MetricsSink` (`metrics`),
  and OTLP / Kafka in `netring-exporters`. `.sink(...)` sets one;
  `Tee` fans out.
- **Layers** wrap the sink chain; the first `.layer(..)` is
  outermost: `MinSeverity`, `DedupeAnomalies::within(..)`,
  `RateLimitAnomalies`, `Sample`.
- **Backpressure.** Sinks are called inline. A slow destination
  (network, database) belongs behind `ChannelSink` + a bounded consumer
  that drops with a counter — never block the capture task.
- **Shutdown.** Sinks and exporters are flushed when the run ends, on
  every exit path (0.31).

---

## 9. Common false-positive patterns

Every detector has a "looks anomalous, isn't" case. Document yours;
allow-list when appropriate.

| Detector | Common FP |
|---|---|
| DNS query burst | mDNS / DNS-SD clients legitimately query at high rates |
| Resolved-but-no-connection | browser DNS prefetch |
| Slow / truncated TLS handshake | captive portals, probe traffic |
| Lateral movement | k8s leader election, SMB browsing, broadcast services |
| Unexplained RST after ICMP | peer-side RSTs at the end of long-lived flows |
| TCP / TLS to an unresolved IP | `/etc/hosts` entries, hard-coded service IPs |
| Reassembly-gap anomalies | a lossy tap or SPAN port, not an attacker — check `CaptureStats` drops first |

Surface the anomaly, and pair it with operator-side allow-lists (CIDR
exclusions, hostname patterns, known service registries).

---

## 10. Mapping to MITRE ATT&CK

Label each detector with the technique(s) it covers — the detector
registry does it for registered detectors (`DetectorKind` carries the
ATT&CK ids), or add it yourself as an observation so it reaches the
SIEM:

```rust
ctx.emit("DnsQueryBurst", Severity::Warning)
    .with("mitre", "T1071.004")
    .emit();
```

| Detector | Technique |
|---|---|
| DNS query burst | T1071.004 (DNS), T1568.002 (DGA, at high cardinality) |
| Resolved-but-no-connection | T1071.004, possible DNS tunnelling |
| Slow TLS handshake | T1573.002 (possible MITM / DPI) |
| Lateral movement | T1021 (Remote Services), T1018 (Remote System Discovery) |
| TCP / TLS to an unresolved IP | T1571 (Non-Standard Port), T1090 (Proxy) |

---

## Further reading

- `examples/monitor/` and `examples/anomaly/` — working detectors.
- `docs/discoverability.md` — which builder method / event to reach for.
- `docs/ASYNC_GUIDE.md` — async handlers and effects.
- flowscope's docs — the parsers' message types and the engine's
  gap / close semantics.
