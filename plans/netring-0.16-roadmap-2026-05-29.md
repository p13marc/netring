# netring 0.16 roadmap — anomaly-correlation as a first-class concern

**Date:** 2026-05-29
**Author:** netring maintainer (self-retrospective)
**Status:** 🟢 **9 of 14 items shipped as of 2026-06-03.** N5/N6/N12
carried to [`netring-0.18-roadmap-2026-06-03.md`](./netring-0.18-roadmap-2026-06-03.md).

**Context:** roadmap document distilled from
1. concrete friction writing the four real-life L7 examples
   committed in `9777eb7`
2. the new strategic direction: **netring is being built as the
   substrate for applications that correlate multiple
   protocols to deduce network anomalies** (DNS-failure cascades,
   slow-TLS-with-fast-DNS, ICMP-error-explained-TCP-resets,
   lateral-movement detection, …).

**Scope rule:** backward-incompatible breaks are explicitly
allowed; pre-1.0; releases ship in lockstep with flowscope.

---

## Status — what shipped vs what carried

Run a `git log --oneline 22f61af..master -- netring/` to see the
~15 commits that landed this roadmap.

| Item | Status | Shipped in |
|---|---|---|
| **N1** Bump flowscope 0.4 → 0.6 | ✅ done | netring 0.16 (commit `6014e0f`) |
| **N2** Fix over-verbose BPF in L7 examples | ✅ done | `6014e0f` |
| **N3** CI smoke tests for examples | 🟡 partial | smoke-tested via `tests/anomaly_monitor_smoke.rs` + `tests/anomaly_pcap_replay.rs` (5 + 2 tests). Full example smoke-via-pcap still pending. |
| **N4** Drop `HashMap<K, L4Proto>` workaround | ✅ done | netring 0.17 (commit `502a484`, unblocked by flowscope 0.7) |
| **N5** Collapse onto flowscope drivers | ❌ deferred | Carried to 0.18 — multi-day internal refactor |
| **N6** `AsyncCapture::broadcast(n)` | ❌ deferred | Carried to 0.18 — design-heavy |
| **N7** `ProtocolMonitor` + builder | ✅ done | netring 0.16 (commit `7b53291`) |
| **N8** `ProtocolEvent<K>` + `ProtocolMessage` | ✅ done | `7b53291` |
| **N9** `AnomalyMonitor<K>` + `AnomalyRule` trait | ✅ done | netring 0.16 (commit `f114b2a`) |
| **N10** 5 reference detectors | ✅ done | All 5 + 2 bonus shipped. See "deliverables" below. |
| **N11** `BpfFilter::builder().ports([...])` | ✅ done | `6014e0f` |
| **N12** `with_message_tap` for L7 streams | ❌ deferred | Carried to 0.18 — blocked on flowscope `serde` feature (G5 in `flowscope-0.8-feedback`) |
| **N13** Synthetic traffic companion | ✅ done | netring 0.17 (commit `bead0e9`) |
| **N14** `--json` output flag | ✅ done | `to_json_line()` on `Anomaly<K>` + `NETRING_JSON=1` env-var toggle (commit `d2e5adf`) |

### N10 reference-detector deliverables

The plan called for 5 detectors; 8 shipped:

| Example | Demonstrates |
|---|---|
| `dns_query_burst.rs` | `TimeBucketedCounter` per-source rate |
| `dns_resolved_no_connection.rs` | `KeyIndexed::drain_expired` cross-protocol |
| `anomaly_monitor_demo.rs` | Two rules composed on `AnomalyMonitor` |
| `slow_tls_handshake.rs` | TLS ClientHello → ServerHello timing |
| `lateral_movement.rs` | Per-source host-pair fan-out |
| `icmp_explained_drop.rs` | `IcmpInner` cross-protocol (flowscope 0.7) |
| `pcap_replay_anomaly.rs` *(bonus)* | Drive `AnomalyMonitor` from a pcap file |
| `tls_to_unresolved_ip.rs` *(bonus)* | **Three-protocol correlator** — Flow + DNS + TLS |

### Bonus items shipped, not on the original plan

- `impl Display for Anomaly<K>` + `impl Display for Severity` —
  drops the per-example `print_anomaly` helpers.
- `From<flowscope::event::Severity> for netring::Severity` +
  `FlowAnomalyRule` — lifts flow-tracker anomalies through the
  same `Vec<Anomaly<K>>` pipeline as user-defined rules.
- `Anomaly::to_json_line()` — hand-rolled RFC 8259 JSON (no
  serde dep). 4 escape-edge-case tests.
- README "Multi-protocol monitor + anomaly correlation" section
  with the full builder + custom-rule recipe.

---

> Companion to
> [`flowscope-0.7-feedback-2026-05-29.md`](./flowscope-0.7-feedback-2026-05-29.md).
> That document covers what flowscope should ship to support
> this roadmap. This document covers what netring should ship
> on top.

---

## At a glance

The roadmap has three parts:

| Part | Theme | Items |
|---|---|---|
| **I — Cleanup** | Fixes for the L7 examples I just shipped + bump to flowscope 0.6 | 5 items |
| **II — Single-capture multiplexing** | One `AsyncCapture`, N typed L7 parsers, one event stream | 3 items |
| **III — Anomaly correlation** | The new use case: cross-protocol detection of network anomalies as a first-class capability | 6 items + 5 example detectors |

| # | Proposal | Tier | Break? | Lives in |
|---|---|---|---|---|
| N1 | Bump `flowscope = "0.4"` → `"0.6"` (lockstep) | **High** | Lockstep break | netring 0.15 |
| N2 | Fix the over-verbose BPF filters in `http_session`/`dns_lookups`/`full_monitor` | **High** | No | netring 0.15 |
| N3 | CI smoke tests for examples via `AsyncPcapSource` | **High** | No | netring 0.15 |
| N4 | Drop the hand-rolled `HashMap<K, L4Proto>` workaround once flowscope F4 ships | Med | No (cleanup) | netring 0.16 |
| N5 | Drop netring's hand-rolled stream choreography once flowscope's `sweep_with_parsers` becomes the default | Med | Internal refactor | netring 0.16 |
| N6 | `AsyncCapture::broadcast(n)` — single-ring fan-out | **High** | Additive | netring 0.16 |
| N7 | `AsyncCapture::protocol_monitor()` — declarative multi-protocol builder | **High** | Additive | netring 0.16 |
| N8 | `ProtocolEvent<K>` — unified enum for ICMP/TCP/UDP/HTTP/TLS/DNS events | **High** | Additive (new type) | netring 0.16 |
| N9 | `AnomalyMonitor<K>` — keyed correlator harness on top of `ProtocolEvent` | **High** | Additive | netring 0.16 |
| N10 | `examples/anomaly/` directory + 5 reference detectors | **High** | No | netring 0.16 |
| N11 | `BpfFilter::builder().ports([...])` — multi-port OR shortcut | Med | Additive | netring 0.16 |
| N12 | `with_pcap_tap` for L7 streams (record parsed messages, not raw packets) | Med | Additive | netring 0.16 |
| N13 | `examples/util/synthetic_traffic.rs` — companion traffic generator for demos | Polish | No | netring 0.16 |
| N14 | `--json` flag pattern across examples; shared `output_event` helper | Polish | No | netring 0.16 |

---

# Part I — Cleanup (netring 0.15 hotfix)

## N1. Bump `flowscope = "0.4"` → `"0.6"`

**Observation.** netring's `Cargo.toml` still has
`flowscope = { version = "0.4", default-features = false }`.
flowscope shipped 0.5 (TCP retransmit classification +
`FlowTick` + `parser_kind`) and 0.6 (driver `S` resurrection,
anomaly split, `AsPacketView`, test_helpers, `finish()`,
`sweep_with_parsers`, …) since netring 0.14 froze its dep
version.

netring 0.15 is currently building against 0.4 by accident.
This is a substantial missed upgrade — half of the items
flagged in this roadmap are already done in flowscope 0.6 but
unreachable from netring until the bump.

**Proposal.** Bump to `flowscope = "0.6"`. Migration touch
points (from the flowscope 0.6 CHANGELOG):

1. **Anomaly variant rename** — `SessionEvent::Anomaly { key:
   Some(k), kind, ts }` → `SessionEvent::FlowAnomaly { key,
   kind, ts }`; `Anomaly { key: None, .. }` →
   `TrackerAnomaly { kind, ts }`. Same on `FlowEvent`.
   Touches `netring/src/async_adapters/{session,datagram}_stream.rs`
   (the forwarding logic added in netring 0.12) + every test
   fixture that destructures `Anomaly`.

2. **`SessionEvent::Application` gains `parser_kind` field**
   — needs `..` or explicit binding in pattern matches.
   Touches the netring forwarding paths + the new L7 examples
   (`http_session.rs`, `dns_lookups.rs`, `full_monitor.rs`,
   `async_pcap_sessions.rs`).

3. **`Reassembler::segment` gains `ts: Timestamp`** — netring
   doesn't implement `Reassembler` directly; the change is
   transparent.

4. **Driver `S` parameter** — netring's `session_stream` /
   `datagram_stream` build their own tracker dispatch, so the
   parameter is irrelevant to current code. After N5 below
   it becomes load-bearing.

5. **`AsPacketView` blanket impl** — netring's `OwnedPacket`
   can implement `AsPacketView` with three lines and feed
   `tracker.track(&owned)` directly. Cleanup in `PcapFlowStream`
   / `PcapSessionStream` / `PcapDatagramStream`.

**Effort.** ~half a day. ~5 forwarding sites + ~10 test
fixtures. **Risk.** Medium — touches the typed-event surface
that downstream code matches on. Mitigated by the staged
walkthrough in flowscope's CHANGELOG migration block.

## N2. Fix over-verbose BPF filters in the L7 examples

**Observation.** In commit `9777eb7` (the example reorg + L7
demos), three examples express "TCP and port {80, 8080}" as:

```rust
.tcp()
.dst_port(80)
.or(|b| b.tcp().src_port(80))
.or(|b| b.tcp().dst_port(8080))
.or(|b| b.tcp().src_port(8080))
```

That's four clauses for what `BpfFilter::builder().tcp().port(80)`
already matches in one (since `port()` matches src OR dst).
Correct version:

```rust
.tcp().port(80)
.or(|b| b.tcp().port(8080))
```

Same pattern in `dns_lookups` and `full_monitor`. The examples
are the canonical reference users will copy from — wrong
shape now is wrong shape forever.

**Proposal.** Patch three files, no API change. Pair with N11
(`ports([80, 8080])` shortcut) for the ultimate one-liner.

**Effort.** 10-line patch. **Risk.** None.

## N3. CI smoke tests for examples via `AsyncPcapSource`

**Observation.** CI runs `cargo build --examples` but the
binaries never execute. So:

- The over-verbose filter in N2 compiled fine.
- A future flowscope minor changing event ordering would
  silently break `full_monitor`'s `tokio::select!` arms.
- The whole `l7/` directory has no runtime coverage.

**Proposal.** Add `tests/example_smoke.rs` that for each L7
example (or each example with a synthetic-driveable input):

1. Opens an `AsyncPcapSource` over a fixture pcap.
2. Drives the example's *core logic* (refactored into a small
   `lib.rs` module per example, called by both the example
   `main` and the smoke test).
3. Asserts that at least one expected event type was emitted.

No CAP_NET_RAW needed since `AsyncPcapSource` doesn't open a
socket. Coverage extends to:

- `http_session`: pcap of a single GET request →
  `HttpMessage::Request` seen.
- `dns_lookups`: pcap of an A query + response → `Query` and
  `Response` (with non-`None` `elapsed`) seen.
- `multi_protocol_monitor`: pcap with one TCP + one UDP + one
  ICMP flow → three distinct `tag` strings observed.
- `full_monitor`: composite pcap → events from all three
  parsers.

**Effort.** ~30 LoC per example (refactor + smoke test). 2
days for the full sweep. **Risk.** Refactor surface — examples
get an extra layer of indirection. Acceptable.

## N4. Drop the `HashMap<K, L4Proto>` workaround once flowscope F4 ships

**Observation.** `multi_protocol_monitor.rs` and `full_monitor.rs`
maintain a side `HashMap<FiveTupleKey, L4Proto>` to recover the
L4 protocol on `FlowEvent::Ended` (which doesn't carry it).

flowscope F4 (proposed) adds `l4` to `Ended`. Once shipped,
delete the workaround from both examples. ~20 LoC simpler each.

**Effort.** Trivial. **Risk.** None.

## N5. Refactor netring streams onto flowscope's drivers

**Observation.** netring's `SessionStream`, `DatagramStream`,
`Multi{Session,Datagram}Stream` all hand-roll the tracker +
parser + reassembler choreography that flowscope's
`FlowSessionDriver` / `FlowDatagramDriver` now do natively
(post-0.6: with `S` parameter restored, with `sweep_with_parsers`
helper, with factory variants).

netring 0.14 had to hand-roll this because flowscope 0.4's
drivers were sealed against per-flow user state. flowscope 0.6
fixes that. So netring's three async stream types can collapse
into "thin async wrapper around `FlowSessionDriver`" /
"thin async wrapper around `FlowDatagramDriver`" — same shape
as `PcapSessionStream` / `PcapDatagramStream` (which I already
wrote that way).

**Proposal.** Internal refactor. Each stream becomes:

```rust
pub struct SessionStream<S, E, F> {
    cap: AsyncCapture<S>,
    driver: FlowSessionDriver<E, F::Parser>,
    pending: VecDeque<SessionEvent<...>>,
    /* tap, dedup, monotonic_ts as before */
}

impl<...> Stream for SessionStream<...> {
    fn poll_next(...) {
        // 1. Drain pending. 2. Pull next packet from cap. 3.
        //    driver.track(&view). 4. Append events.
    }
}
```

Eliminates ~300 LoC of duplicated machinery (parser dispatch,
reassembler factory, `process_session_event`, sweep tick
choreography, `on_tick` forwarding). All of it lives in
flowscope's driver now.

**Effort.** 2–3 days (refactor + ensure all observable
behavior matches). **Risk.** Medium — touches the most-used
async surface in netring. Stage as one PR per stream type with
full test sweep between each.

---

# Part II — Single-capture multiplexing

The L7 examples revealed an architectural awkwardness:
`full_monitor.rs` runs **three independent `AsyncCapture`s on
the same interface** (each with its own kernel ring) because
each L7 specialization wants its own packet stream. That's ~3×
memory for the demo. The right pattern is **one capture, N
filtered+typed sub-streams, joined into one event surface**.

## N6. `AsyncCapture::broadcast(n)`

**Observation.** Today, multi-protocol monitoring needs N
captures (one per protocol). The kernel does N× the work; the
process does N× the memory.

`FlowBroadcast<K>` already exists at the flow-event layer (plan
50.6 / 0.8.0) — multiple subscribers off one `flow_stream`. The
missing piece is the analogous primitive at the **packet
layer**: take one `AsyncCapture`, fan out to N
`AsyncCapture`-shaped consumers, each backed by a tokio
`broadcast` channel.

**Proposal.**

```rust
impl<S: PacketSource + AsRawFd> AsyncCapture<S> {
    /// Fan one capture out to N independent consumers backed by a
    /// tokio broadcast channel. Each consumer can build its own
    /// flow_stream / session_stream / datagram_stream chain on
    /// the broadcast handle.
    ///
    /// Cost: one allocation per packet per consumer (broadcast
    /// channels hold owned buffers). For high-throughput live
    /// capture this is heavier than running multiple kernel rings;
    /// for moderate loads (< 1 Mpps) it's vastly cheaper.
    pub fn broadcast(self, channel_capacity: usize, subscribers: usize)
        -> Vec<BroadcastCapture>;
}

pub struct BroadcastCapture {
    rx: tokio::sync::broadcast::Receiver<Arc<OwnedPacket>>,
}

impl PacketSource for BroadcastCapture { /* ... */ }
impl AsRawFd for BroadcastCapture { /* eventfd-backed readiness */ }
```

`BroadcastCapture` implements the same trait surface as
`AsyncCapture<S>` (`PacketSource + AsRawFd`), so the existing
builder chain (`.flow_stream(ext).session_stream(parser)`)
composes without change.

The `Arc<OwnedPacket>` is the trade-off: we sacrifice mmap
zero-copy in exchange for arbitrary fan-out. Documented
loudly. For users who need both N consumers AND zero-copy,
the `AsyncMultiCapture::open_workers` + kernel fanout path is
still the right answer.

**Effort.** ~200 LoC + tests. ~2 days. **Risk.** Low — tokio
broadcast is well-trodden.

## N7. `AsyncCapture::protocol_monitor()` builder

**Observation.** `full_monitor.rs` is ~200 LoC of boilerplate
to set up three streams. Most of that's mechanical: build a
BPF filter, build a capture, attach the right parser, drive
`tokio::select!`. A declarative builder would replace it with
~10 lines.

**Proposal.**

```rust
impl<S: PacketSource + AsRawFd> AsyncCapture<S> {
    /// Build a multi-protocol monitor from this capture.
    /// Returns a `ProtocolMonitor` whose `next()` yields a
    /// unified `ProtocolEvent<K>` across all enabled protocols.
    ///
    /// Internally uses `broadcast(n)` to share the single
    /// capture across the enabled per-protocol streams.
    pub fn protocol_monitor<E>(self, extractor: E) -> ProtocolMonitorBuilder<S, E>
    where E: FlowExtractor;
}

pub struct ProtocolMonitorBuilder<S, E> { /* private */ }

impl<S, E> ProtocolMonitorBuilder<S, E> {
    /// Track plain flow events (Started, Established, Ended, …)
    /// for every L4 protocol. Always enabled.
    pub fn flow(self) -> Self;

    /// Enable ICMP parsing (requires `flowscope/icmp` — proposal F1).
    pub fn icmp(self) -> Self;

    /// Enable HTTP parsing on TCP/{80, 8080, ...}. Default: [80, 8080].
    pub fn http(self) -> Self;
    pub fn http_on_ports(self, ports: &[u16]) -> Self;

    /// Enable TLS handshake observation on TCP/{443, 8443, ...}.
    pub fn tls(self) -> Self;
    pub fn tls_on_ports(self, ports: &[u16]) -> Self;

    /// Enable DNS on UDP/53 (+ TCP/53 for the DnsTcp parser).
    pub fn dns(self) -> Self;
    pub fn dns_on_ports(self, ports: &[u16]) -> Self;

    /// Custom session parser on a port set.
    pub fn session<P: SessionParser>(self, parser: P, ports: &[u16]) -> Self;

    /// Custom datagram parser on a port set.
    pub fn datagram<P: DatagramParser>(self, parser: P, ports: &[u16]) -> Self;

    pub fn build(self) -> ProtocolMonitor<E::Key>;
}

pub struct ProtocolMonitor<K> { /* impl Stream<Item = ProtocolEvent<K>> */ }
```

Callsite:

```rust
let mut monitor = AsyncCapture::open("eth0")?
    .protocol_monitor(FiveTuple::bidirectional())
    .flow()
    .icmp()
    .http()
    .dns()
    .tls()
    .build();

while let Some(evt) = monitor.next().await {
    // evt: ProtocolEvent<FiveTupleKey>
}
```

**Effort.** ~400 LoC + tests + new example. ~3 days. **Risk.**
Medium — the API has to be right, since it'll be the
recommended entry point for the anomaly-correlation use case.

## N8. `ProtocolEvent<K>` — unified event type

**Observation.** `ProtocolMonitor` needs a single event type
spanning all protocols. Today the user writing
`tokio::select!` over N streams uses N pattern arms with N
different event types. A unified enum collapses that:

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProtocolEvent<K> {
    /// Plain flow lifecycle (Started, Established, StateChange,
    /// Tick, Ended, FlowAnomaly, TrackerAnomaly). Always emitted
    /// when `protocol_monitor().flow()` is enabled.
    Flow(flowscope::FlowEvent<K>),

    /// HTTP/1.x request or response from any HTTP-port flow.
    Http {
        key: K,
        side: flowscope::FlowSide,
        message: flowscope::http::HttpMessage,
        ts: Timestamp,
    },

    /// TLS handshake observation.
    Tls {
        key: K,
        side: flowscope::FlowSide,
        message: flowscope::tls::TlsMessage,
        ts: Timestamp,
    },

    /// DNS query/response/unanswered.
    Dns {
        key: K,
        side: flowscope::FlowSide,
        message: flowscope::dns::DnsMessage,
        ts: Timestamp,
    },

    /// ICMP message (echo, unreachable, time-exceeded, …) —
    /// requires flowscope F1.
    Icmp {
        key: K,
        side: flowscope::FlowSide,
        message: flowscope::icmp::IcmpMessage,
        ts: Timestamp,
    },

    /// Custom L7 message emitted by a `.session(...)` / `.datagram(...)`
    /// parser the user registered. Stringly-typed kind for routing.
    Custom {
        key: K,
        side: flowscope::FlowSide,
        kind: &'static str,
        message: Box<dyn std::any::Any + Send>,
        ts: Timestamp,
    },
}
```

The `Custom` variant uses `Box<dyn Any>` so users can register
arbitrary parser types without infecting `ProtocolEvent`'s
generic shape. The `kind` string lets consumers route via
`match evt.kind() { "myproto" => downcast::<MyMsg>(message), ... }`.

For users who want full type safety, an alternative shape:
make `ProtocolEvent<K, M = ()>` with a user-supplied sum-type
`M` covering their custom messages. Less ergonomic but no
`Any`. Decide after writing the example detectors.

**Effort.** Bundled with N7. **Risk.** API design — be
prepared to iterate on the `Custom` shape.

---

# Part III — Anomaly correlation as a first-class concern

This is the strategic centerpiece. netring should make
"correlate multiple protocols to deduce network anomalies" a
**twenty-line program**, not a "spend three days
re-implementing time-bucketed counters and key-indexed caches"
exercise.

## Use cases we want easy

These are real scenarios drawn from production-monitoring
literature (Suricata rules, Zeek scripts, BGP/DNS health
dashboards):

| # | Anomaly | Trigger | Severity |
|---|---|---|---|
| A1 | **DNS resolves but no connection follows** | `DnsMessage::Response` with `rcode=NoError` and at least one A/AAAA answer; no subsequent `Flow::Started` to that IP within 5s | Warn |
| A2 | **TCP RSTs returned for SYNs that DNS just resolved** | `Dns::Response` → IP X → `Flow::Started` to X → `Flow::Ended { reason: Rst }` within 2s of `Started` | Error |
| A3 | **Slow TLS handshake** | TLS ClientHello → ServerHello round-trip > threshold (e.g. 500ms); annotate with TCP RTT for the same flow if known | Info/Warn |
| A4 | **DNS query rate burst** | Source IP issues > N queries in T seconds | Warn |
| A5 | **Lateral movement** | Internal IP A → Internal IP B on unusual port (SMB/RDP/SSH); A hasn't talked to B in the last hour | Critical |
| A6 | **ICMP-explained drop** | `Flow::Ended { Rst }` correlated with an `Icmp::DestinationUnreachable { Inner: matching flow }` within ±1s | Info (diagnostic) |
| A7 | **Asymmetric flow** | Initiator sent ≥ N bytes; responder sent 0 bytes for > T seconds | Warn |
| A8 | **DNS poisoning** | Same query name, different answers from two resolvers within ms | Error |
| A9 | **HTTP-on-non-HTTP-port** | HTTP parser successfully extracts a request on a port outside common HTTP set | Info |
| A10 | **TCP retransmit storm** | `AnomalyKind::RetransmittedSegment.count > N` per (flow, side) — flowscope 0.5 surfaces the data, netring formalises the rule | Warn |

Most of these are 2–3 building blocks composed together:
**TimeBucketedCounter** (A4), **KeyIndexed**: name→IPs and
IP→name caches (A1, A2, A8), **SequenceDetector**: A-then-B-or-
emit-C (A1, A2, A3, A6), **threshold**: simple aggregate over
window (A10).

## N9. `AnomalyMonitor<K>` — keyed correlator harness

**Observation.** Items A1–A10 above each need a small piece
of state, an event handler, and an emit channel. Today you'd
build that ad-hoc per detector. A reusable harness collapses
the per-detector code to ~20 LoC.

**Proposal.**

```rust
pub struct AnomalyMonitor<K> {
    rules: Vec<Box<dyn AnomalyRule<K>>>,
    state: SharedState<K>,
    pending: VecDeque<Anomaly<K>>,
}

pub trait AnomalyRule<K>: Send + 'static {
    /// Inspect each event. Return any anomalies that fire.
    fn observe(&mut self, evt: &ProtocolEvent<K>, state: &mut SharedState<K>)
        -> SmallVec<[Anomaly<K>; 1]>;
    /// Called on a sweep tick — for time-bound detections.
    fn on_tick(&mut self, now: Timestamp, state: &mut SharedState<K>)
        -> SmallVec<[Anomaly<K>; 4]>;
    /// Display name for logs / metrics.
    fn name(&self) -> &'static str;
}

#[derive(Debug, Clone)]
pub struct Anomaly<K> {
    pub kind: &'static str,
    pub severity: Severity,
    pub key: Option<K>,
    pub ts: Timestamp,
    pub context: AnomalyContext<K>,
}

/// Per-detector context: relevant observations that triggered
/// the anomaly. Serializable so downstream sinks (JSON, Kafka)
/// can carry the full story.
#[derive(Debug, Clone)]
pub struct AnomalyContext<K> {
    pub observations: Vec<Observation<K>>,
    pub metrics: HashMap<&'static str, f64>,
}

pub struct SharedState<K> {
    pub host_seen: KeyIndexed<IpAddr, HostObservations>,
    pub dns_cache: KeyIndexed<String, Vec<IpAddr>>,
    pub ip_to_name: KeyIndexed<IpAddr, String>,
    pub query_counts: TimeBucketedCounter<IpAddr>,
    /* extend as new detectors need new buckets */
}
```

The `SharedState` is the cross-detector indices. Adding a new
detector usually means adding one or two pre-built primitives
to `SharedState` and writing the `observe`/`on_tick` logic.

If flowscope F6 (the `correlate` module) ships, the
`SharedState` primitives come from there. If not, netring
implements them itself.

Usage:

```rust
let mut monitor = AsyncCapture::open(iface)?
    .protocol_monitor(FiveTuple::bidirectional())
    .flow().icmp().http().tls().dns()
    .build();

let mut anomaly_monitor = AnomalyMonitor::new()
    .with_rule(DnsWithoutConnectionRule::with_timeout(Duration::from_secs(5)))
    .with_rule(SlowTlsHandshakeRule::with_threshold(Duration::from_millis(500)))
    .with_rule(LateralMovementRule::with_internal_subnets(&["10.0.0.0/8"]))
    .with_rule(IcmpExplainedDropRule::default())
    .build();

while let Some(evt) = monitor.next().await {
    for anomaly in anomaly_monitor.observe(&evt) {
        match anomaly.severity {
            Severity::Critical => alert(&anomaly),
            Severity::Error => log_error(&anomaly),
            _ => log_info(&anomaly),
        }
    }
}
```

**Effort.** ~400 LoC for the harness + state types. ~3 days
(including doc writing). **Risk.** API design — iterate after
writing the example detectors.

## N10. `examples/anomaly/` directory + 5 reference detectors

**Observation.** The harness in N9 is only worth shipping if
the example detectors prove it ergonomic. Five concrete
detectors covering the canonical correlation patterns:

| Example | Demonstrates |
|---|---|
| `dns_without_connection.rs` | `SequenceDetector` shape (A1); KeyIndexed `name→IPs` |
| `slow_tls_handshake.rs` | Threshold + cross-protocol (A3); pulls TCP RTT from `FlowStats` and TLS handshake time from event timestamps |
| `dns_query_burst.rs` | `TimeBucketedCounter` (A4); per-source-IP rate |
| `icmp_explained_drop.rs` | Cross-protocol correlation (A6); uses ICMP's `Inner` for the flow lookup |
| `lateral_movement.rs` | Persistent state (A5); host-pair history index |

Each example is ~80 LoC (the rule definition) + standard
`protocol_monitor` boilerplate (~10 LoC).

**Effort.** ~80 LoC × 5 = 400 LoC + docs. ~2 days.

This **is the deliverable that justifies the rest of Part
III**. If users can read these five files and immediately
write their own anomaly detector, the architecture works. If
they can't, iterate on the harness shape.

---

# Part IV — Polish (deferrable)

## N11. `BpfFilter::builder().ports([...])` — multi-port OR

```rust
.tcp().ports([80, 8080, 8000, 3128])  // src OR dst in the set
.src_ports([80, 8080])
.dst_ports([443, 8443])
```

Compiles to a chain of JEQ + JA. The builder already has
`port()` for single src-or-dst port. Plural variants are
mechanical.

**Effort.** ~50 LoC. **Risk.** None.

## N12. `SessionStream::with_message_tap`

Plan 20's `with_pcap_tap` records raw packets before the
tracker. For L7 anomaly debugging the more useful thing is
to record **the parser's output** (JSON or a custom format)
so the trace can be replayed against an updated detector.

```rust
stream.with_message_tap(MessageTap::json(writer))
```

Useful for: "replay last week's HTTP messages against
my-detector-v2 to count anomalies pre-deploy."

**Effort.** ~150 LoC + tests. **Risk.** Low.

## N13. Synthetic traffic companion

`examples/util/synthetic_traffic.rs` — a small TX program that
emits representative ICMP/TCP/HTTP/DNS traffic on `lo` so the
L7 examples become self-demoable:

```
# Terminal A:
just synthetic-traffic lo
# Terminal B:
just full-monitor lo 30
```

**Effort.** ~150 LoC. **Risk.** None.

## N14. `--json` output flag across L7 examples

Production users pipe to grafana/prometheus/fluentd. A
shared `--json` flag + `output_event<W: Write>(evt, w)` helper
in `examples/util/` lets the L7 examples double as proof of
production-shaped output.

**Effort.** ~30 LoC per example + shared util module.

---

## Effort summary

| Part | Items | LoC | Risk | Days |
|---|---|---|---|---|
| **I — Cleanup** | N1–N5 | ~50 (deltas) | medium (event surface touch) | ~5 |
| **II — Multiplexing** | N6–N8 | ~700 | medium | ~5 |
| **III — Correlation** | N9–N10 | ~800 | medium-high (API design) | ~5 |
| **IV — Polish** | N11–N14 | ~400 | low | ~3 |

**Total: ~18 days of focused work**. Realistic phasing:

- **netring 0.15** (already in progress): N1, N2, N3 → bump dep
  + fix examples + smoke tests. 1–2 days.
- **netring 0.16**: N4–N10. The big one. ~10 days. Cuts at
  Part III completion if Part II takes longer than expected.
- **netring 0.17**: N11–N14 + whatever Part III RFC feedback
  suggests.

---

## Dependencies on flowscope

Item-level dependencies:

| netring item | depends on flowscope |
|---|---|
| N1 (bump 0.4 → 0.6) | flowscope 0.6 (shipped) |
| N4 (drop l4 workaround) | flowscope F4 (proposed, not shipped) |
| N5 (collapse onto drivers) | flowscope 0.6 (shipped) |
| N7 (`.icmp()` builder leg) | flowscope F1 — ICMP parser (proposed) |
| N8 (`ProtocolEvent::Icmp`) | flowscope F1 |
| N9 (correlator harness) | optional: flowscope F6 (`correlate` module) — netring can ship without and migrate later |
| N10 (example detectors) | flowscope F1 (for the ICMP detector) |
| N12 (message tap) | none |

The critical path is **flowscope F1 (ICMP parser)** + **flowscope
F4 (`Ended.l4`)**. Both small. Land in flowscope 0.7. netring 0.16
picks them up.

---

## Out of scope (deferred)

- **Suricata-compatible rule DSL.** The
  `AnomalyRule<K>` trait gives users a Rust-API shape. Adding
  a text-DSL ("alert tcp any any -> any 80 (msg:'...')") is
  Zeek/Suricata territory and a major project. Revisit if
  there's a concrete consumer.
- **eBPF-side correlator.** Anomaly detection at line rate by
  shipping the rules into eBPF kernel programs is an order of
  magnitude harder than the user-space version. Worth it for
  10G+ workloads; not the netring sweet spot today.
- **Long-term anomaly storage.** netring emits anomalies;
  archiving / querying them is the operator's pipeline
  (ClickHouse, Loki, …). Out of scope.
- **GUI / web dashboard.** Same — operator's concern.
- **Encrypted-traffic anomaly detection (machine-learning-shaped).**
  Different architecture (statistical features over flow
  metadata). Could compose with this roadmap later via a
  user-defined `AnomalyRule` that feeds a learned model, but
  shipping the ML pipeline isn't netring's job.

---

## What success looks like

After this roadmap lands, the following should be true:

1. **Writing a new anomaly detector is ~30 LoC**:

   ```rust
   struct MyDetector { /* state */ }
   impl AnomalyRule<FiveTupleKey> for MyDetector {
       fn observe(&mut self, evt: &ProtocolEvent<K>, state: &mut SharedState<K>)
           -> SmallVec<[Anomaly<K>; 1]> {
           // 20 lines of pattern matching + state lookups
       }
       fn on_tick(...) { ... }
       fn name(&self) -> &'static str { "my-detector" }
   }
   ```

2. **Single-capture multi-protocol monitoring is ~10 LoC**:
   ```rust
   let mut monitor = AsyncCapture::open("eth0")?
       .protocol_monitor(FiveTuple::bidirectional())
       .flow().icmp().http().dns().tls().build();
   while let Some(evt) = monitor.next().await {
       /* … */
   }
   ```

3. **The full `full_monitor` example collapses** to a
   thin wrapper over `protocol_monitor` instead of three
   captures + `tokio::select!`. Drop ~150 LoC.

4. **The `examples/anomaly/` directory** has the five reference
   detectors plus an index README. New users see real-life
   patterns, not toy demos.

5. **netring 0.16's CHANGELOG entry is the most exciting
   release since 0.13.0**.

---

## Closing

The L7 examples I just shipped (commit `9777eb7`) are decent
templates but reveal the architectural limits of the current
"chain one stream per protocol" pattern. Part II
(`protocol_monitor`) fixes the immediate ergonomics. Part III
(anomaly correlator) is the strategic differentiator — the
thing that turns netring from "fast packet capture with flow
tracking" into "the substrate for real network monitors".

Happy to draft individual RFC docs for any specific item.
Recommend starting from Part I (cleanup) since it's prerequisite
and unblocks the rest.
