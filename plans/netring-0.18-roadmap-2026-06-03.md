# netring 0.18 roadmap — carry-over + post-anomaly-toolkit polish

**Date:** 2026-06-03
**Author:** netring maintainer
**Predecessor:** [`netring-0.16-roadmap-2026-05-29.md`](./netring-0.16-roadmap-2026-05-29.md)
**Status:** 📝 drafted; awaiting flowscope 0.8 for the items
gated on G5 (serde).

**Scope rule:** backward-incompatible breaks are explicitly
allowed. Pre-1.0; releases ship in lockstep with flowscope.

---

## At a glance

The 0.16 roadmap shipped 9 of 14 items (plus 5 bonus polish
items). Three carried — N5 / N6 / N12 — because each is genuine
multi-day work that doesn't fit a one-session shipping cadence.
0.18 picks them up alongside new items that emerged from
shipping the 7-detector anomaly toolkit and the
[`flowscope-0.8-feedback`](./flowscope-0.8-feedback-2026-06-03.md)
round-3 retrospective.

| # | Proposal | Tier | Break? | Carry-over? |
|---|---|---|---|---|
| **O1** | `AsyncCapture::broadcast(n)` — single-ring fan-out | **High** | Additive (new API) | N6 |
| **O2** | Collapse session/datagram streams onto flowscope drivers | **Med** | Internal refactor (no API change) | N5 |
| **O3** | `with_message_tap` for L7 streams | **Med** | Additive | N12 (gated on flowscope G5) |
| **O4** | `serde::Serialize` for `Anomaly<K>` / `AnomalyContext` / `Severity` | **High** | Additive (gated on netring `serde` feature) | New |
| **O5** | `docs/WRITING_DETECTORS.md` — tutorial for the `AnomalyRule` trait | **Med** | Doc-only | New |
| **O6** | `benches/anomaly.rs` — perf characterization of the harness | **Med** | None (bench only) | New |
| **O7** | `examples/anomaly/replay_pcap_multi_proto.rs` — multi-protocol pcap replay using the packet-level loop | Polish | None (example) | New |
| **O8** | Lockstep bump to flowscope 0.8 (whenever it ships) | **High** | Breaking (likely field-add) | New (lockstep) |
| **O9** | `ProtocolMonitorBuilder::pcap(path)` — pcap entry alongside `.interface(name)` | **Med** | Additive | New |
| **O10** | `tracing::Subscriber`-friendly emission helper | Polish | Additive | New |

---

## O1. `AsyncCapture::broadcast(n)` — single-ring fan-out (N6)

**Observation.** `ProtocolMonitor` today opens *N* `AsyncCapture`s,
one per enabled protocol, each with its own kernel-side BPF
filter narrowing to that protocol's port set. Wire cost is N ×
ring memory + N kernel BPF evaluations per packet. For a typical
`.flow().http().dns().tls().icmp()` monitor on a busy box, that's
5 rings.

**Trade-off.** Per-ring filtering is *kernel-side fast* — each
ring sees only its subset, so user-space sees less. Broadcasting
inverts this: one wide ring (typically no filter at all), and
user-side filtering for each branch. Saves ring memory; costs
user-side CPU for the filter evaluation + a copy per branch (the
mmap zero-copy story is incompatible with broadcasting).

When broadcast wins:
- Memory-constrained boxes (embedded, dense multi-tenant)
- Many overlapping filters (e.g. 80% of traffic matches multiple
  protocols)
- Workloads where most packets are read by ≥2 branches

When per-ring wins:
- Disjoint protocols on a busy interface (e.g. HTTP on :80 and
  DNS on :53 — narrow filters cut the per-branch load 100×)
- Latency-critical paths where copy overhead matters

So broadcast is an **opt-in choice**, not a strict improvement.

### Design

Two surfaces:

```rust
// 1. Low-level: AsyncCapture::broadcast(n) returns N branches.
let cap = AsyncCapture::open("eth0")?;
let branches: [BroadcastBranch; 3] = cap.broadcast(3)?;
// Each branch implements AsyncPacketSource and can drive its own
// flow_stream / session_stream / datagram_stream chain.
let (a, b, c) = (branches[0], branches[1], branches[2]);
let mut flows = a.flow_stream(FiveTuple::bidirectional());
let mut http = b.session_stream(FiveTuple::bidirectional(), HttpParser::default());
let mut dns = c.datagram_stream(FiveTuple::bidirectional(), DnsUdpParser::with_correlation());

// 2. High-level: ProtocolMonitorBuilder gains an opt-in
//    `.single_ring(true)` that switches its internal wiring to
//    the broadcast pattern.
let mut monitor = ProtocolMonitorBuilder::new()
    .interface("eth0")
    .single_ring(true)  // opt-in: 1 ring + user-side demux
    .flow().http().dns().tls().build(FiveTuple::bidirectional())?;
```

### Implementation sketch

1. New module `netring::async_adapters::broadcast` with
   `BroadcastCapture` + `BroadcastBranch`. Uses
   `tokio::sync::broadcast::channel<Arc<Vec<u8>>>` — each branch
   keeps its own receiver. The producer task reads from the
   underlying `AsyncCapture` and `Arc::new(batch.to_vec())`s the
   bytes (owned; mmap lifetime ends at the broadcast boundary).
2. `BroadcastBranch` implements `AsyncPacketSource` so it slots
   into every existing `flow_stream` / `session_stream` /
   `datagram_stream` constructor.
3. `ProtocolMonitorBuilder::single_ring(true)` opens one
   `AsyncCapture` with no filter, broadcasts to N branches, and
   wires each per-protocol arm to a branch. Out: the per-protocol
   `bpf_*_ports` filters apply *user-side* via a `.filter()` on
   the branch's batch stream.
4. Document the trade-off clearly in `ProtocolMonitorBuilder`
   rustdoc with a "when to choose which" table.

### Open questions

- **Backpressure.** `tokio::sync::broadcast` drops the oldest
  message on lag. Need to decide: alert on `RecvError::Lagged`
  and surface as a metric, or escalate to `BroadcastBranch`
  emitting `Err(Error::Lagged)`? Latter is the right
  user-affordance (matches AF_PACKET's tp_drops semantics).
- **`Arc<Vec<u8>>` vs `Arc<[u8]>`.** Slice is more frugal but
  loses `Vec` ergonomics. Profile under realistic load before
  picking.
- **Eviction of slow branches.** A branch that doesn't poll
  blocks the producer once the channel fills. Document the
  bound; do not silently drop.

### Effort

~400 LoC + benchmarks + a multi-branch smoke test. ~3 days.
**Risk.** Medium — the broadcast tokio primitive is well-known
but the producer-task ergonomics + lifetime story are subtle.

---

## O2. Collapse session/datagram streams onto flowscope drivers (N5)

**Observation.** `netring/src/async_adapters/session_stream.rs`
and `datagram_stream.rs` carry ~700 LoC of hand-rolled state
machine duplicating what flowscope 0.6's `FlowSessionDriver` +
`FlowDatagramDriver` (with the restored `S = ()` parameter)
already do. The duplication exists because netring's adapters
predate the driver restoration in flowscope 0.6.

**Proposal.** Replace netring's hand-rolled chains with thin
wrappers around the flowscope drivers. Behaviour identical;
maintenance burden drops; future flowscope improvements
(retransmit classification, anomaly variants, parser_kind,
on_tick, etc.) flow through without netring needing to mirror.

### Implementation sketch

1. Replace `process_session_event` in `session_stream.rs` with
   `FlowSessionDriver::feed(...)`. The driver already handles:
   - Reassembler creation per (flow, side)
   - Drain-on-FIN / drop-on-RST policy
   - Parser lifecycle (`feed_initiator` / `feed_responder` /
     `fin_*` / `rst_*` / `is_done` / `parser_kind`)
   - Anomaly forwarding
   - The new `EndReason::ParserDone` shape (flowscope 0.7)
2. Same shape for `datagram_stream.rs` + `FlowDatagramDriver`.
3. Keep the public `SessionStream<E, F>` and `DatagramStream<E, P>`
   types and their `Stream` impls — only the internals change.
4. Drop the test-only `process_session_event` fixtures (they
   become equivalent to flowscope's driver tests).

### Open questions

- **Watermark events.** netring currently forwards
  `FlowAnomaly` / `TrackerAnomaly` directly from the underlying
  flow stream; flowscope's driver does the same. Confirm
  semantic equivalence before flipping.
- **Reassembler factory wiring.** netring's `AsyncReassembler`
  story (channel-backed reassembler for backpressure) needs to
  remain compatible. Check that flowscope's driver accepts an
  `Arc<dyn ReassemblerFactory>` cleanly.

### Effort

~500 LoC net delete + ~150 LoC adapter glue. ~3 days. **Risk.**
Med — touches the most-used non-`AsyncCapture` API. Acceptance
gate: all existing session/datagram tests pass without change.

---

## O3. `with_message_tap` for L7 streams (N12)

**Observation.** Plan 20's `with_pcap_tap` records raw packets
before the tracker. For L7 anomaly debugging the more useful
artifact is *parsed L7 messages* — a JSONL file you can replay
against an updated detector. The `pcap_replay_anomaly.rs` example
shipped in 0.17 gets users 80% there by replaying the raw pcap,
but it re-parses every packet; a tap of already-parsed messages
is the production-grade variant.

### Dependency

Blocked on **flowscope G5** — `serde::Serialize` on
`HttpMessage` / `DnsMessage` / `TlsMessage` / `IcmpMessage`. Once
that ships, this is straightforward.

### Design

```rust
use netring::tap::MessageTap;

let stream = cap.flow_stream(FiveTuple::bidirectional())
    .session_stream(HttpParser::default())
    .with_message_tap(MessageTap::jsonl(File::create("trace.jsonl")?));
```

Each `SessionEvent::Application` is JSON-serialized and written
before being forwarded. The tap is a write-side fan-out, not a
filter — every event still flows downstream.

### Effort

~150 LoC + tests. ~1 day **after flowscope G5 lands**. **Risk.**
Low.

---

## O4. `serde::Serialize` for `Anomaly<K>` (with optional `serde` feature)

**Observation.** Today's `Anomaly::to_json_line()` hand-rolls JSON
because we didn't want serde in the dep tree by default. That's
the right call for the lightweight common case, but production
users shipping events to Vector/Fluentd/Loki want serde for
generic pipeline compatibility (custom serializers, batch
formats, etc.).

### Design

Gate behind a new `serde` Cargo feature:

```toml
[features]
serde = ["dep:serde", "flowscope/serde"]  # requires flowscope G5
```

With it on:

```rust
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Anomaly<K> { ... }

#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AnomalyContext { ... }

#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Severity { ... }
```

The hand-rolled `to_json_line()` stays — it's the zero-dep path
and matches the output shape of the serde-derived `serde_json`
serializer (manually). Test for byte-for-byte equivalence under
both feature combinations.

### Open questions

- **Wire vocabulary lock-in.** `#[serde(rename = "...")]` on
  enum variants and field names. Pick a convention
  (snake_case, matching flowscope's metric vocabulary) and
  document it as a stability surface.
- **`K` generic bound.** `Anomaly<K>` requires `K: Serialize`
  when this feature is on. `FiveTupleKey` already derives
  Serialize behind flowscope's `serde` feature. Document the
  composition.

### Effort

~50 LoC + a matrix entry in CI. ~0.5 day **after flowscope G5
lands**. **Risk.** Low.

---

## O5. `docs/WRITING_DETECTORS.md` — tutorial doc

**Observation.** The 7 reference detectors are working
documentation by example, but they don't walk through the *why*
of the design choices: when to use `TimeBucketedCounter` vs
`KeyIndexed`, when an anomaly should be `Info` vs `Warning`, how
to wire `on_tick` for drain-style detectors, how to compose with
`FlowAnomalyRule` for flowscope-side anomalies, how to debug a
rule that doesn't fire.

### Outline

```
1. The anatomy of an AnomalyRule (15 LoC walkthrough)
2. State primitives — KeyIndexed, TimeBucketedCounter, when to use which
3. Severity tiers — Info / Warning / Error / Critical, what fits where
4. The observe / on_tick split — synchronous vs sweep-driven
5. Cross-protocol detectors — three protocols in one rule
6. Composing with FlowAnomalyRule
7. Testing a detector — the smoke + pcap-replay pattern
8. Production deployment — JSON output, Vector pipeline,
   alertmanager wiring
9. Common false-positive patterns
10. Mapping to MITRE ATT&CK (where applicable)
```

### Effort

~400 lines of prose. ~1 day. **Risk.** None.

---

## O6. `benches/anomaly.rs` — perf characterization

**Observation.** We've shipped the toolkit without measuring
its overhead. Open questions: what's the per-event cost? How
does it scale with rule count? What's the `Vec::take`/realloc
cost in the scratch buffer? At what event-rate does the harness
become the bottleneck (vs the underlying parser / extractor)?

### Plan

`benches/anomaly.rs` using `divan` (already a dev-dep):

| Bench | Question answered |
|---|---|
| `bench_observe_no_op_rule` | Per-event overhead with 1 rule that emits nothing |
| `bench_observe_n_rules` | Linear scaling test, N ∈ [1, 4, 16, 64] |
| `bench_observe_emits_anomaly` | Cost when a rule actually fires |
| `bench_on_tick_drain_expired` | KeyIndexed sweep cost at scale |
| `bench_to_json_line` | Per-anomaly JSON-line cost |
| `bench_full_pipeline_dns_burst` | End-to-end: ProtocolEvent::Message → DnsBurstRule.observe → drop |

### Effort

~200 LoC + a CI entry. ~1 day. **Risk.** None.

---

## O7. `examples/anomaly/replay_pcap_multi_proto.rs`

**Observation.** `pcap_replay_anomaly.rs` (shipped in 0.17)
handles single-protocol replay. The follow-on workflow is
*multi-protocol* replay — replaying a pcap against rules that
span Flow + DNS + TLS, like `tls_to_unresolved_ip`. Today this
requires either:
- Opening the pcap twice (slow + wasteful — every byte re-decoded)
- Writing a custom packet-level loop that re-implements
  ProtocolMonitor

### Plan

Ship `examples/anomaly/replay_pcap_multi_proto.rs` that
demonstrates the packet-level-loop pattern: open the pcap once,
walk every packet, feed it to both a flow tracker and per-protocol
parsers manually, fan into ProtocolEvent + AnomalyMonitor.

This is *documentation by example*; the underlying API limitation
(`AsyncPcapSource` consuming itself) is flagged in
`flowscope-0.8-feedback` G4 for a structural fix.

### Effort

~200 LoC. ~0.5 day. **Risk.** Low — pure example code, no
library API change.

---

## O8. Lockstep bump to flowscope 0.8

**When flowscope 0.8 ships,** netring needs to absorb whatever
breaking changes ride along (variant additions, accessor changes,
etc.). The pattern is well-rehearsed by now — see
[`netring-0.17-flowscope-0.7-bump-2026-06-03.md`](./netring-0.17-flowscope-0.7-bump-2026-06-03.md).

Expected items in flowscope 0.8 (per
[`flowscope-0.8-feedback-2026-06-03.md`](./flowscope-0.8-feedback-2026-06-03.md)):

- **G5** `serde` feature → unblocks O4 + O3.
- **G1** `IcmpType::is_error()` + helper → simplifies
  `icmp_explained_drop.rs`.
- **G3** `DnsResolutionCache` primitive → simplifies
  `dns_resolved_no_connection.rs` + `tls_to_unresolved_ip.rs`.

### Effort

Mechanical migration. ~1 day. **Risk.** Low.

---

## O9. `ProtocolMonitorBuilder::pcap(path)` entry

**Observation.** `ProtocolMonitorBuilder` today only takes a live
interface (`.interface(name)`). For the pcap-replay workflow we
have today (`pcap_replay_anomaly.rs`), users reach past the
builder and wire `AsyncPcapSource` directly — losing the
declarative multi-protocol convenience.

### Design

```rust
let mut monitor = ProtocolMonitorBuilder::new()
    .pcap("trace.pcap")?           // or .interface("eth0")
    .flow()
    .http().dns().tls()
    .build(FiveTuple::bidirectional())?;
```

Internally: `enum Source { Live(String), Pcap(PathBuf) }`,
discriminated at `.build()`. Each per-protocol arm either opens
a fresh `AsyncCapture` (Live) or a fresh `AsyncPcapSource` (Pcap).

### Dependency

Requires `AsyncPcapSource` to support multiple consumers (per
`flowscope-0.8-feedback` G4) — or netring opens the pcap N times
(once per protocol arm). Both routes work; the multi-open route
is fine for replay (no real-time constraint).

### Effort

~150 LoC + tests + an `examples/anomaly/pcap_replay_full.rs` to
demo. ~1 day. **Risk.** Low.

---

## O10. `tracing::Subscriber` emission helper

**Observation.** Production deployments often plumb anomalies
through the `tracing` crate's structured-log infrastructure.
Today users do `println!("{a}")` or `println!("{}", a.to_json_line())`;
plugging into `tracing` requires custom code.

### Design

```rust
impl<K: Debug> Anomaly<K> {
    /// Emit at the configured `tracing` level for this anomaly's
    /// severity. Maps Info → INFO, Warning → WARN, Error → ERROR,
    /// Critical → ERROR (no PAGE level in tracing).
    pub fn emit_tracing(&self);
}
```

Gated behind a `tracing` feature. The fields land as structured
key-value pairs in the tracing event, ready for any subscriber
(JSON, OpenTelemetry, log files, etc.).

### Effort

~50 LoC + a tracing-subscriber doctest. ~0.5 day. **Risk.** None.

---

## Effort summary

| Item | LoC | Days | Risk | Blocked on |
|---|---|---|---|---|
| O1 (broadcast) | ~400 | 3 | Med | none |
| O2 (drivers) | ~150 + 500 del | 3 | Med | none |
| O3 (msg tap) | ~150 | 1 | Low | flowscope G5 |
| O4 (serde) | ~50 | 0.5 | Low | flowscope G5 |
| O5 (tutorial) | ~400 prose | 1 | None | none |
| O6 (benches) | ~200 | 1 | None | none |
| O7 (replay example) | ~200 | 0.5 | Low | none |
| O8 (flowscope 0.8 bump) | ~50 + migration | 1 | Low | flowscope 0.8 release |
| O9 (pcap builder leg) | ~150 | 1 | Low | weak — G4 makes it cleaner |
| O10 (tracing helper) | ~50 | 0.5 | None | none |

**Total: ~12 days light-path (~9 if O3/O4 slip to 0.19).**

## Phasing

Realistic split:

- **netring 0.18.0** (target: 2026-06-XX): O2 + O5 + O6 + O7 +
  O10. Internal refactor (O2) + doc/bench debt (O5/O6) +
  multi-protocol replay (O7) + tracing helper (O10). No
  flowscope-cycle dependency. ~6 days.
- **netring 0.19.0** (target: post-flowscope-0.8): O8 lockstep
  bump + O3 + O4 (serde everywhere). ~3 days.
- **netring 0.20.0** (target: post-broadcast-design-doc): O1 +
  O9. Broadcast surface lands first, then the pcap builder leg
  picks it up. ~5 days.

## What 0.18 success looks like

After 0.18 lands:

1. `cargo build -p netring` is ~500 LoC lighter (O2 driver
   collapse) with identical behaviour.
2. A new contributor can write their first `AnomalyRule` after
   reading `docs/WRITING_DETECTORS.md` (O5) and copying one of
   the 7 reference detectors.
3. The anomaly path is benchmarked (O6) — we know the per-event
   cost and the rule-count scaling.
4. Multi-protocol pcap replay is demoable (O7).
5. Anomalies plug into the existing tracing stack (O10) without
   custom code.

## Out of scope (deferred to 0.19+ or further)

- **eBPF-side anomaly correlator.** Still out of scope.
- **Suricata-compatible rule DSL.** Still out of scope.
- **Encrypted-traffic ML detection.** Still out of scope.
- **`PacketBackend` unification** (AF_PACKET + AF_XDP). Tracked
  in `upstream-tracking.md`; revisit when a third consumer asks.
- **Zeek-style log formatters.** Pure plumbing; if a user wants
  Zeek-shaped output they can implement it on top of `Display`
  + `to_json_line`.
- **Live anomaly storage / dashboarding.** Operator concern.
  We emit; the pipeline persists / queries.
