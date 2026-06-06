# flowscope wishlist — netring perspective

**Date:** 2026-06-06
**Author:** maintainer of [`netring`](https://github.com/p13marc/netring)
**Audience:** flowscope team

This is a **consolidated, prioritized wishlist** of everything
netring would like flowscope to ship. It supersedes the three
prior dated feedback rounds:

- [`flowscope-0.5-feedback-2026-05-22.md`](./flowscope-0.5-feedback-2026-05-22.md) — drove flowscope 0.5 + 0.6 (11/12 shipped)
- [`flowscope-0.7-feedback-2026-05-29.md`](./flowscope-0.7-feedback-2026-05-29.md) — drove flowscope 0.7 (8/9 shipped)
- [`flowscope-0.8-feedback-2026-06-03.md`](./flowscope-0.8-feedback-2026-06-03.md) — queued for 0.8

Each round had a high shipping rate (~90%), so most of what
netring previously asked for is already in flowscope. This
document carries forward what's still pending **plus** new
items discovered during the netring 0.18 cycle (writing-detectors
tutorial, anomaly benches, multi-protocol pcap replay, the
`emit_tracing` helper).

**Scope rule.** flowscope is the **source-agnostic** flow &
session tracking + L7 parsing crate. netring is the Linux capture
integration. We're explicitly **not** asking flowscope to take on
runtime concerns (tokio, async-trait, Linux-specific code) — the
"no async in lib crates" boundary the projects already agreed.

**Versioning.** flowscope and netring ship in lockstep. Breaking
changes on `pre-1.0` are fine; netring absorbs them in the next
release.

---

## TL;DR — top 5 highest-leverage asks

| # | Ask | Why it matters | Effort |
|---|---|---|---|
| **A1** | `serde::Serialize` opt-in for L7 message types | Unblocks every production user shipping events to Vector/Fluentd/Loki. Also lets netring derive `Serialize` on `Anomaly<K>`. | ~3 days |
| **A2** | `IcmpType::is_error()` + `error_inner()` helper | Saves every ICMP-correlation consumer ~40 LoC of pattern-matching. | ~0.5 day |
| **A3** | `DnsResolutionCache` primitive | Already implemented twice in netring (3rd consumer shouldn't have to). | ~0.5 day |
| **B1** | `pub const PARSER_KIND_*` constants for parser_kind slugs | Today `kind: "dns-udp"` is a magic string at every match site. Constants close the gap. | ~30 LoC |
| **B2** | Multi-parser composite driver | The "one pcap → many parsers" pattern needed by every cross-protocol detector and currently solved by re-opening the source N times. | ~3 days |

Sections A and B are concrete; section C is long-term wishes that
need more design.

---

## What's already shipped — credit roll

A quick checkpoint on what's already in flowscope as of 0.7. None
of these need attention; listed so future you doesn't propose
them again.

### Tracker / driver / events

- **`FlowDriver<E, F, S>` + `with_state*`** (0.6) — the per-flow
  user-state story is fully restored after the 0.5 single-S
  experiment.
- **`with_factory_and_config`, `with_state_factory`** etc. (0.6) —
  parser-factory variants on all three drivers.
- **`FlowSessionDriver` / `FlowDatagramDriver`** (0.6) — netring
  is *still* hand-rolling its equivalents (the O2 driver-refactor
  in [`netring-0.18-roadmap`](./netring-0.18-roadmap-2026-06-03.md)
  collapses them onto these). The drivers themselves are great;
  the carryover is netring's debt, not yours.
- **`FlowEvent::Ended { l4: Option<L4Proto> }`** +
  `SessionEvent::Closed { l4 }` (0.7) — closes the
  `HashMap<K, L4Proto>` workaround. Used heavily in netring 0.17.
- **`FlowTracker::snapshot_l4` / `snapshot_stats` /
  `snapshot_history`** (0.7) — per-key introspection works
  cleanly.
- **`FlowEvent::Tick`** (0.5, `with_flow_tick_interval`) —
  packet-clock driven sweep. Useful for time-bound rules.

### Parsers + accessors

- **`HttpRequest::host()` / `user_agent()` / `cookie()` /
  `header()` / `headers_all()`** (0.7) — drops the
  `find().and_then(str::from_utf8)` dance.
- **`HttpResponse::content_type()` / `content_length()` /
  `set_cookie()`** (0.7) — same idea.
- **`TlsClientHello::sni()`** (0.7) — accessor symmetry.
- **`DnsTcpParser`** (0.6) — covers DoT framing.
- **`SessionEvent::Application::parser_kind`** (0.5) — routes by
  protocol at the event level. **Heavily used** in netring's
  `ProtocolEvent::Message { kind, ... }` matcher; this is the
  ergonomic foundation of the whole anomaly toolkit.

### Anomaly + observability

- **`Anomaly` split → `FlowAnomaly` + `TrackerAnomaly`** (0.6).
- **`AnomalyKind::severity() -> Severity`** (0.7) — bridges
  perfectly into netring's own `Severity` via the
  `From<flowscope::event::Severity>` impl.
- **`AnomalyKind::RetransmittedSegment`** (0.5).
- **`AnomalyKind::ReassemblerHighWatermark`** (0.6,
  `with_high_watermark_threshold`).
- **`AnomalyKind::FlowTableEvictionPressure`** (0.6).
- **TCP retransmit classification** (0.5).
- **`TcpInfo::window`** (0.5).

### Polish

- **`Display for L4Proto / EndReason / AnomalyKind / Severity`**
  (0.7) — used everywhere in netring's docs / examples.
- **`AsPacketView`** (0.6) — blanket `From<&T>` impl.
- **`flowscope::icmp::IcmpParser`** + **`IcmpInner`** (0.7) — the
  killer feature that unblocked netring's
  `icmp_explained_drop.rs` detector. **`IcmpInner` is exactly the
  right shape**: `(src, dst, proto, src_port, dst_port)` — pure
  data, easy to use as a HashMap key.
- **`SessionParser::is_done()` + `EndReason::ParserDone`** (0.7).
- **`OneShotSessionParser` / `OneShotDatagramParser`** in
  `test_helpers` (0.6) — used in netring's integration tests.
- **`finish()` at `Timestamp::MAX`** (0.6) — drives pcap EOF
  flush in netring's `PcapFlowStream`.
- **`flowscope/l7` umbrella feature** (0.6, 0.7 includes icmp).

This is most of the shipping surface netring depends on.
**Round 1+2+3 shipped 27 of 30 proposed items.** The remaining
items + new asks are below.

---

## Section A — High-priority asks (carried from 0.8 feedback)

These were drafted as flowscope 0.8 items in
[`flowscope-0.8-feedback-2026-06-03.md`](./flowscope-0.8-feedback-2026-06-03.md).
None shipped yet; they remain top-tier.

### A1. `serde::Serialize` feature for L7 message types

**Tier:** **High** — top of the list. **Effort:** ~3 days.
**Risk:** Med (stability surface lock-in).

Today, netring's `Anomaly::to_json_line()` hand-rolls RFC 8259
JSON because we didn't want to pull serde unconditionally. That
works for `Anomaly<K>` (small, controlled struct). It does **not**
work when users want to ship full `HttpMessage` / `DnsMessage` /
`TlsMessage` / `IcmpMessage` values into their log pipelines —
each of those is a deeply nested enum, hand-rolling JSON for them
is brittle, and `#[non_exhaustive]` enums silently miss new
variants if the serializer doesn't keep up.

**Proposal.** Add `serde` as an opt-in Cargo feature. With it on:

```rust
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HttpMessage { ... }

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DnsMessage { ... }
```

Lock the wire vocabulary with `#[serde(rename = "...")]` matching
flowscope's existing metric-label vocabulary (snake_case) — once
shipped, this becomes a stability surface.

**netring side**: gates a corresponding `netring/serde` feature
that derives `Serialize` on `Anomaly<K>`, `AnomalyContext`,
`Severity`. Users get a complete structured-output story without
hand-rolling.

**Bonus.** `Deserialize` is essentially free with the derive;
ship both. Enables replay tooling that reads an event log back in
without parsing through the raw network bytes.

### A2. `IcmpType::is_error()` + `error_inner()` extraction helper

**Tier:** **High**. **Effort:** ~30 LoC + tests.
**Risk:** None.

When writing `examples/anomaly/icmp_explained_drop.rs`, I needed
a 40-LoC `extract_icmp_error()` helper that pattern-matches every
error-bearing variant (`DestinationUnreachable`, `TimeExceeded`,
`Redirect`, `ParameterProblem` on v4; the v6 counterparts;
`PacketTooBig` on v6 only) and pulls out `(label,
&IcmpInner)`. **Every** consumer of `IcmpInner`-bearing types
will write the same helper.

**Proposal.** Two complementary methods on `IcmpType` (or
`IcmpMessage`):

```rust
impl IcmpType {
    /// `true` for variants that carry an `inner: Option<IcmpInner>`
    /// (all the error-class types). v4 EchoRequest/Reply,
    /// Timestamp etc. return `false`.
    pub fn is_error(&self) -> bool;

    /// Convenience: `(short label, &IcmpInner)` for any error
    /// variant whose inner was successfully parsed. `None` for
    /// non-error types or truncated embeds.
    pub fn error_inner(&self) -> Option<(&'static str, &IcmpInner)>;
}
```

`short label` is a stable static string like `"dest_unreachable"`
/ `"time_exceeded"` / `"packet_too_big"` — used directly as a
metric label without case-folding.

This + A1 + A3 together collapse `icmp_explained_drop.rs` from
~250 LoC to maybe ~120.

### A3. `DnsResolutionCache` primitive

**Tier:** **High**. **Effort:** ~60 LoC + tests.
**Risk:** None.

Two netring detectors implement essentially the same primitive:
per-source-IP "what IPs has this host recently resolved?"
(`dns_resolved_no_connection.rs` and `tls_to_unresolved_ip.rs`).
Both wrap `KeyIndexed<IpAddr, ()>` in a `HashMap<IpAddr, _>` and
manually walk DNS responses.

**Proposal.**

```rust
// New module: flowscope::dns::correlate (or just flowscope::dns)
pub struct DnsResolutionCache {
    by_host: HashMap<IpAddr, ...>,  // implementation-defined
    ttl: Duration,
}
impl DnsResolutionCache {
    pub fn new(ttl: Duration) -> Self;

    /// Record every A/AAAA answer in `r` as a resolution by `client_ip`.
    pub fn observe_response(
        &mut self,
        client_ip: IpAddr,
        r: &DnsResponse,
        now: Timestamp,
    );

    /// Has `client_ip` recently resolved a name to `target_ip`?
    pub fn was_resolved(
        &self,
        client_ip: IpAddr,
        target_ip: IpAddr,
        now: Timestamp,
    ) -> bool;

    /// Look up the canonical hostname `client_ip` last resolved
    /// `target_ip` from. Returns `None` if absent / aged out.
    pub fn lookup_name(
        &self,
        client_ip: IpAddr,
        target_ip: IpAddr,
        now: Timestamp,
    ) -> Option<&str>;

    /// Drop aged-out entries. Call from your sweep tick.
    pub fn sweep(&mut self, now: Timestamp);
}
```

If you prefer, ship this as part of a broader `flowscope::correlate`
module (G8 below).

---

## Section B — New asks from netring 0.18

These emerged from work done after the 0.8 feedback was written.

### B1. `pub const PARSER_KIND_*` constants

**Tier:** **Med**. **Effort:** ~30 LoC.
**Risk:** None.

Today, every netring rule body that matches on a parser_kind
slug writes a string literal:

```rust
let ProtocolEvent::Message { kind: "dns-udp", .. } = evt
else { return };
```

The slug values are stable per parser:
- `HttpParser::parser_kind()` → `"http/1"`
- `DnsUdpParser::parser_kind()` → `"dns-udp"`
- `DnsTcpParser::parser_kind()` → `"dns-tcp"`
- `TlsParser::parser_kind()` → `"tls"`
- `IcmpParser::parser_kind()` → `"icmp"`

But they're string-literals at the call site — typos pass the
type checker silently.

**Proposal.** Public constants in each parser module:

```rust
pub mod flowscope::http {
    pub const PARSER_KIND: &str = "http/1";
}
pub mod flowscope::dns {
    pub const PARSER_KIND_UDP: &str = "dns-udp";
    pub const PARSER_KIND_TCP: &str = "dns-tcp";
}
pub mod flowscope::tls {
    pub const PARSER_KIND: &str = "tls";
}
pub mod flowscope::icmp {
    pub const PARSER_KIND: &str = "icmp";
}
```

Users then write:

```rust
let ProtocolEvent::Message { kind: flowscope::dns::PARSER_KIND_UDP, .. } = evt
else { return };
```

Bonus: a top-level `flowscope::parser_kinds` re-export module
with all of them collected.

### B2. Multi-parser composite driver

**Tier:** **Med** (high-value, design-heavy). **Effort:** ~3 days.
**Risk:** Med (touches driver signatures).

The current driver shape consumes one parser per flow direction:
`FlowSessionDriver<E, P>`. To run **multiple** L7 parsers on the
same packet stream (e.g., parse HTTP and TLS on the same TCP
flow when the port can't disambiguate, or replay a pcap through
DNS + TLS in one pass), users today either:

- Open the source N times (slow, wasteful)
- Hand-roll a packet-level loop that demuxes (~300 LoC)

netring's `pcap_replay_multi.rs` example uses the "open twice,
merge by timestamp" approach — readable but loads the pcap 2× from
disk.

**Proposal.** A composite driver shape that accepts a tuple (or
list) of parsers and routes packets to each based on L4 + port
hints:

```rust
// One driver, many parsers. Each parser sees packets matching
// its L4Proto + port set (configured at driver construction).
let driver = FlowMultiSessionDriver::new(FiveTuple::bidirectional())
    .with_parser(HttpParser::default(), &[80, 8080])
    .with_parser(TlsParser::default(),  &[443, 8443])
    .with_parser(DnsTcpParser::default(), &[53]);

// SessionEvent::Application::message becomes a sum type
// covering each registered parser's message:
//   Multi { kind: parser_kind, message: AnyMessage::Http(_) | Tls(_) | Dns(_) }
```

The detail is fiddly (multi-parser per direction, parsing-order
guarantees, dispatch cost) but the user-facing primitive is
massively useful.

If this is too heavy, a lighter version: ship a "packet-level
loop" recipe in `docs/SESSION_GUIDE.md` that users follow when
they need this. We can document the same recipe in netring side
in `docs/WRITING_DETECTORS.md` (which already references the
multi-protocol pattern).

### B3. `FlowEvent::Established { l4 }`

**Tier:** Polish. **Effort:** ~10 LoC.
**Risk:** Pre-1.0 breaking (field add).

Plan 79 added `l4` to `Started` and `Ended`/`Closed`.
`Established` (the TCP-3WHS-completed event) doesn't carry it.
Round out the trio for consistency.

### B4. `AnomalyKind::short_kind() -> &'static str`

**Tier:** Polish. **Effort:** ~20 LoC.
**Risk:** None.

Today, `FlowAnomalyRule` (built into netring) records the
`AnomalyKind` via `kind.to_string()` — the full Display rendering.
But for **metric labels** and **grouping**, users want just the
variant name (`"out_of_order_segment"`, `"buffer_overflow"`)
without the parameter detail.

**Proposal.**

```rust
impl AnomalyKind {
    /// Stable variant slug. `OutOfOrderSegment { ... }` →
    /// `"out_of_order_segment"`. Suitable as a Prometheus label.
    pub fn short_kind(&self) -> &'static str;
}
```

Compositional with `Display` (which can keep including
parameters): users pick which they want.

### B5. Programmatic flow termination

**Tier:** Med-Low. **Effort:** ~50 LoC.
**Risk:** Low.

Today, a flow ends because of:
- FIN/RST (transport)
- Idle timeout
- LRU eviction
- Buffer overflow
- Parser-done (0.7)

There's no way to **programmatically** kill a flow from outside.
Useful for:
- Resource management ("this flow exceeded my per-connection
  byte budget, terminate it")
- Test harnesses ("I want this flow to end now")
- Rate limiting

**Proposal.**

```rust
impl<E, S> FlowTracker<E, S> {
    /// Force-end the flow with this key. Emits an `Ended` event
    /// with `EndReason::ForceClosed` (new variant).
    /// Returns `true` if the key was active.
    pub fn force_close(&mut self, key: &E::Key, now: Timestamp) -> bool;
}

pub enum EndReason {
    ...,
    ForceClosed,  // new
}
```

### B6. `TlsHandshake` aggregator parser

**Tier:** Med-Low. **Effort:** ~50 LoC.
**Risk:** Low.

Carried from 0.7 G2. `slow_tls_handshake.rs` correlates
`ClientHello` with `ServerHello` via `KeyIndexed<FiveTupleKey,
Timestamp>` user-side. flowscope could ship an aggregator parser
that emits one synthetic message instead:

```rust
TlsMessage::HandshakeComplete {
    sni: Option<String>,
    rtt: Duration,
    ja3_hash: Option<String>,
    server_cipher: u16,
    // ...
}
```

Useful, but the manual correlation pattern is fine; not blocking.

### B7. `FlowTracker::iter_active()` for periodic snapshotting

**Tier:** Med. **Effort:** ~30 LoC.
**Risk:** Borrow-checker subtleties.

`tracker_stats()` exposes global counters. For dashboards /
metrics that want **per-flow** snapshots, users today have to
maintain their own shadow state. An iterator over active flows
would close this:

```rust
impl<E, S> FlowTracker<E, S> {
    pub fn iter_active(&self) -> impl Iterator<Item = (&E::Key, &FlowStats, &S)>;
}
```

Useful for: "every 5 seconds, dump the top-10 flows by bytes",
"snapshot all SYN_SENT flows for a stuck-handshake report".

`snapshot_flow_stats()` on each driver gives a partial version
(stats but not `S`); a full iter on the tracker would complete
the story.

---

## Section C — Long-term wishes (speculative, low priority)

Items with real value but big design space. Not blocking netring;
listed so the flowscope team has visibility.

### C1. `flowscope::correlate` module (carried from F6 / G8)

A move-down of `KeyIndexed` and `TimeBucketedCounter` (currently
in `netring::correlate`) into flowscope. Other flowscope
consumers (PCAP analyzers, non-Linux capture tools, embedded
users) would get them for free.

If shipped: netring re-exports `flowscope::correlate::*` and
deprecates its own copies. ~150 LoC move + a `correlate` feature
gate.

### C2. `flowscope::correlate::SequenceDetector`

Once `KeyIndexed` is in flowscope, ship a higher-level
"A-then-B-within-window" detector. The pattern is so common
across netring's detectors (DNS-then-Flow,
ClientHello-then-ServerHello, ICMP-then-Flow) that a shared
abstraction would help.

```rust
let seq = SequenceDetector::new(window: Duration::from_secs(5));
seq.expect(key_a);  // mark "A happened"
if seq.matches(key_a, now) { /* B happened in time */ }
for (k, age) in seq.drain_unfulfilled(now) { /* A without B */ }
```

### C3. Per-flow event filter at tracker construction

Today users get every `FlowEvent::Packet`. Many netring
consumers drop them immediately. A config option to suppress
specific variants at the tracker source would help:

```rust
FlowTrackerConfig::new()
    .with_event_filter(EventFilter::SUPPRESS_PACKET)
```

Net: skip allocating events the consumer doesn't want.

### C4. Composable extractor adapters

`extract::StripVlan`, `extract::InnerVxlan`, `extract::SkipEndpoints`
already exist. Adding:
- `extract::HostPair` (just src/dst hosts, no ports)
- `extract::AppliedFilter` (chain a BPF-style predicate to drop
  irrelevant packets at the extractor)

…would help in some use cases.

### C5. Reassembler with pageable state

When `BufferOverflow` fires, you currently lose the data. A
pageable reassembler (writes excess to disk / a side-channel)
would let consumers preserve evidence for later analysis. Niche
but valuable for forensics.

### C6. Synthetic test fixtures expansion

`test_helpers` ships `OneShotSessionParser` / `OneShotDatagramParser`.
Adding:
- `SyntheticFlowDriver` — programmatically build a Vec of
  `FlowEvent` to drive a downstream consumer (helps netring test
  its session_stream wrappers without going through real packets)
- `pcap_macro!` — a `vec![pkt!(udp, 53, 5353, "query bytes")]`
  shorthand for building synthetic frames in tests

### C7. Tracker pause/resume

For load-shedding: pause the tracker (accept packets but don't
emit events, or drop packets entirely) without losing flow state.
Niche; revisit when a consumer asks.

### C8. JA4 fingerprint

JA3 ships behind a feature. JA4 is the modern replacement
(weighted-by-popularity ordering). Out-of-scope for now; tag in
case someone asks.

---

## Section D — Explicitly out-of-scope

Recorded so a future ask doesn't get re-litigated.

- **Async-trait drivers / `tokio` dependency.** flowscope is
  intentionally sync; netring builds the async layer on top.
  This boundary stays.
- **Network-side capture (AF_PACKET / AF_XDP / pcap-files).**
  That's netring's job; flowscope is source-agnostic.
- **eBPF in-kernel correlation.** Different architecture; would
  belong in a separate crate.
- **ML-based anomaly detection.** Compose with this stack via a
  user-defined `AnomalyRule` that feeds a learned model;
  shipping the ML pipeline isn't flowscope's job.
- **Text-DSL rule language (Suricata-style).** Same reasoning;
  not flowscope's scope.

---

## Effort + impact matrix

| # | Item | Tier | LoC | Days | Risk | Blocks |
|---|---|---|---|---|---|---|
| A1 | serde feature on L7 messages | **High** | ~200 + CI | 3 | Med | netring O3 (msg tap) + O4 (serde Anomaly) |
| A2 | IcmpType::is_error + error_inner | **High** | ~30 | 0.5 | None | nothing (cleanup only) |
| A3 | DnsResolutionCache primitive | **High** | ~60 | 0.5 | None | nothing |
| B1 | parser_kind constants | **Med** | ~30 | 0.2 | None | nothing |
| B2 | Multi-parser composite driver | **Med** | ~400 | 3 | Med | netring O7 cleanup |
| B3 | FlowEvent::Established { l4 } | Polish | ~10 | 0.1 | Pre-1.0 break | nothing |
| B4 | AnomalyKind::short_kind() | Polish | ~20 | 0.2 | None | netring FlowAnomalyRule metric labels |
| B5 | FlowTracker::force_close | Med-Low | ~50 | 0.3 | Low | nothing |
| B6 | TlsHandshake aggregator | Med-Low | ~80 | 0.5 | Low | netring slow_tls_handshake cleanup |
| B7 | FlowTracker::iter_active | Med | ~30 | 0.2 | Low (borrowck) | nothing |
| C1 | flowscope::correlate module | Long-term | ~150 | 1 | None | nothing (cleanup) |
| C2 | SequenceDetector | Long-term | ~100 | 1 | None | nothing (sugar) |
| C3 | Event-variant suppression | Long-term | ~40 | 0.5 | Low | nothing (perf) |
| C4 | More extractor adapters | Long-term | ~100 | 1 | None | nothing |
| C5 | Pageable reassembler | Long-term | ~300 | 2 | Med | nothing |
| C6 | More test fixtures | Long-term | ~150 | 1 | None | nothing |
| C7 | Tracker pause/resume | Long-term | ~50 | 0.5 | Low | nothing |
| C8 | JA4 fingerprint | Long-term | ~250 | 2 | None | nothing |

**Total light path (Section A + B):** ~14 days.
**With Section C:** ~25 days.

If flowscope 0.8 ships only **3** things, prioritize **A1, A2, A3**
in that order. They unblock real workflows that today require
hand-rolled workarounds in netring.

---

## Phasing recommendation

Aligned to what netring would absorb in each release:

### flowscope 0.8 (target: ~2 weeks out)

Items: **A1, A2, A3, B1**.

Total: ~4 days. netring 0.19 would absorb in 1 day (lockstep
bump + use the new APIs in the existing detectors).

### flowscope 0.9 (later cycle)

Items: **B2 (multi-parser driver), B3, B4, B5, B7, C1, C2**.

Total: ~7 days. The multi-parser driver is the biggest item; if
it slips, ship the others as 0.9.x and roll B2 into 0.10.

### Beyond

The rest of Section C as opportunity arises. No netring item
depends on them; they're "next time someone touches the area"
candidates.

---

## How netring will consume each item

Pre-committed integration plan for each item, so the flowscope
team can verify that the proposed API actually fits:

### A1 (serde feature)

netring side: new `netring/serde` feature →
`flowscope/serde` + `serde` direct dep. Derives `Serialize` /
`Deserialize` on `Anomaly<K>`, `AnomalyContext`, `Severity`.
Adds `Anomaly::to_json_value() -> serde_json::Value` that
includes the full underlying parsed message (today's
`to_json_line` only includes metadata).

Acceptance test: `tests/anomaly_serde.rs` round-trips
`Anomaly<FiveTupleKey>` containing each `ProtocolMessage`
variant through `serde_json` and asserts byte-for-byte stable
output (locks the wire vocabulary).

### A2 (IcmpType helpers)

netring side: shrink `examples/anomaly/icmp_explained_drop.rs`'s
`extract_icmp_error` helper from ~40 LoC to a one-liner
(`msg.ty.error_inner()`). Update `docs/WRITING_DETECTORS.md`
ICMP-correlation section.

### A3 (DnsResolutionCache)

netring side: refactor `dns_resolved_no_connection.rs` and
`tls_to_unresolved_ip.rs` to use the new primitive. Drop the
`HashMap<IpAddr, KeyIndexed<IpAddr, ()>>` open-code. ~50 LoC
net delete across the two examples.

### B1 (parser_kind constants)

netring side: refactor all `kind: "dns-udp"` / `"http/1"` /
`"tls"` / `"icmp"` matches in `examples/anomaly/` to use
`flowscope::dns::PARSER_KIND_UDP` etc. ~15 sites.

### B2 (multi-parser driver)

netring side: refactor `examples/anomaly/pcap_replay_multi.rs`
from the "open twice + merge by timestamp" pattern to a one-pass
loop. Ship `ProtocolMonitorBuilder::pcap(path)` as a builder
entry (the deferred O9 in
[`netring-0.18-roadmap`](./netring-0.18-roadmap-2026-06-03.md)).

### B3 (Established { l4 })

netring side: bind `l4` in the relevant destructures (3 sites).

### B4 (short_kind)

netring side: `FlowAnomalyRule` switches from `kind.to_string()`
to `kind.short_kind()` for the `kind` observation. Documented as
a Prometheus-friendly label.

### B5 (force_close)

netring side: probably no direct adoption; we'd add a
`StreamCapture::force_close_flow(key)` convenience for users who
want it.

### B6 (TlsHandshake aggregator)

netring side: refactor `slow_tls_handshake.rs` to use the new
`HandshakeComplete` message instead of the manual ClientHello +
ServerHello correlation. ~30 LoC simpler.

### B7 (iter_active)

netring side: ship `examples/flow/active_flows_snapshot.rs`
demonstrating periodic top-N-by-bytes reporting.

---

## Open questions for the flowscope team

If you want feedback on these before committing to designs:

1. **A1 (serde):** which wire vocabulary do you want? snake_case
   (matches existing metric labels) or camelCase (matches what
   JS-side consumers expect)? netring leans snake_case. Lock
   `#[serde(rename_all = "snake_case")]` once and move on.
2. **B2 (multi-parser):** is the "tuple of parsers" shape
   acceptable, or do you prefer a `Box<dyn ...>` registry? The
   tuple shape preserves zero-cost dispatch but limits N at
   compile time. The dyn shape is more flexible but slower.
3. **B7 (iter_active):** can we expose `S` references in the
   iterator without breaking the borrow checker on
   `tracker_mut().sweep()`? Or should iteration require an
   exclusive borrow + return owned copies?

---

## Closing

netring is currently shipping the 0.16 → 0.17 → 0.18 cycle
focused on multi-protocol anomaly correlation, on top of
flowscope 0.7. The toolkit is complete enough to be useful
(8 reference detectors, ~322 tests, benches, tutorial doc,
tracing integration, JSON output). flowscope 0.7 unblocked
about 60% of what we needed; this wishlist documents the
remaining ~40%.

**Top three asks again, for emphasis:**

1. **A1 — serde feature** (unblocks production pipelines)
2. **A2 — IcmpType::is_error / error_inner** (40 LoC of pain saved per consumer)
3. **A3 — DnsResolutionCache** (third user shouldn't reimplement)

Thanks. Always happy to iterate on shapes before they ship.
