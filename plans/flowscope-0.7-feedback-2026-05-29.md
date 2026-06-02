# Feedback for flowscope 0.7 — second round, post-netring-L7-examples

**Date:** 2026-05-29
**Author:** maintainer of `netring`
**Context:** retrospective from writing the four real-life L7
examples in `netring` (`multi_protocol_monitor`, `http_session`,
`dns_lookups`, `full_monitor`) plus a forward-looking pass on
what netring needs to support **multi-protocol anomaly
correlation** as a first-class use case.

**Scope rule:** backward-incompatible breaks are explicitly
allowed.

> Companion to
> [`flowscope-0.5-feedback-2026-05-22.md`](./flowscope-0.5-feedback-2026-05-22.md).
> That round drove flowscope 0.5 + 0.6 — most of it shipped (see
> "Already shipped in 0.5/0.6" below). This second round focuses
> on what the L7 examples surfaced + what's still missing for
> netring's anomaly-correlation roadmap.

---

## Already shipped in flowscope 0.5 / 0.6 — credit roll

Of the 12 proposals in the 2026-05-22 feedback, **flowscope 0.5
and 0.6 shipped 11**:

| # | Proposal | Shipped in | Notes |
|---|---|---|---|
| 1 | `FlowTracker::sweep_with_parsers` helper | 0.6 (plan 39) | Plus `sweep_with_datagram_parsers` |
| 2 | `with_auto_sweep(interval)` | 0.5 (FlowTick / `flow_tick_interval`) | Packet-clock driven, opt-in |
| 3 | `FlowTracker::finish()` | 0.6 | |
| 4 | Split `Anomaly { key: Option<K> }` → `FlowAnomaly` + `TrackerAnomaly` | 0.6 (plan 43) | |
| 5 | `AsPacketView` trait | 0.6 (plan 50) | Blanket `From<&T>` impl |
| 6 | Driver `S` story | 0.6 (plan 32 reversed via `with_state*`) | netring can drop its hand-rolled chains |
| 7 | Parser-factory variant on drivers | 0.6 (`with_factory` + `with_state_factory`) | |
| 8 | `flowscope::test_helpers` module | 0.6 (plan 59) | |
| 9 | `with_high_watermark_threshold` + live anomaly | 0.6 (plan 44) | Includes `AnomalyKind::ReassemblerHighWatermark` |
| 10 | `SessionParser::is_done()` for graceful close | — | Not shipped |
| 11 | `flowscope/l7` umbrella feature | 0.6 | |
| 12 | Doc recipe for re-export intra-doc links | — | Doc-only; minor |

Plus extras flowscope shipped that I'd asked for indirectly:
- TCP retransmit classification + `AnomalyKind::RetransmittedSegment`
  (0.5)
- `TcpInfo::window` (0.5)
- `DnsTcpParser` (0.6 — covers DoT framing, my C5 from
  post-L7-examples feedback)
- `SessionEvent::Application::parser_kind` field (0.5) — lets
  consumers route by protocol at the event level

**Verdict:** flowscope's 0.5/0.6 absorbed essentially everything
from the netring-integration feedback. Round 2 is much shorter as
a result.

---

## At a glance — round 2

| # | Proposal | Tier | Break? |
|---|---|---|---|
| F1 | `flowscope::icmp::IcmpParser` (`DatagramParser`-shaped) | **High** | Additive |
| F2 | `impl Display for L4Proto` (+ trivially `EndReason`, `AnomalyKind`) | **Med** | Additive |
| F3 | `HttpRequest::host()` / `user_agent()` / `cookie()` convenience accessors | **Med** | Additive |
| F4 | `FlowEvent::Ended { l4: Option<L4Proto> }` — carry l4 through to end-of-flow | **High** | Breaking (field add to `Ended`) |
| F5 | `SessionParser::is_done()` for parser-driven graceful close (carried from 0.5 feedback, not yet shipped) | **Med** | Additive |
| F6 | A `flowscope::correlate` module — shared key-indexed time-window primitives | **Big** | Additive but design-heavy |
| F7 | `FlowExtractor` extensions for cross-protocol key derivation (resolve DNS → IP → flow) | **Big** | Design TBD |
| F8 | Doc recipe for re-export intra-doc links (carried; still not shipped) | Polish | Doc-only |
| F9 | `Anomaly` carries a `Severity` enum | Polish | Additive |

The "Big" items (F6, F7) overlap with netring's roadmap; they
could live in either crate. I make the case below for shipping
them in flowscope so any consumer can use them, not just netring.

---

## Tier 1 — high-impact

### F1. `flowscope::icmp::IcmpParser`

**Observation.** `multi_protocol_monitor` reports
`"[ICMP ] + 10.0.0.1 <-> 10.0.0.2"` based on
`FlowEvent::Started { l4: Some(L4Proto::Icmp), .. }` — but can't
tell echo request from destination-unreachable from
time-exceeded. For any real network monitor, the ICMP type/code
is the most informative field of the protocol; without it ICMP
flows look like undifferentiated noise.

ICMP is the largest L4 protocol with no L7-style parser in
flowscope. The whole protocol is small and well-defined:

- **ICMPv4 header (RFC 792):** type (1 byte), code (1 byte),
  checksum (2 bytes), then 4 bytes of type-specific body. Plus
  a few hundred byte payload for error messages (original IP
  header + 8 bytes).
- **ICMPv6 header (RFC 4443):** identical shape, different
  type-number space.

Type ≈ 30 values for IPv4, ≈ 40 for IPv6. Trivial enum.

**Proposal.** Ship a `flowscope::icmp` module behind a feature
gate (`icmp`):

```rust
// flowscope::icmp::types

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IcmpType {
    EchoReply { id: u16, seq: u16 },
    DestinationUnreachable { code: IcmpDestUnreachCode, inner: Option<IcmpInner> },
    SourceQuench,                       // deprecated but seen
    Redirect { code: IcmpRedirectCode, gateway: Ipv4Addr, inner: Option<IcmpInner> },
    EchoRequest { id: u16, seq: u16 },
    TimeExceeded { code: IcmpTimeExceededCode, inner: Option<IcmpInner> },
    ParameterProblem { pointer: u8, inner: Option<IcmpInner> },
    Timestamp { id: u16, seq: u16, originate: u32, receive: u32, transmit: u32 },
    TimestampReply { id: u16, seq: u16, originate: u32, receive: u32, transmit: u32 },
    Other(u8),
}

/// Embedded IP header + first 8 bytes of payload, parsed out of
/// ICMP error messages so consumers can correlate the error with
/// the original flow.
#[derive(Debug, Clone)]
pub struct IcmpInner {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: L4Proto,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct IcmpMessage {
    pub family: IcmpFamily,  // V4 or V6
    pub ty: IcmpType,
}

pub struct IcmpParser;

impl DatagramParser for IcmpParser {
    type Message = IcmpMessage;
    fn parse(&mut self, payload: &[u8], _side: FlowSide, _ts: Timestamp) -> Vec<IcmpMessage> {
        // Parse type/code/body from payload, extract Inner when applicable.
    }
    fn parser_kind(&self) -> &'static str { "icmp" }
}
```

The `IcmpInner` field is the killer feature for **anomaly
correlation**: ICMP error messages embed the first 8 bytes of
the original L4 header. That gives us src/dst ports for
TCP/UDP, which lets us correlate "ICMP unreachable" back to the
specific TCP flow it's complaining about — no separate lookup
needed.

**Effort.** ~200 LoC + tests + types. ~1 day.
**Risk.** None — additive module behind a feature.

### F4. `FlowEvent::Ended { l4: Option<L4Proto> }`

**Observation.** Carried from round 1 (item C2). Still not
shipped in 0.6. Every multi-protocol consumer has to maintain a
side `HashMap<K, L4Proto>` keyed by flow, populated on `Started`,
queried on `Ended`. netring's `multi_protocol_monitor` and
`full_monitor` examples both do this (~10 LoC of bookkeeping
each). The `parser_kind` field on `Application` events is great
but doesn't help here — `Ended` doesn't have parser context.

**Proposal.** Add `l4: Option<L4Proto>` to
`FlowEvent::Ended` (and to `SessionEvent::Closed`, which mirrors
it).

`Option<L4Proto>` rather than `L4Proto` because the field could
be `None` for non-L4 flows in the future (some IPv6 extension
header cases). For now it'll always be `Some` whenever
`Started.l4` was `Some`, mirroring 1:1.

**Effort.** Trivial — add the field, copy from
`Established`/`Started` state through the existing finalize
path. Migration is a one-line variant-field addition.
**Risk.** Breaking pattern match on `Ended` (need `..` or a new
arm). Pre-1.0, fine.

---

## Tier 2 — medium-impact

### F2. `impl Display for L4Proto` (+ `EndReason`, `AnomalyKind`)

**Observation.** Every L7 example I wrote has its own
`match l4 { L4Proto::Tcp => "TCP", L4Proto::Udp => "UDP", ... }`
boilerplate. Same for `EndReason`. Five mostly-identical impls
across the netring examples alone.

**Proposal.** Ship `impl fmt::Display` on `L4Proto`, `EndReason`,
and `AnomalyKind`. Canonical short names: `TCP`, `UDP`, `ICMP`,
`ICMP6`, `SCTP`, `L4(<num>)`. For `EndReason`: `fin`, `rst`,
`idle-timeout`, `evicted`, `buffer-overflow`, `parse-error`. For
`AnomalyKind`: a short summary string.

**Effort.** Trivial. ~30 LoC. **Risk.** None.

### F3. `HttpRequest::host()` / `user_agent()` / `cookie()` accessors

**Observation.** Every HTTP monitor wants Host (for routing),
User-Agent (for bot detection), Cookie (for session tracking).
Today extracting any of them is a 4-line dance:

```rust
let host = req.headers.iter()
    .find(|(k, _)| k.eq_ignore_ascii_case("host"))
    .and_then(|(_, v)| std::str::from_utf8(v).ok())
    .unwrap_or("?");
```

`netring`'s `http_session` example currently prints
`method + path + version` because adding `host` per-event would
double the example's line count.

**Proposal.** Three accessors on `HttpRequest`:

```rust
impl HttpRequest {
    /// `Host:` header value as UTF-8, or `None` if absent / non-UTF-8.
    pub fn host(&self) -> Option<&str>;
    /// `User-Agent:` header value as UTF-8.
    pub fn user_agent(&self) -> Option<&str>;
    /// `Cookie:` header value as UTF-8 (raw — no parsing into name=value pairs).
    pub fn cookie(&self) -> Option<&str>;
    /// Generic case-insensitive header lookup. Returns the first match.
    pub fn header(&self, name: &str) -> Option<&[u8]>;
}
```

Similar on `HttpResponse`: `content_type()`, `content_length()`,
`set_cookie()` (returns iterator since responses can set
multiple), and the generic `header()`.

For TLS, the most-requested accessor would be `sni()` on
`TlsHandshake::ClientHello` — pull the SNI extension's
`server_name`, return `Option<&str>`. Useful for the netring
"who's connecting to what host" question that HTTP `host()`
answers in cleartext.

**Effort.** Small. ~50 LoC + tests. **Risk.** None — additive.

### F5. `SessionParser::is_done()` for graceful close

**Observation.** Carried from round 1 (item #10). Still not
shipped. Used cases multiply with each new L7 parser: HTTP/1.0
`Connection: close` + body fully received; TLS handshake
complete and you're done observing; DNS-over-TCP query/response
pair completed and you don't want to wait for `Fin`. The
parser knows; the tracker doesn't.

**Proposal.** Re-propose verbatim. Default `false`; driver
synthesises `EndReason::ParserClosed` (new variant in the
existing `#[non_exhaustive]` enum).

---

## Tier 3 — bigger items (overlap with netring's roadmap)

### F6. `flowscope::correlate` module

**Observation.** netring's anomaly-correlation use case
(forthcoming roadmap; see netring-side report) needs three
building blocks that are non-trivial to write correctly:

1. **`TimeBucketedCounter<K>`** — `bump(k)` + `count(k)` +
   automatic eviction of buckets older than `window`. Useful for
   rate-anomaly detection ("host issued >N queries in <T seconds").

2. **`KeyIndexed<K, V>`** — a TTL'd kv-cache: `insert(k, v,
   ts)` + `get(k, now)` (returns `Some` only if not expired) +
   automatic LRU eviction at capacity. Useful for "DNS resolved
   X → IPs Y at time T; was the subsequent TCP connection to Y
   within idle window of T?"

3. **`SequenceDetector<E, S>`** — generic finite-state
   pattern: "event matching A → expect event matching B within
   T seconds → otherwise emit anomaly". Stateful per-correlation
   key.

These aren't netring-specific. Any flowscope consumer building
real-time anomaly logic needs them. Putting them in flowscope
gives `des-rs`, `simple-nms`, future consumers the same
primitives. Behind a `correlate` feature.

**Proposal.** Ship as `flowscope::correlate` module:

```rust
pub mod correlate {
    pub struct TimeBucketedCounter<K> {
        window: Duration,
        buckets: VecDeque<(Timestamp, AHashMap<K, u64>)>,
        bucket_width: Duration,
    }
    impl<K: Hash + Eq + Clone> TimeBucketedCounter<K> {
        pub fn new(window: Duration, bucket_width: Duration) -> Self;
        pub fn bump(&mut self, key: K, now: Timestamp);
        pub fn count(&self, key: &K, now: Timestamp) -> u64;
        pub fn entries_above(&self, threshold: u64, now: Timestamp)
            -> impl Iterator<Item = (&K, u64)>;
    }

    pub struct KeyIndexed<K, V> {
        ttl: Duration,
        capacity: usize,
        inner: LruCache<K, (V, Timestamp)>,
    }
    impl<K: Hash + Eq + Clone, V> KeyIndexed<K, V> {
        pub fn new(ttl: Duration, capacity: usize) -> Self;
        pub fn insert(&mut self, k: K, v: V, ts: Timestamp);
        pub fn get(&mut self, k: &K, now: Timestamp) -> Option<&V>;
        pub fn evict_expired(&mut self, now: Timestamp);
    }

    pub trait SequencePattern: Send + 'static {
        type Event;
        type Anomaly;
        /// Called per event. Returns anomalies the pattern fires.
        fn observe(&mut self, evt: &Self::Event, now: Timestamp)
            -> SmallVec<[Self::Anomaly; 1]>;
        /// Called on a periodic sweep — for timeout-based detections.
        fn on_tick(&mut self, now: Timestamp) -> SmallVec<[Self::Anomaly; 4]>;
    }
}
```

Each primitive carries its own tests + benchmarks (criterion).
Real anomaly examples live downstream (in netring) and exercise
the primitives.

**Effort.** ~600 LoC + tests + bench. Probably its own minor
release (0.7.0). **Risk.** Design surface — the API needs to
be right before lock. Suggest a draft RFC in flowscope's
`plans/` before implementation.

### F7. `FlowExtractor` extensions for cross-protocol key derivation

**Observation.** "DNS resolved 'api.foo.com' to 93.184.216.34;
what subsequent TCP flows went to that IP?" requires the
consumer to extract the IP from the DNS response themselves and
maintain a manual `DnsResolution<IpAddr, String>` index.

This is the **core enabling primitive for cross-protocol
correlation**. A pre-built solution would let netring's anomaly
examples be ~30 LoC instead of ~300.

**Proposal sketch (RFC-shaped, not concrete API yet).** A
`flowscope::correlate::DnsResolutionCache` that:

1. Observes a `Stream<Item = SessionEvent<K, DnsMessage>>`.
2. Indexes `(name → set of (ip, ttl, ts))` and the inverse
   `(ip → name, ts)`.
3. Exposes `who_resolved_to(ip, now) -> Option<&str>` — returns
   the name that most recently resolved to this IP (if within
   reasonable TTL).
4. Composes with `FlowStream` so subsequent TCP flow events get
   their dest IP looked up against the cache and annotated.

This is more design than implementation. The right shape probably
emerges only after writing 2–3 anomaly examples manually first.

**Effort.** TBD. **Risk.** High API churn pre-stable.

---

## Tier 4 — polish

### F8. Doc recipe for re-export intra-doc links

Still not done. Every minor netring touches re-exports, the
same `redundant_explicit_links` warning. A short snippet in
flowscope's `docs/` would save the round trip.

### F9. `Anomaly` carries a `Severity`

**Observation.** All `AnomalyKind` variants are flat — no
indication of "this is a casual observation" vs "drop everything
and page someone". netring's anomaly-correlation engine wants to
route by severity (logs vs alerts vs metrics).

**Proposal.** Add a defaulted `AnomalyKind::severity(&self) ->
Severity` method, returning `Info` / `Warn` / `Error` /
`Critical`. Tracker-globals like `FlowTableEvictionPressure`
warrant `Warn`/`Error`; per-flow `OutOfOrderSegment` is `Info`;
`BufferOverflow`/`ParseError` is `Error`.

**Effort.** Trivial. **Risk.** None — additive.

---

## What this means for netring's anomaly use case

The roadmap netring wants — "easily build apps that correlate
multiple protocols to deduce network anomalies" — leans on
flowscope for:

1. **The unified L7 surface** (FlowAnomaly, SessionEvent, all
   the L7 parsers). ✅ already there in 0.6.

2. **Time-stamped event ordering** so cross-stream correlation
   has a coherent timeline. ✅ already there — every event
   carries `Timestamp`.

3. **An ICMP parser** (F1) — otherwise the most informative
   protocol for diagnosing network failures (unreachable,
   time-exceeded, redirect, parameter problem) is opaque.
   **Critical for the roadmap.**

4. **`Ended.l4`** (F4) — otherwise correlator code carries the
   `HashMap` workaround everywhere.

5. **Correlation primitives** (F6) — the
   `TimeBucketedCounter` / `KeyIndexed` / `SequencePattern`
   trinity is the substrate every concrete anomaly detector
   needs. Shipping them once in flowscope avoids 4–6 different
   downstream implementations.

6. **HTTP/TLS accessors** (F3) — for the SNI / Host / UA-based
   anomaly classifiers that real monitoring needs.

If I had to prioritize for the netring use case: **F1 (ICMP) >
F6 (correlate module) > F4 (Ended.l4) > F3 (HTTP accessors)**.
The others are quality-of-life.

---

## Effort table (rough)

| Item | LoC | Risk | Days |
|---|---|---|---|
| F1 — ICMP parser | ~200 | low | 1 |
| F2 — Display impls | ~30 | none | 0.5 |
| F3 — HTTP accessors | ~50 | none | 0.5 |
| F4 — `Ended.l4` field | ~20 | low (variant-field break) | 0.5 |
| F5 — `is_done()` | ~30 | none | 0.5 |
| F6 — `correlate` module | ~600 | medium (API design) | 4–5 |
| F7 — `DnsResolutionCache` | ~300 | high (design) | 3 + RFC |
| F8 — doc snippet | — | none | 0.25 |
| F9 — `Severity` | ~20 | none | 0.25 |

**Total for 0.7 if everything lands: ~10 days.** Realistic split:

- **0.7.0**: F1, F2, F3, F4, F5, F8, F9 (~3 days)
- **0.8.0**: F6, F7 (~7 days + RFC review)

---

## Closing

flowscope 0.5/0.6 absorbed essentially all of the previous
feedback round — credit roll above. The post-L7-examples gaps
that remain are mostly small (F1 ICMP, F2 Display, F3 accessors,
F4 `Ended.l4`, F9 severity). The big architectural item is the
`correlate` module (F6) — that's the single biggest enabler for
the netring anomaly-correlation roadmap and deserves its own
0.8 cycle with proper RFC review.

Happy to draft individual RFC docs for F6 / F7 if useful.
