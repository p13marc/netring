# Migrating netring 0.27 → 0.28

0.28 adopts **flowscope 0.20** — flowscope's largest pre-1.0 breaking batch
(driver/event convergence + a 1.0-prep strong-typing sweep + new NSM
primitives). netring takes the break as a coordinated release
([#108](https://github.com/p13marc/netring/issues/108)) and uses it to surface
the new race-stable direction primitives.

> **Version note.** This ships as **`0.28.0`** — a pre-1.0 minor, so the breaking
> changes below are expected. The `1.0` API-freeze is deferred and tracked in
> [#37](https://github.com/p13marc/netring/issues/37).

Most application code is unaffected: if you consume the `Monitor` via typed
handlers, only the new additive fields show up (your matches keep working
because the netring event structs are `#[non_exhaustive]`). The breaking surface
is concentrated in **(a)** the async L7 stream layer (`SessionEvent` is now a
netring type), **(b)** the offline pcap drivers, and **(c)** a handful of typed
fields lifted from `&'static str` to enums.

---

## 1. Breaking: `SessionEvent` is now a netring type (`netring::flow::SessionEvent`)

flowscope 0.20 retired its public `SessionEvent` (it became a crate-private
engine carrier). netring now **owns** its session-stream event type. It is a
drop-in with the same variants (`Started` / `Application` / `Closed` /
`FlowAnomaly` / `TrackerAnomaly`), re-exported from `netring::flow` and the
prelude.

```rust
// 0.27
use flowscope::SessionEvent;

// 0.28
use netring::flow::SessionEvent;          // or `use netring::prelude::*;`
```

The `Stream::Item` of `SessionStream` / `DatagramStream` /
`PcapSessionStream` / `PcapDatagramStream` (and the `TaggedEvent`-wrapped multi
variants) now carries this type. `flowscope::FlowEvent` (the lower-level tracker
primitive) is **unchanged** and still re-exported from `netring::flow`.

### New additive field: `orientation`

`SessionEvent::Started` and `SessionEvent::Application` gained an
`orientation: flowscope::Orientation` field next to `side`. `side`
(`FlowSide`) is the arrival-order-relative logical role; `orientation`
(`Forward` / `Reverse`) is the **deterministic, address-sorted** direction
— stable across a tap-merge / multi-queue arrival race. The enum is
`#[non_exhaustive]`, so a `match` with a trailing `..` keeps compiling; add the
field only if you construct events directly or match exhaustively.

## 2. Breaking: offline pcap L7 — `Flow{Session,Datagram}Driver` removed

flowscope 0.20 deleted the per-parser `FlowSessionDriver` / `FlowDatagramDriver`
engines. netring's `AsyncPcapSource::sessions` / `datagrams` and
`PcapFlowStream::session_stream` / `datagram_stream` are unchanged at the call
site — they now drive a flowscope `FlowTracker` directly, reusing the exact same
translation as the live `SessionStream`, so live and offline L7 pipelines are
equivalent.

- `PcapSessionStream::driver()` / `PcapDatagramStream::driver()` are **removed**
  (there is no longer an inner driver). Use **`.tracker()`** for the same
  introspection (`tracker_stats()` / `active_flows()` are unchanged).
- `PcapFlowStream::session_stream` / `datagram_stream` now **preserve in-flight
  flow state** (the existing tracker is moved in rather than rebuilt) — a strict
  improvement; no action needed.

## 3. Breaking: typed `ParserKind` replaces `&'static str`

flowscope 0.20 lifted `SessionParser::parser_kind()` from `&'static str` to the
typed [`ParserKind`](https://docs.rs/flowscope/latest/flowscope/enum.ParserKind.html)
enum (re-exported as `netring::flow::ParserKind`). netring adopts it on:

- `ParserClosed<P>::parser_kind` (field + `ParserClosed::new` argument),
- `SessionEvent::Application::parser_kind`,
- `EventStream::parser_kind()`.

`.as_str()` recovers the original slug (`"http/1"`, `"dns/udp"`, …), so emitted
JSON and metric labels are byte-for-byte unchanged.

```rust
// 0.27
assert_eq!(stream.parser_kind(), "http/1");
let e = ParserClosed::<Tcp>::new(key, "http", reason, ts);

// 0.28
assert_eq!(stream.parser_kind().as_str(), "http/1");
let e = ParserClosed::<Tcp>::new(key, flowscope::ParserKind::Other("http"), reason, ts);
// (built-in parsers return a dedicated variant, e.g. `ParserKind::Http1`)
```

The `Protocol::NAME` constants and `flowscope::parser_kinds::*` `&str` constants
are **unchanged** — only the trait method / event fields moved to the enum.

## 4. Breaking: EVE output — `flow_hash` → `community_id`

flowscope 0.20 `EveJsonWriter` drops the proprietary FNV-1a `flow_hash` field in
favor of the standard Corelight **Community ID** (`community_id`). netring's
`eve-sink` feature now pulls `flowscope/community-id` automatically, so EVE
output keeps a portable, Zeek/Suricata/Arkime-interoperable flow id.

**Re-key any dashboard / correlation** that joined on `flow_hash`:

```diff
- | where flow_hash="9f3c0bb2a17f5048"
+ | where community_id="1:wCb3Oy8JZ7qWp0pXm1mUg6yQ7sE="
```

The in-process FNV hash remains available as `KeyFields::stable_hash()` for
non-portable sharding; it just isn't serialized.

## 4b. Breaking: `export::FlowRecord` gains `community_id`, loses `Copy`

The same Community ID now rides netring's flow-export record (`export::FlowRecord`),
so the JSON / IPFIX exporters surface the portable id alongside EVE — one
canonical flow id across every output sink (issue #33). Two consequences:

- **New field** `community_id: Option<String>` (populated for full 5-tuples
  via the `flow` feature, which now pulls `flowscope/community-id`). The NDJSON
  line gains a `"community_id":"1:…"` key. The default IPFIX templates don't
  carry it on the wire (Community ID is not an IANA IE), but the canonical
  IE-keyed record does.
- **`FlowRecord` is no longer `Copy`** (the `String` owns an allocation). Records
  are handed to exporters by `&`, so the hot path is unaffected; only code that
  *copied* a record out of an exporter callback needs `.clone()`:

```diff
- .export_flows(move |rec: &FlowRecord| sink.lock().unwrap().push(*rec))
+ .export_flows(move |rec: &FlowRecord| sink.lock().unwrap().push(rec.clone()))
```

## 5. Breaking (rarely hit): flowscope wire types are `#[non_exhaustive]`

flowscope 0.20 marked 43 more public types `#[non_exhaustive]` (the DNS / HTTP /
TLS wire records, the flow keys, `Extracted`, …). This affects only code that
**constructs them with a struct literal** or **matches an enum exhaustively**:

```rust
// 0.27
let key = FiveTupleKey { proto, a, b };
match http_msg { HttpMessage::Request(r) => …, HttpMessage::Response(_) => … }

// 0.28
let key = FiveTupleKey::new(proto, a, b);          // also DnsRecord::new, HttpRequest::new, Extracted::new, …
match http_msg { HttpMessage::Request(r) => …, _ => … }   // add a wildcard arm
```

The free `flowscope::<proto>::parse*()` functions also moved `Option<T>` →
`Result<T, ParseError>`; if you call them directly, `if let Some(m)` becomes
`if let Ok(m)` (netring handles its own L2/L3 parse sites internally).

---

## New capabilities you can now opt into

- **Race-robust TCP initiator (`infer_tcp_initiator`).** When capturing across
  multiple AF_XDP queues or a TX/RX-split tap, a `SYN+ACK`-first flow can mislabel
  the initiator. Enable inference to flip it (and set `FlowStats::direction_flipped`):

  ```rust
  Monitor::builder().interface("eth0").infer_tcp_initiator(true) /* … */;
  // multi-source streams: MultiStreamConfig::new().with_infer_tcp_initiator(true)
  ```

  A no-op for a single tap (where the SYN is always seen first). The canonical
  `orientation` axis is race-immune regardless of this flag.

- **Canonical `orientation`** on `FlowStarted<P>`, `FlowPacket`, and
  `SessionEvent::{Started,Application}` — the direction axis that survives a
  tap-merge / two-queue race (the right key for biflow dedup and Community ID
  ordering).

- **Per-direction capture-leg binding.** With `source_idx` now preserved through
  the monotonic-timestamp clamp, a shared/merged tracker surfaces
  `FlowStats::source_idx_{forward,reverse}` + `capture_leg_inconsistent`
  (the tap-miswire / asymmetric-routing IOC) on `SessionEvent::Closed`'s stats.
  The merged-tap stream that exploits this is tracked in
  [#105](https://github.com/p13marc/netring/issues/105).

- **AF_XDP flow streams + multi-interface fan-in
  ([#104](https://github.com/p13marc/netring/issues/104)).** `AsyncXdpCapture`
  now has a `flow_stream(extractor)` — the AF_XDP analogue of
  `AsyncCapture::flow_stream` — and the new `AsyncXdpMultiCapture::open([...])`
  fans N NICs (each internally multi-queue) into one
  `XdpMultiFlowStream` yielding `TaggedEvent { source_idx, event }` (the
  motivating shape for TX/RX-split taps on two NICs):

  ```rust
  let multi = AsyncXdpMultiCapture::open(["eth0", "eth1"])?;
  let mut stream = multi.flow_stream(FiveTuple::bidirectional());
  while let Some(evt) = stream.next().await { let _ = evt?.source_idx; }
  ```

  **AF_XDP L7 too:** `SessionStream` / `DatagramStream` are now source-agnostic,
  so `xdp_cap.flow_stream(ext).session_stream(parser)` / `.datagram_stream(parser)`
  work over AF_XDP, and `AsyncXdpMultiCapture::{session_stream,datagram_stream}`
  fan them in as `XdpMultiSessionStream` / `XdpMultiDatagramStream`.

## Breaking: `FlowStream`'s first type parameter is now the *source*

To share one tracking loop across AF_PACKET and AF_XDP ([#104]), `FlowStream` is
generic over the **capture** rather than the inner socket. Only code that *named*
`FlowStream<S, …>` explicitly is affected — `cap.flow_stream(…)` call chains are
not:

```diff
- FlowStream<MySocket, E>
+ FlowStream<AsyncCapture<MySocket>, E>   // AF_PACKET
+ FlowStream<AsyncXdpCapture, E>          // AF_XDP
```

`SessionStream` / `DatagramStream` are likewise generic over the source now —
explicit `SessionStream<S, E, F>` names become `SessionStream<AsyncCapture<S>, E, F>`
(or `SessionStream<AsyncXdpCapture, E, F>`). `into_conversations` / `broadcast`
and the `StreamCapture` trait stay AF_PACKET-only (`StreamCapture::capture()`
returns a concrete `&AsyncCapture<S>` the AF_XDP source can't provide; AF_XDP
streams expose `xdp_capture()` / `capture_stats()` inherent accessors instead).

[#104]: https://github.com/p13marc/netring/issues/104
