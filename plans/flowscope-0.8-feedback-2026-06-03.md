# Feedback for flowscope 0.8 — third round, post-netring-anomaly-toolkit

**Date:** 2026-06-03
**Author:** maintainer of `netring`
**Context:** retrospective from shipping the netring 0.16
anomaly-correlation roadmap end-to-end — 7 reference detectors,
`ProtocolMonitor` + `AnomalyMonitor` harness, `Severity` bridge,
pcap-replay path, JSON output. flowscope 0.7's ICMP work
unblocked the third N10 reference detector.

**Scope rule:** backward-incompatible breaks are explicitly
allowed; pre-1.0; releases ship in lockstep with netring.

> Companion to
> [`flowscope-0.7-feedback-2026-05-29.md`](./flowscope-0.7-feedback-2026-05-29.md)
> which drove flowscope 0.7 (most items shipped — see "Already
> shipped" below).

---

## Already shipped in flowscope 0.7 — credit roll

Of the 9 round-2 proposals, flowscope 0.7 shipped **8**:

| # | Proposal | Shipped in | Notes |
|---|---|---|---|
| F1 | `flowscope::icmp::IcmpParser` (DatagramParser-shaped) | 0.7 (plan 76) | Plus `IcmpInner` — the cross-protocol primitive that unblocked netring's `icmp_explained_drop` detector |
| F2 | `Display for L4Proto / EndReason / AnomalyKind` | 0.7 (plan 77) | Drops boilerplate in 4 netring examples |
| F3 | HTTP / TLS convenience accessors | 0.7 (plan 78) | `host()` / `user_agent()` / `cookie()` / `content_type()` / `sni()` |
| F4 | `FlowEvent::Ended { l4 }` + `SessionEvent::Closed { l4 }` | 0.7 (plan 79) | Dropped the `HashMap<K, L4Proto>` workaround in netring (N4) |
| F5 | `SessionParser::is_done()` | 0.7 (plan 80) | Plus `EndReason::ParserDone` |
| F6 | `flowscope::correlate` shared primitives | — | Not shipped; netring kept its own `netring::correlate` |
| F7 | `FlowExtractor` cross-protocol key derivation | — | Not shipped; deferred (design-heavy) |
| F8 | Intra-doc-link recipe in published docs | 0.7 (plan 62) | |
| F9 | `Anomaly` carries a `Severity` enum | 0.7 (plan 82) | `AnomalyKind::severity()`; perfectly bridged to `netring::anomaly::Severity` |

**Verdict:** flowscope 0.7 absorbed everything except F6/F7,
which are genuine design work. Round 3 is correspondingly short
and focuses on what 0.7-driven *netring* work (the 0.16 anomaly
toolkit) surfaced.

---

## At a glance — round 3

| # | Proposal | Tier | Break? |
|---|---|---|---|
| G1 | `IcmpType::is_error()` + `IcmpInner` extraction helper | **Med** | Additive |
| G2 | `TlsClientHello::dst_ip()` / handshake-context access via `SessionEvent` | Polish | API design TBD |
| G3 | `DnsResolutionCache` primitive in `flowscope::correlate` (or `flowscope::dns`) | **Med** | Additive |
| G4 | `AsyncPcapSource`-equivalent that doesn't consume the source on `.sessions()` / `.datagrams()` / `.flow_events()` | **Med** | API redesign (additive `Arc<Source>` shape) |
| G5 | `serde::Serialize` opt-in feature on `HttpMessage` / `DnsMessage` / `TlsMessage` / `IcmpMessage` | **High** | Additive (gated on `serde` feature) |
| G6 | `FlowEvent::Established { l4 }` (consistency with `Started`/`Ended`) | Polish | Breaking |
| G7 | `AnomalyKind::short_kind()` returning a stable slug | Polish | Additive |
| G8 | `flowscope::correlate` module (carried from F6) | **Big** | Additive but design-heavy |

---

## G1. `IcmpType::is_error()` + uniform `IcmpInner` extraction

**Observation.** Writing `examples/anomaly/icmp_explained_drop.rs`
required a 40-LoC `extract_icmp_error()` helper that pattern-matches
every error-bearing variant (`DestinationUnreachable`,
`TimeExceeded`, `Redirect`, `ParameterProblem` on v4;
`DestinationUnreachable`, `PacketTooBig`, `TimeExceeded`,
`ParameterProblem` on v6) and pulls out `(label, &IcmpInner)`. Every
consumer of `IcmpInner`-bearing types will write the same helper.

**Proposal.** Two complementary methods on `IcmpMessage` (or on
`IcmpType`):

```rust
impl IcmpType {
    /// `true` for variants that carry an `inner: Option<IcmpInner>`
    /// (i.e. all the error-class types). v4 EchoRequest/Reply,
    /// Timestamp etc. return `false`.
    pub fn is_error(&self) -> bool;

    /// Convenience: `(short label, &IcmpInner)` for any error
    /// variant whose inner was successfully parsed. `None` for
    /// non-error types or truncated embeds.
    pub fn error_inner(&self) -> Option<(&'static str, &IcmpInner)>;
}
```

`short label` is a static string like `"DestUnreachable"` /
`"TimeExceeded"` / `"PacketTooBig"` — used for metric labels and
log lines. The full code/family detail stays in the variant for
consumers that need it.

**Effort.** ~30 LoC + tests. Pure pattern-match.
**Risk.** None. Pre-1.0 additive method.

## G2. TLS handshake-context access

**Observation.** `tls_to_unresolved_ip.rs` extracts the SNI from
`TlsMessage::ClientHello(ch)` via `ch.sni.as_deref()`. That works
because the `sni` field is public. flowscope 0.7 plan 78 added
`TlsClientHello::sni()` for accessor symmetry — good. But
`slow_tls_handshake.rs` needs to correlate the ClientHello with
the eventual ServerHello in the same flow; flowscope doesn't
expose any "handshake-context" view. The detector tracks
ClientHello / ServerHello timing via `KeyIndexed<FiveTupleKey,
Timestamp>` user-side.

**Proposal.** Either:
- Ship a `TlsHandshake` aggregator parser that emits one
  `TlsMessage::HandshakeComplete { client_hello, server_hello,
  rtt }` instead of (or in addition to) the individual messages.
- Or document the pattern (KeyIndexed correlation) clearly. The
  current design is fine; just needs a recipe.

**Effort.** ~50 LoC for the aggregator. **Risk.** Low.

## G3. `DnsResolutionCache` primitive

**Observation.** Two netring detectors
(`dns_resolved_no_connection.rs`, `tls_to_unresolved_ip.rs`)
implement essentially the same primitive: per-source-IP
"resolved IP cache" with TTL. Both wrap
`KeyIndexed<IpAddr, ()>` in a `HashMap<IpAddr, _>` and walk DNS
responses to populate it.

**Proposal.** Ship `flowscope::dns::DnsResolutionCache` (or
better, `flowscope::correlate::DnsResolutionCache` once F6 lands):

```rust
pub struct DnsResolutionCache {
    by_host: HashMap<IpAddr, KeyIndexed<IpAddr, ()>>,
    ttl: Duration,
}
impl DnsResolutionCache {
    pub fn new(ttl: Duration) -> Self;
    /// Record every A/AAAA answer in `r`, attributed to `client_ip`.
    pub fn observe_response(&mut self, client_ip: IpAddr, r: &DnsResponse, now: Timestamp);
    /// Has `client_ip` recently resolved `target_ip` to a name?
    pub fn was_resolved(&self, client_ip: IpAddr, target_ip: IpAddr, now: Timestamp) -> bool;
    pub fn sweep(&mut self, now: Timestamp);
}
```

Saves every consumer ~40 LoC. Could live in `flowscope::dns` to
avoid the broader `correlate` redesign.

**Effort.** ~60 LoC + tests. **Risk.** None.

## G4. `AsyncPcapSource` consumed once

**Observation.** netring's `examples/anomaly/pcap_replay.rs`
documents that `AsyncPcapSource::datagrams()` consumes the
source — so a single pcap file → one L7 protocol stream.
Multi-protocol replay needs to open the same pcap twice (slow +
wasteful) or write a packet-level loop (a lot of code).

This is netring's pcap source, not flowscope's — but the
underlying design pattern (drivers that consume on entry) shows
up everywhere flowscope owns the iteration. Worth a thinking
pass on whether the `S = ()` driver shape (already restored in
0.6) could be extended to a "fork-style" `S = (DnsParser,
HttpParser, TlsParser)` so one packet stream feeds N parsers.

**Proposal.** Two routes, pick one:
- **Light.** Document the workaround (re-open the source) as the
  intended pattern; netring follows suit.
- **Heavy.** Add `FlowDriver::with_parsers((P1, P2, ...))` shape
  that fans the same packet stream into N parsers. Echoes the
  `sweep_with_parsers` design but at construction time.

The heavy version is genuinely useful (lots of multi-protocol
correlation cases would benefit) but design-heavy. The light
version is free.

**Effort.** Light: doc only. Heavy: ~2 days. **Risk.** Heavy is
medium (touches the type signatures of every driver).

## G5. `serde::Serialize` for L7 message types

**Observation.** netring's `Anomaly::to_json_line()` hand-rolls
RFC 8259 escape logic because we don't want to pull serde. That
works for `Anomaly<K>` (small struct, controlled fields). But
when users want to ship full `HttpMessage` / `DnsMessage` /
`TlsMessage` / `IcmpMessage` events into Vector / Fluentd / Loki,
they're stuck — flowscope doesn't ship `serde::Serialize` impls.

Workaround today: users hand-write a `to_json` for each variant
they care about. That's brittle and rots fast (new variants on
`#[non_exhaustive]` enums silently miss the serializer).

**Proposal.** Add a `serde` opt-in feature on flowscope. With it
on, every L7 message type derives `Serialize`. Field-level
`#[serde(rename = "...")]` to lock the wire vocabulary (camelCase
or snake_case, pick one) so consumers don't churn on enum renames.

`netring` could then offer a thin `Anomaly::to_json_value() ->
serde_json::Value` that includes the underlying parsed message
verbatim, not just the metadata.

**Effort.** ~3 days (feature + derives + lock-in serialization
contract + CI matrix entry). **Risk.** Med — the serialization
contract becomes a stability surface.

## G6. `FlowEvent::Established { l4 }`

**Observation.** Plan 79 added `l4` to `Started` and `Ended` /
`Closed`. `Established` (the TCP-3WHS-completed event) doesn't
carry it. For consistency, it should. Same migration shape as
plan 79.

**Effort.** ~10 LoC. **Risk.** Pre-1.0 field add to a struct
variant; same migration shape as 0.7.

## G7. `AnomalyKind::short_kind()`

**Observation.** Every netring rule that lifts a flowscope
anomaly into an `Anomaly<K>` does
`.with_observation("kind", kind.to_string())` — getting the
full Display rendering (e.g. `"buffer_overflow"`). That's fine,
but it includes parameters (e.g. `"out_of_order_segment side=initiator count=12"`
once Display ships richer detail). For metric labels and grouping,
users want just the short kind slug (`"out_of_order_segment"`,
`"buffer_overflow"`, …).

**Proposal.** Add `AnomalyKind::short_kind() -> &'static str`
that returns just the variant name as the canonical metric token.
Compositional with `kind.to_string()` (which can still include
parameters).

**Effort.** ~20 LoC. **Risk.** None.

## G8. `flowscope::correlate` (carried from F6)

Still desirable. netring shipped `netring::correlate` with
`KeyIndexed` and `TimeBucketedCounter`, but they're general
enough that flowscope could host them. Moving them down a layer
would mean other flowscope consumers (PCAP analyzers,
non-Linux capture tools, embedded users) get them for free.

Suggested API: same shape as netring's, gated behind a
`correlate` feature. netring would re-export `flowscope::correlate::*`.

**Effort.** ~1 day (move + tests + feature gate). **Risk.** None
beyond the inter-crate dance.

---

## Effort summary

| # | LoC | Days | Risk |
|---|---|---|---|
| G1 | ~30 | 0.2 | None |
| G2 | ~50 (aggregator) or 0 (doc only) | 0.3 / 0 | Low |
| G3 | ~60 | 0.5 | None |
| G4 | Light: 0 (doc). Heavy: ~200 | 0 / 2 | Heavy: medium |
| G5 | ~200 + CI | 3 | Med (stability) |
| G6 | ~10 | 0.1 | None (pre-1.0) |
| G7 | ~20 | 0.1 | None |
| G8 | ~150 | 1 | None |

**Total: ~5 days light path, ~10 days with G4 heavy + G5.**

## Priorities

If flowscope ships only 3 things in 0.8:

1. **G5 — serde feature.** Highest leverage; unblocks every
   production user shipping events to log pipelines.
2. **G1 — `IcmpType::is_error()` + extraction helper.** Saves
   every ICMP-correlation detector from re-implementing it.
3. **G3 — `DnsResolutionCache` primitive.** Already shipped
   twice in netring; the third user shouldn't have to write it.

G6, G7, G8 are nice-to-have. G2, G4 need design before shipping.

---

## Cross-references

- netring 0.16 prepared on this branch (~322 tests, 56 examples,
  the 7 reference detectors), CHANGELOG entry in
  `netring/CHANGELOG.md`.
- netring's `plans/netring-0.17-flowscope-0.7-bump-2026-06-03.md`
  documents how 0.7's items landed downstream.
- The `tls_to_unresolved_ip.rs` detector in
  `examples/anomaly/` was the most direct test of the harness's
  multi-protocol promise — three protocols joined in one rule.
  Smooth-ish but motivated G2, G3.
