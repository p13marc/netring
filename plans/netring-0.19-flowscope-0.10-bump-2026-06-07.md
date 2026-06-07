# netring 0.19 — flowscope 0.10 bump + wishlist absorption

**Date:** 2026-06-07
**Author:** netring maintainer
**Status:** 📝 drafted; ready to execute
**Predecessor:** [`netring-0.16-roadmap-2026-05-29.md`](./netring-0.16-roadmap-2026-05-29.md),
[`netring-0.17-flowscope-0.7-bump-2026-06-03.md`](./netring-0.17-flowscope-0.7-bump-2026-06-03.md),
[`flowscope-wishlist-2026-06-06.md`](./flowscope-wishlist-2026-06-06.md).

**Driven by:** flowscope 0.10.1 (2026-06-07) — direct response to the
consolidated wishlist plus the absorbed 0.9 and 0.10 design cycles.
flowscope **shipped every item** from sections A and B of the
wishlist, plus a major architectural redesign (unified
`Driver<E, M>` + `Event<K, M>`) plus dozens of new helpers.

**Scope rule:** backward-incompatible breaks are explicitly
allowed; pre-1.0; lockstep with flowscope.

---

## Three-phase absorption strategy

flowscope 0.10 is the biggest release since 0.1. Trying to
absorb it in one cycle invites mistakes. Three sequential
netring roadmaps:

| Phase | Scope | This file? | Days |
|---|---|---|---|
| **netring 0.19** | Lockstep bump (0.7 → 0.10) + immediate wishlist absorption (cleanups that don't change netring's architecture) | **Yes** | ~2 |
| **netring 0.20** | Collapse `ProtocolMonitor` onto flowscope's unified `Driver<E, M>` + `Event<K, M>`. Closes N5 (driver refactor) + N6 (single-ring fan-out) in one strike via the new flowscope-side API. | [`netring-0.20-unified-driver-refactor-2026-06-07.md`](./netring-0.20-unified-driver-refactor-2026-06-07.md) | ~5 |
| **netring 0.21** | New detectors using `flowscope::detect` / `correlate` extensions / `aggregate` / `emit` / `well_known`. Polish + helper-sweep adoption. | [`netring-0.21-new-detectors-2026-06-07.md`](./netring-0.21-new-detectors-2026-06-07.md) | ~4 |

This file covers **0.19 only** — the mechanical migration plus
the wishlist items that drop in without touching netring's
architecture. Each absorbed item is tagged with its wishlist
identifier from `flowscope-wishlist-2026-06-06.md` so the
cross-reference stays explicit.

---

## At a glance — netring 0.19 work items

| # | Item | Wishlist | Tier | Break? |
|---|---|---|---|---|
| **B1** | Bump `flowscope = "0.7"` → `"0.10"` | — | **High** | Yes (transitive) |
| **B2** | MSRV bump 1.95 → keep (1.88 satisfied by 1.95); no-op verify | — | **High** | None |
| **B3** | Migrate to unified `flowscope::Error` | — | **High** | Yes |
| **B4** | Bind `l4` on every `FlowEvent::Established { … }` destructure | — | **High** | Yes (field-add) |
| **B5** | Replace `netring::correlate` with re-exports of `flowscope::correlate` | C1 | **High** | Yes (path change, easy migration) |
| **B6** | Switch every `"http/1"` / `"dns-udp"` / `"dns-tcp"` / `"tls"` / `"icmp"` literal to the new `PARSER_KIND*` constants | B1 (wishlist) | **Med** | None |
| **B7** | Use `IcmpType::error_inner()` in `icmp_explained_drop.rs` — drop the 40-LoC helper | A2 (wishlist) | **Med** | None |
| **B8** | Use `flowscope::dns::DnsResolutionCache` in `dns_resolved_no_connection.rs` + `tls_to_unresolved_ip.rs` | A3 (wishlist) | **Med** | None |
| **B9** | `FlowAnomalyRule` switches from `kind.to_string()` to `kind.short_kind()` | B4 (wishlist) | Polish | None |
| **B10** | Use `TlsHandshakeParser` in `slow_tls_handshake.rs` — drop the hand-rolled `KeyIndexed` correlation | B6 (wishlist) | **Med** | None |
| **B11** | Add `serde` Cargo feature: `serde = ["dep:serde", "flowscope/serde"]` + derive `Serialize`/`Deserialize` on `Anomaly<K>` / `AnomalyContext` / `Severity` | A1 (wishlist) | **High** | None |
| **B12** | Add `Anomaly::to_json_value() -> serde_json::Value` next to `to_json_line()` — full structured payload including the underlying parsed message | A1 (downstream) | **Med** | None |
| **B13** | Cargo.toml version bump 0.16.0 → 0.17.0 (we publish 0.17 to match the just-shipped flowscope 0.10 in lockstep — naming aligned to the *flowscope* release, not the netring counter) | — | **High** | None |
| **B14** | CHANGELOG.md entry for 0.17.0 with the wishlist scorecard | — | **High** | None |
| **B15** | Doc sweep — README + CLAUDE.md + WRITING_DETECTORS + INDEX | — | Polish | None |

**Versioning note.** netring's release-counter and flowscope's
release-counter have drifted (netring 0.16 ↔ flowscope 0.10). We
don't realign — netring's next minor is **0.17** (this plan), not
0.19, despite the plan filename's "0.19" being the *flowscope-side*
naming. See B13 for the rationale.

> The plan filename uses `netring-0.19` because there are already
> drafted plans `netring-0.18-roadmap-2026-06-03.md` and
> `netring-0.18-flowscope-0.10-bump-…` would collide with the
> 0.18 roadmap. We label the *plans* by counter increment
> independently from the *crate version* on Cargo.toml. The
> crate ships as netring 0.17.

---

## B1. Bump `flowscope = "0.7"` → `"0.10"`

Single-line in `netring/Cargo.toml`. Triggers compile errors
that B3 + B4 mop up. Don't worry about `flowscope = "0.10"`
vs `"0.10.1"` — the patch is CI hygiene only.

```diff
- flowscope = { version = "0.7", default-features = false }
+ flowscope = { version = "0.10", default-features = false }
```

Acceptance gate before moving on: `cargo update -p flowscope`
succeeds.

## B2. MSRV check

flowscope 0.10 requires Rust 1.88. netring is already on 1.95 —
no change needed. Just verify with:

```bash
cargo build -p netring --all-features
```

If this fails for MSRV reasons, something else is wrong.

## B3. Migrate to unified `flowscope::Error`

flowscope 0.9 collapsed five module-local enums (`http::Error`,
`tls::Error`, `dns::Error`, `pcap::Error`, `icmp::Error`) into
one `flowscope::Error` carrying `Module` + `ErrorCode`. netring's
error sites that destructure flowscope errors must migrate to
the new shape.

### Touch points

```bash
$ grep -rnE "flowscope::(http|tls|dns|pcap|icmp)::Error" netring/src netring/tests netring/examples
```

Likely sites:
- `netring/src/error.rs` — wrapper / From impls
- Per-parser examples that destructure on the parser's error

### Migration shape

```diff
- match err {
-     flowscope::http::Error::Parse(s)          => log::warn!("parse: {s}"),
-     flowscope::http::Error::BufferOverflow(n) => log::error!("overflow at {n}"),
- }
+ use flowscope::{Module, ErrorCode};
+ match (err.module(), err.code()) {
+     (Module::Http, ErrorCode::Parse)          => log::warn!("http: {err}"),
+     (Module::Http, ErrorCode::BufferOverflow) => log::error!("http: {err}"),
+     _ => {}
+ }
```

The `Display` format is `"{module}: {code}: {message}"` — not
API-stable, do not parse.

If netring's `Error::From<flowscope::http::Error>` (et al)
impls exist, replace with one `From<flowscope::Error>`.

## B4. `FlowEvent::Established { l4, … }` bind

Plan 87 (flowscope 0.8) added `l4: Option<L4Proto>` to
`Established`, rounding out the trio with `Started`/`Ended`
that we already migrated in netring 0.17.

### Touch points

```bash
$ grep -rnE "FlowEvent::Established\s*\{" netring
```

Expected: 2-4 sites in `examples/flow/{summary,history}.rs`
and possibly `session_stream.rs`. Mechanical fix:

```diff
- FlowEvent::Established { key, ts }
+ FlowEvent::Established { key, ts, l4 }
  // or
+ FlowEvent::Established { key, ts, .. }
```

Examples that print flow-state transitions get a free upgrade
— surface the `l4` in the output line.

## B5. Replace `netring::correlate` with re-exports

flowscope 0.9 shipped `flowscope::correlate` with
**`TimeBucketedCounter<K>`** and **`KeyIndexed<K, V>`** —
identical shape to netring's. plus `SequencePattern` and
`KeylessSequencePattern` (new). flowscope 0.10 also shipped
`TimeBucketedSet`, `BurstDetector`, `TopK`, `Ewma` — covered in
the [`0.21 plan`](./netring-0.21-new-detectors-2026-06-07.md).

### Strategy

Delete `netring/src/correlate/` and re-export under the same
path so existing consumer code keeps compiling:

```rust
// netring/src/lib.rs (or netring/src/correlate.rs)
#[cfg(feature = "flow")]
pub mod correlate {
    //! Re-export of [`flowscope::correlate`] — netring's own
    //! `KeyIndexed` and `TimeBucketedCounter` collapsed in
    //! netring 0.17 once flowscope shipped its versions.
    //! Existing consumer code keeps compiling unchanged.
    pub use flowscope::correlate::{
        KeyIndexed, TimeBucketedCounter, SequencePattern,
        KeylessSequencePattern,
    };
}
```

### Touch points

```bash
$ grep -rnE "netring::correlate::" netring
```

Expected: only the 6 reference detector examples + bench.
No consumer-side migration needed (path is identical).

### Deletion

After the re-export ships:
- `netring/src/correlate/mod.rs` (5 lines: module + reexports) →
  shrink to just the re-export
- `netring/src/correlate/key_indexed.rs` (~200 LoC) → delete
- `netring/src/correlate/time_bucket.rs` (~200 LoC) → delete
- Their unit tests → deleted (covered upstream)

Net: ~400 LoC deleted from netring; semantics unchanged.

## B6. `PARSER_KIND*` constants at match sites

flowscope 0.8 (plan 86) shipped `pub const PARSER_KIND` per
parser module + `flowscope::parser_kinds` umbrella. Use them
in netring rule bodies in place of string literals.

### Touch points

```bash
$ grep -rnE 'kind: "(http/1|dns-udp|dns-tcp|tls|icmp)"' netring/examples netring/tests netring/benches
```

Each match arm:

```diff
- let ProtocolEvent::Message { kind: "dns-udp", … } = evt
+ use flowscope::parser_kinds::DNS_UDP;  // or flowscope::dns::PARSER_KIND_UDP
+ let ProtocolEvent::Message { kind: DNS_UDP, … } = evt
```

Net: every site becomes typo-proof (the compiler resolves the
constant; misspellings fail to compile rather than silently
miss at runtime).

### netring side

Consider exposing `netring::parser_kinds` as a re-export of
`flowscope::parser_kinds` for ergonomic parity with
`netring::flow::*` etc.

## B7. `IcmpType::error_inner()` in `icmp_explained_drop.rs`

flowscope 0.8 (plan 84) shipped `IcmpType::is_error()` +
`error_inner() -> Option<(&'static str, &IcmpInner)>` +
`short_kind()`. Collapses our 40-LoC manual match.

### Migration

```diff
- fn extract_icmp_error(msg: &IcmpMessage) -> Option<(String, &IcmpInner)> {
-     match &msg.ty {
-         IcmpType::V4(Icmpv4Type::DestinationUnreachable { code, inner: Some(i) }) =>
-             Some((format!("ICMPv4 DestUnreachable({code:?})"), i)),
-         /* … 35 more LoC of variant matching … */
-         _ => None,
-     }
- }
- if let Some((label, inner)) = extract_icmp_error(msg) { … }
+ if let Some((label, inner)) = msg.ty.error_inner() {
+     // `label` is now a `&'static str` like "dest_unreachable" —
+     // matches the metric-vocabulary convention.
+     …
+ }
```

Net: ~40 LoC deleted from `icmp_explained_drop.rs`.

## B8. `flowscope::dns::DnsResolutionCache`

flowscope 0.8 (plan 85) shipped `DnsResolutionCache` —
TTL'd per-client resolution cache exactly like what
`dns_resolved_no_connection.rs` and `tls_to_unresolved_ip.rs`
hand-rolled.

### Migration

```diff
- // Per-source-IP cache
- let mut resolved_by_host: HashMap<IpAddr, KeyIndexed<IpAddr, ()>> = HashMap::new();
- // Walk DNS Response → for each A/AAAA, insert into cache
- for ans in &r.answers { /* … 10 LoC … */ }
- // Look up: cache.contains_fresh(&dst, ts)
+ use flowscope::dns::DnsResolutionCache;
+ let mut cache = DnsResolutionCache::new(Duration::from_secs(ttl_s));
+ cache.observe_response(client_ip, r, ts);
+ cache.was_resolved(client_ip, target_ip, ts);  // bool
+ cache.lookup_name(client_ip, target_ip, ts);   // Option<&str>
+ cache.sweep(now);
```

Net: ~50 LoC deleted across the two examples.

## B9. `FlowAnomalyRule` switches to `short_kind()`

flowscope 0.8 (plan 88) shipped `AnomalyKind::short_kind() ->
&'static str` — the stable variant slug for metric labels.

### Migration

In `netring/src/anomaly/builtin.rs`:

```diff
  ProtocolEvent::Flow(FlowEvent::FlowAnomaly { key, kind, ts }) => {
      let sev = Severity::from(kind.severity());
      if sev < self.min_severity { return; }
      emit.push(
          Anomaly::new(KIND, sev, *ts)
              .with_key(key.clone())
-             .with_observation("kind", kind.to_string()),
+             .with_observation("kind", kind.short_kind()),
      );
  }
```

`with_observation` takes `impl Into<String>`; the `&'static str`
conversion is free.

Same change in the `TrackerAnomaly` arm. Unit tests in
`builtin.rs` assert on `"out_of_order_segment"` — should
still pass since `short_kind() == Display::fmt(...)` for the
shipped variants (per the flowscope changelog: "Same string as
`Display`; pick whichever expresses your call site's intent").

## B10. `TlsHandshakeParser` in `slow_tls_handshake.rs`

flowscope 0.9 (plan 97) shipped `TlsHandshakeParser` — aggregates
ClientHello + ServerHello + Alert into one `TlsHandshake` event
per handshake. Carries SNI, ALPN, JA3/JA4, negotiated version,
cipher, `resumption_attempted`, and `HandshakeOutcome`
discriminant.

Replaces the hand-rolled `KeyIndexed<FiveTupleKey, Timestamp>`
correlation in `slow_tls_handshake.rs`.

### Migration

```diff
  let mut monitor = ProtocolMonitorBuilder::new()
      .interface(&iface)
      .flow()
-     .tls()              // emits ClientHello + ServerHello + Alert
+     .tls_handshake()    // emits TlsHandshake per completed handshake
      .build(FiveTuple::bidirectional())?;
```

Inside the rule:

```diff
- // Track ClientHello timestamps, correlate against ServerHello
- // arrival, drain on TTL → unfulfilled = slow handshake
- impl AnomalyRule<FiveTupleKey> for SlowTlsHandshakeRule {
-     fn observe(&mut self, evt, _emit) {
-         match (...) {
-             ClientHello => self.pending.insert(*key, *ts, *ts),
-             ServerHello => { self.pending.remove(key); }
-         }
-     }
-     fn on_tick(&mut self, now, emit) {
-         for (key, t0) in self.pending.drain_expired(now) {
-             emit.push(...);
-         }
-     }
- }
+ // One event per handshake; check its rtt/outcome
+ impl AnomalyRule<FiveTupleKey> for SlowTlsHandshakeRule {
+     fn observe(&mut self, evt, emit) {
+         let ProtocolEvent::Message {
+             kind: TLS_HANDSHAKE,
+             message: ProtocolMessage::TlsHandshake(hs),
+             ts, key, ..
+         } = evt else { return };
+         if hs.rtt > self.threshold || matches!(hs.outcome, HandshakeOutcome::Truncated) {
+             emit.push(Anomaly::new("SlowTlsHandshake", Severity::Warning, *ts)
+                 .with_key(*key)
+                 .with_observation("sni", hs.sni.as_deref().unwrap_or(""))
+                 .with_metric("rtt_ms", hs.rtt.as_secs_f64() * 1000.0));
+         }
+     }
+ }
```

Side-effects:
- `ProtocolMessage` gains a `TlsHandshake(TlsHandshake)` variant.
- `ProtocolMonitorBuilder` gains `.tls_handshake()` /
  `.tls_handshake_on_ports()`. The existing `.tls()` stays;
  users pick the granularity they want.

Net: `slow_tls_handshake.rs` shrinks ~80 LoC; logic clarifies.

## B11. `serde` Cargo feature

flowscope 0.8 (plan 83) shipped opt-in `Serialize` +
`Deserialize` on every public event / message / accessor with a
**locked wire vocabulary** (snake_case field/variant names,
adjacent + internal tagging for payloaded enums).

### Cargo.toml

```diff
  [dependencies]
+ serde = { workspace = true, optional = true, features = ["derive"] }
+ serde_json = { workspace = true, optional = true }

  [features]
+ serde = ["dep:serde", "dep:serde_json", "flowscope/serde"]
```

### Derives

```rust
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Anomaly<K> { ... }

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AnomalyContext { ... }

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Severity { ... }
```

`K: Serialize` bound becomes an implicit constraint when the
feature is on — `FiveTupleKey` already satisfies it via
`flowscope/serde`. Document in rustdoc.

### Tests

`tests/anomaly_serde.rs` round-trips an `Anomaly<FiveTupleKey>`
populated with each `ProtocolMessage` variant through
`serde_json` and asserts:
- Output byte-stable across feature-flag combinations
- Deserialize parses back to an equal Anomaly

Lock the wire vocabulary; downstream dashboards depend on it.

### Side-effect

`Anomaly::to_json_line()` stays (it's the zero-dep path). The
serde-derived path gives users `serde_json::to_string(&a)`
plus the next item.

## B12. `Anomaly::to_json_value() -> serde_json::Value`

```rust
#[cfg(feature = "serde")]
impl<K: serde::Serialize> Anomaly<K> {
    /// Returns the structured `Value` representation. Useful for
    /// downstream merging into compound JSON objects (e.g.
    /// attaching tracing-span context) before serializing.
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("Anomaly is always serializable")
    }
}
```

Composes with `to_json_line()` for users who want either format.

## B13. Cargo.toml version bump

```diff
  [package]
  name = "netring"
- version = "0.16.0"
+ version = "0.17.0"
```

netring's release counter increments by 1; we don't realign with
flowscope's `0.10` jump. The next-release bump is conventional
0.17 because the user-facing API surface change (B5 path
deprecation, B11 new feature) is breaking-ish but minor.

## B14. CHANGELOG entry

`netring/CHANGELOG.md` gains a 0.17.0 section:

- Lockstep bump to flowscope 0.10.1
- **Breaking**: `flowscope::Error` migration (downstream users
  destructuring on `flowscope::http::Error` etc. must migrate)
- **Breaking**: `FlowEvent::Established { l4 }` field-add
- **Deprecated then deleted**: `netring::correlate::{KeyIndexed,
  TimeBucketedCounter}` — re-exports from `flowscope::correlate`.
- Added: `netring/serde` Cargo feature
- Added: `Anomaly::to_json_value()`
- Added: `ProtocolMonitorBuilder::tls_handshake()` /
  `.tls_handshake_on_ports()`
- Added: `ProtocolMessage::TlsHandshake(TlsHandshake)` variant
- Cleanup: 8 examples simplified using the new flowscope
  helpers (icmp_explained_drop, dns_resolved_no_connection,
  tls_to_unresolved_ip, slow_tls_handshake, lateral_movement,
  anomaly_monitor_demo, pcap_replay_anomaly, pcap_replay_multi)
- Cleanup: ~400 LoC deleted from `netring::correlate`,
  ~150 LoC deleted across the simplified examples
- Wishlist scorecard table (A1/A2/A3/B1/B3/B4/B5/B6/B7 ✓
  shipped via 0.10)

## B15. Doc sweep

- `netring/README.md` — version refs to 0.17, mention serde
  feature in the anomaly section
- `netring/CLAUDE.md` — "Recent additions" gets a 0.17 block;
  test/example counts updated
- `netring/docs/WRITING_DETECTORS.md` — replace
  `netring::correlate` references with `flowscope::correlate`;
  add a "Serde output" subsection in §8 next to the
  `to_json_line` / `emit_tracing` patterns
- `plans/INDEX.md` — 0.17 / 0.20 / 0.21 plans registered, 0.18
  roadmap marked superseded (most items absorbed by
  flowscope-side work)
- `plans/upstream-tracking.md` — `flowscope::correlate` move
  marks the upstream-tracking item done; flowscope serde
  feature shipped

---

## Effort summary

| Phase | LoC delta | Days | Risk |
|---|---|---|---|
| B1 + B2 (dep bump + MSRV verify) | +1 line, -0 | 0.1 | None |
| B3 (Error migration) | ~20 sites | 0.3 | Low |
| B4 (Established l4 destructures) | ~5 sites | 0.1 | None |
| B5 (correlate re-exports + deletions) | +30 / -400 | 0.3 | Low (path-identical) |
| B6 (PARSER_KIND constants) | ~20 sites | 0.2 | None |
| B7 (IcmpType::error_inner) | +5 / -40 | 0.2 | Low |
| B8 (DnsResolutionCache) | +20 / -50 in 2 files | 0.3 | Low |
| B9 (short_kind) | ~4 sites | 0.1 | None |
| B10 (TlsHandshakeParser wiring) | +50 / -80 + new builder | 0.5 | Med |
| B11 (serde feature) | +30 attr / +60 in Cargo + CI | 0.5 | Med (wire stability) |
| B12 (to_json_value) | +10 | 0.1 | None |
| B13 + B14 + B15 (version + CHANGELOG + docs) | ~200 doc | 0.5 | None |

**Total: ~2 days.** Ship as a single coordinated PR or 3 ship-commits:

- **Commit A** — B1 + B2 + B3 + B4 (mechanical migration).
- **Commit B** — B5 through B10 (wishlist absorption).
- **Commit C** — B11 + B12 + B13 + B14 + B15 (serde + version + docs).

Each commit must pass `cargo fmt --check`, `cargo clippy
--all-targets --all-features -- -D warnings`, `cargo doc -p
netring --no-deps --all-features`, `cargo test --workspace
--features tokio,channel,flow,parse,pcap,http,dns,tls,icmp`,
`cargo build -p netring --examples --features
tokio,channel,flow,parse,pcap,metrics,http,dns,tls,icmp`.

---

## Wishlist scorecard

How items from
[`flowscope-wishlist-2026-06-06.md`](./flowscope-wishlist-2026-06-06.md)
land in this plan:

| Wishlist | Status in flowscope 0.10 | netring 0.17 work |
|---|---|---|
| **A1** serde feature | ✅ shipped 0.8 (plan 83) | B11 + B12 — add `netring/serde` feature |
| **A2** IcmpType::is_error + error_inner | ✅ shipped 0.8 (plan 84) | B7 — adopt in `icmp_explained_drop.rs` |
| **A3** DnsResolutionCache | ✅ shipped 0.8 (plan 85) | B8 — adopt in 2 examples |
| **B1** PARSER_KIND constants | ✅ shipped 0.8 (plan 86) | B6 — migrate match sites |
| **B2** Multi-parser composite driver | ✅ shipped 0.9 (`FlowMultiSessionDriver`) + 0.10 (unified Driver<E,M>) | Adopted in netring 0.20 (separate plan) |
| **B3** FlowEvent::Established { l4 } | ✅ shipped 0.8 (plan 87) | B4 — bind in destructures |
| **B4** AnomalyKind::short_kind | ✅ shipped 0.8 (plan 88) | B9 — adopt in `FlowAnomalyRule` |
| **B5** FlowTracker::force_close | ✅ shipped 0.8 (plan 89) | Optional — surface as `StreamCapture` convenience in 0.18+. Not in this plan. |
| **B6** TlsHandshake aggregator | ✅ shipped 0.9 (plan 97 `TlsHandshakeParser`) | B10 — adopt in `slow_tls_handshake.rs` |
| **B7** FlowTracker::iter_active | ✅ shipped 0.8 (plan 90) | Optional — ship a new example in 0.21 (separate plan) |
| **C1** flowscope::correlate module | ✅ shipped 0.9 + 0.10 (4 new extensions) | B5 — re-export base primitives in 0.17; adopt extensions in 0.21 |
| **C2** SequenceDetector | ✅ shipped 0.9 (`SequencePattern` trait) | Optional — examples in 0.21 |
| **C8** JA4 fingerprint | ✅ shipped 0.9 (plan 97 `ja4` Cargo feature) | Surface via `tls_handshake.ja4` field; documented in 0.17 |

**flowscope absorbed 13 of 13 actionable wishlist items.**

The remaining wishlist items (C3 event-variant suppression, C5
pageable reassembler, C6 expanded test fixtures, C7 tracker
pause/resume, B2 full composite driver as opposed to the
shipped multi-session variant) are either non-blocking,
overlap with the unified Driver redesign (covered in netring
0.18 plan), or never materialized as concrete asks. No netring
work required.

---

## What 0.17 success looks like

After this plan lands:

1. `cargo update -p flowscope` lands `flowscope 0.10.1`. Every
   netring test passes; every example builds; clippy +
   doc warning-free.
2. `cargo bench --bench anomaly --features ...` regression-checks
   against the 2026-06-03 baselines (see commit `fb9bdc0`). No
   significant regressions expected — the new flowscope code is
   *additional* primitives, not a hot-path rewrite.
3. The 6 example files that hand-rolled correlate-via-KeyIndexed
   patterns now use `flowscope::dns::DnsResolutionCache`,
   `IcmpType::error_inner`, and `TlsHandshakeParser`. Each
   shrinks by 40-80 LoC.
4. `netring::correlate::{KeyIndexed, TimeBucketedCounter}` is now
   a re-export of the flowscope-side types. ~400 LoC deleted
   from netring; behaviour unchanged.
5. `cargo build -p netring --features serde` adds the new
   feature gate; `Anomaly<FiveTupleKey>` serializes to JSON via
   serde_json identically (byte-for-byte) to the hand-rolled
   `to_json_line()`.
6. CHANGELOG entry documents every breaking change; downstream
   consumers can migrate.

---

## Out of scope (deferred to 0.18 / 0.19)

- **Unified `Driver<E, M>` + `Event<K, M>` adoption** —
  centerpiece refactor of `ProtocolMonitor`. Multi-day work.
  See [`netring-0.20-unified-driver-refactor-2026-06-07.md`](./netring-0.20-unified-driver-refactor-2026-06-07.md).
- **New detectors using the new correlate / detect / aggregate
  primitives** (`BurstDetector`, `TopK`, `Ewma`,
  `shannon_entropy`, `HttpExchangeParser`, `DnsExchangeParser`).
  See [`netring-0.21-new-detectors-2026-06-07.md`](./netring-0.21-new-detectors-2026-06-07.md).
- **`flowscope::emit::FlowEventNdjsonWriter` / `ZeekConnLogWriter`
  adoption** — would deduplicate netring's hand-rolled
  `Anomaly::to_json_line`. Re-evaluate in 0.21 — likely a
  feature-gated alternative path, not a replacement.
- **`flowscope::layers` adoption** — netring's BPF filters
  already do L2/L3/L4 routing. Adopting `Layers` would help
  for richer per-packet introspection (VLAN walk, ARP slices,
  etc.) but it's not currently a pain point. Defer until a use
  case materializes.
- **`flowscope::well_known` adoption** — `FiveTupleKey::well_known_port()`
  + `protocol_label()` would simplify the heuristics in
  `multi_protocol_monitor.rs`'s `describe()` function. Trivial
  follow-up; defer to 0.19+.
- **`flowscope::Pipeline` adoption** — flowscope's high-level
  entry point. netring's `ProtocolMonitor` is its equivalent;
  no need to switch unless the unified-Driver adoption in 0.18
  prompts a rewrite. Re-evaluate then.
- **`flowscope::detect::signatures` adoption for heuristic
  routing** — would simplify `ProtocolMonitor`'s BPF-based
  protocol dispatch. Land alongside the unified-Driver work in
  0.18.

---

## Critical-path note

This plan is a **bug-free zone**: every item is mechanical or
straightforward replacement. The risk is in volume, not
complexity. Land the three commits (A/B/C) in order; if any
commit fails CI, fix in-place and don't merge unrelated
follow-ups.

The big architectural work (unified Driver) lives in the
[next plan](./netring-0.20-unified-driver-refactor-2026-06-07.md).
That one's where care is needed.
