# netring 0.17 — flowscope 0.7 bump + N10 completion + cleanup

**Date:** 2026-06-03
**Author:** netring maintainer
**Status:** ✅ **Shipped 2026-06-03** in 3 ship-commits:
- A — dep bump + Ended/Closed migration + N4 cleanup (`502a484`)
- B — ICMP wiring + `icmp_explained_drop` + Severity bridge (`8bf53c0`)
- C — cosmetic + docs + version bump 0.15.0 → 0.16.0 (`e044dd8`)

**Predecessor:** [`netring-0.16-roadmap-2026-05-29.md`](./netring-0.16-roadmap-2026-05-29.md)
**Driven by:** flowscope 0.7.0 (2026-05-23) — direct response to
[`plans/flowscope-0.7-feedback-2026-05-29.md`](./flowscope-0.7-feedback-2026-05-29.md).

**Scope rule:** backward-incompatible breaks are allowed. Pre-1.0;
releases ship in lockstep with flowscope.

---

## At a glance

flowscope 0.7 shipped most of what netring asked for in round-2
feedback. The bump itself is small; the value is the items it
*unblocks* — chief among them, the third `icmp_explained_drop.rs`
reference detector deferred from `netring-0.16-roadmap` N10.

| # | Item | Tier | Touch points |
|---|---|---|---|
| B1 | Bump `flowscope = "0.6"` → `"0.7"` | **High** | `Cargo.toml`, migration patterns below |
| B2 | `FlowEvent::Ended` / `SessionEvent::Closed` gain `l4: Option<L4Proto>` — wire through forwarding code, ProtocolEvent | **High** | `async_adapters/session_stream.rs`, `datagram_stream.rs`, `protocol/event.rs`, all destructures + test fixtures |
| B3 | Drop `HashMap<FiveTupleKey, L4Proto>` workaround in `multi_protocol_monitor.rs` + `full_monitor.rs` (N4 from 0.16) | **High** | 2 examples |
| B4 | Add `IcmpParser` / `IcmpMessage` / `IcmpInner` support to `ProtocolMessage` + `ProtocolMonitorBuilder.icmp()` | **High** | `protocol/event.rs`, `protocol/monitor.rs`, new `icmp` feature flag |
| B5 | `examples/anomaly/icmp_explained_drop.rs` — third N10 detector finally in scope, uses `IcmpInner` to tie ICMP errors back to the original TCP/UDP flow | **High** | new example + Cargo.toml entry |
| B6 | Bridge `flowscope::AnomalyKind::severity()` → `netring::anomaly::Severity` so `FlowAnomaly` lifts to `Anomaly<K>` consistently | **Med** | `netring::anomaly` |
| B7 | Drop `match l4 { L4Proto::Tcp => "TCP", … }` in `full_monitor.rs` `l4_tag` helper — use `flowscope::L4Proto`'s `Display` impl | Polish | 1 example |
| B8 | Use HTTP/TLS convenience accessors (`req.host()`, `sni()`, etc.) in `http_session.rs`, `slow_tls_handshake.rs` if it tightens code | Polish | 2 examples |
| B9 | Update `CLAUDE.md` + `examples/README.md` + crate version bump to `0.16.0` (or `0.15.1` if we ship as a minor) | **High** | docs |

---

## B1. Bump `flowscope = "0.6"` → `"0.7"`

Single-line in `netring/Cargo.toml`. No new flowscope features
needed beyond what we already opt into, except adding `icmp` to
the `parse`+`flow` umbrella when we wire B4.

The flowscope 0.7 CHANGELOG flags these breaking changes:

- `FlowEvent::Ended` gains `l4: Option<L4Proto>` — every
  destructure must bind or `..` it (B2).
- `SessionEvent::Closed` gains `l4: Option<L4Proto>` — same.

Everything else in 0.7 is additive.

## B2. `FlowEvent::Ended` / `SessionEvent::Closed { l4 }` migration

Per `grep`, there are ~30 destructures of `Ended`/`Closed` across
`netring/src`, `netring/examples`, and `netring/tests`. The
mechanical fix is `, ..` (or bind `l4`) at each site. Files:

- `netring/src/async_adapters/session_stream.rs` — propagate `l4`
  from `FlowEvent::Ended` into the synthesised
  `SessionEvent::Closed { … , l4 }`. Multiple sites: ~458, ~531,
  ~722, ~760, ~795.
- `netring/src/async_adapters/datagram_stream.rs` — same pattern
  around line 378.
- `netring/src/async_adapters/flow_stream.rs` line 580 — read-only.
- `netring/src/protocol/event.rs` `flow_event_ts` /
  `flow_event_key` — read-only.
- `netring/examples/async_basics/stats_monitor.rs` line 64.
- `netring/examples/l7/full_monitor.rs` (after B3 drops the
  HashMap workaround, the Ended arm reads `l4` directly).
- `netring/examples/l7/multi_protocol_monitor.rs` (same).
- Tests under `netring/tests/` if any destructure `Ended`.
- `netring/tests/anomaly_monitor_smoke.rs` — none (uses `Started`
  only).

`flow_stream.rs` synthesises Ended via the
`FlowTracker::snapshot_l4` accessor (new in 0.7 per plan 79); we
should call it from the place we emit our own `Ended` events for
overflow / parser error / parser_done.

## B3. Drop `HashMap<FiveTupleKey, L4Proto>` workaround (N4)

Two examples carry a per-consumer cache only because pre-0.7
Ended didn't have `l4`:

- `examples/l7/multi_protocol_monitor.rs` line 54.
- `examples/l7/full_monitor.rs` line 77.

Delete the `l4_by_key` HashMap. In the Ended arm, read the field
directly:

```rust
ProtocolEvent::Flow(FlowEvent::Ended { key, reason, stats, l4, .. }) => {
    println!("[FLOW] - {tag:<5} {a} <-> {b} {reason:?} pkts={p}",
             tag = l4_tag(l4), …);
}
```

(B7 follows up by replacing `l4_tag` with `L4Proto::Display`.)

## B4. `IcmpParser` + `ProtocolMessage::Icmp` + `ProtocolMonitorBuilder.icmp()`

flowscope 0.7 ships `flowscope::icmp::{IcmpParser, IcmpMessage,
IcmpInner, IcmpType}` as a `DatagramParser`. The `flowscope/icmp`
Cargo feature is the gate. We mirror this:

- New `netring/Cargo.toml` feature: `icmp = ["flowscope/icmp"]`.
  Pulls `dns`/`tls` parity — when user enables `all-parsers`,
  include `icmp`.
- New `ProtocolMessage::Icmp(flowscope::icmp::IcmpMessage)`
  variant, gated by `feature = "icmp"`. Bumps the enum width by
  one in `event.rs`; no exhaustiveness break thanks to
  `#[non_exhaustive]`.
- `ProtocolMonitorBuilder::icmp()` / `icmp_v4_only()` /
  `icmp_v6_only()` — flowscope's `IcmpParser` handles both
  families, so the default `.icmp()` matches both. BPF filter:
  `ip proto 1 or ip6 proto 58` (no port narrowing — ICMP has no
  ports).
- Internal `build_icmp_stream` helper using
  `datagram_stream(IcmpParser::default())` + a per-arm
  `application_only_icmp` adapter.

## B5. `examples/anomaly/icmp_explained_drop.rs`

The third N10 detector deferred from 0.16. **The cross-protocol
demo that justifies the whole correlation architecture.**

Pattern: when a TCP connection mysteriously RSTs or never
establishes, an ICMP Destination Unreachable / Time Exceeded /
Fragmentation Needed often arrived just before — and `IcmpInner`
tells us which flow it pertained to.

```text
ProtocolMonitor (.flow().icmp())
      │
      ▼  ProtocolEvent::Message{kind:"icmp", Icmp(IcmpMessage{ty: DestUnreachable{inner, …}})}
       inner: IcmpInner { src, dst, src_port, dst_port, proto }
KeyIndexed<FiveTupleKey, IcmpExplanation>::insert(inner_key, …)
      │
      ▼  ProtocolEvent::Flow(FlowEvent::Ended { reason: Rst|Idle|Fin, key, … })
       look up `key` in cache
       if present → ANOMALY (with explanation) OR informational "explained drop"
```

The detector's job is to surface *unexplained* RSTs vs
*explained* RSTs — the latter being normal network behaviour. So
the anomaly fires on RSTs that lack a recent matching ICMP
error.

**Severity tier:** `Info` for explained drops (logged for
context), `Warning` for unexplained RSTs. Matches the spirit of
the AnomalyKind::severity → netring::Severity bridge in B6.

LoC: ~150 plus boilerplate. Same shape as
`dns_resolved_no_connection.rs`.

## B6. `AnomalyKind` → `Severity` bridge

flowscope 0.7's `AnomalyKind::severity() -> flowscope::Severity`
returns `Info | Warning | Error | Critical`. netring's
`netring::anomaly::Severity` is the same shape with the same
order.

Two paths:

1. **Easy path.** Add a `From<flowscope::Severity> for
   netring::anomaly::Severity` impl — direct variant mapping.
2. **Built-in rule.** A `FlowAnomalyRule` shipped in
   `netring::anomaly` that observes `ProtocolEvent::Flow(FlowEvent::FlowAnomaly
   { kind, … })` and emits an `Anomaly<K>` with `severity =
   kind.severity().into()`. Saves users from writing the bridge
   per-detector — sometimes you just want flowscope-level
   anomalies to flow through the same `Vec<Anomaly<K>>` pipeline.

Ship both. The `From` is two lines; the `FlowAnomalyRule` is ~30
LoC + a test in `tests/anomaly_monitor_smoke.rs`.

## B7. Drop `l4_tag` — use `L4Proto::Display`

`full_monitor.rs` carries:

```rust
fn l4_tag(l4: Option<L4Proto>) -> &'static str {
    match l4 {
        Some(L4Proto::Tcp) => "TCP",
        Some(L4Proto::Udp) => "UDP",
        Some(L4Proto::Icmp) => "ICMP",
        …
    }
}
```

After B1 we can replace each call with `l4.map(|p|
p.to_string()).unwrap_or_default()` (or just inline `{l4:?}` if
Debug suffices). Same opportunity in `multi_protocol_monitor.rs`
and `stats_monitor.rs`.

## B8. HTTP/TLS convenience accessors

flowscope 0.7 plan 78 adds `HttpRequest::host()`,
`user_agent()`, `cookie()`, `HttpResponse::content_type()`,
`content_length()`, `set_cookie()`, and `TlsClientHello::sni()`.

Light cleanup in:

- `examples/l7/http_session.rs` — `req.host()` instead of
  manually walking `headers`.
- `examples/anomaly/slow_tls_handshake.rs` — `ch.sni()` (currently
  reads `.sni` directly, so this is a no-op or just doc-aligning).

Not blocking; nice-to-have.

## B9. Version bump + doc sweep

- `netring/Cargo.toml`: `version = "0.15.0"` → `"0.16.0"`. Major
  enough churn (Ended/Closed gain a field; new module;
  ProtocolMessage variant) to justify a minor bump. **Do not run
  `cargo publish`** without explicit user approval.
- `netring/CHANGELOG.md`: new `## 0.16.0 — flowscope 0.7 bump,
  ICMP, l4-on-Ended` section. List migration patterns.
- `netring/CLAUDE.md`: refresh "Recent additions" with the 0.17
  block.
- `netring/examples/README.md`: register `icmp_explained_drop`.
- `netring/README.md`: mention `ProtocolMonitor` now supports
  ICMP if it doesn't already.

---

## Effort + risk

| Phase | LoC | Risk | Days |
|---|---|---|---|
| B1 + B2 (mechanical migration) | ~50 deltas across 30 sites | Low — compile errors will catch all sites | 0.5 |
| B3 (drop HashMap workaround) | -20 | Low | 0.1 |
| B4 (ICMP parser wiring) | +200 (monitor.rs + event.rs + feature flag) | Med — new BPF filter shape (no ports), v6 + v4 in one stream | 1 |
| B5 (icmp_explained_drop) | +250 example + tests | Med — IcmpInner field shape needs verification | 1 |
| B6 (Severity bridge + FlowAnomalyRule) | +80 | Low | 0.3 |
| B7 + B8 (cosmetic cleanup) | -50 | None | 0.2 |
| B9 (docs + version) | +80 | None | 0.3 |

**Total: ~3 days focused work.** Cut at B5 if Part B4 takes
longer than expected; B5 is the value but B1–B4 stand alone.

## Phasing

Ship in two commits:

- **Commit A** — B1 + B2 + B3: dep bump + Ended/Closed migration
  + N4 cleanup. Atomic, mechanical, easy to revert.
- **Commit B** — B4 + B5 + B6: ICMP parser, icmp_explained_drop
  detector, Severity bridge. New feature surface; review-friendly
  to isolate.
- **Commit C** — B7 + B8 + B9: cosmetic + docs + version.

Each commit must pass `cargo fmt --all -- --check`, `cargo clippy
--all-targets --all-features -- -D warnings`, `cargo test
--workspace --features tokio,channel`, `cargo build -p netring
--examples --features tokio,channel,flow,parse,pcap,metrics,http,dns,tls,icmp`
before pushing.

---

## Open questions / deferred

- **B6 — anomaly enum carries `kind: AnomalyKind`?** The bridge
  emits a `netring::Anomaly<K>` with `kind: &'static str` from
  `AnomalyKind`'s `Display` impl (which is consistent with metric
  labels: `"buffer_overflow"`, `"ooo_segment"`, …). Alternative:
  carry the full `AnomalyKind` in `AnomalyContext.observations`
  as a serialisable string. Decide during B6.
- **N6 — `AsyncCapture::broadcast(n)`.** Still pending; orthogonal
  to flowscope 0.7. Picked up post-0.17 — this bump doesn't
  change the per-protocol ring count.
- **N5 — driver refactor.** Now genuinely unblocked (0.6's `S`
  parameter restoration + 0.7's `is_done()` make this clean) but
  multi-day; carry over to 0.18.
- **N12 / N13 / N14 — message tap / synthetic traffic / `--json`.**
  Polish, still pending.

---

## Success criteria

1. `cargo update -p flowscope --precise 0.7.0` succeeds.
2. All ~256 tests pass (previously 256 unit/lib + ~5 smoke; new
   icmp tests bump that).
3. All ~52 examples build (previously 50; +2 from
   `icmp_explained_drop` and any future `icmp_*.rs`).
4. `multi_protocol_monitor.rs` and `full_monitor.rs` no longer
   carry `HashMap<FiveTupleKey, L4Proto>`.
5. `examples/anomaly/icmp_explained_drop.rs` runs against
   `lo` + a synthetic ICMP error and surfaces the matching flow.
6. `From<flowscope::Severity> for netring::Severity` compiles
   and is documented.
