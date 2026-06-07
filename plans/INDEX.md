# plans/ — backlog index

This directory holds **forward-looking work items only** —
concrete plans for features that haven't shipped yet.

Reference material (architecture, async guide, troubleshooting,
the writing-detectors tutorial) lives in
[`../netring/docs/`](../netring/docs/), which is published as
part of the crates.io package.

**Convention** (mirrors flowscope's): when an implementation
plan ships, **delete the plan file** in the same PR series.
`git log` is the historical record; `plans/` is the working
backlog. Released work documented in `CHANGELOG.md`.

> **Scope split.** Flow & session tracking lives in the separate
> [`flowscope`](https://github.com/p13marc/flowscope) crate.
> flowscope's `plans/` covers everything related to flow
> extraction, tracking, reassembly, session / datagram parsing,
> observability of flows, and L7 protocol parsers. This index
> covers only netring-side plans (capture, dedup, async adapters,
> protocol monitor + anomaly toolkit).

---

## Active backlog

### flowscope 0.10 absorption — three-phase rollout

flowscope 0.10 (2026-06-07) shipped the entire 3-round netring
feedback wishlist (rounds for 0.5/0.6, 0.7, 0.8) plus the 0.9
cycle (high-level `Pipeline`, `flowscope::correlate`,
`FlowMultiSessionDriver`, JA4, OOO reassembler, unified
`flowscope::Error`, `flowscope::layers`) plus the 0.10 cycle
(centerpiece unified `Driver<E, M>` + `Event<K, M>`, exchange
aggregators, parser ergonomics, correlate extensions, `detect` /
`aggregate` / `emit` / `well_known` modules, signature
recognizers, helper sweep). Absorbing it in one cycle invites
mistakes; three sequential netring releases instead.

| Crate | Plan | Scope | Days |
|---|---|---|---|
| netring **0.17** | ✅ **shipped** (`151901e`/`96f8d78`/`c1ec36b`) | Lockstep dep bump 0.7 → 0.10 + mechanical wishlist absorption (PARSER_KIND constants, IcmpType helpers, DnsResolutionCache, AnomalyKind::short_kind, TlsHandshakeParser, serde feature). See CHANGELOG.md and `git log`. | done |
| netring **0.18** | [`netring-0.18-unified-driver-refactor-2026-06-07.md`](./netring-0.18-unified-driver-refactor-2026-06-07.md) | **One big release.** Two strands: (1) collapse `ProtocolMonitor` onto `flowscope::driver_unified::Driver<E, M>` + `Event<K, M>` (closes long-deferred N5 + N6 + O1 + O2; deletes ~1300 LoC; adds heuristic-routing via `flowscope::detect::signatures`); (2) 9 new reference detectors using flowscope's new tooling (`shannon_entropy`, `TimeBucketedSet`, `BurstDetector`, `TopK`, `Ewma`, `iter_active`, `ZeekConnLogWriter`, `HttpExchangeParser`, `DnsExchangeParser`) + helper-sweep adoption + WRITING_DETECTORS doc expansion. Pre-merged from the original 0.18 + 0.19 split because shipping the architectural refactor solo would burn a release without delivering visible value; pairing it with new detectors proves the refactor on real workloads. | ~7.5 |

---

## Design docs

| File | Status |
|------|--------|
| [`upstream-tracking.md`](./upstream-tracking.md) | Live — rustc / kernel / flowscope features being watched |

---

## Plan structure

Each `NN-*.md` plan has:

1. **Status** — Planned / In progress / Done (and which crate version)
2. **Prerequisites** — which prior plans must be complete
3. **At a glance** — work-item table with tier + break? marker
4. **Per-item sections** — touch points, migration shape, side effects
5. **Effort summary** — LoC delta, days, risk, commit boundaries
6. **What success looks like** — acceptance criteria
7. **Out of scope** — what this plan does NOT do

Release roadmaps (`netring-X.Y-*.md`) follow this same shape;
they're scoped to one crate version.

---

## Deferred (recorded so a future ask doesn't get re-litigated)

- **simple-nms N1.3 verbatim** (`flow_stream(...).with_bpf_filter(filter)`
  chained builder) — declined in favor of the cleaner
  `stream.set_filter(filter)` verb on `StreamSetFilter`. The
  chained form has ambiguous timing semantics (apply-at-open
  vs. apply-now); the explicit verb avoids the reader-trap.
- **simple-nms N2.2** (`with_extractor_replace` for hot-reload)
  — atomic mid-packet extractor swap is hard (consistency on
  in-flight tracker state) and simple-nms has a working
  `Arc<ArcSwap<...>>`-wrapped-extractor fallback. Revisit
  only if a third consumer asks.
- **simple-nms N2.3** (AF_XDP `Packet`-metadata parity with
  `XdpPacket`) — already tracked in
  [`upstream-tracking.md`](./upstream-tracking.md)
  §"Unified `PacketBackend` trait".
- **simple-nms N3.1** (in-crate XDP-prefilter shape library)
  — speculative; revisit when v3 demands materialise.
- **simple-nms N3.2** (per-fanout-worker drops histogram) —
  `AsyncMultiCapture::per_source_capture_stats()` is the raw
  shape; aggregation belongs in consumer-side dashboards.
- **Suricata-compatible rule DSL** — declined. `AnomalyRule<K>`
  gives the Rust-API shape; a text-DSL is Zeek/Suricata
  territory.
- **eBPF-side anomaly correlator** — declined for now.
  Order-of-magnitude harder than the user-space version; worth
  it for 10G+ workloads but not the netring sweet spot today.
- **Encrypted-traffic ML detection** — out of scope. Compose
  via a user-defined `AnomalyRule` that feeds a learned model.
