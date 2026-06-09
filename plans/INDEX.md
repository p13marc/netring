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

### netring 0.20 — Monitor redesign (Protocol trait + Handler + Layer + macro + sharding)

The 0.20 release replaces the closed `ProtocolMonitor` / `AnomalyMonitor` / `AnomalyRule` surface with a protocol-agnostic `Monitor::builder()` + `Handler<E, M>` blanket impls + tower-style middleware + `detector!` macro + per-CPU sharding. Driven by an in-session API review (June 2026) that concluded the 0.18 architecture is sound but the user-facing surface reads like 2022-era Rust; 0.20 brings it in line with 2026 axum/bevy/tower idioms.

Execution split into 7 sequential phases. Each ships as 2–4 commits on a `0.20-dev` branch; the final phase tags + publishes.

| Phase | Plan | Scope | Days |
|---|---|---|---|
| **A** | [`netring-0.20-phase-A-protocol-trait.md`](./netring-0.20-phase-A-protocol-trait.md) | `Protocol` trait + `Event` trait + 7 builtin marker types (`Tcp`/`Udp`/`Icmp`/`Http`/`Dns`/`Tls`/`TlsHandshake`) | 2–3 |
| **B** | [`netring-0.20-phase-B-handler-trait.md`](./netring-0.20-phase-B-handler-trait.md) | `Handler<E, M>` trait + blanket impls for 0..8 extractors + `Ctx<'a>` + `FromCtx` + `Dispatcher` + `Monitor` builder skeleton | 4–6 |
| **C** | [`netring-0.20-phase-C-perf-hardening.md`](./netring-0.20-phase-C-perf-hardening.md) | `AnomalyWriter` + shipped sinks + `Ctx::split_*` + dhat-gated CI bench (≤512 B / 100k events) | 2–3 |
| **D** | [`netring-0.20-phase-D-middleware.md`](./netring-0.20-phase-D-middleware.md) | `AsyncHandler<E, M>` + `on_async` + 5 tower-style layers (Dedupe / RateLimit / MinSeverity / Sample / Tee) | 3–4 |
| **E** | [`netring-0.20-phase-E-macro-prelude.md`](./netring-0.20-phase-E-macro-prelude.md) | `detector!` macro + `netring::prelude` + multi-interface via `AsyncMultiCapture` | 3–4 |
| **F** | [`netring-0.20-phase-F-percpu-sharding.md`](./netring-0.20-phase-F-percpu-sharding.md) | `fanout_per_cpu` + `merge_state` + sharded run loop + per-CPU state merging | 3–4 |
| **G** | [`netring-0.20-phase-G-migration-release.md`](./netring-0.20-phase-G-migration-release.md) | Rewrite 13 examples + ship `netring-compat` + migration docs + release | 4–5 |

**Total: 21–29 working days.** Single breaking release as netring 0.20.0.

See [`netring-0.20-INDEX-2026-06-09.md`](./netring-0.20-INDEX-2026-06-09.md) for orchestration (sequencing, cross-phase invariants, dependency rules).

### Recently shipped

| Crate | Plan | Status |
|---|---|---|
| netring **0.17** | absorbed flowscope 0.10 (mechanical bump + parser_kinds + DnsResolutionCache + serde feature) | ✅ shipped — see CHANGELOG.md |
| netring **0.18** | unified-driver refactor + 3 new anomaly detectors + 4 flow demos + heuristic routing | ✅ shipped (Commits A/B/C/D, 7a147a4) |
| netring **0.19** | flowscope 0.11.1 absorption: typed `Driver<E>` + `SlotHandle<M, K>` + scratch-buffer parsers + `Bytes`-based HTTP payloads. Stream loses `+ Send` bound (`SlotHandle` is `Rc/RefCell`-based, single-thread-by-design). | ✅ shipped at `daf8557` |

---

## Design docs

| File | Status |
|------|--------|
| [`api-review-2026-06-09.md`](./api-review-2026-06-09.md) | Live — the analytical "why" behind the 0.20 redesign. Companion to the phase plans. |
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
