# netring 0.20 — phased implementation plans (INDEX)

**Date:** 2026-06-09
**Design rationale:** [`api-review-2026-06-09.md`](./api-review-2026-06-09.md) (the *why*)
**Status:** ready for execution; Phase A partial (flowscope-bump portion shipped in 0.19.0)
**Target release:** netring **0.20.0** — single breaking release containing all seven phases

The redesign spec is 2,041 lines covering seven phases (A–G). This INDEX breaks it into per-phase detailed plans so a developer can pick up one file at a time, complete it, ship the commit, and move on. Each phase plan is self-contained — explains its goal, files to touch, types to define, tests to write, acceptance criteria, and risks — without requiring the reader to load the parent spec into context.

## Re-versioning note

The parent spec was written to land everything as **netring 0.19.0**. Then on 2026-06-09 we shipped **netring 0.19.0** as a flowscope 0.11.1 absorption release (mechanical bump only — no Protocol trait, no Handler, no Layer). So the redesign work that the parent spec described now ships as **netring 0.20.0**.

Phase A in this index includes only the *remaining* Phase A work (Protocol trait + Event types + builtin markers). The flowscope bump portion of original Phase A is done.

## Phase plans

| # | Phase | Plan file | Effort | Status |
|---|---|---|---|---|
| A | Protocol trait + Event types + builtin markers | [`netring-0.20-phase-A-protocol-trait.md`](./netring-0.20-phase-A-protocol-trait.md) | 2–3 d | ready |
| B | Handler trait + closure registration + Ctx + dispatcher | [`netring-0.20-phase-B-handler-trait.md`](./netring-0.20-phase-B-handler-trait.md) | 4–6 d | ready |
| C | Performance hardening + AnomalyWriter + dhat CI gate | [`netring-0.20-phase-C-perf-hardening.md`](./netring-0.20-phase-C-perf-hardening.md) | 2–3 d | ready |
| D | Async escape hatch + tower-style middleware | [`netring-0.20-phase-D-middleware.md`](./netring-0.20-phase-D-middleware.md) | 3–4 d | ready |
| E | `detector!` macro + prelude + multi-interface | [`netring-0.20-phase-E-macro-prelude.md`](./netring-0.20-phase-E-macro-prelude.md) | 3–4 d | ready |
| F | Per-CPU sharding + state merging | [`netring-0.20-phase-F-percpu-sharding.md`](./netring-0.20-phase-F-percpu-sharding.md) | 3–4 d | ready |
| G | Migration + docs + release | [`netring-0.20-phase-G-migration-release.md`](./netring-0.20-phase-G-migration-release.md) | 4–5 d | ready |

**Total: 21–29 working days.** (Was 22–30 in the parent spec; Phase A shrank by 1 day because the bump is done.)

## Sequencing rules

Phases must execute in this order — each builds on the previous:

```
A ──► B ──► C ──► D ──► E ──► F ──► G
│     │     │     │     │     │     │
│     │     │     │     │     │     └─ migration recipes, release
│     │     │     │     │     └─ per-CPU sharding (requires E's multi-iface)
│     │     │     │     └─ detector! macro + prelude + multi-iface
│     │     │     └─ async + layers (requires C's AnomalyWriter)
│     │     └─ perf benchmark + AnomalyWriter (requires B's dispatcher)
│     └─ Handler trait + dispatcher (requires A's Protocol trait)
└─ Protocol trait + Event types (the foundation)
```

**No phase ships independently as a release.** All seven land together as netring 0.20.0 at the end of Phase G. Intermediate commits (one per phase, possibly multiple per phase) live on a `0.20-dev` branch and merge to master via squash PR at release time.

## Per-phase commit shape

Each phase ships as **2–4 commits**:

1. `netring 0.20 (X.1): <foundational types>` — defines the trait/struct skeleton without behavior.
2. `netring 0.20 (X.2): <core machinery>` — fills in implementations.
3. `netring 0.20 (X.3): <tests + docs>` — coverage + module docs.
4. (Optional) `netring 0.20 (X.4): <follow-up cleanups>` — for phases that need a polish pass.

Phase G's release commits run `cargo test`, `cargo fmt --check`, `cargo +stable clippy -- -D warnings`, version bump, tag.

## Cross-phase invariants

These hold across **every** phase. Violating them in any commit blocks the merge.

1. **`cargo nextest run -p netring --features tokio,channel,flow,parse,pcap,metrics,http,dns,tls,icmp,emit` passes.** Add tests; never break the existing ones.
2. **`cargo +stable clippy --all-targets --features … -- -D warnings` clean.**
3. **`cargo fmt --check` clean.**
4. **`cargo test --doc` passes.**
5. **The flowscope 0.11.1 API is what we target.** No `flowscope = "0.12"` unless explicitly bumped in a follow-up phase.
6. **`benches/zero_alloc.rs` (after Phase C) tracks ≤512 bytes net heap delta per 100k events.** If a later phase regresses this, the regressing PR cannot merge.

## Phase-pair dependencies (detail)

What each phase needs from prior phases, in concrete terms:

- **B needs A:** `Protocol` trait + `Event` trait + the seven `protocol::builtin` markers exist.
- **C needs B:** `Ctx` struct exists; `Dispatcher` exists; the `Sink<A>` extractor exists as a stub.
- **D needs C:** `AnomalyWriter` + `AnomalySink` exists; `AnomalySinkWrite` trait stable.
- **E needs D:** the `Layer` integration is wired into `Monitor::builder().layer(...)`.
- **F needs E:** `Monitor::builder().interfaces([...])` accepts a multi-interface set; `AsyncMultiCapture` is plumbed.
- **G needs F:** all infrastructure complete; example rewrites can proceed.

## What to do when stuck

Each phase plan has its own **§Risks** section calling out specific failure modes with mitigations. Beyond those:

- **If a flowscope API turns out unsuitable** → file a flowscope plan in `/var/home/mpardo/git/flowscope/plans/` describing the gap; *don't* work around it in netring. (The flowscope 0.10 → 0.11.1 audit that drove netring 0.19.0 is in `git log`; same pattern applies.)
- **If `bon` v3 attributes don't fit** → fall back to hand-rolled typestate. Documented in Phase B's risks.
- **If `tower::Layer` coherence trips** → fall back to a netring-internal `Layer` trait (30 LoC). Documented in Phase D's risks.
- **If a phase's effort blows up beyond +50% of its estimate** → stop, re-plan, possibly defer the phase to 0.21.

## Public-API guarantees during development

The redesign breaks public API. Within the 0.20-dev branch, every phase commit may break unstable users; the master branch stays on 0.19.0 until Phase G's release commit. External users running off `master` continue to get the 0.19.0 surface.

## Reading the phase plans

Each plan file is structured identically:

```
# netring 0.20 — Phase X: <title>

## 1. Goal
## 2. Scope (in / out)
## 3. Dependencies (what must be done first)
## 4. Module layout (files added / modified / deleted)
## 5. Detailed deliverables (type signatures, key code)
## 6. Tests
## 7. Acceptance criteria
## 8. Risks + mitigations
## 9. Estimated effort + commit shape
## 10. Cross-phase notes
```

A developer reading one plan file should be able to write the code without referring to other documents — except the parent spec for design rationale.

## When to start

Start Phase A now. The 0.19.0 absorption release shipped clean; flowscope 0.11.1 is on crates.io; the master branch is at `daf8557` (tagged `0.19.0`). No prerequisites remain.
