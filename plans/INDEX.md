# plans/ — index

This directory holds two kinds of files:

- **Design docs** (`*-design.md`) — architecture, rationale, prior-art
  surveys, decision matrices. The source of truth for *why*.
- **Implementation plans** (`NN-*.md`, numbered) — concrete,
  mechanical, file-by-file work breakdowns. The source of truth for
  *how*. Each plan should be executable: pick it up, follow it
  step-by-step, finish.

If a design doc and a plan disagree, the plan wins for execution
detail; design wins for "why is this even shaped this way."

---

## Files

| File | Kind | Status |
|------|------|--------|
| [`flow-session-tracking-design.md`](./flow-session-tracking-design.md) | Design — pluggable extractor + tracker + reassembler hook | Approved |
| [`high-level-features-design.md`](./high-level-features-design.md) | Design — loopback dedup (Part 2 superseded; see flow design) | Approved |
| [`upstream-tracking.md`](./upstream-tracking.md) | Tracking doc — Rust upstream features (gen blocks, Polonius, etc.) we're waiting on | Live |
| [`00-workspace-split.md`](./00-workspace-split.md) | Plan — convert repo to workspace, create `netring-flow` skeleton | Not started |
| [`01-flow-extractor.md`](./01-flow-extractor.md) | Plan — `FlowExtractor` trait + built-ins + decap combinators | Not started |
| [`02-flow-tracker.md`](./02-flow-tracker.md) | Plan — `FlowTracker<E, S>` + TCP state + `AsyncCapture::flow_stream` | Not started |
| [`03-flow-reassembler.md`](./03-flow-reassembler.md) | Plan — sync `Reassembler` + `AsyncReassembler` + `channel_factory` | Not started |
| [`04-flow-release.md`](./04-flow-release.md) | Plan — docs, CHANGELOG, coordinated 0.7.0 / 0.1.0 release | Not started |
| [`10-dedup.md`](./10-dedup.md) | Plan — `Dedup` primitive + `dedup_stream()` adapter (parallel track) | Not started |

---

## Dependency graph

```
                    ┌─────────────────────────┐
                    │ 00-workspace-split      │  Phase 0 — must come first
                    └────────────┬────────────┘
                                 │
                ┌────────────────┴────────────────┐
                │                                 │
                ▼                                 ▼
   ┌────────────────────────┐         ┌────────────────────────┐
   │ 01-flow-extractor      │         │ 10-dedup               │  parallel
   │ (FlowExtractor + built-ins)│     │ (independent of flow)  │
   └────────────┬───────────┘         └──────────┬─────────────┘
                │                                │
                ▼                                │
   ┌────────────────────────┐                   │
   │ 02-flow-tracker        │                   │
   │ (FlowTracker + Stream) │                   │
   └────────────┬───────────┘                   │
                │                                │
                ▼                                │
   ┌────────────────────────┐                   │
   │ 03-flow-reassembler    │                   │
   │ (sync + async hooks)   │                   │
   └────────────┬───────────┘                   │
                │                                │
                └──────────────┬─────────────────┘
                               ▼
                ┌────────────────────────────┐
                │ 04-flow-release            │  Phase 4 — final
                │ (docs, CHANGELOG, publish) │
                └────────────────────────────┘
```

Sequencing rules:

- **Phase 00 blocks everything else.** No new code until the workspace
  is in place.
- **`10-dedup` is parallel** to flow phases. Could ship in 0.7.0
  alongside the flow stack, or earlier as 0.6.x.
- **Flow phases are linear** (01 → 02 → 03), each depends on types
  from the previous.
- **Phase 04 publishes both** `netring-flow` 0.1.0 and `netring`
  0.7.0 together.

---

## Effort summary

| Phase | LOC (rough) | Effort | Notes |
|-------|------------:|:------:|-------|
| 00 — workspace split | 0 (movement only) | 0.5 day | Mechanical; CI matrix shake-out is the main work |
| 01 — extractor + built-ins | ~600 | 2 days | Decap combinators are the meatiest |
| 02 — tracker + async stream | ~700 | 2.5 days | TCP state machine + `FlowStream` builder |
| 03 — reassembler hooks | ~450 | 1.5 days | Two parallel surfaces, `channel_factory` helper |
| 04 — release | ~50 + 2 docs | 1 day | `FLOW_GUIDE.md`, `CHANGELOG.md`, version bumps |
| 10 — dedup | ~250 | 1 day | Independent; can drop in any time |
| **Total** | ~2 050 | ~8.5 days | |

(Numbers from the design doc; +/-30%.)

---

## Conventions for plan files

Each `NN-*.md` plan has these sections:

1. **Summary** — one paragraph
2. **Status** — Not started / In progress / Done
3. **Prerequisites** — which prior plans must be complete
4. **Out of scope** — what this plan does NOT do
5. **Files** — exact paths to create/modify
6. **API** — concrete type/function signatures to ship
7. **Implementation steps** — numbered, mechanical
8. **Tests** — unit + integration coverage
9. **Acceptance criteria** — what "done" looks like
10. **Risks** — known unknowns specific to this phase
11. **Effort** — LOC and time estimate

Plan files are living documents: update Status + check off
implementation steps as you go. When a phase ships, the plan stays
in `plans/` as a record of what was done — don't delete.

When a plan turns out to be wrong (design assumption breaks during
implementation), update the plan first, then fix code. The plan
should track reality.

---

## Releases coordinated by these plans

| Version | Plans involved |
|---------|---------------|
| `netring-flow` 0.1.0-alpha.0 + `netring` 0.7.0-alpha.0 | 00 |
| `netring-flow` 0.1.0-alpha.1+ + `netring` 0.7.0-alpha.1+ | 01, 02, 03 (rolling alphas) |
| `netring-flow` 0.1.0 + `netring` 0.7.0 | 04 (final) |
| `netring` 0.7.0 (also includes dedup) | 10 |
