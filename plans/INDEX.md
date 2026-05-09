# plans/ — index

Two kinds of files:

- **Design docs** (`*-design.md`) — architecture, rationale, prior-art
  surveys, decision matrices.
- **Implementation plans** (`NN-*.md`, numbered) — concrete,
  mechanical, file-by-file work breakdowns.

If a design doc and a plan disagree, the plan wins for execution
detail; design wins for "why is this even shaped this way."

> **Scope split.** Flow & session tracking moved to the separate
> [`flowscope`](https://github.com/p13marc/flowscope) crate. Plans
> 12, 20, 22–24, 30–32, 41, 50, 60, plus the design docs covering
> flow features, live in flowscope's `plans/` now. This index covers
> only netring-side plans (capture, dedup, observability of capture,
> upstream tracking).

---

## Design docs

| File | Status |
|------|--------|
| [`upstream-tracking.md`](./upstream-tracking.md) | Live |

## Numbering scheme

| Range | Theme |
|-------|-------|
| 00–09 | Workspace + flow stack core (now done; flow plans moved to flowscope) |
| 10–19 | Capture-side features (dedup, etc.) |

---

## Tier 0 — Done (released or release-prep)

| Plan | Crate version | Status |
|------|---------------|--------|
| [`00-workspace-split.md`](./00-workspace-split.md) | `0.7.0-alpha.0` / `0.1.0-alpha.0` | ✅ |
| [`01-flow-extractor.md`](./01-flow-extractor.md) | `0.7.0-alpha.1` / `0.1.0-alpha.1` | ✅ |
| [`02-flow-tracker.md`](./02-flow-tracker.md) | `0.7.0-alpha.2` / `0.1.0-alpha.2` | ✅ |
| [`03-flow-reassembler.md`](./03-flow-reassembler.md) | `0.7.0-alpha.3` / `0.1.0-alpha.3` | ✅ |
| [`04-flow-release.md`](./04-flow-release.md) | `0.7.0` published | ✅ |

These plans built the original flow stack as a workspace inside
netring. The flow code subsequently migrated to the separate
flowscope crate (see header note); these plans stay as historical
record of how it happened.

## Tier 1 — Foundations

| Plan | Goal | Status |
|------|------|--------|
| [`10-dedup.md`](./10-dedup.md) | `Dedup` primitive + `dedup_stream()` for `lo` | ✅ done (folded into 0.7.0) |

---

## Conventions

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

Plan files are living documents: update Status as you go. When a
phase ships, the plan stays as a record — don't delete.
