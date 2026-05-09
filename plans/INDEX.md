# plans/ — index

Two kinds of files:

- **Design docs** (`*-design.md`) — architecture, rationale, prior-art
  surveys, decision matrices.
- **Implementation plans** (`NN-*.md`, numbered) — concrete,
  mechanical, file-by-file work breakdowns.

If a design doc and a plan disagree, the plan wins for execution
detail; design wins for "why is this even shaped this way."

> **Scope split.** Flow & session tracking lives in the separate
> [`flowscope`](https://github.com/p13marc/flowscope) crate.
> flowscope's `plans/` holds everything related to flow extraction,
> tracking, reassembly, session/datagram parsing, observability of
> flows, and L7 protocol parsers. This index covers only
> netring-side plans (capture, dedup, upstream tracking).

---

## Design docs

| File | Status |
|------|--------|
| [`upstream-tracking.md`](./upstream-tracking.md) | Live |

## Numbering scheme

| Range | Theme |
|-------|-------|
| 10–19 | Capture-side features (dedup, etc.) |

---

## Plans

| Plan | Goal | Status |
|------|------|--------|
| [`10-dedup.md`](./10-dedup.md) | `Dedup` primitive + `dedup_stream()` for `lo` | ✅ done (folded into 0.7.0) |
| [`11-busy-poll-prefer.md`](./11-busy-poll-prefer.md) | `SO_PREFER_BUSY_POLL` + `SO_BUSY_POLL_BUDGET` for AF_PACKET + AF_XDP (kernel 5.11+) | ✅ done |
| [`12-xdp-loader.md`](./12-xdp-loader.md) | Built-in XDP redirect-all program loader via optional `aya` (pure Rust, feature-gated) | not started |

Both 11 and 12 close the two gaps identified in
[flowscope's DPI architecture research](https://github.com/p13marc/flowscope/blob/master/plans/DPI_ARCHITECTURE.md):
the AF_XDP busy-poll latency knobs and the XDP program loading step.

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
