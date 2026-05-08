# plans/ — index

Two kinds of files:

- **Design docs** (`*-design.md`) — architecture, rationale, prior-art
  surveys, decision matrices. The source of truth for *why*.
- **Implementation plans** (`NN-*.md`, numbered) — concrete,
  mechanical, file-by-file work breakdowns. The source of truth for
  *how*. Each plan should be executable: pick it up, follow it
  step-by-step, finish.

If a design doc and a plan disagree, the plan wins for execution
detail; design wins for "why is this even shaped this way."

---

## Design docs

| File | Status |
|------|--------|
| [`flow-session-tracking-design.md`](./flow-session-tracking-design.md) | Approved |
| [`high-level-features-design.md`](./high-level-features-design.md) | Approved |
| [`upstream-tracking.md`](./upstream-tracking.md) | Live |

## Numbering scheme

| Range | Theme |
|-------|-------|
| 00–09 | Workspace + flow stack core |
| 10–19 | Capture-side features (dedup, etc.) |
| 20–29 | Companion crates (`netring-flow-*` for protocol bridges + sources) |
| 30–39 | Higher-level abstractions (Conversation, SessionParser) |
| 40–49 | Observability + performance |
| 50–59 | Deferred-feature catchup |
| 60–69 | Tooling (CLIs) |

---

## Tier 0 — Done (released or release-prep)

| Plan | Crate version | Status |
|------|---------------|--------|
| [`00-workspace-split.md`](./00-workspace-split.md) | `0.7.0-alpha.0` / `0.1.0-alpha.0` | ✅ |
| [`01-flow-extractor.md`](./01-flow-extractor.md) | `0.7.0-alpha.1` / `0.1.0-alpha.1` | ✅ |
| [`02-flow-tracker.md`](./02-flow-tracker.md) | `0.7.0-alpha.2` / `0.1.0-alpha.2` | ✅ |
| [`03-flow-reassembler.md`](./03-flow-reassembler.md) | `0.7.0-alpha.3` / `0.1.0-alpha.3` | ✅ |
| [`04-flow-release.md`](./04-flow-release.md) | `0.7.0` / `0.1.0` (manifests bumped) | ⏸ awaiting publish |

## Tier 1 — Foundations (target 0.7.x or 0.8.0)

Short, high-leverage. Each unblocks downstream work.

| Plan | Goal | Effort |
|------|------|--------|
| [`10-dedup.md`](./10-dedup.md) | `Dedup` primitive + `dedup_stream()` for `lo` | ✅ done (folded into 0.7.0) |
| [`12-test-infra.md`](./12-test-infra.md) | pcap fixtures, `proptest`, `cargo-fuzz` harness | 1.5 days |

## Tier 2 — Companion crates (target 0.8.0)

Each crate is independently versioned, lives in the workspace.

| Plan | Crate | Effort |
|------|-------|--------|
| [`20-flow-pcap.md`](./20-flow-pcap.md) | `netring-flow-pcap` — pcap source adapter | 1 day |
| [`21-flow-protolens.md`](./21-flow-protolens.md) | `netring-flow-protolens` — productized protolens bridge | 2 days |
| [`22-flow-http.md`](./22-flow-http.md) | `netring-flow-http` — `httparse`-based HTTP/1.x | 2 days |
| [`23-flow-tls.md`](./23-flow-tls.md) | `netring-flow-tls` — `tls-parser` + optional JA3/JA4 | 2 days |
| [`24-flow-dns.md`](./24-flow-dns.md) | `netring-flow-dns` — query/response correlation | 1.5 days |

## Tier 3 — Higher-level abstractions (target 0.9.0)

| Plan | Goal | Effort |
|------|------|--------|
| [`30-conversation.md`](./30-conversation.md) | `Conversation<E>` aggregate (init+resp byte streams as one Stream) | 1 day |
| [`31-session-parser.md`](./31-session-parser.md) | `SessionParser<P>` trait + `session_stream()` — protocol-agnostic L7 message stream | 5 days |

## Tier 4 — Observability + performance (target 0.9.0/1.0.0)

| Plan | Goal | Effort |
|------|------|--------|
| [`32-flow-export.md`](./32-flow-export.md) | NetFlow/IPFIX export via `netgauze-flow-pkt` | 2 days |
| [`40-observability.md`](./40-observability.md) | `metrics` + `tracing` integration | 1.5 days |
| [`41-perf-foundations.md`](./41-perf-foundations.md) | Zero-copy reassembly (`BytesMut` pool) + LRU hot-cache | 3 days |

## Tier 5 — Deferred catchup + tooling

| Plan | Goal | Effort |
|------|------|--------|
| [`50-deferred-catchup.md`](./50-deferred-catchup.md) | `InnerGre`, `FlowLabel`, `AutoDetectEncap`, manual sweep, async state init, IPv6 frags, `broadcast` helper | 2 days |
| [`60-cli-tools.md`](./60-cli-tools.md) | `flow-replay`, `flow-summary` CLI binaries | 1.5 days |

---

## Suggested release cadence

| Version | Includes | When |
|---------|----------|------|
| `0.7.0` | Tier 0 (current prep) | now |
| `0.7.1` | Plan 10 (dedup), Plan 50 quick wins | +1 week |
| `0.8.0` | Tier 1 + Tier 2 | +4–6 weeks |
| `0.9.0` | Tier 3 + Tier 4 selected | +3 months |
| `1.0.0` | Plan 31 + perf + IPFIX done; API frozen | when ready |

---

## Dependency graph for Tier 1+2

```
                ┌─────────────────────────┐
                │ 0.7.0 published          │
                └────────────┬─────────────┘
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
        ┌──────────────┐         ┌──────────────────┐
        │ 10-dedup     │         │ 12-test-infra    │
        │              │         │ (pcap fixtures + │
        │              │         │  proptest + fuzz)│
        └──────────────┘         └────────┬─────────┘
                                          │
                                          │  (pcap fixtures unlock
                                          ▼   the L7 bridges' tests)
                ┌────────────────────────────┐
                │  Tier 2 — companion crates  │
                │  (parallel; pick any two)   │
                ├────────────────────────────┤
                │ 20-flow-pcap                │
                │ 21-flow-protolens           │
                │ 22-flow-http                │
                │ 23-flow-tls                 │
                │ 24-flow-dns                 │
                └────────────────────────────┘
```

Tier 3+4 plans depend on at least one Tier 2 crate (so we have a real
parser to test SessionParser against).

## Sequencing principles

- **Companion crates are siblings**, not children. Each can be
  worked on independently once Tier 1 is done. Pick highest-leverage
  first based on user demand.
- **Test infra unlocks confidence.** Plan 12's fuzz harness will
  catch parser bugs in Tier 2 before users do.
- **The big abstraction (Plan 31) waits for proof.** SessionParser
  is the pre-1.0 redesign. We need ≥2 Tier-2 parsers in production
  before locking the trait shape.

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
phase ships, the plan stays in `plans/` as a record — don't delete.
When the plan turns out wrong (design assumption breaks during
implementation), update the plan first, then fix code.
