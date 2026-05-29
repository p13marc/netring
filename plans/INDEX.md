# plans/ — index

Two kinds of files:

- **Design docs** (`*-design.md`, `upstream-tracking.md`) — architecture,
  rationale, prior-art surveys, decision matrices, future-work tracking.
- **Implementation plans** (`NN-*.md`, numbered) — concrete,
  mechanical, file-by-file work breakdowns. Live for one release
  cycle, then get pruned: shipped plans from earlier releases are
  removed once their CHANGELOG entry stands as the canonical record.

If a design doc and a plan disagree, the plan wins for execution
detail; design wins for "why is this even shaped this way."

> **Scope split.** Flow & session tracking lives in the separate
> [`flowscope`](https://github.com/p13marc/flowscope) crate.
> flowscope's `plans/` holds everything related to flow extraction,
> tracking, reassembly, session/datagram parsing, observability of
> flows, and L7 protocol parsers. This index covers only
> netring-side plans (capture, dedup, async adapters).

---

## Design docs

| File | Status |
|------|--------|
| [`upstream-tracking.md`](./upstream-tracking.md) | Live — rustc/kernel features being watched |

## Numbering scheme

| Range | Theme |
|-------|-------|
| 10–19 | Capture-side features (dedup, busy-poll, XDP loader, flowscope-version bumps, BPF builder) |
| 20–29 | Async-stream maturity (`StreamCapture` trait, pcap tap, BPF filter ergonomics, multi-source, offline replay) |

---

## Plans

Only the **current release's** plans are kept here. Older shipped
plans live in git history and in CHANGELOG.md. For the historical
shape of any pruned plan, run
`git log --diff-filter=D --name-only -- plans/` or check the
corresponding release commits.

### netring 0.15.0 backlog (simple-nms 2026-08-XX wishlist + general API completion)

| Plan | Goal | Status |
|------|------|--------|
| [`24-stream-api-completion.md`](./24-stream-api-completion.md) | Five small additions: `StreamSetFilter` sub-trait + `StreamCapture::dedup`/`dedup_mut` defaults + `tracker_stats`/`active_flows` accessors + pcap-tap `snaplen` knob + `Capture::busy_poll_config` accessor with `tracing::info` on apply. Closes simple-nms N1.1, N1.3-redirect, N1.4, N1.5, N1.7. | Planned — 0.15.0 |
| [`25-bpf-filter-to-human.md`](./25-bpf-filter-to-human.md) | `impl Display for BpfFilter` + `to_human()` rendering canonical pcap-filter syntax. Powers `simple-nms diag filter`. Stores the `MatchFrag` IR alongside the compiled bytecode (regex-source-pattern style). Closes simple-nms N1.6. | Planned — 0.15.0 |

### netring 0.16.0 backlog (larger ergonomics)

| Plan | Goal | Status |
|------|------|--------|
| [`26-multi-stream-config.md`](./26-multi-stream-config.md) | `MultiStreamConfig<K>` builder + `flow_stream_with` / `session_stream_with` / `datagram_stream_with` constructors on `AsyncMultiCapture`. Applies tracker config + dedup + idle-timeout-fn + monotonic-ts uniformly to every per-source inner stream during construction (architectural fit, vs. post-hoc `with_*` chaining which collides with the boxed `SelectState` fan-in). Requires `impl Clone for Dedup`. Closes simple-nms N2.1. | Planned — 0.16.0 |

### Cross-repo (flowscope)

- [`flowscope/plans/75-skip-endpoints-extractor.md`](https://github.com/p13marc/flowscope/blob/master/plans/75-skip-endpoints-extractor.md) — `extract::SkipEndpoints` + generic `extract::Filter` + `EndpointSet` trait. Closes simple-nms N1.2 (originally directed at netring; redirected because `FlowExtractor` combinators belong in flowscope alongside `StripVlan` / `InnerVxlan` / `FlowLabel`).

### Deferred (recorded so a future ask doesn't get re-litigated)

- **simple-nms N1.3 verbatim** (`flow_stream(...).with_bpf_filter(filter)`
  chained builder) — declined in favor of the cleaner
  `stream.set_filter(filter)` verb on `StreamSetFilter` (plan 24).
  The chained `with_*` form has ambiguous timing semantics
  (apply-at-open vs. apply-now); the explicit verb avoids the
  reader-trap.
- **simple-nms N2.2** (`with_extractor_replace` for hot-reload) —
  deferred indefinitely. Atomic mid-packet extractor swap is hard
  (consistency on the in-flight tracker state), and simple-nms has
  a working `Arc<ArcSwap<...>>`-wrapped-extractor fallback. Revisit
  only if a third consumer asks.
- **simple-nms N2.3** (AF_XDP `Packet`-metadata parity with
  `XdpPacket`) — already tracked in
  [`upstream-tracking.md`](./upstream-tracking.md) §"Unified
  `PacketBackend` trait" and §"XDP RX metadata extensions". Added
  simple-nms as a known consumer waiting on the kernel-side story.
- **simple-nms N3.1** (in-crate XDP-prefilter shape library) —
  speculative; revisit when v3 demands materialise.
- **simple-nms N3.2** (per-fanout-worker drops histogram) —
  current `AsyncMultiCapture::per_source_capture_stats()` is the
  raw shape; aggregation belongs in consumer-side dashboards.

---

## Conventions

Each `NN-*.md` plan has these sections:

1. **Summary** — one paragraph
2. **Status** — Planned / In progress / Done (and which version)
3. **Prerequisites** — which prior plans must be complete
4. **Out of scope** — what this plan does NOT do
5. **Files** — exact paths to create/modify
6. **API** — concrete type/function signatures to ship
7. **Implementation steps** — numbered, mechanical
8. **Tests** — unit + integration coverage
9. **Acceptance criteria** — what "done" looks like
10. **Risks** — known unknowns specific to this phase
11. **Effort** — LOC and time estimate

### Lifecycle

1. Draft the plan — `Status: Planned`.
2. Implement; ship in a release.
3. Flip `Status: Done — landed in vX.Y.Z`. Add an implementation
   note if the shipped design diverges from the plan (e.g. plan 23's
   pivot from eventfd-backed `PacketBatch::Owned` to mpsc + bridge).
4. **Prune on next release.** When the next minor ships, delete the
   prior release's plan files — the CHANGELOG entry plus
   `git log -- plans/<file>` is the long-term record.
