# plans/ — index

Two kinds of files:

- **Design docs** (`*-design.md`, `upstream-tracking.md`,
  `flowscope-*-feedback-*.md`) — architecture, rationale,
  prior-art surveys, decision matrices, future-work tracking,
  cross-repo feedback rounds.
- **Implementation plans** (`NN-*.md`, numbered; or
  `netring-X.Y-*.md` for release roadmaps) — concrete,
  mechanical, file-by-file work breakdowns. Live for one release
  cycle, then get pruned: shipped plans from earlier releases are
  removed once their CHANGELOG entry stands as the canonical
  record.

If a design doc and a plan disagree, the plan wins for execution
detail; design wins for "why is this even shaped this way."

> **Scope split.** Flow & session tracking lives in the separate
> [`flowscope`](https://github.com/p13marc/flowscope) crate.
> flowscope's `plans/` holds everything related to flow extraction,
> tracking, reassembly, session/datagram parsing, observability of
> flows, and L7 protocol parsers. This index covers only
> netring-side plans (capture, dedup, async adapters, protocol
> monitor + anomaly toolkit).

---

## Design docs

| File | Status |
|------|--------|
| [`upstream-tracking.md`](./upstream-tracking.md) | Live — rustc/kernel features being watched |

## Cross-repo feedback rounds

Each one drove a flowscope release; the latest one is queued for
the next.

| File | Status |
|------|--------|
| [`flowscope-0.5-feedback-2026-05-22.md`](./flowscope-0.5-feedback-2026-05-22.md) | ✅ landed — drove flowscope 0.5 + 0.6 (11 of 12 items shipped) |
| [`flowscope-0.7-feedback-2026-05-29.md`](./flowscope-0.7-feedback-2026-05-29.md) | ✅ landed — drove flowscope 0.7 (8 of 9 items shipped) |
| [`flowscope-0.8-feedback-2026-06-03.md`](./flowscope-0.8-feedback-2026-06-03.md) | 📤 queued — flagged G1/G3/G5 as top-3 asks for flowscope 0.8 |
| [`flowscope-wishlist-2026-06-06.md`](./flowscope-wishlist-2026-06-06.md) | 📤 **consolidated wishlist** — supersedes the dated feedback rounds. ~20 items with effort/impact matrix + phasing recommendation + per-item netring integration plan. Top 3: serde feature + IcmpType helpers + DnsResolutionCache primitive. |

## Numbering scheme

| Range | Theme |
|-------|-------|
| 10–19 | Capture-side features (dedup, busy-poll, XDP loader, flowscope-version bumps, BPF builder) |
| 20–29 | Async-stream maturity (`StreamCapture` trait, pcap tap, BPF filter ergonomics, multi-source, offline replay) |
| `netring-X.Y-*` | Release roadmaps |

---

## Release roadmaps + plans

### netring 0.15.0 (shipped — simple-nms wishlist round)

| Plan | Goal | Status |
|------|------|--------|
| [`24-stream-api-completion.md`](./24-stream-api-completion.md) | `StreamSetFilter` + `dedup`/`dedup_mut` defaults + `tracker_stats`/`active_flows` + pcap-tap `snaplen` + `Capture::busy_poll_config` accessor. | ✅ landed (0.15.0) |
| [`25-bpf-filter-to-human.md`](./25-bpf-filter-to-human.md) | `impl Display for BpfFilter` + `to_human()` rendering pcap-filter syntax. | ✅ landed (0.15.0) |
| [`26-multi-stream-config.md`](./26-multi-stream-config.md) | `MultiStreamConfig<K>` builder + `flow_stream_with` / `session_stream_with` / `datagram_stream_with` constructors on `AsyncMultiCapture`. | ✅ landed (0.15.0) |

*To prune at the next minor publish.*

### netring 0.16.0 (prepared on master — anomaly correlation)

| Plan | Goal | Status |
|------|------|--------|
| [`netring-0.16-roadmap-2026-05-29.md`](./netring-0.16-roadmap-2026-05-29.md) | 14-item roadmap building multi-protocol anomaly correlation as a first-class concern. `ProtocolMonitor` + `AnomalyMonitor` + `correlate` primitives + 6 reference detectors. | 🟢 9 of 14 done (N1–N4, N7–N11, N13, N14); N5 / N6 / N12 carried to 0.18 |
| [`netring-0.17-flowscope-0.7-bump-2026-06-03.md`](./netring-0.17-flowscope-0.7-bump-2026-06-03.md) | Lockstep bump to flowscope 0.7. Adds the `icmp` feature, `IcmpInner` cross-protocol correlation, `FlowAnomalyRule`, `Severity` bridge. Closes N4 + the third N10 reference detector. | ✅ landed (Commits A/B/C — `502a484` / `8bf53c0` / `e044dd8`) |

### netring 0.18 (carry-over + post-0.16 polish)

| Plan | Goal | Status |
|------|------|--------|
| [`netring-0.18-roadmap-2026-06-03.md`](./netring-0.18-roadmap-2026-06-03.md) | N5 driver refactor + N6 `AsyncCapture::broadcast(n)` + N12 message tap (once flowscope G5 lands) + anomaly tutorial doc + benches. | 📝 drafted |

### Cross-repo (flowscope)

- [`flowscope/plans/75-skip-endpoints-extractor.md`](https://github.com/p13marc/flowscope/blob/master/plans/75-skip-endpoints-extractor.md) — `extract::SkipEndpoints` + generic `extract::Filter` + `EndpointSet` trait. Closes simple-nms N1.2 (redirected because `FlowExtractor` combinators belong in flowscope alongside `StripVlan` / `InnerVxlan` / `FlowLabel`).

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
- **Suricata-compatible rule DSL** (from 0.16 roadmap) — declined.
  `AnomalyRule<K>` gives the Rust-API shape; a text-DSL is
  Zeek/Suricata territory and a major project. Revisit if a
  concrete consumer materialises.
- **eBPF-side anomaly correlator** (from 0.16 roadmap) — declined
  for now. Order-of-magnitude harder than the user-space version;
  worth it for 10G+ workloads, not the netring sweet spot today.
- **Encrypted-traffic ML detection** (from 0.16 roadmap) — out of
  scope. Compose with this roadmap later via a user-defined
  `AnomalyRule` that feeds a learned model; shipping the ML
  pipeline isn't netring's job.

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

Release roadmaps (`netring-X.Y-*.md`) follow a looser shape:
overview matrix + per-item sections + effort summary + critical
path / dependency map / phasing notes. Less prescriptive than the
numbered plans; meant to be the planning artifact during the
release cycle.

### Lifecycle

1. Draft the plan — `Status: Planned`.
2. Implement; ship in a release.
3. Flip `Status: Done — landed in vX.Y.Z`. Add an implementation
   note if the shipped design diverges from the plan.
4. **Prune on next release.** When the next minor ships, delete
   the prior release's plan files — the CHANGELOG entry plus
   `git log -- plans/<file>` is the long-term record.
