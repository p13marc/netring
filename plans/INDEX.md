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
shape of plans 10–19, run `git log --diff-filter=D --name-only --
plans/` or check the corresponding release commits.

### netring 0.13.0 (current release)

| Plan | Goal | Status |
|------|------|--------|
| [`20-stream-observability.md`](./20-stream-observability.md) | Sealed `StreamCapture` trait + `capture()`/`capture_stats()`/`capture_cumulative_stats()` on all four async stream types. `with_pcap_tap(writer)` + `TapErrorPolicy { Continue, DropTap, FailStream }`. Closes des-rs F#2 + F#3. | ✅ landed (0.13.0) |
| [`21-bpf-filter-ergonomics.md`](./21-bpf-filter-ergonomics.md) | `PacketSetFilter` trait. `Capture::set_filter` + `AsyncCapture::set_filter` for atomic in-kernel BPF swap. `AsyncCapture::open_with_filter(iface, filter)`. Composes via `stream.capture().set_filter(...)`. Closes des-rs F#1 + F#7. | ✅ landed (0.13.0) |
| [`22-multi-source-capture.md`](./22-multi-source-capture.md) | `AsyncMultiCapture` with `open`/`open_workers`/`from_captures`. Three `Multi*Stream` types yielding `TaggedEvent { source_idx, event }`. Per-source + aggregate stats + `alive_sources()`. New `docs/scaling.md` with FanoutMode decision matrix and 7 anti-patterns. Custom round-robin `SelectState` instead of `futures::stream::select_all` (dep-graph minimalism). Closes des-rs F#5 + F#6. | ✅ landed (0.13.0) |
| [`23-async-pcap-source.md`](./23-async-pcap-source.md) | `AsyncPcapSource` (mpsc + spawn_blocking, PCAP/PCAPNG auto-detect, replay pacing) + `PcapFlowStream` bridge. Live + offline pipelines unify via `Stream<Item = FlowEvent<K>>`. Closes des-rs F#4. | ✅ landed (0.13.0) |

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
