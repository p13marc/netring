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
| 10–19 | Capture-side features (dedup, busy-poll, XDP loader, flowscope-version bumps, BPF builder) |
| 20–29 | Async-stream maturity (`StreamCapture` trait, pcap tap, BPF filter ergonomics, multi-source, offline replay) |

---

## Plans

| Plan | Goal | Status |
|------|------|--------|
| [`10-dedup.md`](./10-dedup.md) | `Dedup` primitive + `dedup_stream()` for `lo` | ✅ done (folded into 0.7.0) |
| [`11-busy-poll-prefer.md`](./11-busy-poll-prefer.md) | `SO_PREFER_BUSY_POLL` + `SO_BUSY_POLL_BUDGET` for AF_PACKET + AF_XDP (kernel 5.11+) | ✅ done |
| [`12-xdp-loader.md`](./12-xdp-loader.md) | Built-in XDP redirect-all program loader via optional `aya` (pure Rust, feature-gated) | ✅ phase 1 done (0.8.0); ✅ phase 2 `with_program(...)` done (0.11.0); multi-queue shared-map sharing remains deferred |
| [`13-flowscope-0.2-bump.md`](./13-flowscope-0.2-bump.md) | Bump flowscope dep to 0.2; handle the breaking changes inside async adapters; surface `Anomaly` events | ✅ done (0.9.0) |
| [`14-config-aware-async-streams.md`](./14-config-aware-async-streams.md) | Fix silent config loss across `flow_stream → session_stream`; add `with_config` to `SessionStream`/`DatagramStream` | ✅ done (0.9.0) |
| [`15-dedup-and-pcap-hardening.md`](./15-dedup-and-pcap-hardening.md) | Dedup stress test (10k @ 1 kHz same-direction) + explicit pcap nanosecond round-trip assertion | ✅ done (0.9.0) |
| [`16-session-stream-reassembly.md`](./16-session-stream-reassembly.md) | `SessionStream` runs `BufferedReassembler` per (flow, side) so length-prefixed binary protocols (DES PSMSG etc.) are correct on the live API; honours `FlowTrackerConfig::max_reassembler_buffer` + `overflow_policy` | ✅ done (0.10.0; closes G1 from des-rs analysis) |
| [`17-dedup-flow-chain.md`](./17-dedup-flow-chain.md) | `FlowStream::with_dedup(Dedup)` (+ same on `SessionStream`, `DatagramStream`) so loopback dedup composes with the flow / session pipeline | ✅ done (0.10.0; closes G2 from des-rs analysis) |
| [`18-bpf-builder.md`](./18-bpf-builder.md) | `BpfFilter::builder()` — typed cBPF compiler covering ~90 % of common filters (TCP/UDP/host/port/net/VLAN, AND/OR/NOT). Closes the [156a nlink-lab proposal](./156a-netring-bpf-builder-proposal.md): downstream consumers can drop their `tcpdump -dd` runtime shell-out. | ✅ done (0.11.0) |
| [`19-flowscope-0.3-bump.md`](./19-flowscope-0.3-bump.md) | Bump flowscope 0.2 → 0.3; handle `EndReason::ParseError` + `SessionEvent::Anomaly` (`#[non_exhaustive]` growth); expose `with_idle_timeout_fn`, `with_monotonic_timestamps`, `snapshot_flow_stats()` on `FlowStream` / `SessionStream` / `DatagramStream`. Replaces `tracing::warn!` anomaly drop with typed `SessionEvent::Anomaly` forwarding. | ✅ done (0.12.0) |
| [`20-stream-observability.md`](./20-stream-observability.md) | Sealed `StreamCapture` trait giving `FlowStream` / `SessionStream` / `DatagramStream` / `DedupStream` a uniform `capture()` accessor with default-methoded `capture_stats()` / `capture_cumulative_stats()`. Plus `with_pcap_tap(writer)` + `TapErrorPolicy { Continue, DropTap, FailStream }` on each stream type. Closes des-rs F#2 + F#3. | Planned — 0.13.0 |
| [`21-bpf-filter-ergonomics.md`](./21-bpf-filter-ergonomics.md) | `AsyncCapture::open_with_filter(iface, BpfFilter)` constructor + `Capture::set_filter` / `AsyncCapture::set_filter` for atomic in-kernel filter swap. New `PacketSetFilter` trait gates `set_filter` to AF_PACKET-backed captures (no XDP no-op). Composes with plan 20 via `stream.capture().set_filter(&new_filter)`. Closes des-rs F#1 + F#7. | Planned — 0.13.0 |
| [`22-multi-source-capture.md`](./22-multi-source-capture.md) | One `AsyncMultiCapture` type, two constructors: `open(&[ifaces])` (multi-interface) and `open_workers(iface, n, group_id)` (fanout-group scaling). `MultiFlowStream` / `MultiSessionStream` / `MultiDatagramStream` yield `TaggedEvent { source_idx, event }`. Plus `docs/scaling.md` with `FANOUT_HASH`-on-skewed-traffic anti-pattern callout. Closes des-rs F#5 + F#6. | Planned — 0.13.0 |
| [`23-async-pcap-source.md`](./23-async-pcap-source.md) | `AsyncPcapSource` implementing `PacketSource + AsFd` via eventfd-backed readiness. PCAPNG + legacy PCAP auto-detected at open. Optional packet-timestamp pacing. Same `flow_stream → session_stream` chain runs live or offline. Touches `PacketBatch` with a new owned-backing variant (internal). Closes des-rs F#4. | Planned — 0.13.0 |

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
