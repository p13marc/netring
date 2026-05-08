# Plan 04 — Flow release (0.7.0 / 0.1.0)

## Summary

Coordinate the first stable release of the new flow stack. Land
`docs/FLOW_GUIDE.md` (the user-facing extractor cookbook), update the
top-level README, expand the CHANGELOG, bump versions to non-alpha,
and publish both crates to crates.io.

This plan is short on code and heavy on docs and release mechanics.

## Status

Not started.

## Prerequisites

- [Plan 00](./00-workspace-split.md), [Plan 01](./01-flow-extractor.md),
  [Plan 02](./02-flow-tracker.md), [Plan 03](./03-flow-reassembler.md)
  complete.
- (Optional) [Plan 10](./10-dedup.md) complete if shipping dedup in
  the same release.
- All alpha versions tagged; CI green; ≥1 person has used the API
  for a non-trivial task and reported back.

## Out of scope

- New features. This is purely "publish what we have."
- API revisions in response to early-adopter feedback (those go in
  0.7.1 or 0.8.0).

---

## Files

### NEW

- `netring-flow/docs/FLOW_GUIDE.md` — user guide (~800 LOC).
- `netring-flow/README.md` — short crate-level README. (Currently
  the workspace shares one README; netring-flow needs its own for
  crates.io.)

### MODIFIED

- `README.md` (workspace root + `netring/README.md`) — add a "Flow
  tracking" section pointing to the new guide.
- `CHANGELOG.md` — full 0.7.0 entry consolidating all alpha
  contributions.
- `netring/Cargo.toml` — `version = "0.7.0"`.
- `netring-flow/Cargo.toml` — `version = "0.1.0"`.
- `netring/Cargo.toml` — bump `netring-flow` dep to `^0.1`.
- `docs/` — review existing guides (ASYNC_GUIDE, etc.) for any
  references that need updating after the workspace split.

---

## `netring-flow/docs/FLOW_GUIDE.md` outline

The guide should be a complete cookbook. Sections:

1. **Quick start (async)** — `cap.flow_stream(FiveTuple::bidirectional())`,
   one screen of code.
2. **Quick start (sync)** — pcap input, `FlowTracker::track`, one
   screen of code.
3. **Built-in extractors**
   - `FiveTuple` (directional / bidirectional)
   - `IpPair` (ICMP, fragmented)
   - `MacPair` (L2)
4. **Encapsulation** — when to use which combinator
   - `StripVlan` (VLAN)
   - `StripMpls` (MPLS)
   - `InnerVxlan` (VXLAN, default port 4789)
   - `InnerGtpU` (GTP-U, default port 2152)
   - Composing combinators
5. **Custom extractors** — three worked examples
   - 5-tuple variant ignoring source port (server-side flow id)
   - Application cookie inside UDP/9999 payload
   - DNS query-name as flow key
6. **Per-flow user state** — `with_state` example
7. **TCP state events** — what `Established` and `StateChange` mean,
   reading the history string
8. **Reassembly**
   - Sync (`Reassembler` + `BufferedReassembler` + `FlowDriver`)
   - Async (`AsyncReassembler` + `channel_factory` + spawned tasks)
   - Bridging to `protolens` (link to example, or excerpt)
9. **Backpressure** — how it flows from the kernel ring through the
   stream, the reassembler, and the consumer
10. **Idle timeouts and eviction** — config knobs and defaults
11. **Multiple subscribers** — the `tokio::sync::broadcast` recipe
12. **Performance notes** — flow lookup cost, hash function choice,
    tuning `max_flows` and `initial_capacity`
13. **Limitations** — explicitly: no TCP reassembly engine, no L7
    parsing, IPv6 fragmentation not supported (link to upstream
    etherparse issue)
14. **Source-agnosticism (pcap, tun-tap, embed)** — using
    `netring-flow` without `netring`

Each section has runnable code (in `examples/` where possible).
Length target: ~800 LOC of markdown including code blocks.

---

## `netring-flow/README.md` outline

Short README for the crates.io page (~100 LOC).

```
# netring-flow

Pluggable flow & session tracking for packet capture. Cross-platform,
runtime-free.

## What it is

[1-paragraph elevator pitch]

## What it isn't

- Not a packet capture library — pair with `netring` (Linux), `pcap`,
  `tun-tap`, or any source of `&[u8]` frames.
- Not a TCP reassembly engine — provides a `Reassembler` trait you
  plug `protolens` / `blatta-stream` / your own buffer into.
- Not a NetFlow/IPFIX collector — see `netgauze` for that.

## Quick start

[5–10 line example with pcap input]

## Async usage

When pairing with `netring` and tokio, see [the netring docs] for
`AsyncCapture::flow_stream(...)`.

## Features

- `extractors` (default) — built-in 5-tuple, IpPair, MacPair, VLAN,
  MPLS, VXLAN, GTP-U combinators; pulls `etherparse`.
- `tracker` (default) — `FlowTracker<E, S>` with TCP state machine.
- `reassembler` (default) — `Reassembler` trait + `BufferedReassembler`.

Disable defaults to get only the bare types (`Timestamp`,
`PacketView`, `Extracted`, `FlowExtractor` trait) — useful for
embedded / no-runtime contexts where you implement everything
yourself.

## License

MIT OR Apache-2.0.
```

---

## Implementation steps

1. **Write `netring-flow/docs/FLOW_GUIDE.md`** following the outline
   above. Aim for ~800 LOC. Every code block must compile (use
   `# fn main() { ... }` doctest preludes or `,no_run`).
2. **Write `netring-flow/README.md`.**
3. **Update workspace `README.md`** (and `netring/README.md` if it
   diverges) to:
   - Add a "Flow tracking" section that links to FLOW_GUIDE.md.
   - Update the feature matrix to show the new `flow` feature.
   - Add a code snippet showing the headline `flow_stream`.
4. **Consolidate CHANGELOG.**
   - Open `CHANGELOG.md`. Move all `0.7.0-alpha.*` entries under a
     single `## [0.7.0] - YYYY-MM-DD` heading.
   - Same for `netring-flow` — the alphas were git-only, but
     publish-time should still have a coherent 0.1.0 entry.
   - Format: standard "Added / Changed / Removed / Fixed" sections.
5. **Audit existing docs.**
   - `docs/ASYNC_GUIDE.md`: cross-reference to `FLOW_GUIDE.md`.
   - `docs/ARCHITECTURE.md` (if it exists): mention the workspace
     split + `netring-flow`.
   - `docs/TUNING.md`: add a "Flow tracking" subsection (max_flows,
     hash function, sweep interval).
6. **Bump versions to non-alpha.**
   - `netring/Cargo.toml`: `version = "0.7.0"`.
   - `netring-flow/Cargo.toml`: `version = "0.1.0"`.
   - `netring/Cargo.toml`: `netring-flow = { version = "0.1", path = "../netring-flow", default-features = false }`
     (keep `path` for workspace, but the `version` should match what
     we're about to publish).
7. **Pre-publish checklist.**
   - `cargo build --workspace --all-features` succeeds.
   - `cargo test --workspace --all-features` passes.
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
   - `cargo doc --workspace --all-features --no-deps` builds without
     warnings; spot-check rustdoc output.
   - `cargo publish -p netring-flow --dry-run` succeeds.
   - `cargo publish -p netring --dry-run` succeeds.
   - `cargo deny check licenses` passes for both crates.
   - `cargo machete` reports no unused deps.
   - All examples build under their declared `required-features`.
8. **Commit + tag.**
   - Commit: `0.7.0: flow tracking — pluggable extractors, tracker, reassembler hooks`
   - Tag: `0.7.0` (no `v` prefix).
9. **Publish.**
   - **Order matters**: publish `netring-flow` *first* because
     `netring` depends on it.
   - `cargo publish -p netring-flow`
   - Wait for crates.io to index (usually <1 min; verify via
     `cargo search netring-flow`).
   - `cargo publish -p netring`
   - Verify `https://crates.io/crates/netring-flow/0.1.0` and
     `https://crates.io/crates/netring/0.7.0` exist and have the
     right metadata.
10. **Push tag + create GitHub release.**
    - `git push origin 0.7.0`
    - `gh release create 0.7.0 -F .github/release-notes-0.7.0.md`
      (release notes = the `## [0.7.0]` section of CHANGELOG).
11. **Post-release housekeeping.**
    - Add `## [Unreleased]` heading at the top of CHANGELOG.
    - Bump versions to `0.7.1-pre` / `0.1.1-pre` on master (so
      git users don't accidentally pick up a published version).
    - Update `plans/INDEX.md` Status column for plans 00–04 to
      "Done".
    - Open follow-up issues for any v2 items (manual sweep, async
      state init, additional extractors).

---

## Tests

This phase doesn't add tests, just verifies the existing suite
holds across the workspace at non-alpha versions.

- `cargo test --workspace --all-features --release` passes (the
  release flag catches any debug-only assumptions).
- `cargo test --doc --workspace --all-features` passes (every
  doctest in the new FLOW_GUIDE compiles).
- One human runs `just flow-summary lo` and sees flows.
- One human runs `cargo run -p netring-flow --example pcap_flow_summary -- tests/data/sample-tcp.pcap`
  and sees flows.

---

## Acceptance criteria

- [ ] `netring-flow/docs/FLOW_GUIDE.md` exists, ~800 LOC, all
      examples compile.
- [ ] `netring-flow/README.md` exists.
- [ ] Workspace README has a "Flow tracking" section.
- [ ] CHANGELOG has consolidated 0.7.0 entry (and 0.1.0 for
      netring-flow).
- [ ] `cargo publish --dry-run` succeeds for both crates.
- [ ] `cargo deny check licenses` passes.
- [ ] `cargo machete` clean.
- [ ] Versions bumped to `0.7.0` / `0.1.0`.
- [ ] Both crates published to crates.io.
- [ ] Tag `0.7.0` pushed; GitHub release created with notes.
- [ ] Master bumped to `0.7.1-pre` / `0.1.1-pre`.
- [ ] `plans/INDEX.md` updated.

---

## Risks

1. **`cargo publish` race.** `netring-flow` must finish indexing
   before `netring` can publish (otherwise `netring`'s dep can't
   resolve). Add a verification step: `cargo search netring-flow`
   shows 0.1.0 before running `cargo publish -p netring`.
2. **README discrepancies.** Workspace root README and
   `netring/README.md` may diverge. **Decision**: have one canonical
   README at workspace root; `netring/README.md` is a symlink or a
   short pointer; `netring-flow/README.md` is its own short crate-level
   doc.
3. **License files.** Each crate published to crates.io needs
   LICENSE files locally. Verify both `netring/` and `netring-flow/`
   either contain `LICENSE-MIT` / `LICENSE-APACHE` files or use
   `license-file` in Cargo.toml pointing to the workspace root.
   Cargo will validate during `publish --dry-run`.
4. **`docs.rs` builds.** Both crates need
   `[package.metadata.docs.rs]` set so all-features builds correctly.
   Verify by `cargo doc --workspace --all-features --no-deps`.
5. **Symbol visibility regressions.** During alpha, types may have
   moved between `pub` and `pub(crate)`. Rustdoc output is the best
   audit; review the published API once.
6. **Backwards-compat with 0.6.0.** Anyone who imported
   `netring::Timestamp` directly is fine (re-export). Anyone who
   imported from `netring::packet::Timestamp` (deep path) may break.
   Deep paths weren't documented as stable; OK to break, but mention
   in CHANGELOG → "Changed".
7. **`netring-flow` first-time crate.io presence.** Reserve the name
   on crates.io ahead of publish (manual step) to avoid name squatting.
   Actually — `cargo publish` reserves the name on first push; just
   make sure the name isn't taken. Check `https://crates.io/crates/netring-flow`
   before tagging 0.1.0.
8. **CI matrix needs updating to test the published versions.** After
   publish, CI should still build from path deps (in workspace),
   but consider adding a job that builds a downstream crate using
   the crates.io versions to catch publishing-only issues.

---

## Effort

- LOC: ~50 (Cargo bumps, version coordination).
- Markdown: ~1000 LOC (FLOW_GUIDE + README + CHANGELOG).
- Time: 1 day. Most of that is docs writing + careful pre-publish
  checking.

---

## Out-of-band: dedup integration

If [plan 10](./10-dedup.md) ships in 0.7.0 alongside flow, this plan
also coordinates the dedup CHANGELOG entry and FLOW_GUIDE
cross-reference (since dedup composes well with flow tracking on
loopback captures).
