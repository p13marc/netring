# Plan 14 — config-aware session/datagram streams

## Summary

Fix a silent-config-loss bug in `FlowStream::session_stream` and
`FlowStream::datagram_stream`, then add explicit
`SessionStream::with_config` / `DatagramStream::with_config` builder
methods. After this plan, the documented chain

```rust
cap.flow_stream(extractor)
   .with_config(cfg)
   .session_stream(parser_factory)
```

actually carries `cfg` through to the session-level `FlowTracker`.
This is the netring-side enabler for des-rs's live-capture rewrite
to consolidate its hand-rolled `tcp_stream.rs` reassembler limits
onto flowscope 0.2's `max_reassembler_buffer` /
`OverflowPolicy::DropFlow` (see
`plans/feedback-from-des-rs-2026-05-09.md`, item F2).

## Status

Done — landed in 0.9.0.

## Prerequisites

- [Plan 13](./13-flowscope-0.2-bump.md) — flowscope 0.2's
  `FlowTrackerConfig::max_reassembler_buffer` and `overflow_policy`
  fields are what `with_config` is gated on. Without flowscope 0.2,
  this plan exposes nothing new.

## Out of scope

- A `flow_stream_with_config(extractor, config)` shortcut on
  `AsyncCapture`. Considered and rejected: the existing
  `.flow_stream(ext).with_config(cfg)` chain is one extra method call,
  and adding the shortcut duplicates surface for a marginal ergonomic
  win. The feedback document offered it as one of two equivalent
  shapes; we pick the chained one.

- Any changes to `FlowStream::with_config` itself. Already exists at
  `flow_stream.rs:195` and works correctly.

- Builder support for the `BufferedReassembler` factory used by
  `with_async_reassembler`. flowscope 0.2's overflow policy applies to
  the *flowscope* default reassembler (used by `FlowTracker` internally
  for `track_with_payload`), not the netring `AsyncReassembler` trait.
  Netring's async reassembler users implement their own buffer
  semantics. Out of scope.

---

## The bug

`netring/src/async_adapters/flow_stream.rs:159-182`:

```rust
pub fn session_stream<F>(self, factory: F) -> SessionStream<S, E, F>
where F: SessionParserFactory<E::Key>,
{
    let extractor = self.tracker.into_extractor();
    SessionStream::new(self.cap, extractor, factory)
}
```

`session_stream` consumes the whole `FlowStream`, throws away the
`FlowTracker` (and its config) via `into_extractor`, then constructs
a new `FlowTracker` with default config inside `SessionStream::new`.
Same shape in `datagram_stream`.

So today:

```rust
cap.flow_stream(ext)
   .with_config(cfg)        // applies to the FlowStream's tracker
   .session_stream(parser)  // discards that tracker; new default config
```

is equivalent to

```rust
cap.flow_stream(ext).session_stream(parser)
```

— and the user's `cfg` (including the buffer cap and overflow policy)
is silently lost.

This bug is invisible today because flowscope 0.1's `FlowTrackerConfig`
has no fields the user would notice losing — `idle_timeout_*` and
`max_flows` were the only knobs, and most users default-accept them.
flowscope 0.2's two new fields (`max_reassembler_buffer`,
`overflow_policy`) are ones every `des-rs`-shaped user wants
non-default. Hence the fix needed now.

---

## Files

### MODIFY

```
netring/netring/src/async_adapters/flow_stream.rs
netring/netring/src/async_adapters/session_stream.rs
netring/netring/src/async_adapters/datagram_stream.rs
netring/CHANGELOG.md
```

### NEW

```
netring/netring/tests/session_stream_config.rs
```

No new modules.

---

## API delta

### `SessionStream` and `DatagramStream` both gain `with_config`

```rust
impl<S, E, F> SessionStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    /// Replace the inner [`FlowTracker`]'s config.
    ///
    /// Mirrors [`FlowStream::with_config`]. Use this to set the
    /// reassembler buffer cap and overflow policy for the session
    /// path. Re-arms the sweep timer if `sweep_interval` changed.
    pub fn with_config(mut self, config: FlowTrackerConfig) -> Self {
        let new_interval = config.sweep_interval;
        self.tracker.set_config(config);
        self.sweep = tokio::time::interval(new_interval);
        self
    }
}
```

Same shape on `DatagramStream`. The implementation is one of these
per file plus a `flowscope::FlowTrackerConfig` import.

### Internal change to `FlowStream::session_stream` / `datagram_stream`

They start propagating the tracker config:

```rust
pub fn session_stream<F>(self, factory: F) -> SessionStream<S, E, F>
where F: SessionParserFactory<E::Key>,
{
    let config = self.tracker.config().clone();   // NEW
    let extractor = self.tracker.into_extractor();
    SessionStream::new_with_config(self.cap, extractor, factory, config)
}
```

`SessionStream::new_with_config` is the new private constructor;
`new` becomes a thin wrapper over it that passes
`FlowTrackerConfig::default()`. Same for `DatagramStream`.

This keeps the public `pub(crate) fn new` shape unchanged for any
internal call sites we missed.

### No new public types, no new public free functions.

---

## Implementation steps

1. **`session_stream.rs`**: split `pub(crate) fn new` into a
   `new_with_config` taking an explicit `FlowTrackerConfig`, and have
   `new` delegate to it with `FlowTrackerConfig::default()`. Use
   `FlowTracker::with_config(extractor, config)` (the flowscope sync
   API; check exact name in flowscope 0.2 — likely
   `FlowTracker::with_config` or `FlowTracker::new(...).with_config(...)`).

2. **Same in `datagram_stream.rs`**.

3. **`flow_stream.rs::session_stream`**: pull the config out of the
   tracker before calling `into_extractor`, pass to
   `SessionStream::new_with_config`.

4. **Same for `flow_stream.rs::datagram_stream`**.

5. **Add `with_config` builder method** to both `SessionStream` and
   `DatagramStream`. Exact signature in the API delta above.

6. **Verify** by reading the doc on `FlowStream::with_config` (line
   195) — port the relevant phrasing into the new method docstrings,
   adapted for "the inner tracker that drives session/datagram parsing."

7. **CHANGELOG entry** under the same 0.9.0 section as plan 13. Call
   it a fix, not a feature: "`FlowStream::with_config` now correctly
   propagates through `session_stream` and `datagram_stream`."

---

## Tests

### New: `netring/tests/session_stream_config.rs`

Two assertions, no privilege required:

1. **Config propagation through `flow_stream → session_stream`**.
   - Build a `FlowStream` with `with_config(cfg)` where
     `cfg.max_reassembler_buffer = Some(1)` (deliberately tiny).
   - Convert to `SessionStream` via `.session_stream(...)`.
   - Inspect `session_stream.tracker().config().max_reassembler_buffer`
     and assert it equals `Some(1)`.

2. **Direct `with_config` on `SessionStream`**.
   - Build a `SessionStream` via `.session_stream(...)` (default config).
   - Call `.with_config(cfg)` with a custom config.
   - Assert the same field.

Each test is ~30 LoC. Can use a stub `SessionParser` that returns no
messages — we only care about config plumbing, not parsing.

A symmetric test for `DatagramStream` belongs in the same file (or a
sibling `datagram_stream_config.rs`).

### Existing tests

Should pass unchanged. Quick scan: no test today exercises
`session_stream + with_config`.

---

## Acceptance criteria

- [ ] `SessionStream::with_config(cfg)` and
      `DatagramStream::with_config(cfg)` exist and update the inner
      tracker's config (verified by `tracker().config()`).
- [ ] `FlowStream::with_config(cfg).session_stream(...)` propagates
      `cfg` to the resulting `SessionStream`'s tracker (this is the
      bug fix; covered by the new test).
- [ ] Same for `datagram_stream`.
- [ ] `cargo test --all-features` passes including the new tests.
- [ ] `cargo doc --all-features` builds clean.
- [ ] CHANGELOG mentions both the bug fix and the new builder methods.

---

## Risks

- **`FlowTracker::with_config` signature mismatch in flowscope 0.2**.
  This plan assumes flowscope's `FlowTracker` exposes a way to
  construct with an explicit config. If the only path is
  `FlowTracker::new(extractor)` followed by `.set_config(config)`,
  do that — same end state, one extra line.

- **`FlowTrackerConfig: Clone`?** flowscope 0.1's config was `Clone`.
  flowscope 0.2's likely is too (the `#[non_exhaustive]` attribute
  doesn't block deriving `Clone`). If for some reason it's not, the
  `.clone()` in step 3 needs replacing with explicit field copy.
  Confirm at implementation time.

- **`with_config` on a stream mid-flow**. Today's `FlowStream::with_config`
  re-arms the sweep timer but does *not* re-init the tracker's flow
  table. Same semantics for the new methods. If a user calls
  `with_config` after packets have been processed, only future packets
  see the new config — existing flow entries keep their original
  buffer caps. This is the same caveat as `FlowStream::with_config`
  today; document but don't fix.

---

## Effort

- Code: ~30 LoC (1 split + 1 builder method × 2 files + plumbing).
- Test: ~80 LoC.
- CHANGELOG: 5 lines.
- **Estimate**: 1.5 hours, dominated by writing the propagation test.
  Faster than the feedback document's 1-hour estimate for F2 because
  the existing `FlowStream::with_config` does most of the work.
