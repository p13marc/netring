# Plan 13 — flowscope 0.2 dependency bump

## Summary

Bump netring's `flowscope` dep from `"0.1"` to `"0.2"`, handle the four
breaking changes inside `netring/src/async_adapters/`, propagate the
new `FlowEvent::Anomaly` variant through the session/datagram streams,
and re-export the new public types (`OverflowPolicy`, `AnomalyKind`,
`FlowSessionDriver`) so downstream users don't need to import flowscope
directly.

This is the netring-side blocker for the `des-rs` live-capture rewrite
(see `plans/feedback-from-des-rs-2026-05-09.md`, item F1).

## Status

Done — landed in 0.9.0.

## Prerequisites

- flowscope 0.2.0 published (already done — local source confirms;
  awaiting crates.io publish if this lands before that).

## Out of scope

- New tracker-config plumbing through `session_stream` /
  `datagram_stream` — that's plan 14.
- A new `loopback_exact()` mode for `Dedup` — plan 15 covers the
  verification test only.
- Surfacing `FlowEvent::Anomaly` as anything richer than a passthrough
  in `FlowStream` — already passthrough by construction. Session/
  datagram streams need a deliberate choice (see step 4 below).

---

## Audit findings (2026-05-09)

Done up-front so the work below is mechanical:

1. **`event.key()` callsites in netring/src/**: zero. Every read of a
   flow key uses pattern matching (`FlowEvent::Started { key, .. }`).
   The `&K` → `Option<&K>` widening is invisible to netring's source.
   Flag in CHANGELOG for downstream callers anyway.

2. **`match` blocks over `EndReason`** that don't yet handle
   `BufferOverflow`:
   - `netring/src/async_adapters/flow_stream.rs:325-328`
   - `netring/src/async_adapters/session_stream.rs:194-217`

   `conversation.rs` writes `EndReason` in literals (`Some(EndReason::Fin)`,
   etc.) but does not pattern-match exhaustively over the enum, so it's
   not affected by the new variant.

3. **Struct literals** of `FlowTrackerConfig {}`, `FlowStats {}`,
   `AnomalyKind {}`, `OverflowPolicy {}` in `netring/src/`: zero. The
   `#[non_exhaustive]` change is a no-op for netring.

4. **`FlowEvent::Anomaly`** is not yet matched anywhere in netring.
   `FlowStream` passes events through by value, so `Anomaly` propagates
   for free. `SessionStream::convert_event` (`session_stream.rs:178-225`)
   has a wildcard `_ =>` that will silently drop `Anomaly`. Same for
   `DatagramStream` (`datagram_stream.rs`'s analogous path).

---

## Files

### MODIFY

```
netring/Cargo.toml                                  (workspace)
netring/netring/Cargo.toml                          (member)
netring/netring/src/lib.rs                          (re-exports)
netring/netring/src/async_adapters/flow_stream.rs   (EndReason arm)
netring/netring/src/async_adapters/session_stream.rs (EndReason + Anomaly)
netring/netring/src/async_adapters/datagram_stream.rs (Anomaly)
netring/CHANGELOG.md                                (release notes)
```

### NEW

```
netring/netring/tests/anomaly_passthrough.rs        (integration test)
```

No new modules.

---

## API delta

Two passthroughs and one re-export expansion. No netring-defined types
added.

### Re-exports (netring/src/lib.rs)

Under the existing `feature = "flow"` gate, expand the flowscope
re-export block to include:

```rust
pub use flowscope::{
    AnomalyKind,
    FlowSessionDriver,
    OverflowPolicy,
    // …existing re-exports…
};
```

`FlowSessionDriver` is sync; including it in netring's surface gives
users a discoverable name for the sync mirror of `SessionStream`.

### Behavior change

`SessionStream::Item` and `DatagramStream::Item` already use
`flowscope::SessionEvent`. flowscope 0.2.0's `SessionEvent` does NOT
gain an `Anomaly` variant — confirmed by reading
`/home/mpardo/git/flowscope/src/session.rs`. So we can't pass
`FlowEvent::Anomaly` through the session API as a typed variant.

**Decision**: surface anomalies as a side-channel via tracing. In
`session_stream::convert_event` and the corresponding datagram path,
add an explicit `FlowEvent::Anomaly { key, kind, ts } => { tracing::warn!(...) }`
arm. That preserves the wildcard's "we don't surface this as a
SessionEvent" semantic but stops it being silent. If downstream users
want the structured event, they can use `FlowStream` directly and
chain `.session_stream(...)` only after handling anomalies.

(Alternative considered: change `SessionStream::Item` to a netring-
defined enum that wraps `SessionEvent` plus `Anomaly`. Rejected as a
larger API churn for des-rs's actual use case, which is to detect
buffer overflow via `EndReason::BufferOverflow` on `Closed`.)

---

## Implementation steps

1. **Bump dep version**.
   - `netring/Cargo.toml` line 26 (the comment in workspace Cargo.toml
     refers to it; the actual pin lives in `netring/netring/Cargo.toml`):
     `flowscope = { version = "0.2", default-features = false }`.
   - `cargo check --all-features` from `netring/`. Expect failures
     in two `match` blocks; everything else compiles.

2. **Patch `flow_stream.rs` EndReason match (line 325-328)**:

   ```rust
   let fut = match reason_copy {
       EndReason::Fin | EndReason::IdleTimeout => r.fin(),
       EndReason::Rst | EndReason::Evicted | EndReason::BufferOverflow => r.rst(),
   };
   ```

   `BufferOverflow` is treated as `Rst` because the per-side
   reassembler is poisoned — the cleanest cleanup is to drop pending
   bytes, which is what `rst()` does.

3. **Patch `session_stream.rs::convert_event` (line 178-225)**:

   ```rust
   match ev {
       FlowEvent::Started { key, ts, .. } => { … }
       FlowEvent::Ended { key, reason, stats, .. } => {
           if let Some(mut parser) = parsers.remove(&key) {
               match reason {
                   EndReason::Fin | EndReason::IdleTimeout => {
                       // emit fin_initiator/fin_responder messages …
                   }
                   EndReason::Rst | EndReason::Evicted | EndReason::BufferOverflow => {
                       parser.rst_initiator();
                       parser.rst_responder();
                   }
               }
           }
           pending.push_back(SessionEvent::Closed { key, reason, stats });
       }
       FlowEvent::Anomaly { key, kind, ts } => {
           tracing::warn!(
               target: "netring::flow",
               ?key, ?kind, ?ts,
               "flow tracker anomaly (use FlowStream for structured handling)"
           );
       }
       _ => {}
   }
   ```

   The `Closed` event's `reason` field is `EndReason::BufferOverflow`
   when applicable, so downstream consumers who care can check it.

4. **Patch `datagram_stream.rs`** with the same `Anomaly` arm. Same
   `tracing::warn!` shape.

5. **Update `lib.rs`** re-exports under the `flow` feature gate.
   Search for the existing `pub use flowscope::{…FlowDriver…};` block
   (around lines 88-98) and add the three new names alphabetically
   (`AnomalyKind`, `FlowSessionDriver`, `OverflowPolicy`).

6. **Add CHANGELOG entry** under a new `## 0.9.0 — flowscope 0.2 + …`
   section. Call out:
   - flowscope dep bumped from 0.1 to 0.2 (semver-major reason: see below).
   - **Breaking** for downstream callers who took `&K` from
     `FlowEvent::key()`: the return type is now `Option<&K>`. netring's
     own internals are unaffected because they pattern-match. Anyone
     calling `event.key()` on a re-exported `FlowEvent` will need to
     `.expect("non-anomaly")` or pattern-match.
   - **Breaking** for downstream code that exhaustively matched
     `EndReason`: a new `BufferOverflow` variant exists.
   - New re-exports: `AnomalyKind`, `FlowSessionDriver`, `OverflowPolicy`.
   - Behavior: `Anomaly` events are now warned via `tracing` from
     `SessionStream` and `DatagramStream`. Use `FlowStream` directly
     for structured access.

7. **Run `just ci`**. Specifically `cargo clippy --all-features
   --tests` to catch any auto-derive that breaks under
   `#[non_exhaustive]` (e.g., `..Default::default()` on a remote-
   defined struct in tests). Fix with `..Default::default()` if so.

---

## Tests

### New: `netring/tests/anomaly_passthrough.rs`

Integration test (no privilege required — uses a synthetic packet
source) that:

1. Builds a `FlowStream` over a pcap of TCP traffic with a deliberately
   tiny `max_reassembler_buffer` and `OverflowPolicy::DropFlow`.
2. Feeds enough out-of-order segments to overflow.
3. Asserts that:
   - At least one `FlowEvent::Anomaly { kind: AnomalyKind::BufferOverflow, .. }`
     is yielded by the `FlowStream`.
   - The corresponding `FlowEvent::Ended { reason: EndReason::BufferOverflow, .. }`
     follows.
4. Repeats the same source through `SessionStream` and asserts
   `SessionEvent::Closed { reason: EndReason::BufferOverflow, .. }` is
   yielded (since `Anomaly` is dropped from `SessionStream`'s typed
   surface, but the `Closed` reason is still honest).

The fixture can be assembled in-process via flowscope's
`PcapFlowSource` for offline replay, or by feeding hand-rolled
`PacketView` values directly into a custom `PacketSource`. Prefer the
latter to avoid pulling `flowscope/pcap` into netring's dev-deps.

### Modified: existing tests

The two TCP-stream integration tests in `netring/tests/` that exercise
flow events should be cargo-checked but no logic changes are expected
unless one of them does an exhaustive `match` over `EndReason`. Quick
grep: none do, as of HEAD.

---

## Acceptance criteria

- [ ] `cargo check --all-features` passes from clean.
- [ ] `cargo clippy --all-features --tests -- -D warnings` passes.
- [ ] `cargo test --all-features` passes (including the new
      `anomaly_passthrough.rs`).
- [ ] `just ci-full` passes on a host with `setcap` permissions.
- [ ] CHANGELOG entry calls out the two downstream-visible breaking
      changes (`FlowEvent::key()` → `Option<&K>` and the new
      `EndReason::BufferOverflow` variant).
- [ ] `cargo doc --all-features` builds clean (no missing-docs lint
      regressions on the new re-exports — flowscope's docstrings carry
      through).

---

## Risks

- **flowscope 0.2 not yet on crates.io**: netring's pre-publish
  checklist (`netring/CLAUDE.md` Pre-publish section) already calls out
  the same dependency on flowscope being published. Same prerequisite
  applies here. If we land this plan before flowscope 0.2 is on
  crates.io, netring's `Cargo.toml` will need a `git = "…", tag = "v0.2.0"`
  override that gets swapped to a version dep at netring publish time.

- **Downstream `event.key()` callers**: external code that took `&K`
  from a netring-re-exported `FlowEvent` will not compile. We can't
  prevent this; CHANGELOG flag is the mitigation.

- **Anomaly-as-tracing decision**: if des-rs (or another user) needs
  structured `Anomaly` access from inside `SessionStream`, we'll have
  to revisit and add a typed surface. The `FlowStream` path covers it
  today; deferring until demand is the right call.

---

## Effort

- Code: ~25 LoC (4 match arms + 3 re-exports + tracing calls).
- Test: ~120 LoC for `anomaly_passthrough.rs`.
- CHANGELOG: ~20 lines.
- **Estimate**: half a day end-to-end. Same ballpark as the feedback
  document predicted, but the breakdown shifts: less fix-up code than
  feared, more time on the integration test.
