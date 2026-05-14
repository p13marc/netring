# Plan 19 — flowscope 0.3 dependency bump + new builder knobs

## Summary

Bump `flowscope` from `"0.2"` to `"0.3"` in `netring/netring/Cargo.toml`,
handle the two `#[non_exhaustive]` enum additions (`EndReason::ParseError`,
`SessionEvent::Anomaly`), and pull through the new flowscope builder
knobs onto netring's async stream surfaces (`FlowStream`,
`SessionStream`, `DatagramStream`):

- **Per-key idle timeouts** — `with_idle_timeout_fn(F)`.
- **Monotonic timestamps** — `with_monotonic_timestamps(bool)`.
- **Live flow-stats snapshot** — `snapshot_flow_stats()`.
- **Structured anomaly forwarding** — replaces the current
  `tracing::warn!` side-channel with a typed
  `SessionEvent::Anomaly` arm on the session/datagram surfaces.
- **Reassembler high-watermark** — already on `FlowStats`; rides
  through the existing `Ended` carrier for free, but we document
  the new fields.

Backward-incompatible changes are explicitly allowed. We use that
freedom to:

- Replace the current "silently warn-and-drop" anomaly behaviour on
  `SessionStream` / `DatagramStream` with structured forwarding.
- Drop the `Message: Send + 'static` bound on netring-defined parser
  trait shims if any exist (none today, but worth checking).
- Bump netring's minor version to **0.12.0** (semver-major reason:
  new `SessionEvent` variant + `EndReason` variant on a re-exported
  enum).

This is the netring-side complement to flowscope's "production
hardening" 0.3.0 release ([`flowscope/CHANGELOG.md`](../../flowscope/CHANGELOG.md)).
Direct upstream motivation: `des-rs` and similar consumers asked for
per-protocol idle-timeout control, monotonic timestamps for log
correlation, and a single-source-of-truth anomaly stream.

## Status

✅ Done — landed in 0.12.0.

## Prerequisites

- ✅ flowscope 0.3.0 published on crates.io (confirmed via
  `cargo search flowscope`).
- ✅ netring 0.11.0 shipped (this is the next minor).

## Out of scope

- **`flowscope::Dedup` adoption.** netring has its own `Dedup`
  (`src/dedup.rs`) at the `Packet`/byte layer with the same
  content-hash / window semantics. Two parallel implementations is
  acceptable; flowscope's is for non-netring sync consumers.
- **`track_pending` / `sweep_pending` / `finalize` exposure.** These
  are advanced sync hooks for callers who need to inspect
  reassemblers mid-tick. netring's async surface has no use case
  yet — revisit when one appears.
- **`FlowDatagramDriver` re-export.** Sync mirror of our async
  `datagram_stream`; not relevant to netring's async-first surface.
  Already discoverable via `flowscope::FlowDatagramDriver` for
  users who want it.
- **`tracing-messages` sub-feature.** Could be added as a netring
  feature `flow-tracing-messages = ["flowscope/tracing-messages"]`
  but it's a debug knob — defer unless asked.

---

## Audit findings

Done up-front so the work below is mechanical:

1. **Exhaustive `match EndReason` blocks needing `ParseError`**:
   - `netring/src/async_adapters/flow_stream.rs:383-388`
   - `netring/src/async_adapters/session_stream.rs:366-388`

   In both, `BufferOverflow` is paired with `Rst | Evicted`. The
   same treatment applies to `ParseError` (parser is poisoned →
   `rst()` the side reassemblers).

2. **Exhaustive `match SessionEvent` blocks**: zero in
   `netring/src/`. netring constructs `SessionEvent::Started /
   Application / Closed` but does not pattern-match exhaustively
   over them. Tests likewise.

3. **`FlowEvent::Anomaly` handling today**:
   - `session_stream.rs:393` — `tracing::warn!`, drops the event.
   - `datagram_stream.rs:267` — same.
   - `flow_stream.rs` — passes through verbatim (no change needed).

   These two `tracing::warn!` arms become typed
   `SessionEvent::Anomaly` emissions in this plan.

4. **`SessionParser` / `DatagramParser` impls in netring**: none.
   The new `Debug` bound on `Message` is a downstream-only break,
   surfaced in our CHANGELOG.

5. **`Reassembler` trait impls in netring**: none. netring uses
   `BufferedReassembler` concretely and defines its own
   `AsyncReassembler` trait. The new `high_watermark()` default
   method on `flowscope::Reassembler` is invisible to netring.

6. **`FlowSessionDriver` / `FlowDriver` direct usage in netring**:
   none. The internal rewire (`FlowSessionDriver` now wraps
   `FlowDriver`) is transparent.

7. **Struct-literal construction of `FlowStats`** (which gained
   two `reassembler_high_watermark_*` fields): zero in
   `netring/src/`. The new fields ride for free through the
   existing `Ended { stats }` carrier.

---

## Files

### MODIFY

```
netring/netring/Cargo.toml                              (dep bump + version)
netring/netring/src/lib.rs                              (new re-exports)
netring/netring/src/async_adapters/flow_stream.rs       (EndReason arm + new builders)
netring/netring/src/async_adapters/session_stream.rs    (EndReason arm + Anomaly forwarding + new builders)
netring/netring/src/async_adapters/datagram_stream.rs   (Anomaly forwarding + new builders)
netring/netring/src/async_adapters/conversation.rs      (forward new builders if applicable)
netring/CHANGELOG.md                                    (release notes — 0.12.0)
netring/netring/CLAUDE.md                               (recent-additions section)
netring/netring/README.md                               (mention new knobs)
netring/plans/INDEX.md                                  (mark plan 19 done)
```

### NEW

```
netring/netring/examples/async_flow_idle_per_key.rs     (Phase D demo)
netring/netring/tests/flowscope_03_passthrough.rs       (integration test)
```

### DELETE

None.

---

## API delta

### SessionEvent forwarding (BREAKING)

`SessionStream` / `DatagramStream` `Item` type stays
`flowscope::SessionEvent<K, M>`. flowscope 0.3.0 adds an
`Anomaly { key, side, kind, ts }` variant to `SessionEvent`. We
forward `FlowEvent::Anomaly` → `SessionEvent::Anomaly` instead of
the current `tracing::warn!` drop.

Migration for downstream:

```diff
 while let Some(evt) = stream.next().await {
     match evt? {
         SessionEvent::Started { .. } => …,
         SessionEvent::Application { .. } => …,
         SessionEvent::Closed { .. } => …,
+        SessionEvent::Anomaly { .. } => …,  // new in netring 0.12.0
+        _ => …,                              // forward-compatible
     }
 }
```

Existing wildcard-bearing `match` blocks remain valid; consumers
who exhaustively matched will need a new arm.

### EndReason forwarding

`flowscope::EndReason` is re-exported. New variant `ParseError`
appears on `SessionEvent::Closed { reason }`. Downstream consumers
matching exhaustively need a new arm. Internal netring code treats
`ParseError` like `Rst` (poisoned parser → reassembler `rst()`).

### New builder methods on `FlowStream`

```rust
impl<S, E, U, R> FlowStream<S, E, U, R> {
    /// Override the per-flow idle timeout via a key predicate.
    /// Returning `None` falls back to the protocol-default timeout
    /// from `FlowTrackerConfig`.
    pub fn with_idle_timeout_fn<F>(self, f: F) -> Self
    where F: Fn(&E::Key) -> Option<Duration> + Send + 'static;

    /// Enable monotonic timestamp clamping: each timestamp is at
    /// least the previous one, even if the NIC reports a step-back.
    pub fn with_monotonic_timestamps(self, enable: bool) -> Self;

    /// Borrow-iterator over live `(K, FlowStats)` pairs. Reassembler
    /// high-watermark and end-of-flow diagnostics are included.
    /// Lazy: `.take(1)` / `.filter()` consumers pay nothing for the rest.
    pub fn snapshot_flow_stats(&self)
        -> impl Iterator<Item = (E::Key, FlowStats)> + '_;
}
```

Same three methods on `SessionStream` and `DatagramStream`. The
methods delegate to the underlying `FlowTracker` configuration.

### Re-exports (`netring/src/lib.rs`)

Add under the existing `flow` feature gate:

```rust
pub use flowscope::IdleTimeoutFn;
// FlowStats's new fields (reassembler_high_watermark_initiator /
// _responder) ride through the existing FlowStats re-export — no
// new symbol needed.
```

Optional convenience (debate): re-export
`flowscope::extract::FiveTupleKey::either_port` already via the
`extract::*` glob. No-op.

---

## Implementation steps

### Phase A — version bump + EndReason::ParseError

1. **Bump dep version** in `netring/netring/Cargo.toml`:

   ```toml
   flowscope = { version = "0.3", default-features = false }
   ```

   `cargo check --features tokio,flow,parse,pcap,metrics` — expect
   exhaustive-match failures in two sites.

2. **Patch `flow_stream.rs:383-388`** — add `ParseError` to the
   `Rst` group:

   ```rust
   let fut = match reason_copy {
       EndReason::Fin | EndReason::IdleTimeout => r.fin(),
       EndReason::Rst
       | EndReason::Evicted
       | EndReason::BufferOverflow
       | EndReason::ParseError => r.rst(),
       _ => r.rst(),  // forward-compatible
   };
   ```

   Note the wildcard arm: flowscope 0.3.0 onwards keeps
   `EndReason` `#[non_exhaustive]`, so future variants need a
   default. `rst()` is the safe failure mode (drop pending bytes).

3. **Patch `session_stream.rs:366-388`** — same treatment for the
   parser cleanup match. `ParseError` triggers `rst_initiator()` +
   `rst_responder()`.

4. **Confirm `cargo check` passes**; lib tests still pass.

### Phase B — typed Anomaly forwarding (BREAKING)

5. **Replace `session_stream.rs:393` `tracing::warn!` arm** with:

   ```rust
   FlowEvent::Anomaly { key, kind, ts } => {
       pending.push_back(SessionEvent::Anomaly {
           key,
           kind,
           ts,
       });
   }
   ```

   Verify the `SessionEvent::Anomaly` variant shape against
   flowscope 0.3.0 (`flowscope/src/session.rs`). May include a
   `side: Option<FlowSide>` field; adjust accordingly.

6. **Replace `datagram_stream.rs:267` `tracing::warn!` arm** with
   the same forwarding shape.

7. **Update the existing unit test in `session_stream.rs:646`**
   that asserts the tracing warn happens — change to assert the
   typed `SessionEvent::Anomaly` emission instead.

### Phase C — new builder methods

8. **Audit `FlowTracker` plumbing in `flow_stream.rs`**: confirm
   the inner tracker is mutable and exposes
   `set_idle_timeout_fn` / `with_monotonic_timestamps` accessors
   (per flowscope 0.3.0 `tracker.rs`). Both flowscope APIs are
   on `FlowTracker` itself (not just `FlowDriver`), so netring's
   thin wrapper can forward directly.

9. **Add `FlowStream::with_idle_timeout_fn(F)`**:

   ```rust
   pub fn with_idle_timeout_fn<F>(mut self, f: F) -> Self
   where
       F: Fn(&E::Key) -> Option<Duration> + Send + 'static,
   {
       self.tracker.set_idle_timeout_fn(f);
       self
   }
   ```

   If `FlowTracker` is stored behind a lock or builder buffer,
   adapt to whatever the current shape is. Sibling
   `with_config` already does similar plumbing.

10. **Add `FlowStream::with_monotonic_timestamps(bool)`**.

11. **Mirror on `SessionStream` / `DatagramStream`** — they own
    their own `FlowTracker` via the bundled driver path. Each
    gets the same two builder methods, delegating internally.

12. **`FlowStream::snapshot_flow_stats()`** — return type
    `impl Iterator<Item = (E::Key, FlowStats)> + '_`. Delegates
    to `FlowTracker::all_flow_stats()` (flowscope 0.3.0).
    Mirror on the session/datagram surfaces.

### Phase D — example + tests + docs

13. **`examples/async_flow_idle_per_key.rs`** — minimal demo:

    ```rust
    let stream = AsyncCapture::open("eth0")?
        .flow_stream(FiveTuple::bidirectional())
        .with_idle_timeout_fn(|k| {
            // DNS gets 5s, everything else uses default.
            if k.either_port(53) {
                Some(Duration::from_secs(5))
            } else {
                None
            }
        })
        .with_monotonic_timestamps(true);
    while let Some(evt) = stream.next().await { … }
    ```

14. **`tests/flowscope_03_passthrough.rs`** — integration test
    (no privilege; synthetic packet source) covering:

    - A `SessionStream` over a tiny `max_reassembler_buffer` with
      `OverflowPolicy::DropFlow` yields
      `SessionEvent::Anomaly` followed by `SessionEvent::Closed
      { reason: EndReason::BufferOverflow, .. }`.
    - A `SessionStream` with a parser that returns
      `is_poisoned() == true` after the first segment yields
      `SessionEvent::Anomaly { kind: SessionParseError, .. }`
      followed by `SessionEvent::Closed { reason: ParseError, .. }`.
    - `FlowStream::with_idle_timeout_fn(|_| Some(Duration::from_millis(50)))`
      causes a synthetic idle flow to be reaped within ~50 ms.
    - `FlowStream::with_monotonic_timestamps(true)` clamps a
      manually-stepped-back timestamp to the running max.

    Use a hand-rolled `PacketSource` to avoid the
    `flowscope/pcap` dev-dep.

15. **Update `netring/src/lib.rs`** re-exports under
    `feature = "flow"`. Add `IdleTimeoutFn` alphabetically.

16. **Update `netring/CLAUDE.md`** under
    "Recent additions (0.12.0)" with a one-paragraph summary.

17. **Update `netring/README.md`** — add a one-line bullet under
    "Flow & session tracking" mentioning per-key idle timeouts
    and structured anomaly events.

18. **Update `netring/CHANGELOG.md`** — full release notes for
    0.12.0; see "Migration" subsection in §"CHANGELOG outline"
    below.

19. **Bump `netring/netring/Cargo.toml` version to `0.12.0`**.

20. **Update `plans/INDEX.md`** — mark plan 19 ✅ done, 0.12.0.

21. **Run `just ci`** (clippy + tests + docs + bench compile)
    across the relevant feature combos:
    `cargo clippy -p netring --features tokio,flow,parse,pcap,metrics,af-xdp,xdp-loader --all-targets -- -D warnings`
    `cargo test -p netring --features tokio,flow,parse,pcap,metrics`

---

## CHANGELOG outline

```markdown
## 0.12.0 — flowscope 0.3 + per-key idle timeouts + structured anomalies

Plan 19. Bumps `flowscope` from 0.2 to 0.3 and exposes the new
upstream knobs through netring's async stream surfaces.

### Breaking changes

- **`SessionEvent::Anomaly` is now forwarded** by `SessionStream`
  and `DatagramStream`. Previously these arms went to
  `tracing::warn!` and were dropped from the typed surface.
  Consumers matching `SessionEvent` exhaustively need a new arm.
- **`EndReason::ParseError`** is a new variant on the re-exported
  `flowscope::EndReason`. Exhaustive matches need an arm — treat
  like `Rst` (parser poisoned; reassembler is reset).
- **`SessionParser::Message` / `DatagramParser::Message` require
  `Debug`** (upstream change). Add `#[derive(Debug)]` to your
  message type. All flowscope-shipped parsers already do.

### New — per-key idle timeouts

`FlowStream::with_idle_timeout_fn(F)` and the same on
`SessionStream` / `DatagramStream`. Predicate returns
`Option<Duration>`; `None` falls back to the protocol default.

```rust
.flow_stream(FiveTuple::bidirectional())
.with_idle_timeout_fn(|k| {
    if k.either_port(53) { Some(Duration::from_secs(5)) } else { None }
})
```

### New — monotonic timestamps

`FlowStream::with_monotonic_timestamps(true)` clamps NIC-supplied
timestamps to a running max. Useful when downstream consumers want
a strictly non-decreasing timeline (log correlation, replay).

### New — `snapshot_flow_stats()` accessor

Borrow-iterator over `(K, FlowStats)` for live flows. Includes the
new reassembler high-watermark fields and end-of-flow diagnostics
patched in. Lazy; pays for what you consume.

### Other

- `FlowStats` now carries `reassembler_high_watermark_initiator`
  and `_responder` (set on `Ended` events). Free passthrough.
- New `tests/flowscope_03_passthrough.rs` integration test.
- New `examples/async_flow_idle_per_key.rs` demo.
```

---

## Acceptance criteria

- [ ] `cargo check -p netring --features tokio,flow,parse,pcap,metrics` clean.
- [ ] `cargo clippy -p netring --all-features --all-targets -- -D warnings` clean.
- [ ] `cargo test -p netring --features tokio,flow,parse,pcap,metrics` green (lib + integration + doctests).
- [ ] `cargo doc -p netring --no-deps --all-features` zero warnings.
- [ ] All four assertions in `tests/flowscope_03_passthrough.rs` pass.
- [ ] `examples/async_flow_idle_per_key.rs` compiles.
- [ ] Existing test in `session_stream.rs` (line 646 area) updated
      to assert `SessionEvent::Anomaly` instead of `tracing::warn!`.
- [ ] CHANGELOG, CLAUDE.md, README, plans/INDEX.md updated.
- [ ] `netring/Cargo.toml` version = `0.12.0`.

---

## Risks

- **`SessionEvent::Anomaly` field shape** may differ from
  `FlowEvent::Anomaly` (e.g. `side: Option<FlowSide>`). Confirm
  early in Phase B and adjust the forwarder.
- **`set_idle_timeout_fn` lifetime trickiness**: the closure must
  outlive the tracker. flowscope likely boxes it as
  `Box<dyn Fn>`; confirm and propagate the same bound from
  `FlowStream::with_idle_timeout_fn`.
- **Existing `session_stream.rs:646` test** depends on tracing
  output that we're about to remove. Will need updating to assert
  on the structured `SessionEvent::Anomaly` instead — easier and
  more honest, but a coordinated change.
- **`FlowStream::snapshot_flow_stats()` lifetime**: the returned
  iterator borrows `&self`. In an async context where the stream
  is being polled, this is fine — accessor is `&self`, no mutation.
- **Downstream consumers who match `SessionEvent` exhaustively**
  will need the new arm. This is the headline break for 0.12.0;
  call it out prominently in release notes and (post-publish) in
  a brief note to known integrators (des-rs, nlink-lab).
- **MSRV unchanged** (1.85). flowscope 0.3.0 advertises the same
  MSRV; confirm during the bump.

---

## Effort

- **Phase A** (mechanical bump + `ParseError` arms): ~30 min.
- **Phase B** (typed Anomaly forwarding + test update): ~1 hr.
- **Phase C** (three new builder methods × three streams): ~2 hr.
- **Phase D** (example + integration test + docs + CHANGELOG): ~2 hr.

Total: ~half a day of focused work. Bulk is in Phase C/D, mostly
plumbing and prose.

---

## Follow-ups (not in this plan)

- **`tracing-messages` feature passthrough** if user demand
  surfaces.
- **`FlowStream::with_dedup_pluggable`** to optionally substitute
  flowscope's `Dedup` for netring's. Currently netring's wins by
  default (operates at the `Packet` layer, before flow extraction).
- **Public `XdpPacket::timestamp()`** via XDP RX metadata
  extension (kernel ≥ 6.0) — orthogonal, separate plan.
- **Plan 12 phase 3** — multi-queue shared-map sharing
  (`XdpSocketBuilder::with_xsk_map`) — separate plan.
