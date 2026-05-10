# Plan 17 — Compose `Dedup` with the flow / session pipeline

## Summary

Add a `with_dedup(Dedup)` builder on `FlowStream` so the chain

```rust
cap.flow_stream(extractor)
   .with_dedup(Dedup::loopback())
   .with_config(cfg)
   .session_stream(parser_factory)
```

works end-to-end. Today `dedup_stream` and `flow_stream` are sibling
methods on `AsyncCapture<S>`: calling one consumes the capture and
the other becomes unreachable, so loopback dedup and flow tracking
can't be combined via the high-level chain. Users either skip dedup
(loopback duplicates double-count packet stats) or drop down to a
manual `AsyncCapture::readable()` loop.

This is G2 in `des-rs`'s second-round analysis at
`des-rs/des-discovery/reports/des-capture-rewrite-analysis-2026-05-09.md`.
After plan 16 lands (upstream reassembly inside `SessionStream`),
G1 is closed; this plan closes G2 — at which point the `des-capture`
live binary is just `cap.flow_stream(...).with_dedup(...).with_config(...).session_stream(...).next()`
in a loop.

## Status

Done — landed for 0.10.0.

## Prerequisites

- None hard. Plan 16 is recommended but not required — `with_dedup`
  is independently useful even on `FlowStream<NoReassembler>`.
- Plans 13 + 14 already shipped.

## Out of scope

- A new `Dedup` algorithm. Stays as `Dedup::loopback()` /
  `Dedup::content()` from plan 10.
- Generalising `flow_stream`'s input to "any packet-source trait"
  (would let arbitrary user-supplied filtered streams feed flow
  tracking). Considered: cleaner architecturally, but a much bigger
  surface change. The `with_dedup` builder gets us 95% of the
  practical benefit at 5% of the code change. Defer the generalised
  shape until a second user wants it.
- Mirror plumbing through `dedup_stream` itself. Today
  `cap.dedup_stream(d)` returns `DedupStream<S>` for users who only
  want dedup'd packets (no flow tracking). That path stays. No
  `DedupStream::flow_stream` method is added — `with_dedup` on the
  *flow* side is the cleaner direction (the flow path already owns
  the capture).
- A `with_dedup_for(Dedup, predicate)` overload that lets users
  decide per-packet whether dedup applies. The single
  `Dedup::keep(&pkt)` API already supports arbitrary policies via
  `Dedup::content()`; we don't need a second filter slot.

---

## What changes

`FlowStream` gains an `Option<Dedup>` field. Its `poll_next` (and
the `AsyncReassemblerSlot` variant's poll_next) calls
`dedup.keep(&pkt)` before passing the packet into
`track_with_payload`. Same for `SessionStream` and `DatagramStream`
(they have their own poll loops today; either propagate
`with_dedup` builder methods to them too OR have them inherit the
dedup from their upstream `FlowStream` at construction time).

The cleanest shape, modelled on how `with_config` already mirrors
across the three streams:

- `FlowStream::with_dedup(self, dedup: Dedup) -> Self`
- `SessionStream::with_dedup(self, dedup: Dedup) -> Self`
- `DatagramStream::with_dedup(self, dedup: Dedup) -> Self`

Internally each holds `Option<Dedup>`. When the chain is built via
`flow_stream(...).with_dedup(d).session_stream(parser)`,
`session_stream` carries the dedup forward (along with the config
fix from plan 14).

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
netring/netring/tests/flow_stream_dedup.rs
netring/netring/examples/lo_session_with_dedup.rs   (optional)
```

---

## API delta

```rust
impl<S, E, U, R> FlowStream<S, E, U, R>
where … {
    /// Apply per-packet deduplication before flow tracking.
    /// Useful for capturing on `lo` where each packet appears twice
    /// (`PACKET_OUTGOING` + `PACKET_HOST`); `Dedup::loopback()` is
    /// the canonical choice.
    ///
    /// The dedup state lives on the stream — counters readable via
    /// [`dedup`](Self::dedup) / [`dedup_mut`](Self::dedup_mut) for
    /// observability. Setting a new `Dedup` resets those counters.
    pub fn with_dedup(self, dedup: Dedup) -> Self { /* … */ }

    pub fn dedup(&self) -> Option<&Dedup> { /* … */ }
    pub fn dedup_mut(&mut self) -> Option<&mut Dedup> { /* … */ }
}

// Same three methods on SessionStream + DatagramStream.
```

`session_stream` and `datagram_stream` (both on `FlowStream`) carry
the dedup forward verbatim, just like `with_config` does after
plan 14.

---

## Implementation steps

1. **Add the `Option<Dedup>` field** to `FlowStream`,
   `SessionStream`, `DatagramStream`. Default `None` —
   no behaviour change for existing users.

2. **Wire the field into the per-packet loop** in each stream's
   `poll_next`. The shape today on `FlowStream<NoReassembler>`
   (`flow_stream.rs:228-285`):

   ```rust
   if let Some(batch) = inner.next_batch() {
       for pkt in &batch {
           let view = pkt.view();
           let evts = this.tracker.track(view);
           for ev in evts { this.pending.push_back(ev); }
       }
   }
   ```

   After plan 17:

   ```rust
   if let Some(batch) = inner.next_batch() {
       for pkt in &batch {
           if let Some(dedup) = this.dedup.as_mut() {
               if !dedup.keep(&pkt) { continue; }
           }
           let view = pkt.view();
           let evts = this.tracker.track(view);
           for ev in evts { this.pending.push_back(ev); }
       }
   }
   ```

   Same insertion point in `SessionStream::poll_next`,
   `DatagramStream::poll_next`, and the `AsyncReassemblerSlot`
   variant of `FlowStream`.

3. **Carry dedup through `session_stream` / `datagram_stream`
   transitions.** When `FlowStream::session_stream(...)` consumes
   the `FlowStream`, the `Option<Dedup>` moves into the new
   `SessionStream`. Add `dedup` to the constructor signatures
   (private — no public-API change beyond the builder methods).

4. **Add the builder methods** (`with_dedup`, `dedup`, `dedup_mut`)
   on all three streams.

5. **Reset dedup counters when re-set.** Calling `with_dedup(d)`
   when one was already set replaces it (and resets `seen()` /
   `dropped()` counters). Document.

6. **Doc cross-link**: `with_dedup` doc points at
   `crate::Dedup::loopback()` and the existing
   `examples/async_lo_dedup.rs`. Add a short paragraph under
   `FlowStream`'s top-level doc covering the loopback use case.

7. **CHANGELOG entry** under "Added".

---

## Tests

### `tests/flow_stream_dedup.rs` (new, integration)

Gated on `integration-tests` (real `lo` capture, `CAP_NET_RAW`).

1. **`flow_stream_with_loopback_dedup_drops_duplicates`** — open `lo`
   capture, attach `Dedup::loopback()`, generate 100 ICMP echo
   packets in a loop. Assert `dedup.dropped() ≈ 100` (each packet
   appears twice; one of each pair gets dropped).

2. **`session_stream_with_loopback_dedup_no_double_parse`** —
   combined with plan 16's reassembly: open `lo`, drive a
   length-prefixed protocol exchange, attach
   `Dedup::loopback()`, assert the parser produces exactly N
   messages (not 2N). This is the test that proves G2's workaround
   is no longer needed for des-rs.

3. **`datagram_stream_with_loopback_dedup`** — same as #1 but on
   UDP. Assert parser sees each datagram once.

### Unit-level

In each stream's `tests` module, add a stub `PacketSource` test
that confirms `with_dedup` is correctly threaded through the
constructor of the next stream in the chain (via `session_stream`
and `datagram_stream`).

### Doctest

Update `flow_stream.rs`'s headline doctest to show the chained
form:

```rust
//! ```no_run
//! use futures::StreamExt;
//! use netring::{AsyncCapture, Dedup};
//! use netring::flow::extract::FiveTuple;
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let cap = AsyncCapture::open("lo")?;
//! let mut s = cap.flow_stream(FiveTuple::bidirectional())
//!                .with_dedup(Dedup::loopback());
//! while let Some(evt) = s.next().await { let _ = evt?; break; }
//! # Ok(()) }
//! ```
```

---

## Acceptance criteria

- [ ] `FlowStream::with_dedup(d)`, `SessionStream::with_dedup(d)`,
      `DatagramStream::with_dedup(d)` all compile and behave
      identically to `dedup_stream` for the dedup half of the work.
- [ ] `flow_stream(...).with_dedup(...).session_stream(...)` chain
      compiles and the dedup is honoured in the session path.
- [ ] `flow_stream(...).with_dedup(...).datagram_stream(...)` chain
      compiles and the dedup is honoured in the datagram path.
- [ ] Counters `dedup.dropped()` / `dedup.seen()` accessible via
      `stream.dedup()` after construction.
- [ ] Three integration tests pass under
      `cargo test --features tokio,flow,integration-tests`.
- [ ] Existing tests (notably `flow_stream_config.rs`,
      `dedup_stress.rs`) continue to pass — `with_dedup` is purely
      additive.
- [ ] CHANGELOG + doctest updates.
- [ ] Workspace clippy clean; no new `unsafe`.

---

## Risks

1. **Per-packet hash cost on the hot path.** `Dedup::loopback()`
   does an xxh3-64 hash on every packet body. On `lo` captures of
   high-cadence traffic this is the marginal hot-path cost. Already
   measured under plan 15's `dedup_stress.rs` — fine at 2 kHz.
   When `with_dedup` is *not* set (`Option::None`), the cost is one
   `if let` branch — effectively zero. Acceptable.

2. **State counter naming under chain.** `with_dedup` sets a
   `Dedup` that lives on the stream. `stream.dedup().dropped()`
   reports the running drop count for that stream's lifetime.
   Document that this is independent of any `Dedup` the user might
   have used elsewhere.

3. **Composition with `with_async_reassembler`.** `FlowStream<R>`
   is generic over reassembler slot. `with_dedup` should work on
   any `R`, since dedup happens *before* reassembly. Verify the
   poll loop in the `AsyncReassemblerSlot` variant
   (`flow_stream.rs:286-417`) gets the same insertion-point edit.

4. **`with_dedup` after some flows are tracked.** Symmetric question
   to plan 16's: if you set dedup mid-stream, does it apply
   retroactively? **Decision**: no. The dedup ring starts fresh
   from the moment `with_dedup` is called; flows already tracked
   keep their existing packet/byte stats (which already counted any
   loopback duplicates that arrived pre-dedup). Document.

5. **`AsyncCapture::dedup_stream` becomes redundant?** Not entirely:
   a user who wants dedup'd packets WITHOUT flow tracking still
   reaches for `dedup_stream`. The two paths coexist. Document the
   distinction in the migration guide.

6. **Naming**: `with_dedup` vs `with_loopback_dedup` vs `dedup`.
   Going with `with_dedup` because it matches the
   `with_config`/`with_state` family on the same types and accepts
   any `Dedup`, not just `loopback`.

---

## Effort

- **LoC estimate**:
  - `flow_stream.rs`: 1 field + 3 builder methods + 2 poll-loop
    insertions (NoReassembler + AsyncReassemblerSlot variants) =
    ~30 LoC.
  - `session_stream.rs`: 1 field + 3 builder methods + 1 poll-loop
    insertion + carry-from-FlowStream in `new_with_config`-ish
    constructor = ~25 LoC.
  - `datagram_stream.rs`: same shape, ~25 LoC.
  - Tests: ~150 LoC across 3 integration tests.
  - CHANGELOG + doc: ~20 lines.
- **Time**: half a day. The mechanical work is mirroring an
  existing pattern (`with_config`); time goes to integration-test
  fixture construction.
