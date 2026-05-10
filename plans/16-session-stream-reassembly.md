# Plan 16 — Session/datagram streams integrate `BufferedReassembler`

## Summary

Wire flowscope 0.2's `BufferedReassembler` into netring's
`SessionStream` (and, for symmetry, audit `DatagramStream`) so the
documented chain

```rust
cap.flow_stream(ext)
   .with_config(cfg)              // sets max_reassembler_buffer + overflow_policy
   .session_stream(parser_factory)
```

actually does TCP reassembly between `track_with_payload`'s payload
callback and `parser.feed_*`, exactly the way flowscope's sync
`FlowSessionDriver` does it. After this plan, length-prefixed binary
protocols (DES PSMSG, custom user wire formats, etc.) are correct on
the live API: retransmits are dropped, out-of-order segments are
dropped, the per-side cap is honoured, and `EndReason::BufferOverflow`
flows through to `SessionEvent::Closed` when the cap fires under
`OverflowPolicy::DropFlow`.

This closes G1 in `des-rs`'s second-round analysis at
`des-rs/des-discovery/reports/des-capture-rewrite-analysis-2026-05-09.md`,
which is currently the only thing pushing live-capture des-capture
toward a hand-written `AsyncCapture::readable()` loop.

## Status

Done — landed for 0.10.0.

## Prerequisites

- [Plan 13](./13-flowscope-0.2-bump.md) — flowscope 0.2's
  `BufferedReassembler{,Factory}` + `OverflowPolicy` are what this
  plan integrates. Already shipped.
- [Plan 14](./14-config-aware-async-streams.md) — the `with_config`
  chain that propagates `FlowTrackerConfig` is what carries
  `max_reassembler_buffer` + `overflow_policy` down to the per-flow
  reassemblers this plan adds. Already shipped.

## Out of scope

- Replacing `with_async_reassembler` on `FlowStream`. That trait
  surface is for users who want raw bytes via channels (typically for
  `protolens`-shaped backpressure pipelines). It stays untouched.
  `session_stream` and `with_async_reassembler` continue to be
  disjoint paths on `FlowStream` — picking one or the other.
- Async reassembly inside `SessionStream`. flowscope's
  `BufferedReassembler` is sync; calling its `segment(seq, payload)`
  inside the stream poll loop costs one `Vec::extend_from_slice` per
  TCP segment (or a sliding-window `drain`/`extend` when the cap is
  hit). Negligible on the kernel-ring's hot path. Async reassembly
  would only matter if the consumer wanted backpressure to flow into
  the reassembler itself, which is a separate use case covered by
  `with_async_reassembler`.
- Plumbing through to `DatagramStream` if there's nothing UDP-shaped
  to reassemble. Datagrams have no concept of OOO segments; what
  flowscope 0.2 offers there is the `max_reassembler_buffer` (which
  is moot for UDP) and the per-flow LRU eviction (already wired).
  We'll **audit** `DatagramStream` as part of this plan and confirm
  it needs no changes; ship the SessionStream side only.
- Surfacing `FlowEvent::Anomaly` through `SessionEvent` (`Anomaly`
  variant on the typed surface). Today netring 0.9 emits a
  `tracing::warn!` on `Anomaly` and recommends tapping `FlowStream`
  directly for structured access. With this plan, the per-flow
  `Anomaly { kind: BufferOverflow }` event WILL fire upstream of
  `convert_event`'s match — but the user-visible result is still the
  `tracing::warn!`. The structural signal lives on
  `SessionEvent::Closed { reason: EndReason::BufferOverflow }`, which
  THIS plan makes work end-to-end. (Adding an `Anomaly` variant to
  flowscope's `SessionEvent` is a separate flowscope-side question
  this plan doesn't touch.)
- Adding a way to opt OUT of upstream reassembly per-parser. The
  shipped flowscope parsers (HTTP, TLS, DNS-TCP) all do their own
  per-side `init_buf`/`resp_buf` accumulation; with this plan they'd
  be receiving "reassembled bytes that they then re-buffer". The
  cost is one extra `extend_from_slice` per drain — negligible. If
  a parser ever genuinely wants raw arrival-order bytes, it should
  be using `with_async_reassembler` or rolling its own loop, not
  `session_stream`.

---

## What changes, in one sentence

`SessionStream` gains a `HashMap<(K, FlowSide), BufferedReassembler>`
field; `track_with_payload`'s closure body changes from
`parser.feed_initiator(payload)` (direct) to
`reassembler[(k, side)].segment(seq, payload)` (buffered); after the
tracker call returns, on each `FlowEvent::Packet` event we
`reassembler.take()` and feed the drained bytes into the parser.

It's the FlowSessionDriver pattern (`flowscope/src/session_driver.rs:116-189`)
ported into netring's async stream loop.

---

## Files

### MODIFY

```
netring/netring/src/async_adapters/session_stream.rs
netring/netring/src/async_adapters/datagram_stream.rs   (audit only)
netring/CHANGELOG.md
```

### NEW

```
netring/netring/tests/session_stream_reassembly.rs
```

Optional: a small `examples/length_prefixed_live.rs` that mirrors
flowscope's `length_prefixed_pcap.rs` but on a live `lo` capture.
Defer until des-rs ships its own live binary; we'd duplicate effort.

---

## API delta

No public API changes. The behavioural contract is widened (parsers
now see reassembled bytes, not raw payloads) but no method signature
moves. Document the change loudly in CHANGELOG.

Internal additions in `SessionStream`:

```rust
pub struct SessionStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    cap: AsyncCapture<S>,
    tracker: FlowTracker<E, ()>,
    factory: F,
    parsers: HashMap<E::Key, F::Parser, RandomState>,
    pending: VecDeque<SessionEvent<E::Key, <F::Parser as SessionParser>::Message>>,
    sweep: tokio::time::Interval,
    // NEW in plan 16:
    reassemblers: HashMap<(E::Key, FlowSide), BufferedReassembler, RandomState>,
    reassembler_factory: BufferedReassemblerFactory,
}
```

`reassembler_factory` is built once at construction time from
`config.max_reassembler_buffer` and `config.overflow_policy`,
mirroring `FlowSessionDriver::with_config`.

---

## Implementation steps

1. **Add the two new fields** to `SessionStream`.
2. **Build the factory in `new_with_config`** — when
   `config.max_reassembler_buffer.is_some()`, configure the factory
   with `with_max_buffer(n).with_overflow_policy(config.overflow_policy)`;
   otherwise default factory.
3. **Mirror the factory rebuild in `with_config`** — when the
   builder method is called post-construction, rebuild the factory
   so the new caps apply. Existing in-flight reassemblers keep their
   prior config (we don't retroactively change caps on flows already
   tracking); document this. New flows after the `with_config` call
   get the new factory.
4. **Restructure the `poll_next` per-packet loop**:

   Today (`session_stream.rs:155-179`):
   ```rust
   this.tracker.track_with_payload(view, |key, side, _seq, payload| {
       if payload.is_empty() { return; }
       let parser = parsers.entry(key.clone())
           .or_insert_with(|| factory.new_parser(key));
       let messages = match side {
           FlowSide::Initiator => parser.feed_initiator(payload),
           FlowSide::Responder => parser.feed_responder(payload),
       };
       for message in messages {
           pending.push_back(SessionEvent::Application { key: key.clone(), side, message, ts: view_ts });
       }
   });
   for ev in evts { convert_event(ev, parsers, pending); }
   ```

   After plan 16:
   ```rust
   let evts = this.tracker.track_with_payload(view, |key, side, seq, payload| {
       if payload.is_empty() { return; }
       reassemblers
           .entry((key.clone(), side))
           .or_insert_with(|| reassembler_factory.new_reassembler(key, side))
           .segment(seq, payload);
   });
   for ev in evts {
       drain_reassembler_into_parser(&ev, reassemblers, parsers, factory, pending, view_ts);
       convert_event(ev, reassemblers, parsers, pending);
   }
   ```

   `drain_reassembler_into_parser` is a small helper:
   - On `FlowEvent::Packet { key, side, ts, .. }`: take bytes from the
     reassembler for `(key, side)`, if non-empty feed them through
     the parser, push `SessionEvent::Application` for each returned
     message.
   - On `FlowEvent::Started`: ensure parser exists (it'll be created
     lazily on first byte feed otherwise; explicitly creating here is
     optional but matches `FlowSessionDriver`).
   - Ignore other variants — `convert_event` handles them.
5. **Extend `convert_event` to drop reassemblers on flow end.** When
   `Ended { key, reason, .. }` fires, after the existing parser
   `fin_*`/`rst_*` calls, also remove
   `(key, FlowSide::Initiator)` and `(key, FlowSide::Responder)`
   from `reassemblers`. This mirrors `FlowSessionDriver`'s pattern at
   `session_driver.rs:200-205`.

   For `EndReason::BufferOverflow` specifically: the reassembler is
   already poisoned (that's WHY the tracker emitted overflow Ended),
   but its bytes-already-buffered may still be drainable. Decision:
   skip the final drain when overflow fires (parser would see
   incomplete frames anyway). `rst_*` is called instead.
6. **Audit `DatagramStream`**. UDP datagrams don't need reassembly
   — each packet is a self-contained message. The
   `max_reassembler_buffer` / `overflow_policy` fields don't apply.
   Document this in `datagram_stream.rs` doc comment + add a
   `#[allow(unused)]` note if `with_config` accepts these fields
   without honouring them. **Decision**: emit a debug-level trace
   when a non-default `max_reassembler_buffer` is set on
   `DatagramStream::with_config` to flag the inapplicability; no
   behaviour change.
7. **CHANGELOG entry**. The behavioural change is
   user-visible-but-additive: users who relied on `SessionStream`
   feeding *arrival-order* bytes (i.e. wrote a parser that
   intentionally double-counts retransmits) will see a behaviour
   change. The shipped HTTP/TLS/DNS parsers don't care because they
   re-buffer internally. Document under "Behavioural changes" in
   the next minor.
8. **Update doc comments** on `SessionStream` and `session_stream`
   to mention upstream reassembly. Cross-link from `with_config`'s
   doc to `OverflowPolicy::DropFlow` and the `EndReason::BufferOverflow`
   path on `Closed`.

---

## Tests

### `tests/session_stream_reassembly.rs` (new)

Three tests, all driving an in-process `lo` capture (gated on
`integration-tests` like the existing `flow_stream_config.rs`):

1. **`retransmit_yields_one_message_not_two`** — generate a TCP
   exchange where one segment is sent twice (genuine retransmit
   shape: same seq, same body). Assert the parser produces the
   message once, not twice. Currently (pre-plan-16) this test would
   fail; on plan 16's branch it should pass.

2. **`out_of_order_segment_dropped_via_reassembler`** — generate
   three segments at seq=100,200,150 (in arrival order). Assert the
   parser sees bytes from seq=100 then seq=200 (not seq=150 — that
   was OOO and dropped). Verify via the parser's message stream.

3. **`buffer_overflow_terminates_flow_with_dropflow_policy`** —
   build a `FlowTrackerConfig` with
   `max_reassembler_buffer = Some(64)` and
   `overflow_policy = OverflowPolicy::DropFlow`. Drive >64 bytes of
   in-order data on the initiator side. Assert that
   `SessionEvent::Closed { reason: EndReason::BufferOverflow, .. }`
   is emitted within bounded time. Assert
   `stats.reassembly_bytes_dropped_oversize_initiator > 0`.

### Unit-level test in `session_stream.rs::tests`

A non-integration unit test using a stub `PacketSource` (or
synthetic frames) that verifies `convert_event` drops reassemblers
on `Ended`. Already a small enough surface to test in isolation.

### Doctest

Update the headline doctest in `session_stream.rs` to mention
upstream reassembly:

```rust
//! After plan 16, `SessionStream` runs `BufferedReassembler` per
//! `(flow, side)` between the tracker and the parser. Retransmits
//! and out-of-order segments are dropped before reaching the parser.
//! The buffer cap from `FlowTrackerConfig::max_reassembler_buffer`
//! is honoured; on `OverflowPolicy::DropFlow` the flow ends with
//! `EndReason::BufferOverflow`.
```

---

## Acceptance criteria

- [ ] `SessionStream` holds per-(flow, side) `BufferedReassembler`
      instances built from `FlowTrackerConfig::{max_reassembler_buffer, overflow_policy}`.
- [ ] `track_with_payload` closure routes payloads to the reassembler,
      not directly to the parser.
- [ ] Per-`FlowEvent::Packet`, the reassembler is drained and bytes
      fed to the parser.
- [ ] On `FlowEvent::Ended`, reassemblers are removed; parser
      `fin_*` / `rst_*` are called per existing logic.
- [ ] `EndReason::BufferOverflow` reaches `SessionEvent::Closed`
      end-to-end (verified by integration test).
- [ ] `FlowStats::reassembly_dropped_ooo_*` and
      `reassembly_bytes_dropped_oversize_*` populate on `Closed`
      events under realistic OOO / overflow conditions.
- [ ] All three new integration tests pass under
      `cargo test --features tokio,flow,integration-tests`.
- [ ] All existing tests continue to pass — including the four
      shipped parsers (HTTP, TLS, DNS-UDP, DNS-TCP). They should be
      unaffected: their internal `init_buf`/`resp_buf` re-buffers the
      reassembled bytes with no semantic change.
- [ ] CHANGELOG entry under "Behavioural changes" for the next
      minor.
- [ ] Workspace clippy clean.
- [ ] `cargo doc --all-features --no-deps` zero warnings.

---

## Risks

1. **Behaviour change for users who relied on arrival-order bytes.**
   Any user who wrote a `SessionParser` that intentionally counted
   retransmits would see different output after this plan. Mitigation:
   document loudly; provide an opt-out only if a real user complains.
   The shipped parsers are unaffected (they re-buffer internally).

2. **Performance on the hot path.** Adding a `HashMap::entry().or_insert_with()`
   call + a `BufferedReassembler::segment()` call on every TCP
   payload packet costs at most one allocation (the first segment
   per (flow, side) creates the reassembler) plus one
   `extend_from_slice` per segment. The `take()` + `feed_*` already
   does the equivalent extend on the parser side, so the net cost
   is one extra hash lookup + one extra `extend_from_slice` (when
   the cap doesn't fire). Profile with the existing `criterion`
   bench (if any) before merging; expect <5% perf delta on a typical
   capture.

3. **Memory footprint.** `BufferedReassembler` per (flow, side) is
   ~64 bytes (Vec header + counters). For 100k flows × 2 sides × 64
   bytes = ~13 MiB extra resident. Acceptable; documented.

4. **Reassembler-vs-parser ownership conflict.** The closure passed
   to `track_with_payload` borrows `reassemblers` mutably; the
   surrounding scope needs the `parsers` HashMap drained after the
   closure returns. The same pattern works in `FlowSessionDriver`
   today — copy that shape. No new borrow-checker hazards.

5. **`with_config` retroactivity.** When the user calls
   `session_stream.with_config(new_cfg)` after some flows have
   already been tracked, do existing reassemblers get the new caps?
   **Decision**: no. The factory is rebuilt and applies to flows
   created after the `with_config` call. Existing flows keep their
   old caps. Document. (Symmetric with how `FlowTracker::set_config`
   handles in-flight flows.)

6. **`DatagramStream` audit** might reveal it WAS supposed to honour
   `max_reassembler_buffer` for some UDP-fragment use case. If so,
   spin out a follow-up plan; don't expand this one's scope.

---

## Effort

- **LoC estimate**:
  - `session_stream.rs`: ~50 LoC of additions + ~30 LoC of
    restructuring the per-packet loop = ~80 net additions.
  - `datagram_stream.rs`: 0–10 LoC of doc/trace additions.
  - Tests: ~250 LoC across 3 integration tests + 1 unit test.
  - CHANGELOG + doc: ~30 lines.
- **Time**: 1.5 days. The mechanical work is straightforward
  (FlowSessionDriver is a working reference); the time goes to
  integration-test fixture construction + perf check.
