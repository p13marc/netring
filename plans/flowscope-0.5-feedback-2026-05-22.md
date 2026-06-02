# Feedback for flowscope 0.5 — observations from netring 0.14.0 integration

**Date:** 2026-05-22
**Author:** maintainer of `netring` (Linux AF_PACKET / AF_XDP packet I/O)
**Context:** netring is flowscope's main async consumer (`AsyncCapture →
flow_stream → session_stream/datagram_stream`, plus the offline-pcap
mirror). This document captures friction we hit during the 0.3 → 0.4
bump and concrete proposals for 0.5.

**Scope rule:** backward-incompatible breaks are explicitly allowed.
flowscope is pre-1.0; netring tracks it in lockstep. We'd rather pay
one careful break now than carry workarounds for years.

> Companion document to flowscope's existing
> [`docs/feedback-2026-05-14-des-rs.md`](https://github.com/p13marc/flowscope/blob/master/docs/feedback-2026-05-14-des-rs.md)
> (consumer-side observations from `des-rs`). This one is the
> netring-side equivalent.

---

## At a glance

| # | Proposal | Tier | Break? |
|---|---|---|---|
| 1 | `FlowTracker::sweep_with_parsers` — bake the on_tick choreography into the tracker | **High** | Additive |
| 2 | `FlowTracker::with_auto_sweep(interval)` — packet-clock-driven sweep mode | **High** | Additive (off by default) |
| 3 | `FlowTracker::finish()` — symmetric with the drivers | **High** | Additive |
| 4 | Split `SessionEvent::Anomaly`'s `key: Option<K>` into per-flow + tracker-global variants | **High** | Breaking (matches need new arms) |
| 5 | `flowscope::AsPacketView` trait — let foreign types feed `track()` without intermediate conversion | **Med** | Additive (existing `Into<PacketView>` impls auto-satisfy) |
| 6 | Restore `S` (or document the workaround) — driver path drops per-flow user state | **Med** | Breaking if we resurrect `S` (one type-param re-addition) |
| 7 | Parser-factory variant on drivers — accept `impl FnMut(&K) -> P` for expensive-init parsers | **Med** | Additive (sibling constructor) |
| 8 | `flowscope::test_helpers` module behind a feature gate | **Polish** | Additive |
| 9 | `BufferedReassembler::with_high_watermark_threshold` + live anomaly | **Polish** | Additive |
| 10 | `SessionParser::is_done()` — symmetric with `is_poisoned()` for graceful early close | **Polish** | Additive (default `false`) |
| 11 | `flowscope/l7` umbrella feature | **Polish** | Additive |
| 12 | Documented recipe for downstream intra-doc links across re-exports | **Polish** | Doc-only |

---

## Tier 1 — high-impact

### 1. `FlowTracker::sweep_with_parsers` helper

**Observation.** flowscope's `FlowSessionDriver::sweep` runs this
choreography:

```
1. collect tracker.sweep_pending(now)
2. for each live parser: on_tick(now) → emit Application events
3. driver.finalize(swept_events)
```

The order matters: a flow this sweep is about to close still gets
its final tick *before* the `Closed` event lands. The drivers get
it right because the logic lives in `FlowSessionDriver` /
`FlowDatagramDriver`.

**Footgun.** Anyone using `FlowTracker` directly has to re-implement
the dance. That includes:

- netring's `SessionStream::poll_next` (one copy)
- netring's `DatagramStream::poll_next` (a second copy)
- the four `Multi*Stream` types (potentially N more if they wired it)
- any future external consumer

If a downstream forgets step 2, **`on_tick` silently never fires**
for their consumers. There's no compile error, no panic — just
missing time-driven events.

**Proposal.** Add a helper on `FlowTracker`:

```rust
impl<E: FlowExtractor, S> FlowTracker<E, S> {
    /// Run a sweep, driving `on_tick` on every live parser before
    /// emitting flow events. Caller-owned parser map keeps per-flow
    /// user state, expensive-init parsers, and parser factories
    /// flexible.
    pub fn sweep_with_parsers<P, F>(
        &mut self,
        now: Timestamp,
        parsers: &mut HashMap<E::Key, P>,
        mut on_message: F,
    ) -> Vec<FlowEvent<E::Key>>
    where
        P: SessionParser,
        F: FnMut(&E::Key, FlowSide, P::Message, Timestamp);
}
```

Mirror on the `DatagramParser` side. The drivers reduce to a
thin wrapper around this + their parser-clone bookkeeping. External
consumers (netring) drop two near-identical copies of the
choreography.

**Effort:** small (~50 LoC + tests). **Risk:** none — additive.

### 2. `FlowTracker::with_auto_sweep(interval)` — packet-clock sweep

**Observation.** Live-capture pipelines have a wall-clock sweep tick
(`tokio::time::interval` in netring). Offline-pcap pipelines do not
— they only sweep at EOF. So **the same pipeline gives different
flow-end behavior on live vs offline runs of the same traffic**:
flows that should have timed out mid-pcap stay open until the
final flush.

netring's `PcapFlowStream` currently has this divergence baked in.
We can fix it on the netring side, but the bigger architectural
question is: should `FlowTracker` know about its own sweep cadence?

**Proposal.** Optional mode:

```rust
impl<E: FlowExtractor, S> FlowTracker<E, S> {
    /// Enable packet-clock-driven sweeps. After each `track()`, if
    /// the observed packet timestamp has advanced past
    /// `last_sweep + interval`, run an implicit sweep and merge
    /// its events into the returned `FlowEvents`.
    ///
    /// Off by default. Useful for offline replay where wall-clock
    /// makes no sense, and for unifying online/offline pipelines
    /// under one timing model.
    pub fn with_auto_sweep(mut self, interval: Duration) -> Self;
}
```

Default off → existing behavior. With it on, `tracker.track(view)`
becomes the single entry point — no need for a separate sweep
timer in the consumer.

**Benefits:**
- Online and offline pipelines produce identical event streams for
  identical inputs.
- Consumers (netring, des-rs, anyone with their own driver) can
  drop their sweep-timer code.
- Composes naturally with the packet-clock semantics we already
  have via `with_monotonic_timestamps`.

**Effort:** medium (need to thread the auto-sweep through both
`track` and `track_with_payload`). **Risk:** low — opt-in.

### 3. `FlowTracker::finish()`

**Observation.** `sweep(Timestamp::MAX)` is the only correct way to
flush all open flows at end-of-input. The three drivers expose it
as `finish()`. The tracker doesn't.

netring's `PcapFlowStream` uses `FlowTracker` directly (it predates
the `FlowSessionDriver` wrap and supports per-flow user state via
`U`) and has to spell out:

```rust
for ev in this.tracker.sweep(Timestamp::MAX) { ... }
```

instead of `tracker.finish()`. Tiny, but signals intent and saves
the magic-constant.

**Proposal.**

```rust
impl<E: FlowExtractor, S> FlowTracker<E, S> {
    /// End-of-input flush. Equivalent to `sweep(Timestamp::MAX)`.
    /// Every still-open flow exceeds its idle threshold against
    /// this anchor and emits its terminal `Ended` event.
    pub fn finish(&mut self) -> FlowEvents<E::Key> {
        self.sweep(Timestamp::MAX)
    }
}
```

**Effort:** trivial. **Risk:** none.

### 4. Split `SessionEvent::Anomaly`'s `key: Option<K>`

**Observation.** Today:

```rust
SessionEvent::Anomaly {
    key: Option<K>,    // None for tracker-global anomalies
    kind: AnomalyKind,
    ts: Timestamp,
}
```

The `Option<K>` exists because some `AnomalyKind`s are tracker-
global (`FlowTableEvictionPressure`) and some per-flow
(`OutOfOrderSegment`, `SessionParseError`). Consumers always need
to `if let Some(k) = key { … }` to route. The two categories are
semantically different — a per-flow anomaly is "this stream is
sick", a tracker-global one is "the whole pipeline is sick".

**Proposal.** Two variants:

```rust
#[non_exhaustive]
pub enum SessionEvent<K, M> {
    // … existing variants …
    /// Per-flow anomaly tied to a specific stream.
    FlowAnomaly { key: K, kind: AnomalyKind, ts: Timestamp },
    /// Tracker-global anomaly (e.g., eviction pressure).
    TrackerAnomaly { kind: AnomalyKind, ts: Timestamp },
}
```

Same on `FlowEvent`. Migration is a one-time `match` arm split.
After the break, no more `if let Some(k) = key` plumbing on the
hot path. Each variant has a clean `AnomalyKind` subset (we can
even split `AnomalyKind` itself eventually — but that's a bigger
swing; this proposal is just about the carrier event).

**Effort:** small. **Risk:** breaking — but the migration is
mechanical and matches `0.3.0`'s `#[non_exhaustive]` precedent.

---

## Tier 2 — medium-impact

### 5. `flowscope::AsPacketView` trait

**Observation.** 0.4 added `From<&OwnedPacketView> for PacketView`,
which is great if you use flowscope's `OwnedPacketView`. netring
ships its own `OwnedPacket` (mmap-backed for live capture, owned
for pcap/offline) with the same shape but different name. So we
still construct views manually:

```rust
let view = PacketView::new(&owned.data, owned.timestamp);
this.tracker.track(view);
```

versus the elegant:

```rust
this.tracker.track(&owned);
```

**Proposal.** Add a trait:

```rust
pub trait AsPacketView {
    fn as_packet_view(&self) -> PacketView<'_>;
}

impl AsPacketView for OwnedPacketView { /* … */ }
impl<'a, T: AsPacketView> From<&'a T> for PacketView<'a> { … }
```

Now any foreign type (netring's `OwnedPacket`, a pcap-rs `Packet`,
a zenoh sample, …) opts in with three lines and feeds `tracker.track`
directly.

**Effort:** small. **Risk:** none — existing `Into<PacketView>` impls
satisfy the new trait via blanket impl.

### 6. Driver `S` (per-flow user state) story

**Observation.** 0.4 dropped the `S` type parameter from
`FlowDriver<E, F, S>` → `FlowDriver<E, F>`. The reasoning: the
drivers always ran with `S = ()` anyway. But the implication is
that **anyone who wants both L7 messages AND per-flow user state
cannot use the drivers** — they must drop down to `FlowTracker`
directly and re-implement parser dispatch + reassembler
choreography + on_tick. That's exactly netring's async-stream code
path (~300 LoC of "do what the driver does, but with U on the
tracker").

**Two options:**

**A. Resurrect `S` on the drivers** — `FlowSessionDriver<E, P, S = ()>`
with a default. Backward-compatible for callers who used the type
without specifying `S`. Mild type-system overhead per construction.

**B. Document the workaround prominently** — keep the driver lean,
ship a worked example of "FlowTracker + your own parser dispatch +
your own user state" in flowscope's docs. Pair with #1
(`sweep_with_parsers`) so the workaround is small.

I lean toward **B + #1**: drivers stay the simple path, advanced
users get a documented recipe instead of an undiscoverable
"oh, you can do that too" trap. The current state surprised me
during the netring integration.

**Effort:** doc-only (option B) or small (option A). **Risk:** low.

### 7. Parser-factory variant on drivers

**Observation.** `FlowSessionDriver::new(extractor, parser: P)`
where `P: SessionParser + Clone`. The driver clones the template
parser per flow. For parsers with expensive setup (compiled regex
sets, ML model weights, big TLS cipher tables), that's wasted CPU
on every new flow.

netring's `SessionStream` uses `SessionParserFactory::new_parser(&K)`
explicitly so users can share expensive setup via `Arc` and mint
cheap per-flow handles.

**Proposal.** Sibling constructor:

```rust
impl<E: FlowExtractor, P: SessionParser> FlowSessionDriver<E, P> {
    /// Like `new`, but mint each flow's parser via a closure
    /// instead of cloning a template. Use when parser setup is
    /// expensive enough to warrant sharing state via `Arc`.
    pub fn with_factory<F>(extractor: E, factory: F) -> Self
    where
        F: FnMut(&E::Key) -> P + Send + 'static;
}
```

`new(ext, parser)` stays for the common path (cheap-to-clone
parsers). `with_factory` for the heavy-setup path.

**Effort:** small. **Risk:** none — additive.

---

## Tier 3 — polish

### 8. `flowscope::test_helpers` module

**Observation.** Across netring tests we have **five** hand-rolled
noop / echo parsers with five different names:

```
netring/tests/flow_stream_config.rs        — StubParser
netring/tests/with_dedup_propagation.rs    — StubParser + DatagramParser impl
netring/tests/flowscope_03_passthrough.rs  — StubSessionParser + StubDatagramParser
netring/tests/stream_observability.rs      — StubParser (inline)
netring/src/async_adapters/session_stream.rs — EchoParser (in-module tests)
```

All have `type Message = ()` (mostly) and empty bodies. Every
flowscope minor that touches the trait shape requires patching
all of them — the 0.4 bump's `ts: Timestamp` arg meant 12 line
edits across 5 files just for this.

**Proposal.** Ship under a `test-helpers` feature flag:

```rust
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    pub struct NoopSessionParser;
    pub struct NoopDatagramParser;
    pub struct EchoSessionParser; // emits (FlowSide, Vec<u8>)
    // matching ParserFactory impls
}
```

netring's test files become a single `use flowscope::test_helpers::NoopSessionParser`.
Future trait evolution absorbs in flowscope once, not in every
downstream crate.

**Effort:** small. **Risk:** none.

### 9. `BufferedReassembler::with_high_watermark_threshold`

**Observation.** `high_watermark` is currently read-once-on-Ended.
For tuning `max_reassembler_buffer` in production, you want **live
signal**: "buffer crossed 80 % of cap, here's how close we are".
Today the only live signal is `BufferOverflow` — too late.

**Proposal.**

```rust
impl BufferedReassembler {
    /// Fire an anomaly when buffer occupancy crosses
    /// `threshold` % of cap. Default off.
    pub fn with_high_watermark_threshold(mut self, percent: u8) -> Self;
}

// new variant on AnomalyKind:
#[non_exhaustive]
pub enum AnomalyKind {
    // …
    ReassemblerHighWatermark {
        side: FlowSide,
        bytes: u64,
        cap: u64,
        threshold_pct: u8,
    },
}
```

Operators see cap pressure building before it bites.

**Effort:** small. **Risk:** breaking only if `AnomalyKind` matches
were exhaustive (it's `#[non_exhaustive]` — so additive).

### 10. `SessionParser::is_done()` — symmetric with `is_poisoned()`

**Observation.** Currently:

```rust
trait SessionParser {
    fn is_poisoned(&self) -> bool { false }  // "I'm broken"
}
```

→ driver synthesises `EndReason::ParseError`.

No symmetric "I'm done, please close this flow cleanly". Example
trigger: HTTP/1.0 connection observes `Connection: close` +
end-of-response. The parser knows the flow is done, but the
tracker keeps it alive until idle-timeout.

**Proposal.**

```rust
trait SessionParser {
    fn is_done(&self) -> bool { false }  // "I'm satisfied"
}
```

→ driver synthesises `EndReason::ParserClosed` (new variant) or
treats like `Fin`. Same default-no-op pattern as `is_poisoned`.

**Effort:** small. **Risk:** additive (new `EndReason` variant —
already `#[non_exhaustive]`).

### 11. `flowscope/l7` umbrella feature

**Observation.** Today: `flowscope/dns`, `flowscope/tls`,
`flowscope/http` separately. For benchmarks / all-features tests /
real-world examples that want "give me all the L7", that's three
features to enable.

**Proposal.**

```toml
[features]
l7 = ["dns", "tls", "http"]
```

Sub-features still available individually for users who only need
one. Trivial change; saves typing.

### 12. Doc recipe for downstream intra-doc links

**Observation.** When netring re-exports `flowscope::FlowSessionDriver`,
rustdoc emits `redundant_explicit_links` warnings on
`[FlowSessionDriver](flowscope::FlowSessionDriver)` style patterns.
The fix is `[FlowSessionDriver]` (relying on path resolution
through the re-export). I've hit this three times now across
0.3.0 → 0.4.0 doc fixes.

**Proposal.** A short snippet in flowscope's docs / CLAUDE.md
showing the right pattern for re-exporters. Saves every downstream
crate the same 5-minute debug session.

---

## What I'd ship first

If I were prioritizing **flowscope 0.5**:

1. **#1 (`sweep_with_parsers`)** — biggest discoverability win,
   smallest API surface change. Eliminates a footgun.
2. **#3 (`FlowTracker::finish()`)** — trivial; closes a symmetry
   gap. 5 lines.
3. **#8 (`test_helpers` module)** — absorbs the next round of
   `feed_*` signature evolution painlessly for the whole
   ecosystem. Worth its weight every single minor.
4. **#5 (`AsPacketView` trait)** — small refactor, multi-year
   payoff for foreign-source consumers.
5. **#4 (split `Anomaly`)** — the only big break in the list,
   but the `Option<K>` is awkward enough that it's worth doing
   while pre-1.0 churn is still acceptable.

Items #2 (`with_auto_sweep`) and #6 (driver-vs-tracker symmetry)
are the bigger architectural conversations; both deserve their
own RFC rather than landing in a minor.

---

## Out of scope here

The following are netring-side improvements that came up during
the integration but don't need flowscope changes:

- **Run periodic sweeps in `PcapFlowStream` based on packet-clock
  advancement.** netring-side fix; #2 above would also let us
  drop the explicit sweep timer in live `FlowStream`.
- **Implement `From<&netring::OwnedPacket> for PacketView`.**
  Would land naturally alongside #5's `AsPacketView`.
- **Add a `SessionParserFactory`-style entry point through
  netring's offline pcap path.** Mirror of what `SessionStream`
  does; depends on #7's driver-factory variant for the cleanest
  shape.

These will land in netring 0.15 once the flowscope changes above
ship.

---

## Closing note

The 0.4 release — `on_tick`, `Timestamp::MAX`, `track(impl Into<PacketView>)`,
parser `ts` argument, DNS unification — was a clear net win.
Integration into netring took half a day, and most of the friction
above is "now that I see how this fits together, here's how it
could fit even better." The drivers in particular are a great
shape for the common case; this feedback is mostly about making
the FlowTracker direct-use path catch up to the driver path in
terms of ergonomics and discoverability.

Happy to help draft RFCs for any of the bigger items
(#2, #4, #6) if useful.
