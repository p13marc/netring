# Plan 02 — Flow tracker + async stream

## Summary

Land `FlowTracker<E, S>` in `netring-flow` (sync, runtime-free) with
the TCP state machine, idle-timeout sweep, and `FlowEvent` emission.
Land `AsyncCapture::flow_stream(extractor)` and the `FlowStream<E, S>`
builder in `netring`, driven from `AsyncFd<OwnedFd>`.

After this plan, a tokio user can write:

```rust
let mut events = cap.flow_stream(FiveTuple::bidirectional());
while let Some(evt) = events.next().await { … }
```

and a sync user (pcap, tun-tap) can use `FlowTracker::track` directly.

## Status

Not started.

## Prerequisites

- [Plan 00](./00-workspace-split.md) and [Plan 01](./01-flow-extractor.md)
  complete.

## Out of scope

- Reassembler (plan 03). The tracker exposes TCP `payload_len > 0`
  events but doesn't dispatch payloads anywhere yet.
- Per-flow user-state observers/notifications. `S` is owned by the
  tracker; users access it via `get`/`get_mut` and via factory init.
- Manual sweep API for tests (deferred to v2 per design Part 9).

---

## Files

### NEW (in `netring-flow`)

```
netring-flow/src/
├── tracker.rs        # FlowTracker<E, S>, FlowEntry, FlowStats, FlowState, FlowTrackerConfig
├── event.rs          # FlowEvent, FlowSide, EndReason
├── tcp_state.rs      # TCP state machine (private)
└── history.rs        # HistoryString
```

### NEW (in `netring`)

```
netring/src/
└── async_adapters/
    └── flow_stream.rs   # FlowStream<E, S>, AsyncCapture::flow_stream
```

### MODIFIED

- `netring-flow/src/lib.rs` — add `pub mod tracker; pub mod event;
  pub mod history;` re-exports.
- `netring-flow/Cargo.toml` — add `tracker` feature pulling
  `ahash`, `smallvec`, `arrayvec`.
- `netring/src/async_adapters/tokio_adapter.rs` — link
  `flow_stream` module under `flow` + `tokio` features.
- `netring/Cargo.toml` — add `flow` feature.

### NEW (examples)

- `netring/examples/async_flow_summary.rs` — print one line per
  ended flow.
- `netring/examples/async_flow_filter.rs` — only process packets in
  matching flows.
- `netring/examples/async_flow_history.rs` — Zeek-style `conn.log`
  output.
- `netring-flow/examples/pcap_flow_summary.rs` — same as
  `async_flow_summary` over pcap input. **No tokio.**

---

## API

### `netring-flow/src/event.rs`

```rust
use crate::Timestamp;
use crate::extractor::L4Proto;
use crate::history::HistoryString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSide { Initiator, Responder }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason { Fin, Rst, IdleTimeout, Evicted }

#[derive(Debug, Clone, Default)]
pub struct FlowStats {
    pub packets_initiator: u64,
    pub packets_responder: u64,
    pub bytes_initiator: u64,
    pub bytes_responder: u64,
    pub started: Timestamp,
    pub last_seen: Timestamp,
}

#[derive(Debug, Clone)]
pub enum FlowEvent<K> {
    Started { key: K, side: FlowSide, ts: Timestamp, l4: Option<L4Proto> },
    Packet  { key: K, side: FlowSide, len: usize, ts: Timestamp },
    Established { key: K, ts: Timestamp },
    StateChange { key: K, from: FlowState, to: FlowState, ts: Timestamp },
    Ended { key: K, reason: EndReason, stats: FlowStats, history: HistoryString },
}

// FlowState is in tracker.rs (visible from here).
pub use crate::tracker::FlowState;
```

### `netring-flow/src/tracker.rs`

```rust
use std::collections::HashMap;
use std::time::Duration;
use ahash::RandomState;
use smallvec::SmallVec;

use crate::Timestamp;
use crate::extractor::{Extracted, FlowExtractor, L4Proto, Orientation};
use crate::event::{EndReason, FlowEvent, FlowSide, FlowStats};
use crate::history::HistoryString;
use crate::tcp_state;
use crate::view::PacketView;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    SynSent, SynReceived, Established, FinWait, ClosingTcp,
    Active,
    Closed, Reset, Aborted,
}

#[derive(Debug, Clone)]
pub struct FlowEntry<S> {
    pub stats: FlowStats,
    pub state: FlowState,
    pub history: HistoryString,
    pub user: S,
    pub(crate) initiator_orientation: Orientation,
    pub(crate) l4: Option<L4Proto>,
}

#[derive(Debug, Clone)]
pub struct FlowTrackerConfig {
    pub idle_timeout_tcp: Duration,
    pub idle_timeout_udp: Duration,
    pub idle_timeout_other: Duration,
    pub max_flows: usize,
    pub initial_capacity: usize,
    pub sweep_interval: Duration,
}

impl Default for FlowTrackerConfig {
    fn default() -> Self {
        Self {
            idle_timeout_tcp:   Duration::from_secs(300),
            idle_timeout_udp:   Duration::from_secs(60),
            idle_timeout_other: Duration::from_secs(30),
            max_flows: 100_000,
            initial_capacity: 1024,
            sweep_interval: Duration::from_secs(1),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FlowTrackerStats {
    pub flows_created: u64,
    pub flows_ended: u64,
    pub flows_evicted: u64,
    pub packets_unmatched: u64,
}

pub struct FlowTracker<E: FlowExtractor, S = ()> {
    extractor: E,
    flows: HashMap<E::Key, FlowEntry<S>, RandomState>,
    config: FlowTrackerConfig,
    stats: FlowTrackerStats,
    /// LRU bookkeeping — track insertion order via a parallel
    /// VecDeque<(key, last_seen_ts)> for O(1) eviction. Implementation
    /// detail; users don't see this.
    lru_order: std::collections::VecDeque<(E::Key, Timestamp)>,
}

pub type FlowEvents<K> = SmallVec<[FlowEvent<K>; 2]>;

// Sub-trait for users who want default S.
impl<E: FlowExtractor, S: Default + Send + 'static> FlowTracker<E, S> {
    pub fn new(extractor: E) -> Self;
    pub fn with_config(extractor: E, config: FlowTrackerConfig) -> Self;
    pub fn track(&mut self, view: PacketView<'_>) -> FlowEvents<E::Key>;
}

// Sub-trait for any S.
impl<E: FlowExtractor, S: Send + 'static> FlowTracker<E, S> {
    pub fn with_state<F>(extractor: E, init: F) -> Self
    where F: FnMut(&E::Key) -> S + Send + 'static;
    // (init function stored as Box<dyn FnMut> internally so the type
    // signature stays simple.)

    pub fn with_config_and_state<F>(extractor: E, config: FlowTrackerConfig, init: F) -> Self
    where F: FnMut(&E::Key) -> S + Send + 'static;

    pub fn track_with<F>(&mut self, view: PacketView<'_>, init: F) -> FlowEvents<E::Key>
    where F: FnOnce(&E::Key) -> S;

    pub fn sweep(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>>;

    pub fn get(&self, key: &E::Key) -> Option<&FlowEntry<S>>;
    pub fn get_mut(&mut self, key: &E::Key) -> Option<&mut FlowEntry<S>>;
    pub fn flows(&self) -> impl Iterator<Item = (&E::Key, &FlowEntry<S>)>;
    pub fn flow_count(&self) -> usize;
    pub fn stats(&self) -> &FlowTrackerStats;
    pub fn config(&self) -> &FlowTrackerConfig;
}
```

### `netring-flow/src/tcp_state.rs` (private)

```rust
use crate::extractor::TcpFlags;
use crate::event::FlowSide;
use crate::tracker::FlowState;

/// One-step transition. Pure function; returns the new state and
/// optionally a history-string character to append.
pub(crate) fn transition(
    state: FlowState,
    flags: TcpFlags,
    side: FlowSide,
) -> (FlowState, Option<u8>);

/// Maps TCP flags + side to a Zeek-style history character:
/// S = SYN initiator, s = SYN responder, A = ACK initiator,
/// a = ACK responder, F = FIN initiator, f = FIN responder,
/// R = RST initiator, r = RST responder, D = data initiator,
/// d = data responder.
pub(crate) fn history_char(flags: TcpFlags, side: FlowSide, has_payload: bool) -> Option<u8>;
```

### `netring-flow/src/history.rs`

```rust
/// Compact lifecycle representation, capped at 16 chars (ArrayString).
/// Capital = initiator action, lowercase = responder action.
/// Same encoding as Zeek's conn.log `history` field.
pub type HistoryString = arrayvec::ArrayString<16>;
```

(If `arrayvec` is too much: hand-roll a `[u8; 16] + len` struct
implementing `Display`. Probably easier to depend on `arrayvec`.)

### `netring/src/async_adapters/flow_stream.rs`

```rust
use std::pin::Pin;
use std::task::{Context, Poll};
use std::future::Future;

use futures_core::Stream;
use netring_flow::{FlowExtractor, FlowEvent, FlowTracker, FlowTrackerConfig, PacketView};
use tokio::time::{Interval, interval};

use crate::async_adapters::AsyncCapture;

pub struct FlowStream<E: FlowExtractor, S = ()> {
    cap: AsyncCapture,
    tracker: FlowTracker<E, S>,
    sweep_tick: Interval,
    pending: std::collections::VecDeque<FlowEvent<E::Key>>,
}

impl AsyncCapture {
    /// Convert this capture into a stream of `FlowEvent`s using
    /// `extractor`. `S` defaults to `()`; chain `.with_state(...)`
    /// to attach per-flow user state.
    #[cfg(feature = "flow")]
    pub fn flow_stream<E: FlowExtractor>(self, extractor: E) -> FlowStream<E, ()>
    where
        E::Key: Clone,
    {
        FlowStream {
            sweep_tick: interval(Duration::from_secs(1)),
            tracker: FlowTracker::new(extractor),
            cap: self,
            pending: Default::default(),
        }
    }
}

impl<E: FlowExtractor> FlowStream<E, ()> {
    pub fn with_state<S, F>(self, init: F) -> FlowStream<E, S>
    where
        S: Send + 'static,
        F: FnMut(&E::Key) -> S + Send + 'static,
    { ... }
}

impl<E: FlowExtractor, S: Send + 'static> FlowStream<E, S> {
    pub fn with_config(mut self, config: FlowTrackerConfig) -> Self { ... }
}

impl<E: FlowExtractor, S: Send + 'static> Stream for FlowStream<E, S>
where E::Key: Clone + Unpin
{
    type Item = std::io::Result<FlowEvent<E::Key>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>)
        -> Poll<Option<Self::Item>>
    {
        // 1. Drain pending events first.
        let this = self.get_mut();
        if let Some(evt) = this.pending.pop_front() {
            return Poll::Ready(Some(Ok(evt)));
        }

        // 2. Drive the sweep timer (non-blocking).
        if this.sweep_tick.poll_tick(cx).is_ready() {
            let now = current_timestamp();
            this.pending.extend(this.tracker.sweep(now));
            if let Some(evt) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(evt)));
            }
        }

        // 3. Pull from AsyncFd.
        loop {
            let mut guard = match this.cap.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => return Poll::Pending,
            };
            match guard.try_io(|inner| inner.get_mut().next_batch()) {
                Ok(Ok(Some(batch))) => {
                    for pkt in &batch {
                        let view = pkt.view();
                        for evt in this.tracker.track(view) {
                            this.pending.push_back(evt);
                        }
                    }
                    drop(batch);
                    if let Some(evt) = this.pending.pop_front() {
                        return Poll::Ready(Some(Ok(evt)));
                    }
                    // No events from this batch; try another readiness loop.
                }
                Ok(Ok(None)) => continue,         // no batch yet
                Ok(Err(e)) => return Poll::Ready(Some(Err(e))),
                Err(_would_block) => continue,    // poll again
            }
        }
    }
}
```

(Sketch only — the actual impl will need the existing
`AsyncCapture::poll_read_ready` shape. May require a new public
`poll_*` method on `AsyncCapture` if the existing one isn't quite
right. See implementation step 7.)

---

## Cargo manifest changes

### `netring-flow/Cargo.toml`

```toml
[features]
default    = ["extractors", "tracker"]
extractors = ["dep:etherparse"]
tracker    = ["dep:ahash", "dep:smallvec", "dep:arrayvec"]

[dependencies]
bitflags   = { workspace = true }
etherparse = { workspace = true, optional = true }
ahash      = { version = "0.8", default-features = false, optional = true }
smallvec   = { version = "1", optional = true }
arrayvec   = { version = "0.7", optional = true }
```

### `netring/Cargo.toml`

```toml
[features]
flow = ["parse", "netring-flow/tracker"]
# tokio + flow → AsyncCapture::flow_stream available
```

---

## Implementation steps

1. **Add deps to `netring-flow`.**
   - Update `Cargo.toml` with `ahash`, `smallvec`, `arrayvec`.
   - `cargo build -p netring-flow --features tracker` succeeds.
2. **Land `event.rs`.**
   - Plain enum + struct definitions; no logic.
   - Compile-only; nothing to test yet.
3. **Land `history.rs`.**
   - 1-line type alias (or hand-rolled struct if not pulling
     arrayvec).
   - Smoke test: push chars, verify Display.
4. **Land `tcp_state.rs`.**
   - `transition` function: pattern-match on
     `(state, side, SYN/ACK/FIN/RST)`. Reference: TCP RFC 793 § 3.4.
   - Test against known sequences:
     - SYN(I) → SynSent
     - SYN(I) + SYN-ACK(R) → SynReceived
     - SYN(I) + SYN-ACK(R) + ACK(I) → Established
     - Established + FIN(I) → FinWait
     - FinWait + FIN(R) → ClosingTcp
     - ClosingTcp + ACK(I) → Closed
     - Any state + RST → Reset
   - `history_char` function: returns `Some(b'S')` etc.
5. **Land `tracker.rs` core (no LRU yet).**
   - `FlowTracker<E, S>` struct, `new`, `with_config`,
     `track`, `track_with`, `get`, `get_mut`, `flows`, `flow_count`,
     `stats`, `config`.
   - Implementation:
     1. Call `extractor.extract(view)`. If `None`, increment
        `packets_unmatched` and return empty events.
     2. Lookup or insert flow entry.
     3. On insert: emit `FlowEvent::Started`, set
        `initiator_orientation` = the orientation of the first
        packet, set `state = Active` for non-TCP, `state = Closed`
        not yet — initial TCP state is `Active` until we see SYN.
     4. Compute `side` from `initiator_orientation` and current
        `orientation`.
     5. Update `stats` (packets/bytes by side, `last_seen`).
     6. If `Extracted::tcp` is Some, run TCP state machine.
        - Append history char.
        - Emit `FlowEvent::Established` if transitioning to
          Established for the first time.
        - Emit `FlowEvent::StateChange` for any other state
          change.
     7. Emit `FlowEvent::Packet`.
     8. If state transitioned to Closed/Reset/Aborted, emit
        `FlowEvent::Ended` and remove the flow.
6. **Land idle-timeout sweep.**
   - `FlowTracker::sweep(now)`:
     1. Walk flows. For each, compute idle = `now - last_seen`.
     2. If idle > timeout-for-its-l4, emit `Ended { IdleTimeout }`
        and remove.
     3. Return a `Vec<FlowEvent<K>>` of the ended flows.
   - Test: insert a UDP flow, call sweep with `now = started + 61s`,
     verify Ended event.
7. **Land LRU eviction.**
   - On insert when `flow_count() == max_flows`:
     1. Pop oldest from `lru_order`.
     2. Emit `Ended { Evicted }` (this event must be returned to
        the caller — collected into the FlowEvents returned by
        `track`).
     3. Remove from HashMap.
     4. Insert new flow.
   - Update `lru_order` on every `track`: move the touched key to
     the back. Use a `VecDeque<(Key, Timestamp)>` paired with the
     HashMap. This is O(N) on update for naive impl — for the v1
     target of 100k flows it's fine; document the upgrade path
     (intrusive linked list or `lru` crate) in risks.
   - Alternative: use the `lru` crate as a wholesale replacement
     (bounded, O(1) eviction, integrated). Adds a dep but cleaner.
     **Decision**: use `lru` crate; small (~600 LOC), well-tested,
     drop-in. Add to `tracker` feature.
8. **Land FlowStream and AsyncCapture::flow_stream.**
   - New file `netring/src/async_adapters/flow_stream.rs`.
   - Module is gated by `#[cfg(all(feature = "flow", feature = "tokio"))]`.
   - `Stream` impl follows AsyncFd pattern (see API sketch above).
   - May need to add a `poll_read_ready` accessor on
     `AsyncCapture` if not already public — this is the Stream
     impl's main entry point. Verify in code: review
     `src/async_adapters/tokio_adapter.rs`.
9. **Land builder methods.**
   - `FlowStream::with_state<S, F>(self, F)` — type-shifts
     `FlowStream<E, ()>` to `FlowStream<E, S>`.
   - `FlowStream::with_config(self, c)` — same-type, just sets the
     tracker config.
10. **Update justfile.**
    - `flow-summary *args:` `cargo run -p netring --example async_flow_summary --features tokio,flow -- {{args}}`
    - `flow-filter *args:` `cargo run -p netring --example async_flow_filter --features tokio,flow -- {{args}}`
    - `flow-history *args:` `cargo run -p netring --example async_flow_history --features tokio,flow -- {{args}}`
11. **Examples.**
    - `netring-flow/examples/pcap_flow_summary.rs`:
      ```rust
      // sync: open pcap, FlowTracker::new(FiveTuple::bidirectional()),
      // for each frame call tracker.track(view), print Ended events.
      ```
    - `netring/examples/async_flow_summary.rs`: see design Part 4
      headline example.
    - `netring/examples/async_flow_filter.rs`: filter to a specific
      flow key, print only that.
    - `netring/examples/async_flow_history.rs`: print Ended events
      in Zeek format.
12. **Update CHANGELOG.**
    - `0.7.0-alpha.2` / `0.1.0-alpha.2`: "Added — FlowTracker, TCP
      state, AsyncCapture::flow_stream".

---

## Tests

### `netring-flow/tests/tracker_basic.rs`

- TCP 3WHS sequence: Started → Established events fire correctly.
- TCP graceful close: FIN/FIN/ACK → Ended event with reason=Fin.
- TCP RST: Ended with reason=Rst.
- UDP: 3 packets, no state events except Started/Packet*3.
- Bidirectional: A→B then B→A → same key, sides flip correctly.
- History string: "ShAdaFf" or similar over a full TCP session.

### `netring-flow/tests/tracker_lifecycle.rs`

- Idle timeout: insert flow, sweep at `started + 301s`, expect
  Ended.
- Eviction: insert `max_flows + 1` flows, expect oldest got Evicted.
- Stats accuracy: packets/bytes by side after a sequence.

### `netring-flow/tests/tracker_user_state.rs`

- `track_with(view, |key| MyState::new(key))` — verify `S` is
  initialized once per flow.
- `get_mut` returns the same `MyState` instance.

### `netring/tests/flow_stream.rs` (integration, requires
   `integration-tests`)

- Open AsyncCapture on `lo`, send 5 TCP packets via raw socket,
  expect `Started + Established + Packet*5 + Ended` from the
  stream.
- Drop the stream mid-flow, verify no panic.
- `flow_stream(...).with_state(init).with_config(c)` — builder
  type-shifts compile.

### Doctest

In `netring/src/async_adapters/flow_stream.rs`:

```rust
/// ```no_run
/// use netring::AsyncCapture;
/// use netring_flow::extract::FiveTuple;
/// use futures::StreamExt;
///
/// # async fn example() -> std::io::Result<()> {
/// let cap = AsyncCapture::open("eth0")?;
/// let mut stream = cap.flow_stream(FiveTuple::bidirectional());
/// while let Some(evt) = stream.next().await {
///     // process FlowEvent
///     # break;
/// }
/// # Ok(())
/// # }
/// ```
```

---

## Acceptance criteria

- [ ] `FlowTracker<E, S>` compiles and passes ≥10 unit tests
      covering TCP 3WHS, FIN, RST, idle, eviction, bidirectional
      reorientation.
- [ ] `cargo test -p netring-flow --features tracker` passes.
- [ ] `AsyncCapture::flow_stream` available under `flow + tokio`.
- [ ] `cargo build -p netring --features flow` succeeds.
- [ ] `cargo build -p netring --features flow,tokio` succeeds.
- [ ] `FlowStream` is `Stream<Item = io::Result<FlowEvent<K>>>` —
      verified by `futures::StreamExt::next` doctest.
- [ ] All 4 new examples build and one of them runs against a live
      `lo` capture without crashing.
- [ ] Workspace clippy clean.
- [ ] `0.7.0-alpha.2` / `0.1.0-alpha.2` tagged.

---

## Risks

1. **AsyncFd integration friction.** The existing
   `AsyncCapture::next_batch_async()` (or whatever it's named) may
   not expose `poll_read_ready` cleanly. Likely need to add a
   `poll_read_ready` method or split out a low-level helper.
   Investigate `src/async_adapters/tokio_adapter.rs` carefully
   before writing `flow_stream.rs`.
2. **TCP state machine corner cases.**
   - SYN retransmissions
   - SYN/ACK without prior SYN (we never saw the first packet)
   - Half-closed (one side FIN, other still sending)
   - Simultaneous close
   - Out-of-order FIN
   Suricata's `flow_state.c` handles all these; we should match it
   for the common cases. Document any deviation.
3. **`init` storage as `Box<dyn FnMut>`.** Adds a heap alloc and
   pointer chase per new flow. For 1 Mpps with 10k new flows/sec,
   that's 10k allocs/sec — fine. Document the cost and offer a
   non-`Default` constructor.
4. **`E::Key: Clone` in `lru_order`.** We store keys twice (once in
   HashMap, once in LRU bookkeeping). For a 32-byte key × 100k
   flows, that's ~3 MiB extra. Acceptable.
5. **`FlowEvents` SmallVec capacity 2.** Most packets emit ≤2
   events. Some sequences (Started + Established + Packet) emit 3.
   Bump to 3 if benchmarks show spillover. Easy fix.
6. **Sweep ticking on `tokio::time::Interval`.** Fires every 1s.
   At low packet rates the stream may yield from `poll_tick` even
   when no events; ensure no busy-loop. Test by running an empty
   stream for 5s and confirming no CPU spin.
7. **`FlowEvent::Packet` includes len; users who want full payload
   need plan 03's reassembler.** Document the difference.
8. **Sweep emits multiple events at once.** A long-idle session
   sweep can emit 100+ Ended events. The `pending` queue absorbs
   them. Stream consumer drains one per `poll_next` call. No issue
   in practice but worth a sustained-load test.
9. **Per-flow user-state `S` must be `Send + 'static`** because the
   tracker outlives any single async task scope (in the FlowStream
   case). Document.

---

## Effort

- LOC: ~700 (design estimate).
  - `event.rs`: ~100
  - `tracker.rs`: ~350
  - `tcp_state.rs`: ~150
  - `history.rs`: ~30
  - `flow_stream.rs`: ~150 (in `netring`)
- Tests: ~500 LOC.
- Examples: ~300 LOC.
- Time: 2.5 days.
