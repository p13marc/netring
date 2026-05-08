# Plan 03 — Reassembler hooks (sync + async)

## Summary

Land the `Reassembler` trait + `BufferedReassembler` + factory in
`netring-flow` (sync, runtime-free). Land `AsyncReassembler` trait +
`channel_factory` helper in `netring` (async, gated by `flow + tokio`).
Wire both into `FlowStream` via `with_reassembler` (sync) and
`with_async_reassembler` (async).

After this plan, the user can hand off TCP byte streams to a parser
of their choice (`protolens`, `httparse`, custom) with backpressure
all the way to the kernel ring.

## Status

Not started.

## Prerequisites

- [Plan 00](./00-workspace-split.md), [Plan 01](./01-flow-extractor.md),
  [Plan 02](./02-flow-tracker.md) complete.

## Out of scope

- Shipping a TCP reassembly engine (out-of-order buffer, segment
  reorder). We only hook; users plug in `protolens` / their own.
- L7 protocol parsing.
- A `protolens` integration as a runtime dep. We ship a
  documentation example only.

---

## Files

### NEW (in `netring-flow`)

```
netring-flow/src/
└── reassembler.rs   # Reassembler trait, ReassemblerFactory<K>, BufferedReassembler
```

### NEW (in `netring`)

```
netring/src/async_adapters/
└── async_reassembler.rs   # AsyncReassembler trait, AsyncReassemblerFactory<K>, channel_factory
```

### MODIFIED

- `netring-flow/src/lib.rs` — re-export `reassembler::*` under
  `reassembler` feature.
- `netring-flow/Cargo.toml` — add `reassembler` feature (no extra
  deps; the trait + buffered impl are pure std).
- `netring/Cargo.toml` — add optional `bytes` dep, gated by
  `flow + tokio`.
- `netring/src/async_adapters/flow_stream.rs` (from plan 02) —
  add `with_reassembler` and `with_async_reassembler` methods to
  `FlowStream`. Drive reassembler dispatch in `poll_next`.

### NEW (examples)

- `netring/examples/async_flow_channel.rs` — headline
  `channel_factory` usage with spawned tasks per (flow, side).
- `netring/examples/async_flow_protolens.rs` — bridge to
  `protolens` via `AsyncReassembler` (gated behind a dev-feature
  `protolens-example`).
- `netring-flow/examples/pcap_buffered_reassembly.rs` — sync,
  pcap input, `BufferedReassembler` per flow.

---

## API

### `netring-flow/src/reassembler.rs`

```rust
use crate::event::FlowSide;

/// Receives TCP segments for one (flow, side). Sync trait — no
/// awaits. For async needs, use `netring::AsyncReassembler` instead.
pub trait Reassembler: Send + 'static {
    /// `payload` borrows from the underlying frame; copy if needed.
    fn segment(&mut self, seq: u32, payload: &[u8]);
    fn fin(&mut self) {}
    fn rst(&mut self) {}
}

pub trait ReassemblerFactory<K>: Send + 'static {
    type Reassembler: Reassembler;
    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> Self::Reassembler;
}

/// Built-in: drop OOO segments, accumulate in-order bytes into a
/// `Vec<u8>` per direction. Drain via `take()`.
pub struct BufferedReassembler {
    buffer: Vec<u8>,
    expected_seq: Option<u32>,
    dropped_segments: u64,
}

impl BufferedReassembler {
    pub fn new() -> Self {
        Self { buffer: Vec::new(), expected_seq: None, dropped_segments: 0 }
    }
    pub fn take(&mut self) -> Vec<u8> { std::mem::take(&mut self.buffer) }
    pub fn dropped_segments(&self) -> u64 { self.dropped_segments }
    pub fn buffered_len(&self) -> usize { self.buffer.len() }
}

impl Reassembler for BufferedReassembler {
    fn segment(&mut self, seq: u32, payload: &[u8]) {
        match self.expected_seq {
            None => {
                self.expected_seq = Some(seq.wrapping_add(payload.len() as u32));
                self.buffer.extend_from_slice(payload);
            }
            Some(exp) if seq == exp => {
                self.expected_seq = Some(seq.wrapping_add(payload.len() as u32));
                self.buffer.extend_from_slice(payload);
            }
            Some(_) => {
                self.dropped_segments += 1;
            }
        }
    }
}

/// Default factory that builds `BufferedReassembler` on demand.
pub struct BufferedReassemblerFactory;

impl<K> ReassemblerFactory<K> for BufferedReassemblerFactory {
    type Reassembler = BufferedReassembler;
    fn new_reassembler(&mut self, _key: &K, _side: FlowSide)
        -> BufferedReassembler { BufferedReassembler::new() }
}
```

### `netring/src/async_adapters/async_reassembler.rs`

```rust
use std::future::Future;
use bytes::Bytes;
use tokio::sync::mpsc;
use netring_flow::FlowSide;

/// Async-shaped reassembler. The flow stream awaits each call, so
/// returning a slow future propagates backpressure all the way back
/// to the kernel ring.
///
/// Uses `Bytes` (not `&[u8]`) so implementors can hold the payload
/// across `.await` points.
pub trait AsyncReassembler: Send + 'static {
    fn segment(&mut self, seq: u32, payload: Bytes)
        -> impl Future<Output = ()> + Send + '_;
    fn fin(&mut self) -> impl Future<Output = ()> + Send + '_ {
        async {}
    }
    fn rst(&mut self) -> impl Future<Output = ()> + Send + '_ {
        async {}
    }
}

pub trait AsyncReassemblerFactory<K>: Send + 'static {
    type Reassembler: AsyncReassembler;
    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> Self::Reassembler;
}

/// Common pattern as a free helper: factory hands out a fresh
/// `mpsc::Sender<Bytes>` per (flow, side); the returned
/// AsyncReassembler does `tx.send(payload).await` on every segment,
/// `tx.close()` on fin/rst.
///
/// Users typically spawn a tokio task inside their closure that
/// consumes the receiver.
pub fn channel_factory<K, F>(make_sender: F)
    -> ChannelFactory<K, F>
where
    F: FnMut(&K, FlowSide) -> mpsc::Sender<Bytes> + Send + 'static,
    K: Clone + Send + 'static,
{
    ChannelFactory { make_sender, _phantom: std::marker::PhantomData }
}

pub struct ChannelFactory<K, F> {
    make_sender: F,
    _phantom: std::marker::PhantomData<fn(&K)>,
}

impl<K, F> AsyncReassemblerFactory<K> for ChannelFactory<K, F>
where
    F: FnMut(&K, FlowSide) -> mpsc::Sender<Bytes> + Send + 'static,
    K: Clone + Send + 'static,
{
    type Reassembler = ChannelReassembler;
    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> ChannelReassembler {
        ChannelReassembler { tx: (self.make_sender)(key, side) }
    }
}

pub struct ChannelReassembler {
    tx: mpsc::Sender<Bytes>,
}

impl AsyncReassembler for ChannelReassembler {
    fn segment(&mut self, _seq: u32, payload: Bytes)
        -> impl Future<Output = ()> + Send + '_
    {
        async move {
            // backpressure: if receiver is slow, this awaits.
            // If receiver is dropped, send returns Err — silently drop.
            let _ = self.tx.send(payload).await;
        }
    }

    fn fin(&mut self) -> impl Future<Output = ()> + Send + '_ {
        async move {
            // Drop the sender so the receiver sees Closed.
            // We can't actually drop self.tx mid-method, so just
            // close the channel (drains).
            // (Strategy: tx is &mut, so we close-on-drop; we may need
            // a separate close signal — see implementation step 5.)
        }
    }
}
```

### `FlowStream` integration (in `netring/src/async_adapters/flow_stream.rs`)

```rust
use netring_flow::{Reassembler, ReassemblerFactory};
use crate::async_adapters::async_reassembler::{AsyncReassembler, AsyncReassemblerFactory};

impl<E: FlowExtractor, S> FlowStream<E, S, NoReassembler> {
    /// Attach a synchronous reassembler. The factory builds one
    /// reassembler per (flow, side). On every TCP packet event with
    /// non-empty payload, `segment(seq, payload)` is called inline.
    pub fn with_reassembler<R>(self, factory: R)
        -> FlowStream<E, S, SyncReassemblerSlot<E::Key, R>>
    where R: ReassemblerFactory<E::Key>;

    /// Attach an async reassembler. Same dispatch shape, but the
    /// futures returned by `segment` / `fin` / `rst` are awaited
    /// inline before the corresponding event is yielded by the stream.
    pub fn with_async_reassembler<R>(self, factory: R)
        -> FlowStream<E, S, AsyncReassemblerSlot<E::Key, R>>
    where R: AsyncReassemblerFactory<E::Key>;
}

// Internal types (private). FlowStream<..., R> is generic over the
// reassembler slot to avoid a per-stream Box and to let the compiler
// monomorphize the dispatch.
pub struct NoReassembler;
pub struct SyncReassemblerSlot<K, R: ReassemblerFactory<K>> {
    factory: R,
    instances: HashMap<(K, FlowSide), R::Reassembler>,
}
pub struct AsyncReassemblerSlot<K, R: AsyncReassemblerFactory<K>> {
    factory: R,
    instances: HashMap<(K, FlowSide), R::Reassembler>,
}
```

The `FlowStream::poll_next` impl branches on the slot type at compile
time (via separate impl blocks for `NoReassembler` / `SyncReassembler*`
/ `AsyncReassembler*`).

---

## Cargo manifest changes

### `netring-flow/Cargo.toml`

```toml
[features]
default     = ["extractors", "tracker", "reassembler"]
extractors  = ["dep:etherparse"]
tracker     = ["dep:ahash", "dep:smallvec", "dep:arrayvec", "dep:lru"]
reassembler = []   # pure std — no extra deps
```

### `netring/Cargo.toml`

```toml
[dependencies]
bytes = { version = "1", optional = true }

[features]
flow = ["parse", "netring-flow/tracker", "netring-flow/reassembler"]
# When tokio + flow are both on, AsyncReassembler is in scope; bytes is needed.
# Cargo conditional dep activation:
# Tokio + flow ⇒ require bytes.
```

The `bytes` dep activation is a bit tricky in Cargo features. The
cleanest:

```toml
[features]
flow = ["parse", "netring-flow/tracker", "netring-flow/reassembler"]
flow-async = ["flow", "tokio", "dep:bytes"]
```

But that adds a feature flag the user has to remember. Alternative:
make `bytes` a transitive activation via a feature pair:

```toml
[features]
flow = ["parse", "netring-flow/tracker", "netring-flow/reassembler"]
tokio = ["dep:tokio", "dep:futures-core", "dep:bytes"]
```

This pulls `bytes` whenever `tokio` is on, even without `flow`.
~50 KB extra; tolerable. Going with this.

---

## Implementation steps

1. **Land `Reassembler` trait + `BufferedReassembler` in `netring-flow`.**
   - `netring-flow/src/reassembler.rs`.
   - Pure std + `crate::event::FlowSide`.
   - `cargo build -p netring-flow --features reassembler` succeeds.
2. **Unit-test `BufferedReassembler`.**
   - In-order bytes are concatenated.
   - OOO segments are dropped, counter increments.
   - `take()` drains and resets buffer.
3. **Land `AsyncReassembler` trait in `netring`.**
   - `netring/src/async_adapters/async_reassembler.rs`.
   - Manually-spelled `impl Future + Send + '_` on each method.
   - Default impls for `fin` / `rst` return `async {}`.
4. **Land `ChannelReassembler` + `channel_factory`.**
   - On `fin` / `rst`: how do we signal the consumer? The simplest
     approach: when the FlowStream finishes a flow (Ended event), it
     drops its `ChannelReassembler` — the sender drops — the
     receiver sees Closed. So `fin` / `rst` are actually no-ops on
     `ChannelReassembler` itself; the close happens via Drop.
   - This means `AsyncReassembler::fin/rst` default is fine.
5. **Wire reassembler into `FlowStream`.**
   - Re-shape `FlowStream<E, S>` (from plan 02) to
     `FlowStream<E, S, R>` with a `R = NoReassembler` default.
   - Add three impl blocks for `Stream`:
     - `impl Stream for FlowStream<E, S, NoReassembler>` — current
       plan-02 behavior.
     - `impl Stream for FlowStream<E, S, SyncReassemblerSlot<K, RF>>`
       — calls `reassembler.segment(seq, payload)` synchronously
       before yielding the corresponding `FlowEvent::Packet`.
     - `impl Stream for FlowStream<E, S, AsyncReassemblerSlot<K, RF>>`
       — awaits the future returned by `reassembler.segment(...)`
       inline. Requires the `Stream`'s `poll_next` to manage a
       pending future (via `Pin<Box<dyn Future>>` or a typed slot).
6. **Manage in-flight async reassembler future.**
   - When `segment(seq, payload)` returns a `Future`, the stream
     can't yield until it completes. Store the future in
     `FlowStream`'s state:
     ```rust
     struct AsyncReassemblerSlot<K, R> {
         factory: R,
         instances: HashMap<(K, FlowSide), R::Reassembler>,
         pending: Option<Pin<Box<dyn Future<Output = (FlowEvent<K>, K, FlowSide)> + Send>>>,
     }
     ```
   - In `poll_next`: if `pending.is_some()`, poll it. Otherwise
     dequeue an event; if it's a `Packet` for TCP with payload,
     create the future and store it.
7. **Reassembler lifecycle on `Ended`.**
   - When the tracker emits `FlowEvent::Ended { reason, .. }`:
     - Take the (key, Initiator) and (key, Responder) reassemblers
       from `instances` HashMap.
     - For sync: call `fin()` or `rst()` synchronously.
     - For async: chain the futures (call `fin()` / `rst()` on
       both, await both before yielding `Ended`).
     - Drop the reassemblers.
8. **Examples.**
   - `netring/examples/async_flow_channel.rs`: see design Part 4
     headline. Spawn a task per flow, log lengths.
   - `netring-flow/examples/pcap_buffered_reassembly.rs`:
     ```rust
     // Read pcap, FlowTracker + with_reassembler(BufferedReassemblerFactory).
     // ... actually since the tracker doesn't expose with_reassembler
     // directly (that's on FlowStream), the example needs to drive
     // reassembly manually:
     //   tracker.track(view)  → FlowEvents
     //   for FlowEvent::Packet { ..., tcp_payload, ... } { reassembler.segment(...) }
     ```
     Hmm — the tracker returns `FlowEvent` which doesn't carry the
     payload bytes. The reassembler is driven by the tracker
     internally only when `with_reassembler` is set. For the sync
     case in `netring-flow`, we'd need either:
     - A `FlowTracker::track_with_reassembler(view, &mut R)` method,
       OR
     - Sync `FlowReassemblyDriver` wrapper analogous to FlowStream.
   - **Decision**: ship a sync wrapper too. Add to `netring-flow`:
     ```rust
     pub struct FlowDriver<E, S, R> {
         tracker: FlowTracker<E, S>,
         reassembler: R,
     }
     impl FlowDriver {
         pub fn track(&mut self, view: PacketView) -> Vec<FlowEvent<E::Key>>;
     }
     ```
     This keeps the sync side feature-complete with the async side.
9. **Land `protolens` example as a dev-feature.**
   - `netring/examples/async_flow_protolens.rs`.
   - In `netring/Cargo.toml`:
     ```toml
     [dev-dependencies]
     protolens = { version = "...", optional = true }
     [features]
     protolens-example = ["dep:protolens"]
     [[example]]
     name = "async_flow_protolens"
     required-features = ["tokio", "flow", "protolens-example"]
     ```
   - Bridge: implement `AsyncReassembler` in terms of a
     `protolens::Prolens` instance + `protolens::Task`.
10. **Update justfile.**
    - `flow-channel *args:` `cargo run -p netring --example async_flow_channel --features tokio,flow -- {{args}}`
    - `flow-protolens *args:` `cargo run -p netring --example async_flow_protolens --features tokio,flow,protolens-example -- {{args}}`
11. **CHANGELOG.**
    - `0.7.0-alpha.3` / `0.1.0-alpha.3`: "Added — Reassembler hook
      (sync + async), channel_factory helper".

---

## Tests

### `netring-flow/tests/reassembler_basic.rs`

- `BufferedReassembler` in-order: feed 3 in-order segments, `take()`
  returns the concatenation.
- OOO: feed seq=100 then seq=200 (skipping seq=110), expect 1
  buffered + 1 dropped.
- `take()` resets state (next segment starts fresh).

### `netring-flow/tests/reassembler_driver.rs`

- `FlowDriver` over a synthetic IPv4-TCP exchange (3WHS + payload +
  FIN).
- Verify Reassembler.segment was called for the payload.
- Verify Reassembler.fin was called on FIN.

### `netring/tests/flow_stream_reassembly.rs` (integration, requires
   `integration-tests`)

- Open AsyncCapture on `lo`, generate a real TCP exchange, attach
  `with_async_reassembler(channel_factory(...))`, verify spawned
  task receives bytes.
- Backpressure test: spawned task sleeps 1s between recvs;
  generate 100 segments quickly; verify the kernel ring eventually
  drops (visible via `cap.statistics()`) — backpressure flows
  end-to-end.
- Drop test: drop the `FlowStream` mid-flow; verify spawned tasks
  exit cleanly.

### Doctest

In `netring/src/async_adapters/async_reassembler.rs`:

```rust
/// ```no_run
/// use netring::AsyncCapture;
/// use netring::flow::extract::FiveTuple;
/// use netring::flow::channel_factory;
/// use bytes::Bytes;
/// use tokio::sync::mpsc;
/// use futures::StreamExt;
///
/// # async fn example() -> std::io::Result<()> {
/// let cap = AsyncCapture::open("eth0")?;
/// let mut events = cap
///     .flow_stream(FiveTuple::bidirectional())
///     .with_async_reassembler(channel_factory(|_key, _side| {
///         let (tx, _rx) = mpsc::channel::<Bytes>(64);
///         tx
///     }));
/// while let Some(_evt) = events.next().await { break; }
/// # Ok(())
/// # }
/// ```
```

---

## Acceptance criteria

- [ ] `Reassembler` + `BufferedReassembler` + factory compile in
      `netring-flow` under `reassembler` feature.
- [ ] `AsyncReassembler` + `channel_factory` + `ChannelReassembler`
      compile in `netring` under `flow + tokio`.
- [ ] `FlowStream::with_reassembler` and
      `FlowStream::with_async_reassembler` compile and type-shift
      correctly.
- [ ] `cargo test -p netring-flow --features reassembler` passes.
- [ ] `cargo build -p netring --features flow,tokio` succeeds.
- [ ] Backpressure integration test passes — slow consumer ⇒
      kernel-level drops visible.
- [ ] `protolens` example builds with `--features protolens-example`.
- [ ] All examples run on `lo` capture without crashing.
- [ ] Workspace clippy clean.
- [ ] `0.7.0-alpha.3` / `0.1.0-alpha.3` tagged.

---

## Risks

1. **Async-trait `Send` bounds.** Manually returning
   `impl Future<Output = ()> + Send + '_` on each method works on
   stable Rust 1.85, but is verbose. If the compiler diagnostics get
   ugly, switch to `trait_variant::make` macro (adds a tiny
   proc-macro dep). Defer that decision to implementation time.
2. **`pending: Option<Pin<Box<dyn Future + Send>>>` in
   `AsyncReassemblerSlot`.** Box per pending future is a small
   alloc (per packet for TCP traffic). Likely 50–100 ns at most;
   acceptable. If perf testing shows it as a hot spot, switch to
   a typed slot via GATs.
3. **`fin`/`rst` await semantics.** When a flow ends, both
   reassemblers' `fin`/`rst` futures must complete before yielding
   `FlowEvent::Ended`. That's two awaits in series — fine, but
   tracking the sub-state in `poll_next` is finicky. Test
   thoroughly for cancellation safety.
4. **`ChannelReassembler` doesn't signal close.** When the flow
   ends, the FlowStream drops the `ChannelReassembler`, which drops
   the `Sender`. The user's spawned task observes `recv() →
   None`. If the user wanted a "graceful EOF" signal vs a "RST"
   signal, they don't get it via `channel_factory`. **Mitigation**:
   document; users who need the distinction implement
   `AsyncReassembler` directly.
5. **Sync `FlowDriver` adds API surface.** It's a thin wrapper, but
   ~80 LOC. Worth it for the sync+pcap users; matches the async
   shape.
6. **Memory: per-flow reassembler instances.** A `BufferedReassembler`
   holds a `Vec<u8>`. For 100k flows × 1 KiB buffer = 100 MiB. User
   needs to drain or use a different reassembler for high-flow-count
   workloads. Document.
7. **Reassembler factory failure.** What if `new_reassembler` panics
   or returns something that fails to `segment` on the first call?
   Stream should propagate as an error or skip that flow.
   **Decision**: panic propagates; log on failure; drop the flow's
   reassembler slot. Document.
8. **`bytes` dep widens whenever `tokio` is on.** Trade-off
   accepted (50KB compiled). Alternative is a separate `flow-async`
   feature flag the user has to remember.

---

## Effort

- LOC: ~450 (design estimate).
  - `netring-flow/reassembler.rs`: ~150
  - `netring-flow` `FlowDriver`: ~80
  - `netring` `async_reassembler.rs`: ~150
  - `FlowStream` integration: ~70
- Tests: ~300 LOC.
- Examples: ~250 LOC (3 examples + protolens dev-only).
- Time: 1.5 days.
