# Plan 30 — `Conversation<E>` aggregate

## Summary

Sugar over `flow_stream + with_async_reassembler`: bundle a flow's
two byte streams (Initiator-side and Responder-side) into a single
`Stream<Item = ConversationChunk>`. Removes the spawn-task-per-flow
boilerplate that `channel_factory` requires for the simple "I just
want all the bytes from this flow" use case.

## Status

Not started.

## Prerequisites

- Plans 00–04 published.
- Plan 22 (HTTP) or 23 (TLS) ideally landed first — they're the
  workloads that motivate this abstraction.

## Out of scope

- Replacing `with_async_reassembler` / `channel_factory` — those
  remain available for users who want full control.
- Per-message framing (that's Plan 31's `SessionParser`).

---

## Why this abstraction

Today, getting both directions' bytes for a flow looks like:

```rust
let mut events = cap
    .flow_stream(FiveTuple::bidirectional())
    .with_async_reassembler(channel_factory(|key, side| {
        let (tx, mut rx) = mpsc::channel(64);
        tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                // process...
            }
        });
        tx
    }));
while let Some(evt) = events.next().await { /* lifecycle events */ }
```

The user has to:
1. Spawn a task per (flow, side).
2. Wire up the mpsc channel.
3. Manage join handles if they care about parser-task results.
4. Separately consume `FlowEvent`s from the main stream.

For "give me both byte streams in one async iterator", we ship:

```rust
let mut convs = cap
    .flow_stream(FiveTuple::bidirectional())
    .into_conversations();

while let Some(conv) = convs.next().await {
    let conv = conv?;
    println!("flow {} <-> {}", conv.key.a, conv.key.b);
    while let Some(chunk) = conv.next_chunk().await {
        match chunk {
            ConversationChunk::Initiator(bytes) => process_request(bytes),
            ConversationChunk::Responder(bytes) => process_response(bytes),
            ConversationChunk::Closed { reason } => break,
        }
    }
}
```

One stream, no manual spawning, but each `Conversation` is itself
async-iterable.

---

## Files

### NEW

```
netring/src/async_adapters/
└── conversation.rs       # Conversation<K> + ConversationStream<S, E>
```

### MODIFIED

- `netring/src/async_adapters/mod.rs` — add `pub mod conversation;`
  under `flow + tokio` features.
- `netring/src/lib.rs` — re-export.

---

## API

```rust
use bytes::Bytes;
use netring_flow::{FlowEvent, FlowSide};

/// One side's byte stream + flow lifecycle status.
pub struct Conversation<K> {
    pub key: K,
    pub started_at: Timestamp,
    initiator_rx: mpsc::Receiver<Bytes>,
    responder_rx: mpsc::Receiver<Bytes>,
    /// Set after EndedFor when the underlying flow ends.
    end_reason: Arc<Mutex<Option<EndReason>>>,
}

#[derive(Debug, Clone)]
pub enum ConversationChunk {
    Initiator(Bytes),
    Responder(Bytes),
    /// Flow ended; no more chunks will follow.
    Closed { reason: EndReason },
}

impl<K> Conversation<K> {
    /// Get the next byte chunk from either side.
    ///
    /// Returns `None` when both sides' channels have closed AND the
    /// flow has ended. Otherwise alternates fairly between sides
    /// (selects whichever has data ready).
    pub async fn next_chunk(&mut self) -> Option<ConversationChunk>;

    /// Drain the initiator side specifically.
    pub async fn next_initiator(&mut self) -> Option<Bytes>;

    /// Drain the responder side specifically.
    pub async fn next_responder(&mut self) -> Option<Bytes>;
}

/// Stream of `Conversation`s.
///
/// Each new flow becomes a new `Conversation`. The outer stream
/// yields conversations in the order their flows are first seen.
pub struct ConversationStream<S, E>
where
    S: PacketSource + AsRawFd,
    E: FlowExtractor,
{
    flow_stream: FlowStream<S, E, (), AsyncReassemblerSlot<E::Key, ConversationFactory<E::Key>>>,
    /// Pending conversations waiting to be yielded.
    new_conversations: VecDeque<Conversation<E::Key>>,
}

impl<S, E> Stream for ConversationStream<S, E>
where ...
{
    type Item = Result<Conversation<E::Key>, Error>;
    fn poll_next(...) -> Poll<...>;
}

impl<S, E> FlowStream<S, E, (), NoReassembler> {
    /// Convert into a `ConversationStream` that yields one
    /// `Conversation` per flow.
    ///
    /// Each conversation owns two channels (init + resp); chunks
    /// land in them as the flow progresses.
    pub fn into_conversations(self) -> ConversationStream<S, E>
    where E::Key: Clone + Send + Sync + 'static;
}
```

---

## Implementation

The trick: `ConversationFactory<K>` is an `AsyncReassemblerFactory`
that, on each new flow, builds **both** sides' channels and yields
the matching `Conversation` to a side queue (`new_conversations`)
so the outer `Stream` can hand it to the user.

```rust
struct ConversationFactory<K> {
    pending_emit: Arc<Mutex<VecDeque<Conversation<K>>>>,
    /// For each new (key), build a Conversation if one isn't already
    /// in flight. We need both sides to share the same Conversation
    /// instance — track via a (key -> Conversation) intermediate map.
    in_flight: Arc<Mutex<HashMap<K, ConvBuilder<K>>>>,
}

struct ConvBuilder<K> {
    key: K,
    init_tx: Option<mpsc::Sender<Bytes>>,
    resp_tx: Option<mpsc::Sender<Bytes>>,
    /// Set once both sides' channels exist.
    conv: Option<Conversation<K>>,
}

impl<K> AsyncReassemblerFactory<K> for ConversationFactory<K>
where K: Eq + Hash + Clone + Send + Sync + 'static
{
    type Reassembler = ConvSideReassembler<K>;

    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> ConvSideReassembler<K> {
        let mut in_flight = self.in_flight.lock().unwrap();
        let builder = in_flight.entry(key.clone()).or_insert_with(|| ConvBuilder { ... });
        let (tx, rx) = mpsc::channel::<Bytes>(64);
        match side {
            FlowSide::Initiator => builder.init_tx = Some(tx.clone()),
            FlowSide::Responder => builder.resp_tx = Some(tx.clone()),
        }
        // If both sides now have channels, build the Conversation
        // and emit it via pending_emit.
        if builder.init_tx.is_some() && builder.resp_tx.is_some() {
            let (init_rx, resp_rx) = ...;
            let conv = Conversation { key: key.clone(), ..., initiator_rx: init_rx, responder_rx: resp_rx };
            self.pending_emit.lock().unwrap().push_back(conv);
        }
        ConvSideReassembler { tx }
    }
}
```

The `ConversationStream::poll_next` checks `pending_emit` first and
yields any new conversations before pulling from the inner
`FlowStream`. The inner `FlowStream` runs as before, dispatching
bytes via the factory's reassemblers.

### Lifecycle

When the underlying flow emits `FlowEvent::Ended`:
- Both side reassemblers' `fin()` (or `rst()`) fire.
- Senders drop → receivers see `recv() → None`.
- `Conversation::next_chunk` then returns `Some(Closed { reason })`
  followed by `None`.

---

## Edge cases

- **Unidirectional flows** (only one side ever sends data). The
  Conversation builder waits for both sides; we'd never emit it.
  **Decision**: emit on `Started` (i.e., as soon as the flow is
  seen), with both channels created upfront. The "no responder
  data" case just means `next_responder()` returns `None` early.
- **Already-Established flows** (capture started mid-stream). We
  see the first packet from whichever side; same fix applies —
  emit Conversation on first packet, both channels exist.
- **Drop order**: if the user drops the `Conversation` early, the
  underlying receivers drop, the senders see `try_send` failures,
  and bytes are silently dropped. The flow continues in the inner
  tracker but bytes are gone. Document.

---

## Tests

### Unit

- `single_flow_emits_one_conversation` — synthetic 3WHS + data,
  expect 1 conversation yielded.
- `next_chunk_alternates_fairly` — stress test with both sides
  sending; verify rough fairness.
- `closed_after_fin` — flow ends, `next_chunk` returns `Closed`
  then `None`.

### Integration

- `pcap_http_session_via_conversation` — using Plan 12's
  `http_session.pcap`, drive via Conversation, accumulate both
  sides' bytes, verify request line is in initiator stream and
  response line is in responder stream.

---

## Acceptance criteria

- [ ] `Conversation` + `ConversationStream` compile.
- [ ] `into_conversations` available on `FlowStream`.
- [ ] ≥3 unit tests pass.
- [ ] ≥1 integration test using a pcap fixture.
- [ ] doctest in `lib.rs` shows the headline usage.
- [ ] Workspace clippy clean.

---

## Risks

1. **Channel buffer sizing.** Default 64 is fine for most
   workloads; high-throughput flows fill it and backpressure kicks
   in (good). Make it configurable via
   `into_conversations_with_capacity(N)`.
2. **Memory: O(flows × buffer_size × 2).** For 100k flows × 64 × 2
   slots × ~1 KiB = ~12 GiB worst case. Document. Users who run
   massive concurrency need a different pattern (sample, filter, or
   use Plan 31's session parser with bounded internal buffers).
3. **Conversation ordering.** "First seen" = when both sides have
   sent something (or when `Started` fires). Fairness across
   conversations isn't guaranteed beyond FIFO of new-flow events.

---

## Effort

- LOC: ~400.
- Time: 1 day.
