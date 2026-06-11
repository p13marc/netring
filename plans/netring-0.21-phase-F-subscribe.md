# netring 0.21 Phase F — Streaming consumer (`monitor.subscribe`)

## 1. Summary

`monitor.subscribe::<E>()` returns a stream-style receiver of events. Consumers can read live events without registering a Handler. Backed by flowscope 0.13.0's `BroadcastSlotHandle<M, K>` — each subscriber sees every message, and dropped subscribers prune automatically.

## 2. Status

Not started. Depends on Phase H.1 (flowscope 0.13.0) and Phase A.1 (`Arc<dyn Fn>` for the dispatcher's internal subscriber-list state).

## 3. Prerequisites

- Phase H.1 — flowscope 0.13.0 dep bump.
- flowscope's `BroadcastSlotHandle` 0.13.0 limitation: session-shaped protocols only (`session_on_ports_broadcast_each`). Datagram (DNS, ICMP) and heuristic broadcast variants defer to flowscope 0.14.

## 4. Out of scope

- Datagram/heuristic subscribe — deferred until flowscope 0.14 ships the variants.
- Backpressure beyond `BroadcastSlotHandle`'s built-in `drain_n` (Phase A doesn't add new flow control on top).
- Replaying buffered events to late subscribers. Subscribers see only events from registration forward.

## 5. Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/monitor/mod.rs` | `Monitor::subscribe::<E>() -> EventStream<E::Payload>`; `MonitorBuilder::with_broadcast::<P>()` opt-in marker |
| New | `src/monitor/subscribe.rs` | `EventStream<T>` wrapper over `BroadcastSlotHandle<T, FiveTupleKey>` |
| Modify | `src/monitor/registry.rs` | Track which protocols opted into broadcast at build time |
| Modify | `src/protocol/mod.rs` | `Protocol::register_broadcast(builder) -> Result<BroadcastSlotHandle<...>>` companion to `register` |
| New | `examples/monitor/stream_consumer.rs` | Demo: subscribe to HTTP messages from a separate task |

## 6. API

### F.1 — Subscribe + builder marker

```rust
impl MonitorBuilder {
    /// Opt protocol `P` into broadcast delivery. Required before
    /// `monitor.subscribe::<P>()` works for this protocol.
    /// Calls flowscope's `session_on_ports_broadcast_each` instead
    /// of the default `session_on_ports`.
    pub fn with_broadcast<P: Protocol>(self) -> Self { … }
}

impl Monitor {
    /// Subscribe to events of type `E`. Returns a stream-like receiver.
    /// The protocol that owns `E` must have been registered via
    /// `with_broadcast::<P>()` at build time.
    pub fn subscribe<E: Event>(&self) -> Result<EventStream<E::Payload>> { … }
}

// src/monitor/subscribe.rs
pub struct EventStream<T> {
    handle: flowscope::driver::BroadcastSlotHandle<T, FiveTupleKey>,
    drain_buf: Vec<flowscope::driver::SlotMessage<T, FiveTupleKey>>,
}

impl<T: Send + Clone + 'static> EventStream<T> {
    /// Drain pending events into the caller's buffer.
    /// Lossy: if the stream has buffered more than `max_pending`,
    /// older messages are dropped (per BroadcastSlotHandle's per-subscriber queue).
    pub fn recv_many(&mut self, out: &mut Vec<T>, max: usize) -> usize { … }

    /// Single-message convenience. Returns `None` when no messages pending.
    pub fn try_recv(&mut self) -> Option<T> { … }
}

// futures_core is already an optional dep gated on the `tokio` feature
// (Cargo.toml: `tokio = ["dep:tokio", "dep:tokio-stream", "dep:futures-core"]`).
// EventStream itself only exists under `tokio`, so Stream impl is unconditional
// within the existing feature scope — no new feature flag needed.
impl<T> futures_core::Stream for EventStream<T> { … }
```

### F.2 — `stream_consumer.rs` example

```rust
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let monitor = Monitor::builder()
        .interface("eth0")
        .protocol::<Http>()
        .with_broadcast::<Http>()
        .sink(StdoutSink::default())
        .build()?;

    let mut http_stream = monitor.subscribe::<Http>()?;

    // Consumer task reads HTTP messages independent of the run loop.
    let consumer = tokio::spawn(async move {
        let mut buf = Vec::new();
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let n = http_stream.recv_many(&mut buf, 32);
            for msg in buf.drain(..) {
                println!("http: {:?}", msg);
            }
        }
    });

    monitor.run_until_signal().await?;
    consumer.abort();
    Ok(())
}
```

## 7. Implementation steps

1. **F.1** — extend `Protocol` trait with `register_broadcast(builder) -> Result<BroadcastSlotHandle<...>>`. Default impl uses `register` then adapts; explicit override for session-shaped protocols can call `session_on_ports_broadcast_each` directly.
2. **F.2** — `MonitorBuilder::with_broadcast::<P>()` records the marker; at build time, protocols opted into broadcast use the broadcast slot constructor.
3. **F.3** — `Monitor::subscribe::<E>()` looks up the protocol's broadcast handle, calls `.clone()` (adds a new subscriber), wraps in `EventStream<E::Payload>`.
4. **F.4** — implement `futures_core::Stream for EventStream<T>` (always-on under `tokio` feature; futures-core is already a `tokio`-gated dep).
5. **F.5** — example + matching test.

## 8. Tests

- `tests/subscribe::http_message_visible_to_subscriber` — synthetic HTTP traffic; subscriber drains messages.
- `tests/subscribe::clone_of_subscriber_doubles_drain` — second clone confirms broadcast (both see every message), not competitive consumption.
- `tests/subscribe::subscriber_drop_prunes_subscriber_list` — drop a subscriber, monitor continues without it.
- `tests/subscribe::not_opted_in_returns_error` — `subscribe::<Http>()` without `with_broadcast::<Http>()` returns `Error::NotBroadcast`.
- Doctest on `Monitor::subscribe`.

## 9. Acceptance criteria

- `cargo build --example monitor_stream_consumer --features "tokio,flow,http"` builds.
- A subscriber + a registered `on_ctx::<Http>` handler both see every HTTP message (broadcast preserves the dispatched-handler path).
- Dropping a subscriber doesn't deadlock the run loop.
- Zero-alloc bench unchanged (subscribe is opt-in; protocols not in `with_broadcast` use the existing `SlotHandle` path).

## 10. Risks

- **R1 — flowscope 0.13 limitation: session only.** DNS, ICMP (datagram-shaped) and heuristic protocols can't broadcast yet. Documented. Track flowscope 0.14 for the variants.
- **R2 — `M: Clone` bound.** flowscope's broadcast requires `M: Send + Clone + 'static`. Every shipped `Protocol::Message` already meets this (HttpMessage, DnsMessage, TlsMessage are all Clone via Bytes). Verified.
- **R3 — Subscriber memory growth.** Per-subscriber queue is unbounded. Slow consumers see queue growth. Documented; consumers use `recv_many` with a cap.
- **R4 — Two paths for the same event.** Subscribers AND handlers both receive every event. This is intentional (subscribe is additive to the dispatch path), but document the implication: a side-effecting handler runs before any subscriber sees the event.

## 11. Effort

- LoC delta: +300 (subscribe.rs ~150, builder marker ~50, protocol trait extension ~50, example + tests ~50).
- Time estimate: **~1 day** (was 3, then 1; flowscope 0.13's `BroadcastSlotHandle` does the heavy lifting).

## 12. Provenance

- §3.4 (`monitor.subscribe::<E>`) → F.1.
- flowscope 0.13.0 plan 150 (`BroadcastSlotHandle`) ships the upstream foundation.
- Original "Arc-allocate per dispatch when subscribers > 0" gating concern is moot — flowscope handles it via the broadcast slot's internal subscriber tracking.
