# Async / tokio guide

netring's recommended API is the async one. The async wrappers register
the underlying socket fd with tokio's reactor (via [`AsyncFd`]), so
readiness waits use the same epoll the rest of your tokio program is
already paying for. Zero-copy semantics carry through to the async path.

This guide walks through the four async types, picks the right entry
point per use case, and documents the `Send`/`!Send` rules.

## The four async types

| Type | Backend | Direction | Feature |
|------|---------|-----------|---------|
| [`AsyncCapture<S>`](#asynccapture) | AF_PACKET (or any `PacketSource + AsRawFd`) | RX | `tokio` |
| [`AsyncInjector`](#asyncinjector) | AF_PACKET | TX | `tokio` |
| [`AsyncXdpSocket`](#asyncxdpsocket) | AF_XDP | RX + TX (one fd) | `tokio + af-xdp` |
| [`Bridge::run_async`](#bridge) | AF_PACKET (paired) | bidirectional | `tokio` |

All four are cancel-safe at every `await` point: dropping a future
between awaits abandons the readiness wait without affecting kernel
state, and the next call re-arms via the reactor.

## AsyncCapture

```toml
[dependencies]
netring = { version = "0.21", features = ["tokio"] }
```

```rust,no_run
let mut cap = netring::AsyncCapture::open("eth0")?;
```

`AsyncCapture::open(iface)` is shorthand for
`AsyncCapture::new(Capture::open(iface)?)`. For configured captures use
the builder:

```rust,no_run
use netring::{AsyncCapture, Capture, FanoutMode, RingProfile};
let cap = Capture::builder()
    .interface("eth0")
    .profile(RingProfile::HighThroughput)
    .promiscuous(true)
    .fanout(FanoutMode::Cpu, 42)
    .build()?;
let mut acap = AsyncCapture::new(cap)?;
```

### Three reception modes

There are three ways to take a batch off `AsyncCapture`. They differ in
ergonomics and `Send`-ness.

#### 1. Guarded (recommended)

```rust,no_run
let mut cap = netring::AsyncCapture::open("eth0")?;
loop {
    let mut guard = cap.readable().await?;
    if let Some(batch) = guard.next_batch() {
        for pkt in &batch {
            // zero-copy access to packet data
            let _ = pkt.data();
        }
    }
    // guard drops, releasing tokio's readiness flag iff next_batch was None
}
```

The guard manages tokio's readiness flag for you: it clears ready only
when `next_batch` returned `None`, eliminating the
`wait_then_read` race that the older `wait_readable` API had.

#### 2. Single-call zero-copy

```rust,no_run
let mut cap = netring::AsyncCapture::open("eth0")?;
let batch = cap.try_recv_batch().await?;  // retries on spurious wakeup
for pkt in &batch {
    let _ = pkt.data();
}
```

Convenient sugar over `readable().await?.next_batch()` plus the
spurious-wakeup retry loop. Returns `PacketBatch<'_>` borrowing from
`&mut self`. Same `Send`/`!Send` rules apply (see below).

#### 3. Owned (`Send`-friendly)

```rust,no_run
let mut cap = netring::AsyncCapture::open("eth0")?;
let packets: Vec<netring::OwnedPacket> = cap.recv().await?;
for pkt in &packets {
    let _ = pkt.data.len();
}
```

Returns `Vec<OwnedPacket>` — copies data out of the ring before the
future resolves. Use this when the surrounding future must be `Send`,
e.g. `tokio::spawn`, `mpsc::Sender::send().await`.

#### `!Send` rule

`PacketBatch<'_>` and `XdpBatch<'_>` borrow from the underlying mmap
region (which is `!Sync` because of cached cursor state). Holding one
across an `.await` makes the surrounding future `!Send`:

```rust,compile_fail
tokio::spawn(async move {
    let batch = cap.try_recv_batch().await.unwrap();
    // Compile error: future is !Send because PacketBatch is !Send.
    for pkt in &batch {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        let _ = pkt.data();
    }
});
```

When you need `Send`:
- `cap.recv().await` (yields `Vec<OwnedPacket>` — `Send + 'static`)
- `cap.into_stream()` and consume via `StreamExt::next` (yields the same)
- `cap.try_recv_batch().await` followed by `.iter().map(|p| p.to_owned()).collect()`
  *before* the next `.await`

## AsyncInjector

```rust,no_run
let mut tx = netring::AsyncInjector::open("eth0")?;
tx.send(&[0xff; 64]).await?;     // awaits POLLOUT if ring is full
tx.flush().await?;
tx.wait_drained(std::time::Duration::from_secs(1)).await?;
```

`send()` is the headline feature: when the TX ring is saturated it
**awaits** `POLLOUT` rather than returning `None` — the caller doesn't
have to retry. `wait_drained` blocks until every queued frame has been
transmitted (or the timeout expires).

## AsyncXdpSocket

AF_XDP wrapper. Same three reception modes as `AsyncCapture`, plus
`AsyncInjector`-style backpressured `send`. AF_XDP shares one fd for
both directions, so a single wrapper covers both.

```rust,no_run
use netring::{AsyncXdpSocket, XdpMode, XdpSocket};

// Default mode is RxTx (50/50 UMEM split). For TX-only or RX-only
// workloads, configure via the builder.
let socket = XdpSocket::builder()
    .interface("eth0")
    .queue_id(0)
    .mode(XdpMode::Tx)
    .build()?;
let mut xdp = AsyncXdpSocket::new(socket)?;

xdp.send(&[0xff; 64]).await?;      // awaits POLLOUT when full
xdp.flush().await?;

// RX side (requires an XDP program redirecting to this queue):
// let batch = xdp.try_recv_batch().await?;
```

AF_XDP RX still requires an external XDP program attached to the NIC
(typically via [aya] or [libbpf-rs]). The async wrapper doesn't change
this — it just makes the userland half await-friendly.

## Bridge

```rust,no_run
use netring::bridge::{Bridge, BridgeAction};

let mut bridge = Bridge::builder()
    .interface_a("eth0")
    .interface_b("eth1")
    .build()?;

bridge.run_async(|_pkt, _dir| BridgeAction::Forward).await?;
```

`run_async` uses `tokio::select!` over `AsyncFd::readable()` on both RX
fds — no manual `poll(2)`, the tokio reactor drives the loop. Combine
with `tokio::signal::ctrl_c()` for graceful shutdown:

```rust,no_run
let mut bridge = Bridge::open_pair("eth0", "eth1")?;
tokio::select! {
    res = bridge.run_async(|_, _| BridgeAction::Forward) => res?,
    _ = tokio::signal::ctrl_c() => eprintln!("shutdown"),
}
```

## Stream adapter

`AsyncCapture::into_stream()` and `AsyncXdpSocket::into_stream()` return
adapters implementing [`futures_core::Stream`]. Use with `futures::StreamExt`
combinators:

```toml
[dependencies]
netring = { version = "0.21", features = ["tokio"] }
futures = "0.3"
```

```rust,no_run
use futures::StreamExt;

let mut stream = netring::AsyncCapture::open("eth0")?.into_stream();

// Take 100 batches and count packets:
let total: usize = stream
    .take(100)
    .map(|batch| batch.map(|b| b.len()).unwrap_or(0))
    .fold(0, |acc, n| async move { acc + n })
    .await;

println!("captured {total} packets across 100 batches");
```

Stream items are `Vec<OwnedPacket>`, so the future is `Send` —
combinators that need `Send` (`buffered`, `for_each_concurrent`, etc.)
work without ceremony.

## Patterns

### Capture → mpsc → workers

The canonical fan-out pattern. One task captures, N workers process.

See `examples/async_pipeline.rs` for a complete example. The capture
task uses `cap.recv().await` (returns owned packets) so the future is
`Send`-able into `tokio::spawn`.

### Graceful shutdown

```rust,no_run
let mut cap = netring::AsyncCapture::open("eth0")?;
loop {
    tokio::select! {
        res = cap.readable() => {
            let mut guard = res?;
            if let Some(batch) = guard.next_batch() {
                for pkt in &batch { let _ = pkt.data(); }
            }
        }
        _ = tokio::signal::ctrl_c() => break,
    }
}
let stats = cap.cumulative_stats()?;
println!("done: {stats}");
```

Both arms are cancel-safe.

### Stats + metrics integration

```rust,no_run
let mut cap = netring::AsyncCapture::open("eth0")?;
let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));

loop {
    tokio::select! {
        res = cap.readable() => {
            let mut g = res?;
            if let Some(batch) = g.next_batch() {
                for pkt in &batch { let _ = pkt.data(); }
            }
        }
        _ = tick.tick() => {
            // delta since last tick — feeds into Prometheus etc.
            let delta = cap.stats()?;
            netring::metrics::record_capture_delta("eth0", &delta);
        }
    }
}
```

Pair with `metrics-exporter-prometheus` and the counters surface as
`netring_capture_packets_total{iface="eth0"}` etc.

## Examples

| File | Demonstrates |
|------|--------------|
| `examples/async_capture.rs` | Basic `readable() + next_batch()` |
| `examples/async_stream.rs` | `PacketStream`, hand-polled |
| `examples/async_streamext.rs` | `PacketStream` + `futures::StreamExt` |
| `examples/async_inject.rs` | `AsyncInjector` with backpressure |
| `examples/async_signal.rs` | Ctrl-C graceful shutdown |
| `examples/async_pipeline.rs` | mpsc fan-out, multi-worker |
| `examples/async_bridge.rs` | `Bridge::run_async` + Ctrl-C |
| `examples/async_xdp.rs` | `AsyncXdpSocket` (feature: `af-xdp`) |
| `examples/async_metrics.rs` | `tokio::time::interval` + metrics |

## Declarative Monitor (0.21+)

The high-level `Monitor::builder()` API composes the async types
above (one `AsyncCapture` per interface, plus internally
generated owned-batch futures) behind a typed handler graph.
Key async facts:

- **Monitor is `Send`.** Since 0.21 + flowscope 0.13
  (`Driver<E>: Send + Sync` unconditional), `Monitor: Send`
  unconditionally and plain `#[tokio::main]` (multi-thread)
  works without ceremony.
- **The run-loop future is `Send + 'static` (since 0.23).** The
  future returned by `run_for` / `run_until` / `run_until_signal`
  / `run_until_idle` can be `tokio::spawn`'d onto its own worker
  task — you no longer have to keep it on the main task with
  `tokio::select!` (that still works; spawning is now also an
  option). The capture's owned-batch run path is `Send` and the
  async-dispatch path no longer holds a raw pointer across
  `.await`. The one tradeoff: `on_async` handlers must return
  `Send` futures (the same rule `tokio::spawn` imposes) — handlers
  that capture `Arc<…>` and do I/O already satisfy it. See
  `examples/monitor/multi_thread_default.rs`.
- **Backpressure contract (the capture task never blocks).** When
  you fan anomalies out to a downstream task, the capture task must
  not stall on a slow consumer. Two `ChannelSink` shapes encode the
  choice: `ChannelSink::channel()` is **unbounded** (never drops, but
  a slow consumer grows memory without bound), while
  `ChannelSink::bounded(cap)` returns `(sink, receiver, dropped)` and
  **never blocks** — when the channel is full the anomaly is dropped
  and the `Arc<AtomicU64>` `dropped` counter is incremented. Prefer
  `bounded` in production and surface `dropped` through your metrics;
  silent unbounded growth and silent drops are both failure modes a
  trustworthy monitor makes visible. Broadcast subscribers
  (`subscribe::<P>()`) have the same property via tokio-broadcast
  `Lagged` (slow subscribers miss messages, they don't stall capture).
- **Subscribers are `Stream`s.**
  `Monitor::subscribe::<P>() -> EventStream<P::Message>` returns
  a `futures_core::Stream + Unpin` backed by
  `tokio::sync::broadcast`. Plug into any `StreamExt`
  combinator. `Lagged(n)` arrives when a consumer falls behind.
- **Run modes** —
  - `run_until_signal()` — SIGINT/SIGTERM via
    `tokio::signal::unix`.
  - `run_for(d)` / `run_until(deadline)` — bounded.
  - `run_until_idle(window)` — exit after `window` of no event.
  - `replay()` — drive a `pcap_source(...)` configuration
    instead of live capture; `pcap_speed_factor(f)` paces
    via `tokio::time::sleep`.
- **Graceful drain.** `MonitorBuilder::drain_timeout(d)`
  schedules a final `FlowEnded` sweep on shutdown — handlers
  see the last batch of in-flight flows before the runtime
  exits.
- **Per-CPU sharding.**
  `ShardedRunner::new(iface, FanoutMode::Cpu, group_id, n,
  build_shard)` spawns N independent `Monitor` instances bound
  to the same `PACKET_FANOUT` group. Each shard owns its own
  state map + dispatcher; the kernel does the work-stealing.
  The closure-builder pattern (`Arc<dyn Fn(MonitorBuilder)
  -> MonitorBuilder>`) means user code stays declarative.

See `examples/monitor/` for full demos and
[`MIGRATING_0.20_TO_0.21.md`](MIGRATING_0.20_TO_0.21.md) for
the Send-sweep recipe in detail.

[`AsyncFd`]: https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFd.html
[`futures_core::Stream`]: https://docs.rs/futures-core/latest/futures_core/stream/trait.Stream.html
[aya]: https://crates.io/crates/aya
[libbpf-rs]: https://crates.io/crates/libbpf-rs
