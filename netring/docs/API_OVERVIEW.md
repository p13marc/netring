# API Overview

netring exposes one type per role. There is no high-level/low-level split —
the type you see is the type you use.

## At a glance

| Concept | Type | Backend | Feature |
|---------|------|---------|---------|
| Receive packets | `Capture` | AF_PACKET | core |
| Inject packets | `Injector` | AF_PACKET | core |
| Receive + inject (one fd) | `XdpSocket` | AF_XDP | `af-xdp` |
| Bridge two interfaces | `Bridge` | AF_PACKET | core |
| Async capture | `AsyncCapture<S>` | any | `tokio` |
| Async inject | `AsyncInjector` | AF_PACKET | `tokio` |
| Async stream | `PacketStream<S>` | wraps `AsyncCapture` | `tokio` |
| Channel adapter | `ChannelCapture` | AF_PACKET | `channel` |

Every type with a backing kernel resource has both:

- `Type::open(iface)` — one-liner with defaults
- `Type::builder()` — fluent configuration

## Capture (RX)

```rust,no_run
use netring::Capture;

// Simplest form.
let mut cap = Capture::open("eth0")?;

// Configured.
let mut cap = Capture::builder()
    .interface("eth0")
    .promiscuous(true)
    .block_timeout_ms(60)
    .ignore_outgoing(true)
    .build()?;
```

### Three reception modes

```rust,no_run
// 1. Flat iterator (zero-copy, blocks indefinitely)
for pkt in cap.packets().take(1000) {
    let data: &[u8] = pkt.data();        // borrows from ring
    let _ts = pkt.timestamp();           // nanosecond kernel timestamp
    let _owned = pkt.to_owned();         // copy out for long-lived storage
}

// 2. Bounded iterator
for pkt in cap.packets_for(Duration::from_secs(5)) { /* ... */ }

// 3. Block-level batches with sequence-gap detection
while let Some(batch) = cap.next_batch_blocking(Duration::from_millis(100))? {
    println!("seq={} pkts={} timed_out={}",
        batch.seq_num(), batch.len(), batch.timed_out());
    for pkt in &batch { /* ... */ }
    // batch dropped → block returned to kernel
}
```

### Stats

```rust,no_run
let s = cap.stats()?;             // since last call (resets kernel counters)
let s2 = cap.cumulative_stats()?; // since open (monotonic)
```

## Injector (TX)

```rust,no_run
use netring::Injector;

let mut tx = Injector::builder()
    .interface("eth0")
    .qdisc_bypass(true)    // skip qdisc for lower latency
    .build()?;

if let Some(mut slot) = tx.allocate(64) {
    slot.data_mut()[0..6].copy_from_slice(&[0xff; 6]);  // dst MAC
    slot.set_len(64);
    slot.send();           // mark for transmission
}
tx.flush()?;               // kick kernel to send

// Observability accessors:
let _ = tx.frame_capacity();
let _ = tx.pending_count();
let _ = tx.available_slots();
let _ = tx.rejected_slots();
```

## AF_XDP (`af-xdp` feature)

Kernel-bypass packet I/O via XDP sockets. Pure-Rust `libc` syscalls — no
native C deps. Method names mirror `Capture` for naming parity.

```rust,no_run,ignore
use netring::{XdpMode, XdpSocket};
use std::time::Duration;

// TX-only — no BPF program required. **Must** set XdpMode::Tx, otherwise
// the default (RxTx) prefills half the UMEM and starves the TX path.
let mut xdp = XdpSocket::builder()
    .interface("eth0")
    .queue_id(0)
    .mode(XdpMode::Tx)
    .build()?;

xdp.send(&frame)?;
xdp.flush()?;

// RX (requires an attached XDP program — see `aya`).
if let Some(batch) = xdp.next_batch_blocking(Duration::from_millis(100))? {
    for pkt in &batch {
        println!("{} bytes", pkt.data().len());
    }
}
```

## Bridge

```rust,no_run
use netring::bridge::{Bridge, BridgeAction};

let mut bridge = Bridge::builder()
    .interface_a("eth0")
    .interface_b("eth1")
    .build()?;

bridge.run(|_pkt, _dir| BridgeAction::Forward)?;
```

Async variant under `tokio` feature:

```rust,no_run,ignore
bridge.run_async(|_pkt, _dir| BridgeAction::Forward).await?;
```

## Async (`tokio` feature)

### `AsyncCapture<S>` — three reception entry points

```rust,no_run
use netring::{AsyncCapture, Capture};

let mut cap = AsyncCapture::new(Capture::open("eth0")?)?;

// Guarded zero-copy (recommended).
let mut guard = cap.readable().await?;
if let Some(batch) = guard.next_batch() {
    for pkt in &batch { /* ... */ }
}

// Single-call zero-copy.
let batch = cap.try_recv_batch().await?;

// Owned copies — use when the future must be Send (tokio::spawn etc.).
let packets = cap.recv().await?;
```

### `PacketStream` — futures-compatible

```rust,no_run
use netring::{AsyncCapture, Capture};

let stream = AsyncCapture::new(Capture::open("eth0")?)?.into_stream();
// Use with `futures::StreamExt::next` or `tokio_stream`.
```

### `AsyncInjector` — TX with backpressure

```rust,no_run
use netring::{AsyncInjector, Injector};

let mut tx = AsyncInjector::new(Injector::open("eth0")?)?;
tx.send(&[0xff; 64]).await?;          // awaits POLLOUT if ring is full
tx.flush().await?;
tx.wait_drained(std::time::Duration::from_secs(1)).await?;
```

**TX symmetry (0.25 Phase D).** Stream-inject with rate pacing + egress
timestamps:

```rust,no_run
use netring::{AsyncInjector, Injector, TxPacer};
// Egress timestamps via SO_TIMESTAMPING:
let inj = Injector::builder().interface("eth0").tx_timestamps(true).build()?;
let mut tx = AsyncInjector::new(inj)?;
let frames = futures::stream::iter((0..1000).map(|_| vec![0u8; 64]));
// Send a stream, paced to 10k pps:
tx.send_stream(frames, Some(TxPacer::packets_per_second(10_000.0))).await?;
let _egress_ts = tx.read_tx_timestamp(); // hw-preferred, else software, else None
```

### `ChannelCapture` (runtime-agnostic)

```rust,no_run
use netring::async_adapters::channel::ChannelCapture;

let rx = ChannelCapture::spawn("eth0", 4096)?;
for pkt in &rx {
    println!("{} bytes", pkt.data.len());
}
```

## Flow & session tracking (`flow` feature)

Built on top of [`flowscope`](https://github.com/p13marc/flowscope).
Each stream consumes an `AsyncCapture<S>` and emits typed events.

| Stream | Item | Built via |
|--------|------|-----------|
| [`FlowStream<S, E, U, R>`](https://docs.rs/netring/latest/netring/struct.FlowStream.html) | `FlowEvent<K>` | `cap.flow_stream(extractor)` |
| [`SessionStream<S, E, F>`](https://docs.rs/netring/latest/netring/struct.SessionStream.html) | `SessionEvent<K, M>` (TCP via reassembler) | `cap.flow_stream(ext).session_stream(parser)` |
| [`DatagramStream<S, E, F>`](https://docs.rs/netring/latest/netring/struct.DatagramStream.html) | `SessionEvent<K, M>` (UDP, no reassembler) | `cap.flow_stream(ext).datagram_stream(parser)` |
| [`FlowBroadcast<K>`](https://docs.rs/netring/latest/netring/struct.FlowBroadcast.html) | per-subscriber `FlowEvent<K>` | `flow_stream(...).broadcast(buffer)` |

Each stream chain accepts the same builder knobs:

- `.with_config(FlowTrackerConfig)` — idle timeouts, reassembler caps, overflow policy.
- `.with_dedup(Dedup)` — loopback-aware content dedup before flow extraction.
- `.with_idle_timeout_fn(F)` — per-key idle override (`Fn(&K, Option<L4Proto>) -> Option<Duration>`).
- `.with_monotonic_timestamps(bool)` — clamp NIC timestamps to a running max.
- `.with_pcap_tap(writer)` — record every packet to a `CaptureWriter` before flow tracking.
- `.snapshot_flow_stats()` — borrow-iterator over live `(&K, &FlowStats)`.

The [`StreamCapture`](https://docs.rs/netring/latest/netring/trait.StreamCapture.html)
trait gives all four stream types `capture()`, `capture_stats()`, and
`capture_cumulative_stats()` for out-of-band ring observability +
plan-21 `stream.capture().set_filter(...)` BPF swap.

Parsers (`SessionParser` / `DatagramParser`) get a periodic
[`on_tick`](https://docs.rs/flowscope/latest/flowscope/trait.SessionParser.html#method.on_tick)
hook called on every sweep — useful for unanswered-request timeouts,
heartbeats, any time-driven L7 logic.

### Multi-source (`flow` feature)

`AsyncMultiCapture` fans in N AF_PACKET captures (multi-interface or
per-CPU workers in a fanout group) and yields `TaggedEvent { source_idx, event }`.
See [`docs/scaling.md`](scaling.md) for the recipe +
`FanoutMode` decision matrix.

### Offline pcap (`pcap + flow` features)

| Type | Item | Built via |
|------|------|-----------|
| [`AsyncPcapSource`](https://docs.rs/netring/latest/netring/struct.AsyncPcapSource.html) | `OwnedPacket` | `AsyncPcapSource::open(path).await?` |
| [`PcapFlowStream<E>`](https://docs.rs/netring/latest/netring/struct.PcapFlowStream.html) | `FlowEvent<K>` | `source.flow_events(extractor)` |
| [`PcapSessionStream<E, P>`](https://docs.rs/netring/latest/netring/struct.PcapSessionStream.html) | `SessionEvent<K, M>` | `source.sessions(ext, parser)` |
| [`PcapDatagramStream<E, P>`](https://docs.rs/netring/latest/netring/struct.PcapDatagramStream.html) | `SessionEvent<K, M>` | `source.datagrams(ext, parser)` |

Format (PCAP vs PCAPNG) is auto-detected at `open`. EOF flush via
`Timestamp::MAX` so every still-open flow emits its terminal event.

## Declarative Monitor (0.21+)

The high-level entry point for "watch this interface and react
to typed events". Built on top of the flow / session / parser
machinery above; same kernel and async plumbing.

```rust,ignore
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Monitor::builder()
        .interface("eth0")
        .protocol::<Tcp>()
        .protocol::<Http>()
        .on(|msg: &HttpMessage| {
            println!("{} {}", msg.method, msg.path);
            Ok(())
        })
        .layer(MinSeverity::warning())
        .sink(StdoutJsonSink::default())
        .run_until_signal()
        .await?;
    Ok(())
}
```

### Builder surface

| Method | Purpose |
|---|---|
| `.interface(s)` / `.interfaces([...])` | One or more capture interfaces |
| `.name(s)` | Label surfaced through `Ctx::monitor_name` |
| `.protocol::<P>()` | Enroll a `Protocol` impl (parser + dispatch) |
| `.on(handler)` | Payload-only handler: `Fn(&E::Payload)` |
| `.on_ctx(handler)` | Payload + `&mut Ctx<'_>` handler |
| `.on_async::<E>(handler)` | Boxed-future async handler |
| `.detect(detector_macro)` | Sugar over `.on_ctx(...)` for `detector!` / `pattern_detector!` |
| `.with_broadcast::<P>()` | Enrol a broadcast slot for `subscribe::<P>()` |
| `.state::<T>()` / `.state_init::<T>(initial)` | Register a per-handler `T` state slot |
| `.flow_state::<T>(idle)` | Register a per-flow `T` state map; access via `ctx.flow_state_mut::<T>()` |
| `.counter::<K>(window, bucket)` | Register a `TimeBucketedCounter<K>` slot |
| `.sink(s)` | Anomaly sink (innermost in layer chain) |
| `.layer(L)` | Tower-style middleware wrapping the sink |
| `.tick(period, handler)` | Periodic non-event handler |
| `.fanout(mode, group_id)` | Bind to a `PACKET_FANOUT` group (use with `ShardedRunner`) |
| `.pcap_source(path)` | Source from offline pcap instead of live capture |
| `.pcap_speed_factor(f)` | Replay pacing multiplier (1.0 = wire, `f32::INFINITY` = as-fast) |
| `.drain_timeout(d)` | Graceful drain phase after shutdown signal |
| `.subscribe(sub)` | **(0.25)** register a typed subscription (`packet()`/`flow::<P>()`/`session::<P>()`) — see below |
| `.on_effect::<E>(handler)` | **(0.25)** async read+effect: `Fn(&Payload, &Ctx) -> impl Future<Output=Result<Effects>>` |
| `.export_flows(exporter)` | `FlowRecord` per completed flow (NetFlow/IPFIX/`conn.log` shape) |
| `.export_active_timeout(period)` | **(0.25)** interim `FlowRecord`s for long-lived flows (active timeout) |
| `.xdp_interface(s)` / `.xdp_interface_loaded(s)` | AF_XDP source; `_loaded` (feat `xdp-loader`) attaches the built-in redirect program itself |
| `.xdp_queues(Queues)` | **(issue #6)** capture every RX queue of each `_loaded` AF_XDP interface (`Queues::Auto`), not just queue 0 — removes the silent single-queue under-capture on multi-queue NICs. Default `Single(0)` |
| `.backend_error_policy(p)` | `FailFast` / `SkipSource` / **(0.25)** `Reopen` (rebuild a failed source in place) |
| `.catch_handler_panics(b)` | **(0.25)** convert sync-handler panics to `Error::HandlerPanic` (route via `HandlerErrorPolicy`) |
| `.build()` | Validate + freeze into a `Monitor` |

### Subscriptions (0.25)

The typed front door. Three tiers, each with per-subscription filters that split
into a kernel conjunction (BPF-pushable) + a userspace remainder; `.expr("…")`
parses a runtime filter string into the same `Predicate` AST.

```rust,ignore
use netring::monitor::subscription::{packet, flow, session};

.subscribe(packet().tcp().dst_port(443).to(|view, ctx| Ok(())))   // every matching frame
.subscribe(flow::<Tcp>().bytes_over(1 << 20).to(|evt, ctx| Ok(())))// once, at flow end
.subscribe(session::<Tls>().sni_glob("*.bank").to(|msg, ctx| Ok(())))// each parsed L7 msg
.subscribe(packet().expr("udp and dst port 53")?.to(|view, ctx| Ok(())))
```

| Tier | Constructor | Handler | Fires |
|---|---|---|---|
| packet | `packet()` | `Fn(&PacketView, &mut Ctx)` | every matching frame (pre-tracking) |
| flow | `flow::<P>()` | `Fn(&FlowEnded<P>, &mut Ctx)` | once per matching flow, at its end |
| session | `session::<P>()` | `Fn(&P::Message, &mut Ctx)` | each parsed L7 message that matches |

Combinators: packet — `tcp()`/`udp()`/`dst_port()`/`port()`/`host()`; flow —
`bytes_over()`/`packets_over()`; session — `sni_glob()` (`Tls`) /
`host_glob()` (`Http`) / `qname_glob()` (`Dns`). All also accept `.expr("…")`.

### Run modes

| Method | Behaviour |
|---|---|
| `monitor.run_until_signal()` | Loop until SIGINT/SIGTERM (then drain) |
| `monitor.run_for(Duration)` | Bounded wall-clock window |
| `monitor.run_until(Instant)` | Until a deadline |
| `monitor.run_until_idle(window)` | Exit when no event has fired for `window` |
| `monitor.replay()` | Drain a `pcap_source(...)` configuration |
| `monitor.subscribe::<P>()` | Mint an `EventStream<P::Message>` (`futures_core::Stream`) |

### Per-CPU sharding

```rust,ignore
use std::sync::Arc;
use netring::prelude::*;
use netring::monitor::ShardedRunner;

let runner = ShardedRunner::new(
    "eth0",
    FanoutMode::Cpu,
    0xC001,
    num_cpus::get(),
    Arc::new(|b: MonitorBuilder| {
        b.protocol::<Tcp>().sink(StdoutJsonSink::default())
    }),
)?;
runner.run_until_signal().await?;
```

### Build-time validation

`BuildError` rejects misconfigurations at `.build()`:

| Variant | Trigger |
|---|---|
| `HandlerForUnregisteredProtocol { event }` | `.on::<E>(...)` without `.protocol::<E>()` |
| `CounterNotRegistered { key_type }` | `ctx.counter_mut::<K>()` for un-registered `K` |
| `ProtocolNotBroadcast { protocol }` | `subscribe::<P>()` without `.with_broadcast::<P>()` |
| `PcapSourceRequired` | `monitor.replay()` without `.pcap_source(...)` |
| `MultiInterfaceWithFanout` | `fanout` + N > 1 interfaces (forbidden by the shard model) |
| `TooManyEventTypes` | > 16 distinct typed-event slots |

### Anomaly sinks

| Sink | Feature | Output |
|---|---|---|
| `StdoutSink` | core | One-line human-readable text |
| `StdoutJsonSink` | `serde` | One-line JSON (RFC 8259) |
| `TracingSink` | core | `tracing::event!` at matching `Level` |
| `ChannelSink` | core | tokio mpsc of `OwnedAnomaly` |
| `EveSink` | `eve-sink` | Suricata-compatible EVE JSON |
| `MetricsSink` | `metrics` | Prometheus-style counter facade |

### Middleware layers

`MinSeverity`, `DedupeAnomalies`, `RateLimitAnomalies`,
`Sample` (inline xorshift64*), `Tee` (`into(secondary)` /
`factory(|| sink)` per-shard minting).

### Cargo features (Monitor)

| Feature | Pulls |
|---|---|
| `monitor` | `tokio + channel + flow + parse + http + dns + tls + icmp + emit + serde + metrics` |
| `monitor-quickstart` | `monitor + eve-sink + file-hash` (app-tier umbrella) |
| `eve-sink` | EveSink only |
| `metrics` | MetricsSink only |
| `file-hash` | flowscope `Sha256Sink + FileType` |
| `serde` | Anomaly + sink JSON output |

## Configuration reference

### CaptureBuilder

| Method | Default | Description |
|--------|---------|-------------|
| `.interface(name)` | required | Network interface |
| `.profile(...)` | Default | Apply a [`RingProfile`] preset |
| `.block_size(bytes)` | 4 MiB | Block size (power of 2, multiple of PAGE_SIZE) |
| `.block_count(n)` | 64 | Number of blocks |
| `.frame_size(bytes)` | 2048 | Min frame size (multiple of 16, ≥ 68) |
| `.snap_len(bytes)` | unset | Shortcut: sets frame_size to fit only the first N bytes |
| `.block_timeout_ms(ms)` | 60 | Block retirement timeout |
| `.fill_rxhash(bool)` | true | Kernel populates `tp_rxhash` |
| `.promiscuous(bool)` | false | Promiscuous mode |
| `.ignore_outgoing(bool)` | false | Skip outgoing packets |
| `.busy_poll_us(us)` | disabled | Kernel NIC polling timeout |
| `.reuseport(bool)` | false | `SO_REUSEPORT` |
| `.rcvbuf(bytes)` | unset | `SO_RCVBUF` (or `SO_RCVBUFFORCE` if `rcvbuf_force`) |
| `.timestamp_source(src)` | Software | Timestamp source |
| `.poll_timeout(dur)` | 100ms | Iterator poll timeout |
| `.fanout(mode, id)` | disabled | Join fanout group |
| `.fanout_flags(flags)` | empty | Fanout options |
| `.bpf_filter(filter)` | disabled | Classic BPF filter (`BpfFilter`, built via `BpfFilter::builder()…build()` or `BpfFilter::new(insns)?`) |

### InjectorBuilder

| Method | Default | Description |
|--------|---------|-------------|
| `.interface(name)` | required | Network interface |
| `.frame_size(bytes)` | 2048 | TX frame size |
| `.frame_count(n)` | 256 | Number of TX frames |
| `.qdisc_bypass(bool)` | false | Skip qdisc layer |
| `.tx_timestamps(bool)` | false | **(0.25)** request egress `SO_TIMESTAMPING`; read via `read_tx_timestamp()` |

### XdpSocketBuilder

| Method | Default | Description |
|--------|---------|-------------|
| `.interface(name)` | required | Network interface |
| `.queue_id(id)` | 0 | NIC queue to bind |
| `.frame_size(size)` | 4096 | UMEM frame size |
| `.frame_count(count)` | 4096 | UMEM frame count |
| `.mode(mode)` | RxTx | RX/TX/RxTx/Custom split |
| `.need_wakeup(bool)` | true | `XDP_USE_NEED_WAKEUP` optimization |
| `.hugepages(bool)` | false | **(0.25)** back the UMEM with `MAP_HUGETLB` (graceful fallback) |
| `.numa_node(n)` | — | **(0.25)** `mbind` the UMEM to NUMA node `n` (best-effort) |
| `.promiscuous(bool)` | false | put the interface in promiscuous mode for the socket's lifetime (issue #4); self-cleaning `PACKET_MR_PROMISC` guard. The Monitor exposes a backend-agnostic `MonitorBuilder::promiscuous(bool)` |
| `.with_default_program()` / `.with_program(p)` | — | attach an XDP redirect program (feat `xdp-loader`); `filter_program()` is the table-driven variant |

> **AF_XDP & promiscuous mode.** AF_XDP runs in the driver RX path *after* the
> NIC's MAC filter, so on a non-promiscuous interface a socket only sees frames
> addressed to that NIC (plus broadcast/multicast). Use `.promiscuous(true)` to
> capture everything on the wire. Two gotchas: `PACKET_MR_PROMISC` does not set
> the user-visible `IFF_PROMISC` flag (`ip link` won't show `PROMISC`, but the
> interface *is* promiscuous), and on a multi-queue NIC one XSK still only sees
> its bound queue's RSS share — for full capture use `XdpCapture` (below) or
> force a single queue (`ethtool -L <iface> combined 1`).

### XdpCapture — full-NIC multi-queue capture (issue #6, feature `xdp-loader`)

`XdpSocket` binds a single queue; `netring::xdp::XdpCapture` opens **one socket
per RX queue** and drains them through a unified round-robin — the right entry
point for real-NIC AF_XDP capture.

```rust
use netring::xdp::{XdpCapture, Queues};

let mut cap = XdpCapture::builder()
    .interface("eth0")
    .queues(Queues::Auto)        // all RSS queues (ethtool); or ::range(0..4) / ::single(0)
    .promiscuous(true)           // one interface-global guard for every queue
    .build()?;
while let Some((queue_id, batch)) = cap.next_batch_blocking(timeout)? {
    for pkt in &batch { /* … */ }
}
// or: let (sockets, _guard) = cap.into_parts();  // one socket per worker thread
```

| Method | Description |
|--------|-------------|
| `XdpCapture::open(iface)` | all RSS queues + promiscuous, one call |
| `.builder()…build()` | full control (queues, mode, frames, attach flags, custom program) |
| `.next_batch()` / `.next_batch_blocking(t)` | unified round-robin RX → `(queue_id, batch)` |
| `.into_parts()` | `(Vec<XdpSocket>, XdpCaptureGuard)` for worker-per-queue |
| `.is_zerocopy()` / `.queue_ids()` / `.socket_count()` | introspection |
| `.busy_poll(us)` / `.numa_auto()` | **(issue #6)** per-queue `SO_BUSY_POLL` + NIC-NUMA UMEM binding (line-rate levers) |
| `netring::xdp::queue_count(iface)` / `interface_numa_node(iface)` | RSS queue count (`ETHTOOL_GCHANNELS`) / NIC NUMA node (sysfs) |
| `netring::monitor::XdpShardedRunner` | one `Monitor` per RX queue (worker-per-core, busy-poll) — the line-rate tier |

Each socket gets its **own UMEM** (safe default — sharing one across per-CPU
sockets races on the FILL ring). See [scaling.md](scaling.md) for the
multi-queue model and `examples/xdp/xdp_multiqueue.rs`.

## Error handling

All errors are `netring::Error`:

| Variant | Cause |
|---------|-------|
| `PermissionDenied` | Missing `CAP_NET_RAW` |
| `InterfaceNotFound(name)` | Interface doesn't exist |
| `Config(msg)` | Invalid builder parameters |
| `Socket(io)` | Socket creation failed |
| `Mmap(io)` | Ring buffer mmap failed |
| `Bind(io)` | Interface bind failed |
| `SockOpt { option, source }` | setsockopt failed |
| `Io(io)` | Generic I/O error |

## eBPF integration

All handles implement `AsFd`. Use with `aya`, `libbpf-rs`, etc.:

```rust,no_run
use std::os::fd::AsFd;
let cap = netring::Capture::open("eth0")?;
let _fd = cap.as_fd();
```

For socket-filter attachment, prefer the inherent helpers:

```rust,no_run,ignore
cap.attach_ebpf_filter(prog.fd())?;
cap.attach_fanout_ebpf(prog.fd())?;  // if FanoutMode::Ebpf was selected
cap.detach_filter()?;
```

## Migration notes

Per-release breaking changes and migration recipes live in
[`CHANGELOG.md`](../CHANGELOG.md). The current canonical entries:

- **0.22.0 (breaking)** — typed protocol roles (`FlowProtocol` /
  `MessageProtocol` — `on::<Tcp>` and `FlowStarted<Http>` are compile
  errors); flat `FlowPacket { proto, … }` (was `FlowPacket<P>`); the
  legacy `ProtocolMonitor` / `AnomalyMonitor` / `AnomalyRule` /
  `ProtocolEvent` API is **removed**. New high-level toolkit:
  `on_bandwidth` / `BandwidthReport`, `on_icmp_error` / `IcmpError`,
  `on_tcp_reset` / `TcpRst`, `label_table`, `all_l4`/`all_l7`, the
  report stream (`report` / `report_to` / `ReportSink`), cross-shard
  `merge_state` + `LayerSpec`. Recipes in
  [`netring/docs/MIGRATING_0.21_TO_0.22.md`](MIGRATING_0.21_TO_0.22.md).
- **0.21.0** — `Monitor` becomes `Send` (flowscope 0.13);
  `AnomalySink::write` key narrowed from `&dyn Debug` to
  `&dyn Key`; legacy `ProtocolMonitor` / `AnomalyMonitor` /
  `AnomalyRule` carry `#[deprecated]`. Full recipes in
  [`MIGRATING_0.20_TO_0.21.md`](./MIGRATING_0.20_TO_0.21.md).
- **0.20.0** — declarative `Monitor::builder()` API replaces
  the legacy `ProtocolMonitor`. Both APIs coexist in 0.20–0.21;
  legacy removed in 0.22.
- **0.14.0** — flowscope 0.4: `SessionParser` / `DatagramParser`
  data methods gain a `ts: Timestamp` parameter; driver `S` type
  parameter removed.
- **0.13.0** — `SessionEvent` adds `Anomaly` arm; `StreamCapture`
  trait gives async streams uniform ring access.
- **0.11.0** — `BpfFilter::new` becomes fallible; typed
  `BpfFilter::builder()` available.
