# netring

High-performance zero-copy packet I/O for Linux, **async-first**.

`netring` provides packet capture and injection via AF_PACKET (TPACKET_V3
block-based mmap ring buffers) and AF_XDP (kernel-bypass via XDP sockets).
The recommended API is async/tokio; sync types are first-class but
mostly used as the underlying source for the async wrappers.

## Quick start (async, recommended)

```toml
[dependencies]
netring = { version = "0.21", features = ["tokio"] }
```

```rust,no_run
// Capture: zero-copy borrowed batches via AsyncFd.
# async fn _ex() -> Result<(), netring::Error> {
let mut cap = netring::AsyncCapture::open("eth0")?;
loop {
    let mut guard = cap.readable().await?;
    if let Some(batch) = guard.next_batch() {
        for pkt in &batch {
            handle(pkt.data()).await;
        }
    }
}
# async fn handle(_: &[u8]) {}
# }
```

```rust,ignore
// Stream-style consumption with futures::StreamExt
// (add `futures = "0.3"` to your Cargo.toml):
use futures::StreamExt;

let mut stream = netring::AsyncCapture::open("eth0")?.into_stream();
while let Some(batch) = stream.next().await {
    for pkt in batch? {
        let _ = pkt.data;
    }
}
```

```rust,no_run
// Inject with backpressure (awaits POLLOUT when ring is full):
# async fn _ex() -> Result<(), netring::Error> {
let mut tx = netring::AsyncInjector::open("eth0")?;
tx.send(&[0xff; 64]).await?;
tx.flush().await?;
# Ok(()) }
```

```rust,no_run
// AF_XDP (kernel bypass, 10M+ pps) — same shape as AsyncCapture:
# #[cfg(feature = "af-xdp")]
# async fn _ex() -> Result<(), netring::Error> {
let mut xdp = netring::AsyncXdpSocket::open("eth0")?;
let batch = xdp.try_recv_batch().await?;
for pkt in &batch {
    let _ = pkt.data();
}
# Ok(()) }
```

See [docs/ASYNC_GUIDE.md](docs/ASYNC_GUIDE.md) for the full async story —
patterns, trade-offs, when to use which entry point, and `Send`/`!Send`
considerations.

## Flow & session tracking

```toml
[dependencies]
netring = { version = "0.21", features = ["tokio", "flow"] }
futures = "0.3"
```

```rust,ignore
use futures::StreamExt;
use netring::AsyncCapture;
use netring::flow::extract::FiveTuple;
use netring::flow::FlowEvent;

let cap = AsyncCapture::open("eth0")?;
let mut stream = cap.flow_stream(FiveTuple::bidirectional());
while let Some(evt) = stream.next().await {
    match evt? {
        FlowEvent::Started { key, .. } => println!("+ {} <-> {}", key.a, key.b),
        FlowEvent::Ended { key, history, .. } => println!("- {} <-> {}  hist={history}", key.a, key.b),
        _ => {}
    }
}
```

Pluggable flow keys (5-tuple, IpPair, MacPair, VLAN/MPLS/VXLAN/GTP-U
decap combinators, custom extractors), bidirectional sessions, TCP
state machine with Zeek-style history string, idle-timeout sweep,
LRU eviction, optional TCP reassembly hook (sync `Reassembler` or
async `AsyncReassembler` with `channel_factory` for backpressure).

The flow types live in a separate cross-platform crate
[`flowscope`](https://github.com/p13marc/flowscope) (no Linux, no
tokio, no async runtime — usable with pcap, tun-tap, embedded).
`netring` is the Linux capture integration; the underlying flow API
works on any source of `&[u8]` frames.

`flowscope` also ships feature-gated L7 modules: `http` (HTTP/1.x),
`tls` (TLS handshake observation, optional JA3), `dns` (DNS-over-UDP
parser + correlator), `icmp` (ICMPv4 + ICMPv6 with `IcmpInner`
cross-protocol correlation), and `pcap` (offline replay).

## Declarative Monitor (recommended)

The `Monitor::builder()` API is a single fluent surface: typed event
handlers, a tower-style middleware chain over the anomaly sink, an
opt-in async escape hatch, `detector!` and `pattern_detector!` macros,
streaming subscribers, per-CPU sharding, offline pcap replay, and (0.22)
a high-level operations toolkit — bandwidth-by-app, ICMP-error
correlation, TCP-reset alerts, custom port labels, and a report stream.

```toml
[dependencies]
# Full app-tier experience (Monitor + all sinks + parsers):
netring = { version = "0.22", features = ["monitor-quickstart"] }

# Lean embedded build — pick what you need:
netring = { version = "0.22", features = ["monitor", "eve-sink", "metrics"] }
```

> **0.22 is a breaking release.** Typed protocol roles make `on::<Tcp>`
> and `FlowStarted<Http>` compile errors; `FlowPacket` is now flat
> (`FlowPacket { proto, … }`); the legacy 0.19 `ProtocolMonitor` /
> `AnomalyMonitor` / `AnomalyRule` API is removed. See
> [docs/MIGRATING_0.21_TO_0.22.md](docs/MIGRATING_0.21_TO_0.22.md).

**Monitor is `Send`** as of 0.21 — plain `#[tokio::main]` (the
multi-thread runtime) works without ceremony. The
`Monitor::run_for` / `run_until_signal` *futures* stay `!Send`
because the underlying `AsyncCapture<S>` borrows from the
`!Sync` mmap ring across awaits — `tokio::spawn(monitor.run_for(d))`
won't compile. Keep the run-loop future on the main task and
use `tokio::select!` (or `ChannelSink` to ship anomalies to a
spawned consumer task). flowscope's `Driver<E>: Send + Sync`
is unconditional upstream as of 0.13.

```rust,ignore
use std::time::Duration;
use netring::prelude::*;

#[derive(Default)]
struct HttpStats { requests: u64 }

let truncated_tls = detector! {
    name:     "TruncatedTls",
    severity: Warning,
    event:    TlsHandshake,
    matches:  |hs| hs.outcome == flowscope::tls::HandshakeOutcome::Truncated,
    emit:     |hs, ctx| {
        let now = ctx.ts;
        ctx.sink_mut()
            .begin("TruncatedTls", Severity::Warning, now)
            .with("sni", hs.sni.as_deref().unwrap_or("<none>"))
            .emit();
    },
};

Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()             // FlowStarted/Ended<Tcp> lifecycle events
    .protocol::<Http>()            // HttpMessage events from flowscope's HttpParser
    .protocol::<TlsHandshake>()    // one synthesised event per completed TLS handshake
    .state::<HttpStats>()
    .on_ctx::<Http>(|_msg, ctx| {        // payload + &mut Ctx
        ctx.state_mut::<HttpStats>().requests += 1;
        Ok(())
    })
    .detect(truncated_tls)
    .layer(MinSeverity::warning())                          // outermost: drop Info
    .layer(DedupeAnomalies::within(Duration::from_secs(60)))// drop dups
    .sink(StdoutJsonSink::default())                        // innermost: stdout
    .run_until_signal()
    .await?;
```

**Builder surface** — `.interface(s)` / `.protocol::<P>()` /
`.all_l4()` / `.all_l7()` / `.on::<E>(handler)` (payload only) /
`.on_ctx::<E>(handler)` (payload + `&mut Ctx`) / `.on_async::<E>(handler)` /
`.state::<T>()` / `.counter::<K>(window, bucket)` / `.sink(s)` /
`.layer(L)` / `.tick(period, handler)` / `.tick_ctx(period, |ctx| …)` /
`.detect(handler)` / `.build()`.

**0.22 high-level toolkit** — one-call operational signals:
`.on_bandwidth(period, |bw| …)` (per-app bytes/sec → a typed
`BandwidthReport`), `.on_icmp_error(|err, ctx| …)` (unified v4/v6 ICMP
errors with the originating flow joined), `.on_tcp_reset(|rst, ctx| …)`,
`.label_table(table)` (custom port labels), and `.report(period, …)` /
`.report_to(period, build, sink)` (periodic typed snapshots → a
`ReportSink`). The `examples/monitor/net_diagnostic.rs` example uses the
first three.

**Run modes** — `run_until(Instant)`, `run_for(Duration)`,
`run_until_signal()` (SIGINT/SIGTERM), `run_until_idle(window)`.

**`Ctx` accessors** — handlers receive `&mut Ctx<'_>`:
`ctx.state_mut::<T>()`, `ctx.counter_mut::<K>()`,
`ctx.sink_mut()`, plus the public fields `ctx.ts`, `ctx.flow`,
`ctx.source`. The `split_state_sink::<T>()` /
`split_state_counter::<T, K>()` helpers project disjoint
`&mut` references when a handler needs simultaneous access.

**5 shipped middleware** —
[`MinSeverity`](docs.rs/netring/latest/netring/layer/struct.MinSeverity.html),
[`DedupeAnomalies`](docs.rs/netring/latest/netring/layer/struct.DedupeAnomalies.html),
[`RateLimitAnomalies`](docs.rs/netring/latest/netring/layer/struct.RateLimitAnomalies.html),
[`Sample`](docs.rs/netring/latest/netring/layer/struct.Sample.html),
[`Tee`](docs.rs/netring/latest/netring/layer/struct.Tee.html).
Compose freely; ordering is outermost-first.

**4 shipped sinks** — `StdoutSink` (text), `StdoutJsonSink`
(JSON, `feature = "serde"`), `TracingSink` (`tracing::event!` at
the matching `tracing::Level`), `ChannelSink` (tokio mpsc with
`OwnedAnomaly` payloads).

**Zero allocations on the dispatch path.** Verified by the
`benches/zero_alloc.rs` dhat benchmark: 100k synthetic dispatches
(state mutation, counter bump, sink emit) measure
Δ 0 bytes / 0 blocks in steady state.

**Async escape hatch.** `on_async::<E>(handler)` runs each
event through a boxed future (one allocation per event per
handler — only when explicitly registered). Async handlers
receive payload only; capture `Arc<Pool>` in the closure or
pair with `ChannelSink` to ship anomalies to an async I/O
task.

**0.21 builder additions** — same `Monitor::builder()` plus:
`.with_broadcast::<P>()` (enrolls a broadcast slot for
`Monitor::subscribe::<P>()`); `.fanout(FanoutMode::Cpu, group_id)`
(per-CPU sharding via `ShardedRunner`); `.pcap_source(path)` +
`.pcap_speed_factor(f)` (offline pcap replay); `.drain_timeout(d)`
(graceful drain phase after shutdown); `.flow_state::<T>(idle)`
(per-flow state map, `ctx.flow_state_mut::<T>()`);
`.name(s)` (label surfaced through `ctx.monitor_name`).

**Streaming subscribers** — pull events out of the dispatcher
as a `futures_core::Stream` instead of registering a handler:

```rust,ignore
use futures::StreamExt;
use netring::prelude::*;

let monitor = Monitor::builder()
    .interface("eth0")
    .protocol::<Http>()
    .with_broadcast::<Http>()      // enrol the broadcast slot
    .build()?;

let mut stream = monitor.subscribe::<Http>();
tokio::spawn(monitor.run_until_signal());

while let Some(msg) = stream.next().await {
    println!("HTTP {} {}", msg.method, msg.path);
}
```

**Per-CPU sharding** — fan one capture across N AF_PACKET
sockets via `PACKET_FANOUT_CPU`:

```rust,ignore
use std::sync::Arc;
use netring::prelude::*;
use netring::monitor::ShardedRunner;

let runner = ShardedRunner::new(
    "eth0",
    FanoutMode::Cpu,
    0xC001,                         // fanout group id
    num_cpus::get(),                // shard count
    Arc::new(|b: MonitorBuilder| {
        b.protocol::<Tcp>()
         .sink(StdoutJsonSink::default())
    }),
)?;
runner.run_until_signal().await?;
```

**Pcap replay** — same handler graph, offline:

```rust,ignore
Monitor::builder()
    .pcap_source("trace.pcap")
    .pcap_speed_factor(10.0)         // 10× wire speed
    .protocol::<Http>()
    .on(|msg| { println!("{:?}", msg); Ok(()) })
    .build()?
    .replay()
    .await?;
```

See [docs/MIGRATING_0.21_TO_0.22.md](docs/MIGRATING_0.21_TO_0.22.md) for
the breaking-change recipes (typed protocol roles, flat `FlowPacket`,
the removed 0.19 API), and `examples/monitor/` for runnable demos.

## Multi-protocol monitoring + anomaly correlation

> The 0.19 `ProtocolMonitor` / `AnomalyMonitor` / `AnomalyRule`
> correlation API was **removed in 0.22**.

Watch one interface for several protocols and correlate across them on
the declarative `Monitor::builder()` API — register protocols with
`.all_l4()` / `.all_l7()` / `.protocol::<P>()`, handle events with
`.on::<E>` / `.on_ctx::<E>` / `detector!` / `pattern_detector!`, share
state across handlers with `.state::<T>()` + `ctx.state_mut::<T>()`, and
emit findings via `ctx.emit(kind, severity)` into the layered sink chain:

```rust,ignore
use std::net::IpAddr;
use std::time::Duration;
use netring::prelude::*;
use flowscope::dns::DnsMessage;

Monitor::builder()
    .interface("eth0")
    .all_l4()                          // Tcp + Udp + Icmp
    .protocol::<Dns>()                 // + the DNS parser
    .counter::<IpAddr>(Duration::from_secs(10), Duration::from_secs(1))
    .on_ctx::<Dns>(|msg: &DnsMessage, ctx| {
        if let DnsMessage::Query(q) = msg {
            let ip = ctx.flow.map(|k| k.a.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0]));
            let (counter, sink) = ctx.split_sink_counter::<IpAddr>();
            counter.bump(ip, /* ts */ flowscope::Timestamp::default());
            let _ = (q, sink);
        }
        Ok(())
    })
    .layer(MinSeverity::warning())
    .sink(StdoutJsonSink::default())
    .run_until_signal()
    .await?;
```

The cross-protocol correlation primitives (`TimeBucketedCounter`,
`KeyIndexed`, `RollingRate`, `BurstDetector`, `Ewma`, `TopK`) live in
`netring::correlate`; `examples/monitor/` ships reference detectors
(`port_scan`, `beacon_detector`, `dga_query`, `net_diagnostic`).

`Anomaly<K>` impls `Display` for one-line greppable output and
`to_json_line()` for production-pipeline JSON (no `serde` dep —
escaping is hand-rolled to RFC 8259 §7). Severity tiers
(`Info/Warning/Error/Critical`) port directly to flowscope's
`AnomalyKind::severity()` via a `From` impl. Reference detectors
live under `examples/monitor/` on the declarative `Monitor::builder()`
API (`port_scan`, `beacon_detector`, `dga_query`, `net_diagnostic`,
`file_hash_dfir`), plus raw-primitive correlators under
`examples/anomaly/` (`dns_query_burst`, `dns_resolved_no_connection`).
Pair with `cargo run --example synthetic_traffic` to demo on `lo`
without `CAP_NET_RAW`.

See [docs/WRITING_DETECTORS.md](docs/WRITING_DETECTORS.md) for
the full tutorial — anatomy of an `AnomalyRule`, state-primitive
decision table, `observe` vs `on_tick`, cross-protocol patterns,
testing, production deployment, and MITRE ATT&CK mapping.

## Stream observability

Every async stream type — `FlowStream`, `SessionStream`,
`DatagramStream`, `DedupStream` — implements the sealed
[`StreamCapture`] trait. That gives uniform access to kernel ring
stats and the underlying `AsyncCapture` even after the stream has
consumed it:

```rust,ignore
use netring::{AsyncCapture, BpfFilter, StreamCapture};
use netring::flow::extract::FiveTuple;

let cap = AsyncCapture::open("eth0")?;
let stream = cap.flow_stream(FiveTuple::bidirectional());

// Kernel ring stats while the stream runs:
let stats = stream.capture_stats()?;
println!("ring drops: {}", stats.drops);

// Atomic BPF filter swap on a running stream:
let new_filter = BpfFilter::builder().tcp().dst_port(443).build()?;
stream.capture().set_filter(&new_filter)?;
```

Pair with `with_pcap_tap(writer)` on any of the four stream types
to record raw frames **before** the flow tracker processes them —
decoded events and a wire-faithful capture file from one invocation:

```rust,ignore
use std::fs::File;
use std::io::BufWriter;
use netring::pcap::CaptureWriter;

let writer = CaptureWriter::create(BufWriter::new(File::create("trace.pcap")?))?;
let stream = cap
    .flow_stream(FiveTuple::bidirectional())
    .with_pcap_tap(writer);
```

`TapErrorPolicy::{Continue (default), DropTap, FailStream}`
controls disk-full / I/O-glitch handling.

## BPF filter ergonomics

`AsyncCapture::open_with_filter` is the one-call sugar for the
common case:

```rust,no_run
use netring::{AsyncCapture, BpfFilter};

let filter = BpfFilter::builder().tcp().dst_port(15987).build().unwrap();
let _cap = AsyncCapture::open_with_filter("eth0", filter).unwrap();
```

For runtime filter swaps without tearing down the kernel ring:

```rust,no_run
use netring::{AsyncCapture, BpfFilter};

let cap = AsyncCapture::open("eth0").unwrap();
let new = BpfFilter::builder().tcp().dst_port(8443).build().unwrap();
cap.set_filter(&new).unwrap();  // atomic in-kernel replacement
```

`set_filter` is gated to AF_PACKET-backed captures via the
`PacketSetFilter` trait; `AsyncCapture<XdpSocket>` doesn't expose
it (XDP filtering belongs in the XDP program).

## Multi-source capture

`AsyncMultiCapture` fans in N captures of two shapes — multiple
interfaces, or one interface with a fanout-group worker pool — into
a single tagged stream:

```rust,ignore
use futures::StreamExt;
use netring::AsyncMultiCapture;
use netring::flow::extract::FiveTuple;

// Multi-interface gateway:
let multi = AsyncMultiCapture::open(["eth0", "eth1"])?;
let mut stream = multi.flow_stream(FiveTuple::bidirectional());
while let Some(tagged) = stream.next().await {
    let evt = tagged?;
    let iface = stream.label(evt.source_idx).unwrap_or("?");
    println!("[{iface}] {:?}", evt.event);
}

// Worker pool scaling (FanoutMode::Cpu by default):
let workers = AsyncMultiCapture::open_workers("eth0", 4, 0xDE57)?;
```

Per-source breakdown and aggregate stats:

```rust,ignore
let agg = stream.capture_stats();
for (label, stats) in stream.per_source_capture_stats() { /* ... */ }
```

See [`docs/scaling.md`](docs/scaling.md) for the canonical multi-core
recipe, the `FanoutMode` decision matrix, and 7 anti-patterns
(including the `FANOUT_HASH`-on-skewed-traffic and `PACKET_FANOUT`
-on-`lo` gotchas).

## Offline replay

`AsyncPcapSource` reads PCAP and PCAPNG files asynchronously (format
auto-detected at open) and yields `OwnedPacket`s through a tokio
`Stream`. The companion `PcapFlowStream` bridges to the same
flowscope `FlowTracker` used by live capture, so the same downstream
code runs both live and offline:

```rust,ignore
use futures::StreamExt;
use netring::AsyncPcapSource;
use netring::flow::extract::FiveTuple;

let source = AsyncPcapSource::open("trace.pcap").await?;
let mut events = source.flow_events(FiveTuple::bidirectional());
while let Some(evt) = events.next().await {
    let _ = evt?;
}
```

`AsyncPcapConfig` controls pacing (`replay_speed = 1.0` for wire
rate, `2.0` for double speed, `0.0` for as-fast-as-possible) and
`loop_at_eof` for stress testing.

[`StreamCapture`]: https://docs.rs/netring/latest/netring/trait.StreamCapture.html

## BPF filtering

netring ships a typed classic-BPF builder — no shelling out to
`tcpdump -dd`, no native-library deps:

```rust,no_run
use netring::{BpfFilter, Capture};

let filter = BpfFilter::builder()
    .tcp()
    .dst_port(443)
    .or(|b| b.udp().dst_port(53))
    .build()
    .unwrap();

let cap = Capture::builder()
    .interface("eth0")
    .bpf_filter(filter)
    .build()
    .unwrap();
```

Vocabulary: `eth_type` / `ipv4` / `ipv6` / `arp`, `vlan` / `vlan_id`,
`ip_proto` / `tcp` / `udp` / `icmp`, `src_host` / `dst_host` / `host`,
`src_net` / `dst_net` / `net`, `src_port` / `dst_port` / `port`,
plus `negate()` and `or(|b| ...)`. See
[`examples/bpf_filter.rs`](examples/bpf_filter.rs) for a runnable
demo. The escape hatch `BpfFilter::new(insns)` still accepts raw
bytecode from `tcpdump -dd` or any other source.

`BpfFilter::matches(&[u8]) -> bool` runs the bytecode in pure Rust
for offline validation against pcap data.

## Sync API

The sync types power the async wrappers and are also usable directly:

```rust,no_run
// Flat iterator — simplest path.
let mut cap = netring::Capture::open("eth0").unwrap();
for pkt in cap.packets().take(100) {
    println!("[{}] {} bytes", pkt.timestamp(), pkt.len());
}
```

```rust,no_run
// Batch processing with sequence-gap detection.
use netring::Capture;
use std::time::Duration;

let mut cap = Capture::builder()
    .interface("eth0")
    .block_size(1 << 22)
    .build()
    .unwrap();

while let Some(batch) = cap.next_batch_blocking(Duration::from_millis(100)).unwrap() {
    for pkt in &batch {
        let _ = pkt.data();
    }
}
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `tokio` | off | Async wrappers (`AsyncCapture`, `AsyncInjector`, `AsyncXdpSocket`, `PacketStream`) |
| `af-xdp` | off | AF_XDP kernel-bypass packet I/O (pure Rust, no native deps) |
| `xdp-loader` | off | Built-in redirect-all XDP program loader for AF_XDP via [`aya`](https://crates.io/crates/aya). Implies `af-xdp`. See [`async_xdp_self_loaded`](netring/examples/async_xdp_self_loaded.rs) example. |
| `channel` | off | Thread + bounded channel adapter (runtime-agnostic) |
| `parse` | off | Packet header parsing via `etherparse` |
| `pcap` | off | Stream packets to PCAP files |
| `metrics` | off | `metrics` crate counters (`netring_capture_*_total`) |
| `flow` | off | Pluggable flow & session tracking (pulls `flowscope`, see [Flow & session tracking](#flow--session-tracking) above) |

## Public API

| Concept | Sync type | Async wrapper |
|---------|-----------|---------------|
| AF_PACKET RX | `Capture` | `AsyncCapture<Capture>` |
| AF_PACKET TX | `Injector` | `AsyncInjector` |
| AF_XDP (RX + TX) | `XdpSocket` | `AsyncXdpSocket` |
| Bridge two interfaces | `Bridge` | `Bridge::run_async` |
| Channel adapter | — | `ChannelCapture` (sync threads) |

Every type has a `::open(iface)` shortcut for the simple case and a
`::builder()` for full configuration.

## Default Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `block_size` | 4 MiB | Ring buffer block size |
| `block_count` | 64 | Number of blocks (256 MiB total) |
| `frame_size` | 2048 | Minimum frame size |
| `block_timeout_ms` | 60 | Block retirement timeout |
| `fill_rxhash` | true | Kernel fills RX flow hash |

## Performance Tuning

| Profile | block_size | block_count | timeout_ms | Notes |
|---------|-----------|-------------|------------|-------|
| High throughput | 4 MiB | 128–256 | 60 | + `FanoutMode::Cpu` + thread pinning |
| Low latency | 256 KiB | 64 | 1–10 | + `busy_poll_us(50).prefer_busy_poll(true).busy_poll_budget(64)` (kernel ≥ 5.11) |
| Memory-constrained | 1 MiB | 16 | 100 | 16 MiB total ring |
| Jumbo frames | 4 MiB | 64 | 60 | `frame_size(65536)` |

See [docs/TUNING_GUIDE.md](docs/TUNING_GUIDE.md) for detailed tuning advice.

## Fanout Modes

Distribute packets across multiple sockets for multi-threaded capture:

| Mode | Strategy |
|------|----------|
| `Hash` | Flow hash (same flow → same socket) |
| `Cpu` | Route to CPU that received the NIC interrupt |
| `LoadBalance` | Round-robin |
| `Rollover` | Fill one socket, overflow to next |
| `Random` | Random distribution |
| `QueueMapping` | NIC hardware queue mapping |

```rust,no_run
use netring::{Capture, FanoutMode, FanoutFlags};

let cap = Capture::builder()
    .interface("eth0")
    .fanout(FanoutMode::Cpu, 42)
    .fanout_flags(FanoutFlags::ROLLOVER | FanoutFlags::DEFRAG)
    .build()
    .unwrap();
```

## Statistics

```rust,no_run
# let cap = netring::Capture::open("lo").unwrap();
let stats = cap.stats().unwrap();
println!("received: {}, dropped: {}, frozen: {}",
    stats.packets, stats.drops, stats.freeze_count);
```

Reading stats resets the kernel counters — call periodically for rate calculation.

## System Requirements

- **Linux** kernel 3.2+ (for TPACKET_V3), 5.4+ (for AF_XDP)
- **Rust** 1.95+ (edition 2024)

### Capabilities

| Capability | Required For |
|------------|-------------|
| `CAP_NET_RAW` | Creating AF_PACKET / AF_XDP sockets |
| `CAP_IPC_LOCK` | `MAP_LOCKED` (or sufficient `RLIMIT_MEMLOCK`) |
| `CAP_NET_ADMIN` | Promiscuous mode |

```bash
# Recommended: use justfile (sudo only once for setcap)
just setcap          # grants CAP_NET_RAW on all binaries
just test            # runs without sudo
just capture eth0    # runs without sudo

# Manual alternative
sudo setcap cap_net_raw+ep target/release/examples/capture
```

## Examples

```bash
just setcap                  # grant capabilities once (needs sudo)
just capture eth0            # basic packet capture
just batch eth0              # low-level batch API with sequence gap detection
just fanout eth0 4           # multi-threaded fanout capture
just inject lo               # packet injection
just stats eth0              # live statistics monitor (pkt/s, drops)
just low-latency eth0        # low-latency tuning demo
just dpi eth0                # deep packet inspection (HTTP/TLS/DNS/SSH detection)
just channel eth0            # channel adapter (runtime-agnostic)
just async eth0              # async capture with tokio (readable() pattern)
just async-stream eth0       # async capture as a futures::Stream
just async-inject lo 1000    # async TX with backpressure (AsyncInjector)
just async-signal eth0       # async capture with Ctrl-C graceful shutdown
just async-pipeline eth0 4   # async capture → tokio::mpsc → 4 worker tasks
just async-bridge eth0 eth1  # async transparent bridge (Bridge::run_async)
just ebpf                    # eBPF/aya integration demo (AsFd verification)
cargo run --example xdp_send --features af-xdp -- lo  # AF_XDP TX-only (uses XdpMode::Tx)

# 0.13.0 — stream observability, BPF ergonomics, multi-source, offline replay:
cargo run --example async_flow_with_tap   --features "tokio,flow,parse,pcap" -- eth0 out.pcap
cargo run --example async_filter          --features "tokio,flow,parse" -- eth0 80
cargo run --example async_fanout_workers  --features "tokio,flow,parse" -- eth0 4
cargo run --example async_multi_interface --features "tokio,flow,parse" -- lo eth0
cargo run --example async_pcap_replay     --features "tokio,flow,parse,pcap" -- trace.pcap 1.0
# 0.13.1 — async sibling of stats_monitor (StreamCapture::capture_stats demo):
cargo run --example async_stats_monitor   --features "tokio,flow,parse" -- eth0 30
# 0.14.0 — flowscope 0.4 ergonomics: one-step pcap-to-sessions + on_tick parsers:
cargo run --example async_pcap_sessions   --features "tokio,flow,parse,pcap" -- trace.pcap
cargo run --example async_on_tick         --features "tokio,flow,parse" -- lo 30
# 0.15.0+ — real-life L7 monitors using flowscope's HTTP / DNS parsers:
cargo run --example multi_protocol_monitor --features "tokio,flow,parse"  -- eth0 30
cargo run --example http_session           --features "tokio,http"        -- eth0 60
cargo run --example dns_lookups            --features "tokio,dns"         -- eth0 60
# "watch everything" recipe — use the declarative Monitor (0.22):
cargo run --example monitor_net_diagnostic --features "monitor-quickstart,icmp" -- eth0 60
# 0.21 — declarative Monitor (subscribe / pcap replay / pattern detectors):
cargo run --example monitor_basic            --features "monitor-quickstart"  -- eth0
cargo run --example monitor_stream_consumer  --features "monitor-quickstart"  -- eth0
cargo run --example monitor_pcap_replay      --features "monitor-quickstart"  -- trace.pcap
cargo run --example monitor_sharded_runner   --features "monitor-quickstart"  -- eth0 4
cargo run --example monitor_eve_to_filebeat  --features "monitor-quickstart"  -- eth0 eve.json
cargo run --example monitor_metrics_export   --features "monitor-quickstart"  -- eth0
cargo run --example monitor_port_scan        --features "monitor-quickstart"  -- eth0
cargo run --example monitor_beacon_detector  --features "monitor-quickstart"  -- eth0
cargo run --example monitor_dga_query        --features "monitor-quickstart"  -- eth0
cargo run --example monitor_file_hash_dfir   --features "monitor-quickstart"  -- eth0
cargo run --example monitor_ech_adoption     --features "monitor-quickstart"  -- eth0
```

Examples are organized by topic under
[`examples/`](examples/README.md) — `basic/`, `async_basics/`,
`filter/`, `scaling/`, `xdp/`, `flow/`, `l7/`, `pcap/`. See
[`examples/README.md`](examples/README.md) for a per-category
index with the right `--features` flags.

## Documentation

- [Scaling capture across cores](docs/scaling.md) — `FanoutMode`
  decision matrix, multi-worker recipe, anti-patterns (added 0.13.0)
- [Architecture](docs/ARCHITECTURE.md) — system design, lifetime model, ring layout
- [API Overview](docs/API_OVERVIEW.md) — all types, methods, and configuration
- [Async / tokio guide](docs/ASYNC_GUIDE.md) — async patterns, Send rules, Monitor on multi-thread
- [Writing detectors](docs/WRITING_DETECTORS.md) — detector! / pattern_detector! tutorial
- [Migrating 0.22 → 0.23](docs/MIGRATING_0.22_TO_0.23.md) — **breaking**: spawnable `Send` run-loop future; `on_async` handlers must return `Send` futures
- [Migrating 0.21 → 0.22](docs/MIGRATING_0.21_TO_0.22.md) — **breaking**: typed protocol roles, flat `FlowPacket`, ops toolkit, report stream, legacy 0.19 API removed
- [Migrating 0.20 → 0.21](docs/MIGRATING_0.20_TO_0.21.md) — Send Monitor, key narrowing, subscribers, sharding
- [Migrating 0.19 → 0.20](docs/migration-0.19-to-0.20.md) — legacy → declarative Monitor
- [Tuning Guide](docs/TUNING_GUIDE.md) — performance profiles, system tuning, monitoring
- [Troubleshooting](docs/TROUBLESHOOTING.md) — common errors and fixes

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT License](LICENSE-MIT) at your option.
