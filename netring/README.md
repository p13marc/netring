# netring

High-performance, zero-copy packet I/O for Linux — **async-first**, pure Rust,
no native C dependencies.

netring captures and injects packets over **AF_PACKET** (TPACKET_V3 block-based
mmap rings) and **AF_XDP** (kernel-bypass XDP sockets), and pairs them with a
declarative **Monitor** for flow tracking, L7 parsing, and anomaly detection.
Flow/session logic lives in the companion crate
[`flowscope`](https://github.com/p13marc/flowscope) (cross-platform, no tokio).

```toml
[dependencies]
netring = { version = "0.28", features = ["tokio"] }
```

```rust,ignore
// Zero-copy borrowed batches via AsyncFd — nothing is copied per packet.
let mut cap = netring::AsyncCapture::open("eth0")?;
loop {
    let mut guard = cap.readable().await?;
    while let Some(batch) = guard.next_batch() {
        for pkt in &batch {
            let _data: &[u8] = pkt.data();   // borrows from the ring
            let _ts = pkt.timestamp();       // nanosecond kernel timestamp
        }
    }
}
```

## Why netring

- **Zero-copy, zero-alloc hot path.** Borrowed batches; the Monitor run loop
  does **0 allocations per packet** (enforced by a dhat regression bench).
- **Two backends, one API.** AF_PACKET everywhere; AF_XDP for kernel-bypass
  line rate — same shapes, no native C deps (pure `libc`/`aya`).
- **Async-first.** tokio adapters with a `Send + 'static` run loop you can
  `tokio::spawn`; a runtime-agnostic channel adapter too.
- **Batteries included.** Typed BPF builder, flow/session tracking, L7 parsers
  (HTTP/TLS/DNS/ICMP/QUIC + Tier-2: SSH, FTP, SMTP, NTP, SNMP, Modbus, DNP3,
  STUN, WireGuard, SMB/Kerberos/LDAP/RDP), fingerprinting (JA3/JA4/JA4H/JA4X,
  HASSH, p0f), and a fluent Monitor with detectors, middleware, sinks, and
  exporters.
- **Network security monitoring.** Threat-intel IOC matching, YARA-X payload
  scanning, Sigma rule evaluation (with live hot-reload of IOC/Sigma sets),
  nDPI-style flow-risk scoring, RITA beacon detection, passive asset inventory
  (MAC-keyed from ARP/NDP/LLDP/CDP/DHCP/SSDP/mDNS), nPrint + CICFlowMeter ML
  feature export, and an OCSF Detection-Finding sink for Security Lake / Splunk.

## The Monitor: subscriptions

The `Monitor` is the high-level "watch an interface and react to typed events"
API. The front door is the **typed subscription engine** — three strongly-typed
tiers whose filters split into a kernel part (pushed into BPF, so uninteresting
traffic is shed before it reaches userspace) and a userspace remainder:

```rust,ignore
use netring::monitor::Monitor;
use netring::monitor::subscription::{packet, flow, session};
use netring::protocol::builtin::{Tcp, Tls};

Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()
    .protocol::<Tls>()
    // every frame to :443 (the tcp+port part is pushed into the kernel BPF)
    .subscribe(packet().tcp().dst_port(443).to(|view, ctx| Ok(())))
    // once per flow, at its end, for flows over 1 MiB
    .subscribe(flow::<Tcp>().bytes_over(1 << 20).to(|ended, ctx| Ok(())))
    // each parsed TLS handshake whose SNI matches a glob
    .subscribe(session::<Tls>().sni_glob("*.bank.example").to(|msg, ctx| Ok(())))
    // a runtime filter string → the SAME predicate AST as the typed combinators
    .subscribe(packet().expr("udp and dst port 53")?.to(|view, ctx| Ok(())))
    .build()?
    .run_until_signal()
    .await?;
```

| Tier | Constructor | Handler sees | Fires |
|---|---|---|---|
| packet | `packet()` | `&PacketView` | every matching frame (pre-tracking) |
| flow | `flow::<P>()` | `&FlowEnded<P>` | once per matching flow, at its end |
| session | `session::<P>()` | `&P::Message` | each parsed L7 message that matches |

Runnable: `examples/monitor/subscriptions.rs`.

## The Monitor: handlers, detectors, sinks

`on::<E>` / `on_ctx::<E>` register typed handlers; `detect(...)` plugs in
`detector!` / `pattern_detector!` rules; a tower-style **layer** chain processes
the anomaly sink; and **sinks** ship the results.

```rust,ignore
use std::time::Duration;
use netring::prelude::*;

Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()                                    // FlowStarted/Ended<Tcp>
    .protocol::<Http>()                                   // HttpMessage events
    .on_ctx::<Http>(|msg, ctx| {
        ctx.emit("HttpRequest", Severity::Info).with("path", msg.path).emit();
        Ok(())
    })
    .layer(MinSeverity::warning())                        // outermost: drop Info
    .layer(DedupeAnomalies::within(Duration::from_secs(60)))
    .sink(StdoutJsonSink::default())                      // innermost: NDJSON
    .run_until_signal()
    .await?;
```

- **Handlers:** `on` (payload), `on_ctx` (payload + `&mut Ctx`), `on_async`
  (payload → `Send` future), and **`on_effect`** — read `Ctx` synchronously,
  do async I/O, return deferred `Effects` (0.25).
- **Middleware (5):** `MinSeverity`, `DedupeAnomalies`, `RateLimitAnomalies`,
  `Sample`, `Tee` — compose freely, outermost-first.
- **Sinks (4 core):** `StdoutSink`, `StdoutJsonSink`, `TracingSink`,
  `ChannelSink`; plus `EveSink`/`EveTlsSink` (Suricata EVE), `SyslogSink`
  (RFC 5424), `IpfixExporter` (RFC 7011), and OTLP/Kafka in
  [`netring-exporters`](../netring-exporters).
- **Run modes:** `run_until_signal()`, `run_for(Duration)`, `run_until(Instant)`,
  `run_until_idle(window)`, `replay()` (offline pcap).

The Monitor is `Send` and its **run-loop future is `Send + 'static`** — so
`tokio::spawn(monitor.run_for(d))` works on the default multi-thread runtime.

See [docs/WRITING_DETECTORS.md](docs/WRITING_DETECTORS.md) for the detector
tutorial and [examples/monitor/](examples/monitor) for runnable demos
(subscriptions, port-scan/beacon/DGA detectors, EVE/OTLP export, resilience,
sharding, tracing-JSON).

## Capture & inject

Every type has a `::open(iface)` shortcut and a `::builder()` for full config.

```rust,ignore
// Async inject with backpressure (awaits POLLOUT when the ring is full):
let mut tx = netring::AsyncInjector::open("eth0")?;
tx.send(&frame).await?;
tx.flush().await?;

// TX symmetry (0.25): stream-inject, rate-paced, with egress timestamps.
use netring::TxPacer;
let inj = netring::Injector::builder().interface("eth0").tx_timestamps(true).build()?;
let mut tx = netring::AsyncInjector::new(inj)?;
tx.send_stream(frames, Some(TxPacer::packets_per_second(10_000.0))).await?;
let _egress_ts = tx.read_tx_timestamp();
```

```rust,ignore
// AF_XDP (kernel bypass) — same shape as AsyncCapture; needs an XDP redirect
// program. `xdp_interface_loaded` (feature `xdp-loader`) attaches one for you.
let monitor = netring::monitor::Monitor::builder()
    .xdp_interface_loaded("eth0")
    .protocol::<Tcp>()
    .build()?;
```

The sync `Capture` / `Injector` / `XdpSocket` power the async wrappers and are
usable directly (flat `packets()` iterator or block-level batches). See
[docs/API_OVERVIEW.md](docs/API_OVERVIEW.md) and
[docs/ASYNC_GUIDE.md](docs/ASYNC_GUIDE.md).

## Flow & session tracking

```toml
netring = { version = "0.28", features = ["tokio", "flow"] }
```

```rust,ignore
use futures::StreamExt;
use netring::AsyncCapture;
use netring::flow::FlowEvent;
use netring::flow::extract::FiveTuple;

let cap = netring::AsyncCapture::open("eth0")?;
let mut stream = cap.flow_stream(FiveTuple::bidirectional());
while let Some(evt) = stream.next().await {
    match evt? {
        FlowEvent::Started { key, .. } => println!("+ {} <-> {}", key.a, key.b),
        FlowEvent::Ended { key, history, .. } => println!("- {} <-> {}  {history}", key.a, key.b),
        _ => {}
    }
}
```

Pluggable flow keys (5-tuple, IpPair, MacPair, VLAN/MPLS/VXLAN/GTP-U decap),
bidirectional sessions, a TCP state machine with Zeek-style history, idle-timeout
sweep + LRU eviction, optional TCP reassembly, and feature-gated L7 parsers
(`http`, `tls` with JA3/JA4 fingerprinting, `dns`, `icmp`). The flow API itself
lives in [`flowscope`](https://github.com/p13marc/flowscope) and works on any
source of `&[u8]` frames (pcap, tun/tap, embedded).

## BPF filters

A typed classic-BPF builder — no `tcpdump -dd`, no libpcap:

```rust,no_run
use netring::{BpfFilter, Capture};

let filter = BpfFilter::builder()
    .tcp().dst_port(443)
    .or(|b| b.udp().dst_port(53))
    .build()
    .unwrap();

let _cap = Capture::builder().interface("eth0").bpf_filter(filter).build().unwrap();
```

Vocabulary: `ipv4`/`ipv6`/`arp`, `vlan`/`vlan_id`, `tcp`/`udp`/`icmp`,
`src_host`/`dst_host`/`host`, `src_net`/`dst_net`/`net`,
`src_port`/`dst_port`/`port`, `negate()`, `or(|b| …)`.
`AsyncCapture::set_filter` swaps the filter atomically on a running ring;
`BpfFilter::matches(&[u8])` runs the bytecode in pure Rust for offline testing.

## Performance & scaling

- **Per-CPU sharding:** `ShardedRunner::new(iface, FanoutMode::Cpu, group, n, build)`
  fans one interface across N sockets in a `PACKET_FANOUT` group;
  `.pin_cpus(true)` binds each shard to its core.
- **AF_XDP tuning:** UMEM hugepages (`MAP_HUGETLB`) + NUMA binding (`mbind`);
  busy-poll trio (`busy_poll_us`/`prefer_busy_poll`/`busy_poll_budget`).
- **Numbers & methodology:** [docs/PERFORMANCE.md](docs/PERFORMANCE.md) (capture
  vs. dispatch split, the dispatch-throughput bench, tuning levers) and
  [docs/scaling.md](docs/scaling.md) (`FanoutMode` matrix + anti-patterns).

## Companion crate: netring-exporters

OTLP and Kafka anomaly export live in
[`netring-exporters`](../netring-exporters), keeping those heavy dependency
trees out of netring's core. `OtlpAnomalySink` (feature `otlp`) and `KafkaSink`
(feature `kafka`) both implement netring's `AnomalySink`, so they drop straight
into `.sink(...)`.

## Features

Features are organized as orthogonal axes (full matrix + recipes in
[docs/FEATURES.md](docs/FEATURES.md)). The common ones:

| Feature | Description |
|---|---|
| `tokio` | Async wrappers (`AsyncCapture`/`AsyncInjector`/`AsyncXdpSocket`) + the Monitor |
| `af-xdp` / `xdp-loader` | AF_XDP kernel bypass; `xdp-loader` bundles the redirect program (via `aya`) |
| `channel` | Runtime-agnostic thread + bounded-channel adapter |
| `flow` | Flow & session tracking (pulls `flowscope`) |
| `http` / `dns` / `tls` / `icmp` / `quic` | L7 parsers; `ja4plus` adds JA4S (FoxIO License) |
| `arp` / `ndp` / `lldp` / `cdp` / `asset` | L2/discovery: ARP + IPv6 NDP watch, LLDP/CDP, passive `asset::Inventory` |
| `ssh` / `infra-protocols` / `ot-protocols` / `ftp` / `smtp` / `stun` / `wireguard` | Tier-2 protocol markers (SSH/HASSH, NTP/SNMP/TFTP/RADIUS, Modbus/DNP3, …) |
| `ad-protocols` / `asset-protocols` | Active-Directory (SMB/Kerberos/LDAP/RDP) + DHCP/SSDP/NBNS device facts |
| `ioc` / `sigma` / `yara` / `p0f` | Threat-intel IOC, Sigma rules, YARA-X payload scan, p0f OS fingerprint |
| `nprint` / `ml-features` | Per-flow ML export (nPrint header-bit matrix, CICFlowMeter features) |
| `pcap` | PCAP/PCAPNG read + write |
| `eve-sink` / `syslog` / `ipfix` / `metrics` / `ocsf-sink` | Suricata EVE / RFC 5424 / RFC 7011 / Prometheus / OCSF Detection Finding |
| `monitor` / `monitor-lite` / `monitor-quickstart` | Monitor umbrellas (full / lean / app-tier) |

## Public API

| Concept | Sync | Async |
|---|---|---|
| AF_PACKET RX | `Capture` | `AsyncCapture<Capture>` |
| AF_PACKET TX | `Injector` | `AsyncInjector` |
| AF_XDP (RX+TX) | `XdpSocket` | `AsyncXdpSocket` |
| Bridge two interfaces | `Bridge` | `Bridge::run_async` |
| Multi-source fan-in | — | `AsyncMultiCapture` |
| Declarative pipeline | — | `Monitor` / `ShardedRunner` |

## Requirements

- **Linux** kernel 3.2+ (TPACKET_V3), 5.4+ (AF_XDP).
- **Rust** 1.95+ (edition 2024).
- **Capabilities:** `CAP_NET_RAW` (open sockets), `CAP_NET_ADMIN` (promiscuous,
  XDP attach), `CAP_IPC_LOCK` (`MAP_LOCKED`, or a sufficient `RLIMIT_MEMLOCK`).

`just setcap` grants the capabilities once so tests/examples run without `sudo`.

## Examples

Organized by topic under [`examples/`](examples/README.md) — `basic/`,
`async_basics/`, `filter/`, `scaling/`, `xdp/`, `flow/`, `l7/`, `pcap/`,
`monitor/`. Each is listed with its required `--features` in
[examples/README.md](examples/README.md). Start with
`monitor_subscriptions` for the typed subscription API.

## Documentation

- [docs/INDEX.md](docs/INDEX.md) — the full documentation map.
- [API Overview](docs/API_OVERVIEW.md) · [Architecture](docs/ARCHITECTURE.md) ·
  [Async guide](docs/ASYNC_GUIDE.md) · [Features](docs/FEATURES.md)
- [Performance](docs/PERFORMANCE.md) · [Scaling](docs/scaling.md) ·
  [Tuning](docs/TUNING_GUIDE.md) · [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Writing detectors](docs/WRITING_DETECTORS.md) ·
  [Fingerprints](docs/FINGERPRINTS.md) · [Metrics](docs/METRICS.md)
- **Migrating:** [0.27 → 0.28](docs/MIGRATING_0.27_TO_0.28.md) ·
  [0.26 → 0.27](docs/MIGRATING_0.26_TO_0.27.md) ·
  [0.24 → 0.25](docs/MIGRATING_0.24_TO_0.25.md) ·
  [earlier guides](docs/INDEX.md#migration-guides)

## License

Licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your
option. (The optional `ja4plus` feature is FoxIO License 1.1 — see
[docs/FINGERPRINTS.md](docs/FINGERPRINTS.md).)
