# netring examples

All ~45 examples are organized by topic. Example *names* (what you
pass to `cargo run --example <name>`) are stable across the
reorganization — only the file paths inside this directory changed.

Most examples need `CAP_NET_RAW` on the test binary. Use `just
setcap` once to grant capabilities, then run examples as your
normal user.

---

## basic/ — sync capture, TX, bridge

The lowest-level synchronous API. Start here if you want to
understand the building blocks before reaching for the async
wrappers.

| Example | What it shows |
|---|---|
| `capture` | Plain `Capture::open` → batch loop |
| `inject` | Plain `Injector::open` → `send` |
| `bridge` | Forward packets between two interfaces sync |
| `batch_processing` | Walking a `PacketBatch` with sequence-gap detection |
| `low_latency` | `LowLatency` ring profile + busy-poll |
| `stats_monitor` | Live `Capture::stats()` polling loop |
| `channel_consumer` | `ChannelCapture` (runtime-agnostic, no tokio) |
| `pcap_write` | Sync capture → `CaptureWriter` pcap file |
| `dpi` | Simple deep-packet-inspection demo |

## async_basics/ — async wrappers, no flow features

The async API surface. Use these as templates for the typical
`AsyncCapture::open(iface)?` recipe.

| Example | What it shows |
|---|---|
| `async_capture` | `AsyncCapture::readable().await` loop |
| `async_inject` | `AsyncInjector::send().await` with backpressure |
| `async_bridge` | Async bidirectional bridge |
| `async_stream` | `into_stream()` + `futures::StreamExt` |
| `async_streamext` | Stream combinator usage (`map`, `filter`, …) |
| `async_pipeline` | tokio `mpsc` pipeline with worker pool |
| `async_signal` | Ctrl-C graceful shutdown |
| `async_lo_dedup` | `Dedup::loopback()` for `lo` capture |
| `async_stats_monitor` | `StreamCapture::capture_stats()` (plan 20) |
| `async_metrics` | `metrics` crate counters |

## filter/ — BPF and eBPF filtering

| Example | What it shows |
|---|---|
| `bpf_filter` | Typed `BpfFilter::builder()` end-to-end |
| `ebpf_filter` | `aya`-loaded eBPF socket filter |
| `async_filter` | `AsyncCapture::open_with_filter` + runtime swap |

## scaling/ — fanout and multi-source

| Example | What it shows |
|---|---|
| `fanout` | Sync `Capture` joining a `PACKET_FANOUT` group |
| `async_fanout_workers` | `AsyncMultiCapture::open_workers` |
| `async_multi_interface` | `AsyncMultiCapture::open(&["lo", "eth0"])` |

See [`docs/scaling.md`](../docs/scaling.md) for the fanout decision
matrix and anti-patterns.

## xdp/ — AF_XDP kernel bypass

| Example | What it shows |
|---|---|
| `xdp_send` | TX-only AF_XDP via `XdpMode::Tx` |
| `async_xdp` | Default `AsyncXdpSocket` recipe |
| `async_xdp_busy_poll` | Busy-poll trio for latency |
| `async_xdp_self_loaded` | `with_default_program()` — no external XDP loader |
| `async_xdp_custom_program` | `with_program(prog)` for a caller-loaded XDP program |

## flow/ — flow tracking (no L7 parsing)

| Example | What it shows |
|---|---|
| `async_flow_keys` | Bare `FiveTuple` extraction |
| `async_flow_summary` | Lifecycle events + summary stats |
| `async_flow_history` | Zeek-style `HistoryString` per flow |
| `async_flow_channel` | `cap.flow_stream` over an mpsc channel |
| `async_flow_filter` | Combining `with_dedup` + `flow_stream` |
| `async_flow_idle_per_key` | `with_idle_timeout_fn` for protocol-aware timeouts |
| `async_flow_conversations` | `Conversation<K>` aggregate |
| `async_flow_with_tap` | `with_pcap_tap` — record while you track |

## l7/ — session + datagram parsing (HTTP, DNS, custom)

The L7 surface. `multi_protocol_monitor` demuxes ICMP/TCP/UDP at
the flow level; `http_session` and `dns_lookups` add real protocol
parsing. For the "watch this interface for everything" recipe, use
the declarative `Monitor::builder()` API (see `monitor/` below).

| Example | What it shows | Features |
|---|---|---|
| `async_on_tick` | Custom `DatagramParser::on_tick` emitting heartbeats | `tokio,flow,parse` |
| `multi_protocol_monitor` | One `flow_stream`, demux per-L4 (ICMP / TCP / UDP) | `tokio,flow,parse` |
| `http_session` | TCP/80,8080 → `HttpParser` → request/response events | `tokio,http` |
| `dns_lookups` | UDP/53 → `DnsUdpParser::with_correlation()` → query/response/RTT/unanswered | `tokio,dns` |

## pcap/ — offline replay

| Example | What it shows |
|---|---|
| `async_pcap_replay` | `AsyncPcapSource::open(...).flow_events(ext)` for flow-level replay |
| `async_pcap_sessions` | `AsyncPcapSource::open(...).sessions(ext, parser)` one-liner |

## monitor/ — declarative Monitor API (0.21+)

The `Monitor::builder()` API. Each example targets a single
aspect of the 0.21 surface; compose them as needed for your own
code. All examples use plain `#[tokio::main]` (multi-thread
runtime) — `Monitor` is `Send` since 0.21.

| Example | What it shows |
|---|---|
| `monitor_basic` | `Monitor::builder()` + `.on::<FlowStarted<Tcp>>(...)` + StdoutSink |
| `monitor_detector_macro` | `detector!` macro for 3 stateless detectors (SshAttempt / HttpRequest / DnsQuery) |
| `monitor_layered_sinks` | `MinSeverity` + `DedupeAnomalies` + `RateLimitAnomalies` + `Tee::factory` over `StdoutSink` |
| `monitor_async_handler` | `on_async::<E>(...)` with `Arc<Pool>` capture for simulated I/O |
| `monitor_stream_consumer` | `with_broadcast::<Http>()` + `subscribe::<Http>()` → `EventStream` consumer |
| `monitor_pcap_replay` | `pcap_source(path) + pcap_speed_factor(f) + replay()` offline pipeline |
| `monitor_sharded_runner` | `ShardedRunner::new(iface, FanoutMode::Cpu, group, N, build)` per-CPU sharding |
| `monitor_eve_to_filebeat` | `EveSink` (feature `eve-sink`) writing Suricata-format EVE JSON for Filebeat ingest |
| `monitor_tracing_json` | structured JSON logging of anomalies + telemetry via `tracing-subscriber` (`TracingSink` + `on_capture_stats`) |
| `monitor_metrics_export` | `MetricsSink` (feature `metrics`) Prometheus counter facade |
| `monitor_port_scan` | `pattern_detector!` over `PortScanDetector` (TRW scoring) |
| `monitor_beacon_detector` | `pattern_detector!` over `BeaconDetector` (period variance) |
| `monitor_dga_query` | `pattern_detector!` over `DgaScorer` (bigram entropy on DNS) |
| `monitor_file_hash_dfir` | `Sha256Sink + FileType` (feature `file-hash`) DFIR file hashing |
| `monitor_ech_adoption` | ECH downgrade detection via `EchOutcome` |
| `monitor_net_diagnostic` | **3 signals in one Monitor** (0.22 high-level API): unified ICMP errors via `on_icmp_error` (flow-joined), TCP resets via `on_tcp_reset`, per-app bandwidth via `on_bandwidth` + typed `BandwidthReport`. The 0.22 headline — 306 LoC of hand-rolled classifiers/HashMap/tick collapsed to ~70. |
| `monitor_multi_thread_default` | plain `#[tokio::main]` (multi-thread) — `Monitor` is `Send` (0.21) and **the run-loop future is `Send + 'static` (0.23)**, demonstrated via `tokio::spawn(monitor.run_for(..))` |
| `monitor_report_stream` | `report_to(period, build, sink)` + `JsonReportSink` (0.22 §3) shipping a typed `BandwidthSnapshot` report — the third output stream beside anomalies and broadcast |
| `monitor_label_table` | `LabelTable::new().set(...)` + `MonitorBuilder::label_table` — custom well-known port → app-label map feeding `on_bandwidth` |

All take an `<iface>` argument (default `lo`) and an optional
`<seconds>` deadline. Pair with `synthetic_traffic` for
self-demoable runs without root.

```sh
cargo run --features "monitor-quickstart" --example monitor_basic -- lo 10
cargo run --features "monitor-quickstart" --example monitor_stream_consumer -- lo 10
cargo run --features "monitor-quickstart" --example monitor_sharded_runner -- lo 4 10
```

See [`docs/MIGRATING_0.21_TO_0.22.md`](../docs/MIGRATING_0.21_TO_0.22.md)
for the 0.21 → 0.22 transition guide (typed protocol roles, flat
`FlowPacket`, the operations toolkit `on_bandwidth` / `on_icmp_error` /
`on_tcp_reset`, the report stream, cross-shard merge, and the legacy
0.19 API removal).

## anomaly/ — multi-protocol anomaly correlators

Real-life detectors built on `netring::correlate`'s primitives
(`TimeBucketedCounter`, `KeyIndexed`) over raw `AsyncCapture` streams.

> **0.22:** the legacy `AnomalyMonitor` / `AnomalyRule` harness was
> removed. The detector examples that used it are gone; their
> equivalents live under `monitor/` on the declarative
> `Monitor::builder()` + `detector!` / `pattern_detector!` API
> (`monitor/port_scan`, `monitor/beacon_detector`, `monitor/dga_query`,
> `monitor/net_diagnostic`).

| Example | What it shows | Features |
|---|---|---|
| `dns_query_burst` | Per-source-IP DNS rate anomaly via `TimeBucketedCounter`. Raw primitives, no harness. | `tokio,dns` |
| `dns_resolved_no_connection` | Cross-protocol: DNS resolved but no TCP/UDP follows within timeout. Uses `KeyIndexed::drain_expired` to surface unfulfilled resolutions. Raw primitives. | `tokio,dns` |

## util/ — demo helpers

| Example | What it shows | Features |
|---|---|---|
| **`synthetic_traffic`** | **Companion traffic generator** — fires DNS queries / TCP SYN→RST flows / HTTP-shaped requests / per-source fan-out on `lo` so the L7 and anomaly examples are self-demoable. Userspace sockets only; **no `CAP_NET_RAW` / root required**. Run in one terminal, run the example you want to demo in another. | `tokio` |

---

## Running

The L7 + anomaly examples need real traffic to fire. The
`synthetic_traffic` helper provides enough on `lo` to demo most of
them without root:

```bash
# Terminal A — generator:
just synthetic-traffic 30

# Terminal B — pick a detector:
just example dns_query_burst tokio,dns -- lo 30 50
just example monitor_net_diagnostic monitor-quickstart,icmp -- lo 30
```

Other run patterns:

```bash
# Most examples take an `iface` arg, default `lo`:
cargo run --example multi_protocol_monitor --features tokio,flow,parse -- lo 30

# Full L4+L7 monitor on a real interface (declarative API):
cargo run --example monitor_net_diagnostic --features monitor-quickstart,icmp -- eth0 60

# Offline pcap replay (no privileges needed):
cargo run --example async_pcap_sessions --features tokio,flow,parse,pcap -- trace.pcap
```

```bash
The `justfile` also has shortcut targets (`just async`, `just dpi`,
`just bpf-filter`, etc.) — see `just --list`.
