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

See [`docs/scaling.md`](docs/scaling.md) for the fanout decision
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
parsing; `full_monitor` combines all three concurrently — the
production-style "watch this interface for everything" recipe.

| Example | What it shows | Features |
|---|---|---|
| `async_on_tick` | Custom `DatagramParser::on_tick` emitting heartbeats | `tokio,flow,parse` |
| `multi_protocol_monitor` | One `flow_stream`, demux per-L4 (ICMP / TCP / UDP) | `tokio,flow,parse` |
| `http_session` | TCP/80,8080 → `HttpParser` → request/response events | `tokio,http` |
| `dns_lookups` | UDP/53 → `DnsUdpParser::with_correlation()` → query/response/RTT/unanswered | `tokio,dns` |
| **`full_monitor`** | **One `ProtocolMonitorBuilder` call drives flow + HTTP + DNS through a unified `ProtocolEvent` stream.** The "all at once" showcase. Replaces the previous hand-rolled `tokio::select!` boilerplate. | `tokio,http,dns` |

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
| `monitor_metrics_export` | `MetricsSink` (feature `metrics`) Prometheus counter facade |
| `monitor_port_scan` | `pattern_detector!` over `PortScanDetector` (TRW scoring) |
| `monitor_beacon_detector` | `pattern_detector!` over `BeaconDetector` (period variance) |
| `monitor_dga_query` | `pattern_detector!` over `DgaScorer` (bigram entropy on DNS) |
| `monitor_file_hash_dfir` | `Sha256Sink + FileType` (feature `file-hash`) DFIR file hashing |
| `monitor_ech_adoption` | ECH downgrade detection via `EchOutcome` |
| `monitor_net_diagnostic` | **3 signals in one Monitor** (0.22 high-level API): unified ICMP errors via `on_icmp_error` (flow-joined), TCP resets via `on_tcp_reset`, per-app bandwidth via `on_bandwidth` + typed `BandwidthReport`. The 0.22 headline — 306 LoC of hand-rolled classifiers/HashMap/tick collapsed to ~70. |

All take an `<iface>` argument (default `lo`) and an optional
`<seconds>` deadline. Pair with `synthetic_traffic` for
self-demoable runs without root.

```sh
cargo run --features "monitor-quickstart" --example monitor_basic -- lo 10
cargo run --features "monitor-quickstart" --example monitor_stream_consumer -- lo 10
cargo run --features "monitor-quickstart" --example monitor_sharded_runner -- lo 4 10
```

See [`docs/MIGRATING_0.20_TO_0.21.md`](../docs/MIGRATING_0.20_TO_0.21.md)
for the 0.20 → 0.21 transition guide (Send sweep, key narrowing,
broadcast subscribers, sharded runner, `pattern_detector!`),
and [`docs/migration-0.19-to-0.20.md`](../docs/migration-0.19-to-0.20.md)
for the older legacy → 0.20 path.

## anomaly/ — multi-protocol anomaly correlators

Real-life detectors built on `netring::correlate`'s primitives
(`TimeBucketedCounter`, `KeyIndexed`). The foundation for plan
[`netring-0.16-roadmap-2026-05-29.md`](../../plans/netring-0.16-roadmap-2026-05-29.md)
Part III's `AnomalyMonitor` harness.

**See [`docs/WRITING_DETECTORS.md`](../docs/WRITING_DETECTORS.md)
for the full tutorial** — anatomy of a rule, state primitives
(when to use which), `observe` vs `on_tick`, cross-protocol
correlator pattern, testing recipes, production deployment, false
positives, MITRE mapping.

| Example | What it shows | Features |
|---|---|---|
| `dns_query_burst` | Per-source-IP DNS rate anomaly via `TimeBucketedCounter`. Raw primitives, no harness. | `tokio,dns` |
| `dns_resolved_no_connection` | Cross-protocol: DNS resolved but no TCP/UDP follows within timeout. Uses `KeyIndexed::drain_expired` to surface unfulfilled resolutions as anomalies. Raw primitives. | `tokio,dns` |
| **`anomaly_monitor_demo`** | **Both detectors above in one event loop using `AnomalyMonitor` + `ProtocolMonitor`.** The "easy to write" recipe: each rule is a small `AnomalyRule<FiveTupleKey>` impl. Compose freely; one builder + one event loop drives the whole correlator. | `tokio,dns` |
| `slow_tls_handshake` | `SlowTlsHandshakeRule` — `ClientHello` not followed by `ServerHello` within threshold. Uses `KeyIndexed::drain_expired` on sweep tick. | `tokio,tls` |
| `lateral_movement` | `LateralMovementRule` — one internal IP contacts > N distinct internal peers in window. Per-source `KeyIndexed<IpAddr, ()>` fan-out tracking; persistent state across flows. | `tokio,flow,parse` |
| **`icmp_explained_drop`** | **`IcmpExplainedDropRule` — cross-protocol correlation using `IcmpInner` (flowscope 0.7).** Classifies aborted flows into "explained" (matching ICMP Destination Unreachable / Time Exceeded arrived first; Severity::Info) vs "unexplained" (no matching ICMP; Severity::Warning). Catches firewall silent-drop / peer-RST patterns. | `tokio,icmp` |
| **`pcap_replay_anomaly`** | **Drive any `AnomalyMonitor` from a pcap file.** `AsyncPcapSource` + `datagrams()` → `ProtocolEvent::Message` (constructed in-place since the variant is `pub`) → rules. Same detector code as live capture; no privileges needed. The "replay incident pcap against detector-v2 pre-deploy" workflow. | `tokio,flow,parse,pcap,dns` |
| **`pcap_replay_multi`** | **Multi-protocol pcap replay.** Opens the pcap twice (DNS + TLS passes), merges events by timestamp, then drives the same `TlsToUnresolvedIpRule` shape that runs on live traffic. The pattern for any detector that needs ≥2 protocols off a recorded trace. | `tokio,flow,parse,pcap,dns,tls` |
| **`tls_to_unresolved_ip`** | **Three-protocol correlator** — joins DNS resolutions with TLS ClientHello observations to flag TLS connections to IPs the host never DNS-resolved. MITRE T1571 / T1090 signal: hardcoded-IP C2, misconfigured clients, exfil over TLS skipping the resolver. Per-source `HashMap<IpAddr, KeyIndexed<IpAddr, ()>>` cache. | `tokio,dns,tls` |

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
just example lateral_movement tokio,flow,parse -- lo 30 10 60
just example full_monitor tokio,http,dns -- lo 30
```

Other run patterns:

```bash
# Most examples take an `iface` arg, default `lo`:
cargo run --example multi_protocol_monitor --features tokio,flow,parse -- lo 30

# Full L4+L7 monitor on a real interface:
cargo run --example full_monitor --features tokio,http,dns -- eth0 60

# Offline pcap replay (no privileges needed):
cargo run --example async_pcap_sessions --features tokio,flow,parse,pcap -- trace.pcap
```

```bash
The `justfile` also has shortcut targets (`just async`, `just dpi`,
`just bpf-filter`, etc.) — see `just --list`.
