# CLAUDE.md

## Project Overview

netring is a pure Rust library for zero-copy packet capture and injection on Linux,
built on AF_PACKET with TPACKET_V3 (block-based mmap ring buffers) and AF_XDP.

- Edition 2024, MSRV 1.95, Linux only
- Two API levels: high-level `Capture`/`Injector` and low-level `AfPacketRx`/`AfPacketTx`
- AF_XDP backend via `XdpSocket` (feature: `af-xdp`) for kernel-bypass packet I/O
- Optional self-contained AF_XDP via `xdp-loader` feature (loads + attaches a redirect-all
  XDP program, no external `aya`/`libxdp`/`bpftool` dance)
- Zero-copy via mmap with lifetime-enforced safety
- Async adapters: tokio (`AsyncCapture`) and channel (`ChannelCapture`)
- Flow & session tracking lives in the separate
  [`flowscope`](https://github.com/p13marc/flowscope) crate; netring's
  `flow` feature pulls it in and adds tokio Stream adapters
  (`flow_stream`, `session_stream`, `datagram_stream`,
  `dedup_stream`, `flow_broadcast`).

## Implementation Status

**Active.** netring 0.20.0 prepared (this branch); 0.19.0 last
published. ~399 tests + zero warnings + dhat zero-alloc bench
(`Δ 0 bytes / 0 blocks` over 100k synthetic dispatches).

### Recent additions (netring 0.20 — declarative Monitor API)

Driven by `plans/netring-0.20-phase-{A..G}-*.md` (7 phase plans).
The Phase G commit deletes the plans per the "delete on ship"
convention.

The 0.20 release adds a fluent `Monitor::builder()` API alongside
the existing 0.19 `ProtocolMonitor` / `AnomalyMonitor` surface
(both coexist; 0.21.x will `#[deprecated]` the legacy types;
0.22.0 will remove them).

**Phase A — Protocol trait + 7 builtin markers:**
- `pub trait Protocol { type Message; const NAME; fn dispatch(); fn register(builder) -> Result<SlotHandle, _>; }`
- `Dispatch` enum: `Tcp(Vec<u16>)`, `Udp(Vec<u16>)`, `Icmp`,
  `AllTcp`, `AllUdp`, `Signature(fn(&[u8]) -> SignatureMatch)`
- `SignatureMatch` enum mirroring `flowscope::detect::signatures::SignatureMatch`
- `ProtocolInitError(String)` thiserror struct
- Builtin markers in `src/protocol/builtin/`: `Tcp`, `Udp` (lifecycle-only),
  `Icmp` (feature = "icmp"), `Http`, `Dns`, `Tls`, `TlsHandshake`
- A.4 corrected the trait shape: `parser()` returned a `Box<dyn …>`
  which failed flowscope's `P: SessionParser + Clone + Send` bound;
  `register(builder)` keeps the parser concrete at the call site.
- Typed events under `src/protocol/event_typed.rs`:
  `FlowStarted<P>`, `FlowEnded<P>`, `FlowEstablished<P>`,
  `AnyFlowAnomaly`, `Tick`. `Event` trait + blanket
  `impl<P: Protocol> Event for P { type Payload = P::Message; }`.

**Phase B — Handler trait + Ctx + Dispatcher + Monitor builder:**
- `src/ctx/` — `Ctx<'a>` + `SourceIdx` + ctx-method accessors
  (`state_mut::<T>()`, `counter_mut::<K>()`, `sink_mut()`).
  Plus `StateMap` (TypeId-keyed `FxHashMap`) and `CounterRegistry`.
- `src/monitor/handler.rs` — `Handler<E, Marker>` trait with two
  blanket impls (`PayloadOnly` / `PayloadCtx`). Multi-extractor
  closures don't work in sync Rust (mutual `&mut Ctx` borrows);
  the method-on-Ctx pattern recovers the same ergonomics.
- `src/monitor/dispatcher.rs` — `Dispatcher` with TypeId-keyed
  `ArrayVec<(TypeId, u8), 16>` slot table (`MAX_EVENT_TYPES = 16`).
  Sync + async slots in parallel `Box<[Vec<…>]>` arrays.
- `src/monitor/registry.rs` — `HandlerRegistry` collects boxed
  handlers; `into_dispatcher()` freezes. `TypedProtocolSlot<P>`
  wraps a `flowscope::driver::SlotHandle` for the run loop drain.
- `src/monitor/mod.rs` — `Monitor` + `MonitorBuilder`. Builder
  surface: `.interface(s)`, `.protocol::<P>()`,
  `.on::<E, _, _>()`, `.state::<T>()`, `.counter::<K>(...)`,
  `.sink(s)`, `.tick(...)`, `.build()`. Run modes:
  `run_until(Instant)`, `run_for(Duration)`, `run_until_signal()`.
- `src/monitor/run.rs` — single-stream run loop, `dispatch_lifecycle`
  translates `flowscope::driver::Event` into typed payloads, awaits
  sync + async passes per event. `ShutdownSignal` manages
  SIGINT/SIGTERM via `tokio::signal::unix`.
- `src/monitor/tick.rs` — `TickRegistration` recorded by `.tick()`
  (Phase F lights up the firing pump).
- Monitor is `!Send` (flowscope's SlotHandle uses `Rc<RefCell<…>>`).
  Use with `flavor = "current_thread"` or `LocalSet`.
- `error::BuildError` with `NoInterface`, `MultiInterfaceNotYetSupported`,
  `TooManyEventTypes`, `ProtocolDispatchMismatch`.

**Phase C — Perf hardening + AnomalyWriter + dhat bench:**
- `src/anomaly/sink.rs` — real `AnomalySink` trait body:
  `write(kind, severity, ts, key, observations, metrics)` +
  default `flush()`. Object-safe. `begin(...)` lives on both
  `impl dyn AnomalySink + '_` and a blanket `AnomalySinkExt`
  trait — works through trait objects (layered chains) AND
  typed sinks.
- `AnomalyWriter<'sink>` — stack-only builder with
  `ArrayVec<(&'static str, Cow<'sink, str>), 8>` observations
  and `ArrayVec<(&'static str, f64), 8>` metrics. Overflow
  silently dropped. `&'static str` values stay `Cow::Borrowed`.
- `src/anomaly/shipped_sinks.rs` — `StdoutSink`, `StdoutJsonSink`
  (`feature = "serde"`), `TracingSink`, `ChannelSink` + `OwnedAnomaly`.
- `src/ctx/split.rs` — `split_state_sink::<T>()`,
  `split_state_counter::<T, K>()`, `split_sink_counter::<K>()`,
  `split_state_sink_counter::<T, K>()` — disjoint-field
  projection via audited `unsafe` (one `// SAFETY:` block per helper).
- `benches/zero_alloc.rs` (`feature = "bench-zero-alloc"`) —
  dhat profiler over 100k synthetic dispatches asserts
  `Δ heap < 512 bytes / Δ blocks < 100`. Measured: **Δ 0 / 0**.
  Run: `cargo bench --features bench-zero-alloc --bench zero_alloc`.

**Phase D — Async escape hatch + 5 middleware layers:**
- `src/monitor/async_handler.rs` — `AsyncHandler<E>` trait,
  blanket impl over `Fn(&E::Payload) -> impl Future<Output = Result<()>> + 'static`.
  Payload-only (no `&mut Ctx<'_>` — the HRTB lifetime gymnastics
  don't coerce cleanly in stable Rust). Async closures that
  need state capture `Arc<…>` or pair with `ChannelSink`.
- `Dispatcher::dispatch_async::<P>(&P)` + parallel `async_slots`
  table. Sequential awaits per event (short-circuit on first error).
- `MonitorBuilder::on_async::<E, _>(handler)`.
- `src/layer/` — netring-internal `Layer` trait (object-safe);
  builder applies layers innermost-first so the first
  `.layer(X)` ends up outermost at runtime.
- 5 shipped layers: `MinSeverity`, `DedupeAnomalies`,
  `RateLimitAnomalies`, `Sample` (inline xorshift64*, no rand
  dep), `Tee` (fan-out).

**Phase E — detector! macro + prelude + monitor umbrella feature:**
- `src/detector_macro.rs` — `detector!` macro_rules! DSL.
  Expands to `Handler<E, PayloadCtx>` closure.
- `MonitorBuilder::detect(handler)` — sugar alias for `.on(...)`.
- `src/prelude.rs` — `use netring::prelude::*;` brings ~30 names
  (Monitor, builtin markers, event types, Ctx, Severity, sinks,
  layers, correlate primitives, common externals).
- Cargo feature `monitor = ["tokio", "channel", "flow", "parse",
  "metrics", "http", "dns", "tls", "icmp", "emit", "serde"]` —
  umbrella for app users.
- Multi-interface support and tick-handler firing deferred to
  Phase F (sharded run loop).

**Phase G — version bump + CHANGELOG + migration guide:**
- `Cargo.toml` 0.19.0 → 0.20.0.
- `CHANGELOG.md` 0.20.0 entry covering all Phase A–E work.
- `docs/migration-0.19-to-0.20.md` — 4 recipes for the legacy →
  0.20 transition.
- Phase F (per-CPU sharding) deferred to 0.21+.
- Legacy `ProtocolMonitor` / `AnomalyMonitor` deletion deferred
  to 0.22.0 (0.21.x adds `#[deprecated]`).

### Recent additions (netring 0.17 — flowscope 0.10 lockstep bump)

Driven by
[`plans/netring-0.17-flowscope-0.10-bump-2026-06-07.md`](../plans/netring-0.17-flowscope-0.10-bump-2026-06-07.md).

- **flowscope 0.7 → 0.10.1**. Dramatically backward-compatible
  for netring (the plan's `flowscope::Error` migration and
  `Established { l4 }` destructure work both ended up as
  no-ops on master).
- **`netring/serde` Cargo feature.** Derives `Serialize` on
  `Anomaly<K>` / `AnomalyContext` / `Severity` + adds
  `Anomaly::to_json_value() -> serde_json::Value`. Composes
  with `flowscope/serde` (shipped 0.8) so users can ship full
  parsed `ProtocolMessage` payloads through line-oriented
  JSON sinks (Vector / Fluentd / Loki). `Deserialize` not
  derived (`&'static str` fields can't roundtrip).
- **`ProtocolMonitorBuilder::tls_handshake()`** opt-in leg
  runs flowscope's `TlsHandshakeParser` aggregator alongside
  (or instead of) `.tls()`. `ProtocolMessage::TlsHandshake`
  variant carries SNI / ALPN / JA3 / JA4 / version / cipher /
  outcome.
- Detector simplification across the board: 16 string-literal
  match sites switched to `flowscope::parser_kinds::*`
  constants; `IcmpType::error_inner()` collapses
  `icmp_explained_drop`'s 40-LoC extractor; `DnsResolutionCache`
  replaces the per-source HashMap shape in `tls_to_unresolved_ip`;
  `AnomalyKind::short_kind()` for stable Prometheus labels in
  `FlowAnomalyRule`; `slow_tls_handshake` rewritten to alert
  on `HandshakeOutcome::Truncated`.

### Earlier — netring 0.17 (was scheduled as flowscope 0.7 bump)

Driven by
[`plans/netring-0.17-flowscope-0.7-bump-2026-06-03.md`](../plans/netring-0.17-flowscope-0.7-bump-2026-06-03.md).

- **flowscope 0.6 → 0.7.** `FlowEvent::Ended` and
  `SessionEvent::Closed` gain `l4: Option<L4Proto>`; the
  `HashMap<FiveTupleKey, L4Proto>` workaround in
  `full_monitor.rs` / `multi_protocol_monitor.rs` is gone.
- **New `icmp` Cargo feature** + `ProtocolMessage::Icmp` +
  `ProtocolMonitorBuilder::icmp()` (with `.icmp_v4_only()` /
  `.icmp_v6_only()` variants). Combined v4 + v6 BPF
  (`ip proto 1 or ip6 ip_proto 58`).
- **`From<flowscope::event::Severity> for netring::Severity`** —
  1:1 variant map. `Severity` gains `Default = Info`.
- **`FlowAnomalyRule`** built-in `AnomalyRule` — lifts every
  `FlowEvent::FlowAnomaly` / `TrackerAnomaly` into the same
  `Vec<Anomaly<K>>` pipeline as user-defined rules. Tier comes
  from `AnomalyKind::severity()`; the kind name lands in
  `context.observations["kind"]`. Optional `min_severity` floor.
- **`examples/anomaly/icmp_explained_drop.rs`** — the third
  N10 reference detector. Uses `IcmpInner` to correlate ICMP
  errors (Destination Unreachable / Time Exceeded / Redirect /
  PacketTooBig / ParameterProblem) back to the originating
  TCP/UDP flow via `KeyIndexed`. Classifies aborted flows into
  Info/explained vs Warning/unexplained.

### Earlier — netring 0.16 roadmap, Part I + Part II + III

Part III — anomaly correlation harness:

- **N9 `AnomalyMonitor<K>` + `AnomalyRule<K>`** in new
  `netring::anomaly` module. A rule is `fn name() -> &'static
  str`, `fn observe(&mut self, evt: &ProtocolEvent<K>, emit:
  &mut Vec<Anomaly<K>>)`, optional `fn on_tick(now: Timestamp,
  emit: ...)`. The monitor reuses one scratch `Vec` across
  rules.
- `Anomaly<K>` value type: `kind` slug, `severity`
  (Info/Warning/Error/Critical), optional `key`, `ts`,
  `AnomalyContext { observations: Vec<(&'static str, String)>,
  metrics: Vec<(&'static str, f64)> }`. Builder-style
  `with_key`/`with_observation`/`with_metric` setters.
- `examples/anomaly/anomaly_monitor_demo.rs` — reference
  composition: DnsBurstRule (rate, `TimeBucketedCounter`) +
  DnsResolvedNoConnectionRule (cross-protocol, `KeyIndexed`)
  in one event loop driven by `ProtocolMonitor` + `AnomalyMonitor`.

Part II — single-call multi-protocol monitor:

- **N8 `ProtocolEvent<K>` + `ProtocolMessage`** in new
  `netring::protocol` module. Sum-type over `FlowEvent` + L7
  messages (Http/Dns/Tls). Each Message carries `parser_kind`
  (from flowscope 0.5) for routing without downcasting.
  Feature-gated variants — only present when the corresponding
  parser feature is enabled.
- **N7 `ProtocolMonitorBuilder` + `ProtocolMonitor<K>`** —
  declarative entry. `.interface(name).flow().http().dns().build(extractor)`
  internally opens N AsyncCaptures (one per protocol, each with
  its kernel BPF filter narrowing to that protocol's ports),
  boxes each as `Stream<Item = Result<ProtocolEvent<K>, Error>>`,
  and round-robin polls them through a single unified stream.
- `examples/l7/full_monitor.rs` rewritten on top of the new
  builder — drops ~80 LoC of `tokio::select!` orchestration in
  favour of one `.build()` call. Same kernel/runtime behaviour.

Per-protocol arms only forward `SessionEvent::Application` events
as `ProtocolEvent::Message`; the lifecycle (Started/Ended/etc.)
is owned by the `.flow()` arm, avoiding duplicate Started events
when both `.flow()` and e.g. `.http()` are enabled.

### Recent additions (netring 0.16 roadmap, Part I + foundation for III)

Executing
[`plans/netring-0.16-roadmap-2026-05-29.md`](../plans/netring-0.16-roadmap-2026-05-29.md).
Items landed:

- **N1** — `flowscope` bumped 0.4 → 0.6. Anomaly split
  (`FlowAnomaly`/`TrackerAnomaly`), `SessionEvent::Application
  .parser_kind` field plumbed, `Reassembler::segment(seq, payload,
  ts)` migration. Catches up with everything that shipped in
  flowscope 0.5/0.6.
- **N11** — `BpfFilter::builder().ports([P...])` / `.src_ports`
  / `.dst_ports` multi-port OR shortcut. Lets examples write
  `.tcp().ports([80, 8080])` instead of nested `.or(|b| ...)`
  chains.
- **N2** — over-verbose BPF filters in `http_session` /
  `dns_lookups` / `full_monitor` collapsed to use the shortcut.
- **N9 foundation** — new `netring::correlate` module
  (`#[cfg(feature = "flow")]`) with two anomaly-detection
  primitives:
  - `TimeBucketedCounter<K>` — sliding-window per-key rate counter
    (DNS bursts, connection storms). 8 unit tests.
  - `KeyIndexed<K, V>` — TTL'd kv-cache for cross-protocol
    correlation (DNS resolutions, last-seen hostnames). 9 unit
    tests including `drain_expired` for "expected B-after-A didn't
    happen" detectors.
- **`examples/anomaly/`** — first two reference detectors:
  - `dns_query_burst` (tokio,dns): >50 DNS queries / 10s window
    from one source IP. Uses `TimeBucketedCounter`. ~100 LoC.
  - `dns_resolved_no_connection` (tokio,dns): DNS Response cached
    by answer IP; absence of subsequent TCP/UDP to that IP within
    5s emits anomaly. Uses BOTH primitives + two `AsyncCapture`s
    joined via `tokio::select!`. ~150 LoC.

### Recent additions (0.15.0+ — example reorg + real-life L7)

Major example overhaul:

- **`examples/` reorganized into topic dirs** (`basic/`,
  `async_basics/`, `filter/`, `scaling/`, `xdp/`, `flow/`, `l7/`,
  `pcap/`). Example *names* (the `cargo run --example <name>`
  argument) stay stable — only file paths moved. `Cargo.toml`
  uses explicit `[[example]] name = ..., path = ...` entries.
- **`examples/README.md`** — per-directory index with the right
  `--features` flags.
- **4 new L7 examples** under `examples/l7/`:
  - `multi_protocol_monitor` — single `flow_stream`, demux per-L4
    (ICMP / TCP / UDP) with port hints. ~150 LoC.
  - `http_session` — TCP/80,8080 → `flowscope::http::HttpParser`
    → request/response events. ~110 LoC.
  - `dns_lookups` — UDP/53 → `flowscope::dns::DnsUdpParser::with_correlation()`
    → query / response (with RTT) / unanswered. ~110 LoC.
  - **`full_monitor`** — three concurrent streams via
    `tokio::select!`: flow + HTTP + DNS, each on its own
    BPF-filtered `AsyncCapture`. The "watch this interface for
    everything" recipe. ~200 LoC.
- **New `http` / `dns` / `tls` / `all-parsers` features** on
  netring — pass-through to flowscope's per-protocol parsers.

### Recent additions (0.14.0)

flowscope 0.3 → 0.4 bump. Headline pickup: the new periodic
`SessionParser::on_tick` / `DatagramParser::on_tick` hook is
driven by `SessionStream` / `DatagramStream` on every sweep
tick — time-driven L7 patterns (DNS unanswered-request
timeouts, heartbeats, etc.) flow through netring's async chain
with no extra builder calls.

- **Breaking**: `feed_initiator` / `feed_responder` / `parse`
  gain a `ts: Timestamp` arg. netring forwards the carrying
  packet's timestamp automatically.
- **Breaking**: flowscope's `FlowDriver<E, F, S>` /
  `FlowSessionDriver<E, P, S>` / `FlowDatagramDriver<E, P, S>`
  lose the `S` type parameter — transparent re-export through
  netring; users naming the types directly drop the trailing
  `, ()`.
- Sweep order in `SessionStream` / `DatagramStream` now matches
  flowscope's `FlowSessionDriver::sweep`: collect tracker
  events, fire `on_tick` on every live parser (including ones
  about to close), then translate flow events. Default `on_tick`
  is a no-op so existing parsers are unaffected.
- **New** `PcapSessionStream<E, P>` and `PcapDatagramStream<E, P>`
  — async session/datagram streams over offline pcap, wrapping
  flowscope's `FlowSessionDriver` / `FlowDatagramDriver` (so
  `on_tick` integration + EOF flush via `Timestamp::MAX` come
  along for free).
- **New** one-line offline pipeline constructors:
  `AsyncPcapSource::sessions(extractor, parser)` and
  `.datagrams(extractor, parser)`. Mirrors flowscope 0.4's
  `PcapFlowSource::sessions()` / `datagrams()` for the async
  side. `PcapFlowStream::session_stream(parser)` /
  `.datagram_stream(parser)` for users who built a flow stream
  first and want to layer L7 on top.
- `PcapFlowStream`'s EOF flush now anchors at `Timestamp::MAX`
  (matches flowscope's `finish()`); previously used wall-clock
  `now()` which could under-sweep against pcaps with future
  timestamps.
- Other 0.4 additions (`track(impl Into<PacketView>)`,
  driver `finish()`, DNS-over-UDP unification on `DnsUdpParser`)
  flow through netring transparently.

### Recent additions (0.13.1)

Patch release — no API changes, no new features.

- **MSRV raised to 1.95** (was 1.85 in 0.13.0). Reason: the
  flow-tracker / pcap-tap / multi-streams hot paths already used
  `if let X && let Y` let-chains (stabilized in 1.88), and the
  Rust 1.95 clippy promoted `clippy::manual_is_multiple_of` and
  refined `clippy::collapsible_if` to fire through let-chain
  bindings. Bumping MSRV to 1.95 lets the codebase track current
  stable idioms directly.
- **Code-quality**: 8 `n % m == 0` → `n.is_multiple_of(m)`
  conversions across `afpacket/`, `config/`, and 5 examples;
  4 nested-`if let` blocks collapsed to let-chains. Clippy clean
  under `-D warnings` for default + `tokio,channel` +
  `--all-features` matrices.
- **CI**: pinned matrix `rust: [stable, "1.95"]`. Test fixture
  for `bpf_filter_lifecycle` now uses `#[tokio::test]` so
  `AsyncCapture::open_with_filter` sees the runtime it needs.
- **New example**: `async_stats_monitor.rs` — async sibling of
  `stats_monitor.rs`. Demonstrates `StreamCapture::capture_stats()`
  /`capture_cumulative_stats()` polling on a live `FlowStream`
  without disrupting the consumer. Builds on plan 20.

### Recent additions (0.13.0)

Four consolidated plans (20-23) closing all 7 items from des-rs's
2026-05-14 feedback round.

- **Plan 20**: Sealed `StreamCapture` trait gives `FlowStream`,
  `SessionStream`, `DatagramStream`, `DedupStream` a uniform
  `capture()` accessor with default-methoded `capture_stats()` /
  `capture_cumulative_stats()`. Plus `with_pcap_tap(writer)` +
  `TapErrorPolicy { Continue, DropTap, FailStream }` builders on
  each stream type — records each packet to `CaptureWriter` before
  the flow tracker processes it; tap survives session/datagram/
  with_async_reassembler conversions.
- **Plan 21**: New `PacketSetFilter` trait (implemented for
  `Capture`, not for `XdpSocket`). `Capture::set_filter` +
  `AsyncCapture::set_filter` for atomic in-kernel BPF swap.
  `AsyncCapture::open_with_filter(iface, filter)` one-call
  constructor. Composes with plan 20 via
  `stream.capture().set_filter(&new_filter)`.
- **Plan 22**: `AsyncMultiCapture` with five constructors
  (multi-interface, fanout-group workers, heterogeneous). Three
  `Multi*Stream` types yielding `TaggedEvent { source_idx, event }`
  via custom round-robin select (no `futures-util` dep). Per-source
  and aggregate `capture_stats`. New `docs/scaling.md` with
  `FanoutMode` decision matrix and 7 anti-patterns.
- **Plan 23**: `AsyncPcapSource` reads PCAP/PCAPNG via mpsc channel
  fed by `spawn_blocking` task. Format auto-detect; optional
  packet-timestamp pacing; loop-at-eof. `PcapFlowStream` bridges to
  flowscope `FlowTracker`. Live + offline pipelines unify via
  generic `Stream<Item = FlowEvent<K>>` consumer.

### Recent additions (0.12.0)

- **Plan 19**: flowscope 0.3 bump. New builder knobs on `FlowStream`
  / `SessionStream` / `DatagramStream`: `with_idle_timeout_fn(F)`
  (per-key idle timeout override), `with_monotonic_timestamps(bool)`
  (strictly non-decreasing timestamp clamp), `snapshot_flow_stats()`
  (live `(K, FlowStats)` iterator with reassembler high-watermark
  diagnostics). **Breaking**: `SessionEvent::Anomaly` is now
  forwarded as a typed event (previously `tracing::warn!`-and-drop);
  `EndReason::ParseError` is new (treated like `Rst` internally);
  `SessionParser::Message` / `DatagramParser::Message` require
  `Debug` (upstream). `flow_stream(...).session_stream(...)` and
  `.datagram_stream(...)` now move the tracker (preserving
  `idle_timeout_fn` + hot-cache + in-flight flows) instead of
  rebuilding it.

### Recent additions (0.11.0)

- **Plan 18**: Typed `BpfFilter::builder()` — a fluent in-tree
  compiler from a small match vocabulary (`tcp`, `udp`, `vlan`,
  `host`, `net`, `port`, `negate`, `or`) to classic BPF bytecode.
  No external tools (no `tcpdump -dd`), no native deps (no libpcap,
  libbpf, clang), no `unsafe`, no panics. `BpfFilter::matches`
  software interpreter for offline validation. `BpfFilter::new`
  becomes fallible (`Result<_, BuildError>`); `CaptureBuilder::bpf_filter`
  takes a `BpfFilter` directly. See `examples/bpf_filter.rs`.
- **Plan 12 phase 2**: `XdpSocketBuilder::with_program(XdpProgram)`
  for caller-loaded XDP programs (compiled via `aya-bpf` /
  `bpf-linker` / `clang -target bpf`). Same orchestration as
  `with_default_program()` (register socket on map → attach program
  → RAII detach on drop) but pointing at user-supplied bytecode.
  Mutually exclusive with `with_default_program()`. See
  `examples/async_xdp_custom_program.rs`.

### Recent additions (0.8.0)

- **Plan 11**: `SO_PREFER_BUSY_POLL` + `SO_BUSY_POLL_BUDGET` builder
  methods on AF_PACKET and AF_XDP (kernel ≥ 5.11). Closes the AF_XDP↔
  DPDK latency gap on payload-touching workloads.
- **Plan 12 phase 1+2**: built-in XDP redirect-all program loader via
  optional `aya`. `XdpSocketBuilder::with_default_program()` is a
  full AF_XDP recipe in one call. `XdpProgram::from_aya(...)` lets
  users wrap their own compiled programs and reuse netring's
  attach + register + RAII teardown.
- **Plan 50.6**: `FlowStream::broadcast(buffer)` →
  `FlowBroadcast<K>` for multi-subscriber flow events with
  per-subscriber `Lagged` semantics (tokio `broadcast` channel under
  the hood).
- **Workspace split**: flow tracking (formerly `netring-flow{,-http,
  -tls,-dns,-pcap}`) extracted to a separate `flowscope` crate. No
  user-facing API broke; `netring::flow::*` re-exports still work.

## Build & Test

```bash
# Unit tests (no privileges)
cargo test

# Full tests (need CAP_NET_RAW — use justfile)
just setcap          # sudo once — grants capabilities on all binaries
just test            # runs all tests without sudo
just test-unit       # unit tests only
just test-one <name> # run specific test

# Examples
just capture eth0    # basic capture
just dpi eth0        # deep packet inspection
just stats eth0      # live statistics

# Plan 11 example: AF_XDP with busy-poll trio
just async-xdp-busy eth0 30   # 30s capture, busy-poll-tuned

# Plan 12 example: AF_XDP self-loaded (no external XDP loader)
just async-xdp-self lo 10     # 10s capture on lo, SKB mode

# Lint
just ci              # clippy + unit tests + docs + bench compile
just ci-full         # setcap + full test suite
```

## Key Files

- `SPEC.md` — Complete specification (source of truth for design)
- `docs/` — Architecture, API overview, tuning guide, troubleshooting
- `src/capture.rs` — High-level Capture + CaptureBuilder
- `src/inject.rs` — High-level Injector
- `src/traits.rs` — PacketSource, PacketSink, AsyncPacketSource traits
- `src/packet.rs` — Packet, PacketBatch, BatchIter, Timestamp, PacketStatus
- `src/dedup.rs` — Loopback dedup primitive (plan 10)
- `src/config/` — Config types module
  - `bpf.rs` — `BpfFilter` + `BpfInsn` + `BuildError`
  - `bpf_builder.rs` — Typed `BpfFilterBuilder` + `MatchFrag` IR
  - `bpf_compile.rs` — Symbolic-IR cBPF compiler (plan 18)
  - `bpf_interp.rs` — Software cBPF interpreter (`BpfFilter::matches`)
  - `ipnet.rs` — Zero-dep `IpNet` (addr + prefix)
  - `mod.rs` — `FanoutMode` / `FanoutFlags` / `TimestampSource` / `RingProfile`
- `src/error.rs` — Error enum (now includes `Loader` for `xdp-loader` feature)
- `src/afpacket/rx.rs` — AfPacketRx + builder (busy-poll trio added in 0.8)
- `src/afpacket/tx.rs` — AfPacketTx + builder (V1 frame-based TX)
- `src/afpacket/ring.rs` — MmapRing (NonNull, strict provenance, AtomicU32)
- `src/afpacket/socket.rs` — All setsockopt wrappers (incl. busy-poll trio)
- `src/afpacket/ffi.rs` — libc re-exports + supplemental constants
- `src/afpacket/fanout.rs` — `PACKET_FANOUT` plumbing (Hash/CPU/QM/EBPF/LB)
- `src/afxdp/mod.rs` — XdpSocket + XdpSocketBuilder (AF_XDP public API)
- `src/afxdp/ffi.rs` — libc re-exports for XDP constants/structs
- `src/afxdp/socket.rs` — AF_XDP socket/setsockopt/bind wrappers
- `src/afxdp/umem.rs` — UMEM mmap + frame allocator
- `src/afxdp/ring.rs` — 4 XDP ring types (Fill, RX, TX, Completion)
- `src/afxdp/loader/` — XDP program loader (plan 12, `xdp-loader` feature)
  - `mod.rs` — public `XdpProgram` / `XdpAttachment` / `XdpFlags`
  - `default_program.rs` — built-in `bpf_redirect_map` loader
  - `program.rs` — RAII attach + register helpers (uses `aya`)
  - `programs/redirect_all.bpf.{c,o}` — vendored compiled bytecode
- `src/async_adapters/` — tokio and channel adapters
  - `flow_stream.rs` — `AsyncCapture::flow_stream(extractor)` core
  - `session_stream.rs` — `.session_stream(parser)` (plan 31)
  - `datagram_stream.rs` — `.datagram_stream(parser)` (plan 31)
  - `flow_broadcast.rs` — `.broadcast(buffer)` multi-subscriber (plan 50.6)
  - `conversation.rs` — `Conversation<K>` aggregate
  - `dedup_stream.rs` — loopback dedup async wrapper
  - `async_reassembler.rs` — async TCP reassembly hook
  - `stream_capture.rs` — sealed `StreamCapture` trait (plan 20)
  - `multi_capture.rs` — `AsyncMultiCapture` + constructors (plan 22)
  - `multi_streams.rs` — `MultiFlowStream`/`MultiSessionStream`/
    `MultiDatagramStream` + `TaggedEvent` (plan 22)
- `src/pcap_tap.rs` — `PcapTap` + `TapErrorPolicy` (plan 20; `pcap + tokio`)
- `src/pcap_source.rs` — `AsyncPcapSource` + `AsyncPcapConfig` +
  `PcapFormat` (plan 23; `pcap + tokio`)
- `src/pcap_flow.rs` — `PcapFlowStream` bridge to flowscope's
  `FlowTracker`, plus `PcapSessionStream` (over
  `FlowSessionDriver`) and `PcapDatagramStream` (over
  `FlowDatagramDriver`) for one-line offline L7 pipelines
  (`pcap + tokio + flow`)
- `docs/scaling.md` — fanout decision matrix + anti-patterns (plan 22)

### 0.20 Monitor API (gated `flow + tokio`)

- `src/protocol/` — Protocol plugin layer
  - `mod.rs` — `Protocol` trait, `Dispatch`, `SignatureMatch`,
    `ProtocolInitError`, `FlowKey` alias. Also still hosts the
    legacy `ProtocolMonitor` from 0.16; both coexist.
  - `event_typed.rs` — `Event` trait + typed event markers
    (`FlowStarted<P>`, `FlowEnded<P>`, `FlowEstablished<P>`,
    `AnyFlowAnomaly`, `Tick`).
  - `builtin/{tcp,udp,icmp,http,dns,tls,tls_handshake}.rs` —
    the 7 builtin `Protocol` impls.
- `src/ctx/` — per-event context
  - `mod.rs` — `Ctx<'a>` struct + `SourceIdx` + method accessors
    (`state_mut`, `counter_mut`, `sink_mut`).
  - `from_ctx.rs` — `StateMap` + `CounterRegistry` (TypeId-keyed
    `FxHashMap`).
  - `split.rs` — `split_state_sink::<T>` / `split_state_counter`
    / `split_state_sink_counter` / `split_sink_counter` — audited
    `unsafe` for disjoint-field projection.
- `src/monitor/` — the dispatcher + builder + run loop
  - `mod.rs` — `Monitor` + `MonitorBuilder` (public). Builder
    accumulates protocols, handlers, state, sinks, layers, ticks;
    `build()` freezes into the dispatcher and applies layers
    innermost-first.
  - `handler.rs` — `Handler<E, Marker>` trait + blanket impls
    for `Fn(&E::Payload)` and `Fn(&E::Payload, &mut Ctx<'_>)`.
    `PayloadOnly` / `PayloadCtx` marker types.
  - `async_handler.rs` — `AsyncHandler<E>` trait + blanket impl
    over `Fn(&E::Payload) -> impl Future + 'static`. `BoxFuture`
    type alias for the boxed-future return.
  - `dispatcher.rs` — `Dispatcher` (TypeId-keyed slot table,
    `MAX_EVENT_TYPES = 16`). `dispatch::<P>` (sync) +
    `dispatch_async::<P>` (async). `BoxedHandler`,
    `BoxedAsyncHandler`, `DynAsyncHandler` trait.
  - `registry.rs` — `HandlerRegistry` build-time collector,
    `ProtocolSlot` trait + `TypedProtocolSlot<P>` adapter for
    flowscope's `SlotHandle` drain.
  - `run.rs` — `run_loop` + `dispatch_lifecycle` +
    `dispatch_lifecycle_async`. `ShutdownSignal` for SIGINT/SIGTERM.
  - `tick.rs` — `TickRegistration` boxed callback (Phase F
    consumer).
- `src/anomaly/sink.rs` — `AnomalySink` trait + `AnomalyWriter`
  + `NoopSink` + `AnomalySinkExt`. `ANOMALY_INLINE_CAPACITY = 8`.
- `src/anomaly/shipped_sinks.rs` — `StdoutSink`, `StdoutJsonSink`
  (`feature = "serde"`), `TracingSink`, `ChannelSink` +
  `OwnedAnomaly`.
- `src/layer/` — middleware over the sink chain
  - `mod.rs` — `Layer` trait (object-safe).
  - `min_severity.rs` — `MinSeverity` + `MinSeverityLayered`.
  - `dedupe.rs` — `DedupeAnomalies` + sliding-window `FxHashMap`.
  - `rate_limit.rs` — `RateLimitAnomalies` per-kind token bucket.
  - `sample.rs` — `Sample` with inline xorshift64* RNG.
  - `tee.rs` — `Tee` fan-out wrapper.
- `src/detector_macro.rs` — `detector!` `macro_rules!` DSL.
- `src/prelude.rs` — `use netring::prelude::*;` glob surface.
- `benches/zero_alloc.rs` — dhat allocation regression bench
  (`feature = "bench-zero-alloc"`).
- `docs/migration-0.19-to-0.20.md` — legacy → 0.20 migration recipes.

## Architecture

- `nix` 0.31 for standard syscalls (mmap, poll, if_nametoindex)
- Raw `libc` for TPACKET-specific setsockopt and sendto(NULL) for TX
- `libc` 0.2.183 exports all TPACKET_V3 structs and busy-poll constants —
  `ffi.rs` re-exports only
- Strict provenance (`ptr.map_addr()`) for all mmap pointer math
- `OwnedFd` / `BorrowedFd` / `AsFd` — no raw fd in public API
- Drop ordering: `ring: MmapRing` before `fd: OwnedFd` in struct fields
- XDP loader (when `xdp-loader` enabled): `_xdp_attachment: Option<XdpAttachment>`
  in `XdpSocket` drops before the rings + fd, so the program detaches from
  the interface before AF_XDP shuts down
- `flowscope` is a non-optional dep with `default-features = false` (just
  `bitflags` + `thiserror`); `Timestamp` and `PacketView` are unconditionally
  re-exported from it. The `parse` / `flow` features add flowscope's heavier
  modules (extractors, tracker, reassembler, session)

## Design Constraints

- `LendingIterator` not stabilized — flat `packets()` iterator uses unsafe (raw pointer + lifetime erasure via transmute)
- `gen` blocks not stabilized — `nightly` feature reserved for future
- TX uses V1 frame-based semantics (not V3 blocks)
- `tpacket_bd_ts.ts_usec` in libc — read as nanoseconds for TPACKET_V3
- `AsyncCapture` uses `wait_readable()` + `get_mut().next_batch()` for zero-copy, or `recv()` for owned packets, due to borrow-checker limitations with AsyncFd + lending returns
- `MAP_LOCKED` fallback: catches EPERM, ENOMEM, and EAGAIN, retries without MAP_LOCKED
- Integration tests must use deadline-based loops with `next_batch_blocking()`, NOT `packets()` (which blocks forever on timeout)
- `xdp-loader` ships a vendored 1 KB ELF (`redirect_all.bpf.o`); regenerating
  needs `clang` but only the maintainer touches it
- AF_XDP `with_default_program()` defaults to `SKB_MODE` so it works on
  `lo` and unprivileged interfaces; users on real NICs should switch to
  `DRV_MODE` for native-driver AF_XDP

## Pre-publish checklist

For the next `cargo publish` of netring:

1. Ensure `flowscope` is published to crates.io at the version netring
   needs (currently `0.4`).
2. Verify `netring/Cargo.toml`'s `flowscope` version dep matches
   (default features false; same feature selectors as today).
3. Bump `netring/Cargo.toml` `version` if more changes have landed
   beyond what's in this CHANGELOG.
4. `cargo publish -p netring --dry-run` to verify the package
   contents.
5. `cargo publish -p netring`.

**Known operator gotcha**: on at least one dev machine
`~/.cargo/credentials.toml` is an empty root-owned directory (likely
a misconfigured Docker volume mount). `cargo publish` fails with
"Is a directory". Workarounds: `export CARGO_REGISTRY_TOKEN=<token>`
or `sudo rmdir ~/.cargo/credentials.toml && cargo login`.
