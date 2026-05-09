# Changelog

## Unreleased

### Built-in XDP program loader for AF_XDP (plan 12)

`XdpSocketBuilder::with_default_program()` makes AF_XDP self-contained:
the builder loads a pre-compiled redirect-all XDP program, attaches
it to the interface, and registers the AF_XDP socket on its embedded
XSKMAP — all in one call. Previously every AF_XDP user had to load
and attach an XDP program externally (via aya, libxdp, bpftool); now
you don't.

- New optional Cargo feature `xdp-loader = ["af-xdp", "dep:aya"]`. Pulls
  `aya` (pure Rust) for the runtime program-load and netlink-attach
  machinery. With the feature off, netring builds without aya.
- New module `netring::xdp` (gated): `default_program(max_queues)`,
  `XdpProgram`, `XdpAttachment` (RAII detach guard), `XdpFlags`
  (`SKB_MODE` / `DRV_MODE` / `HW_MODE` / `REPLACE`).
- New `XdpSocketBuilder` methods (gated): `with_default_program()`,
  `xdp_attach_flags(...)`, `force_replace(true)`. Default attach mode
  is `SKB_MODE` (works on every interface including `lo`); switch to
  `DRV_MODE` for native-driver XDP on supported NICs.
- The 5-instruction redirect-all program (`bpf_redirect_map(&xsks_map,
  ctx->rx_queue_index, XDP_PASS)`) is hand-written in C and
  pre-compiled to `redirect_all.bpf.o` (~1 KB ELF). The compiled
  object is committed; only `clang` is needed to regenerate (and only
  the maintainer ever does that). Consumers don't need clang/libbpf.
- 3 unit tests verify ELF magic, BPF machine type, and presence of
  the program and map symbols in the vendored object.
- RAII teardown: dropping `XdpSocket` detaches the program from the
  interface and unloads the map.
- Example: `examples/async_xdp_self_loaded.rs`.

Out of scope for this release (deferred follow-ups):
- `XdpSocketBuilder::with_program(prog)` for caller-loaded custom aya
  programs.
- Multi-queue XSKMAP sharing (`with_xsk_map(&map)`).
- Hardware offload validation for SmartNICs.

References: <https://docs.kernel.org/networking/af_xdp.html>,
<https://aya-rs.dev/book/>.

### AF_XDP / AF_PACKET busy-poll trio (plan 11)

Expose Linux ≥ 5.11 socket options that close most of the latency
gap between AF_XDP and DPDK on payload-touching workloads:

- `SO_BUSY_POLL` (kernel ≥ 4.5) — already supported via `busy_poll_us`
  on `Capture::builder()`; now also on `XdpSocketBuilder`.
- `SO_PREFER_BUSY_POLL` (≥ 5.11) — new `prefer_busy_poll(bool)`
  builder method on both. Tells the kernel to prefer the busy-poll
  path over softirq scheduling.
- `SO_BUSY_POLL_BUDGET` (≥ 5.11) — new `busy_poll_budget(u16)` builder
  method on both. Caps per-poll packet count.

Pulled libc constants directly (`libc 0.2.183` exports both new
options); no native deps. The trio matches Suricata's
`af-xdp.busy-poll{,_budget,prefer}` config keys.

Example: `examples/async_xdp_busy_poll.rs`.

Reference: <https://docs.kernel.org/networking/af_xdp.html>,
arxiv 2402.10513 *Understanding Delays in AF_XDP-based Applications*.

### Build fix: flowscope dep is non-optional

The previous workspace-extraction commit (`0a04082`) made `flowscope`
an optional dep, which broke `cargo build` without the `parse`
feature because `Packet::view()` and `pub use flowscope::Timestamp`
in `lib.rs` are unconditional. This release makes `flowscope` a
non-optional dep with `default-features = false`. With no features,
flowscope pulls only `bitflags` + `thiserror` — both already in
netring's tree, so the no-feature dep tree is unchanged in
practice.

### Workspace split: flow tracking moves to `flowscope`

The flow & session tracking crate previously known as `netring-flow`
(plus its companions `netring-flow-{http,tls,dns,pcap}`) has been
extracted to a separate repository and consolidated into a single
crate, [`flowscope`](https://github.com/p13marc/flowscope). The
companion crates are now feature-gated modules of `flowscope`
(`http`, `tls` + `ja3`, `dns`, `pcap`).

netring's `flow` feature now pulls `flowscope` instead of
`netring-flow`. Until `flowscope` is published to crates.io, the
dep is sourced from git. Async stream adapters
(`AsyncCapture::flow_stream`, `.session_stream`, `.datagram_stream`)
remain in netring; only the underlying traits and parsers moved.

If you imported anything from `netring-flow` or its companions:
- `netring_flow::X` → `flowscope::X`
- `netring_flow_http::X` → `flowscope::http::X`
- `netring_flow_tls::X` → `flowscope::tls::X`
- `netring_flow_dns::X` → `flowscope::dns::X`
- `netring_flow_pcap::X` → `flowscope::pcap::X`

If you went through `netring::flow::*`, no change.

The CHANGELOG entries for plans 10, 12, 20, 22–24, 30, 31 (the flow
work shipped under netring 0.7.0) are preserved below as the original
release record. New flow-related changes will be tracked in
`flowscope`'s changelog.

## 0.7.0 — Flow & session tracking (workspace split)

A major release introducing pluggable flow & session tracking,
delivered across two crates in a Cargo workspace:

- **`netring` 0.7.0** — the existing AF_PACKET / AF_XDP capture +
  inject crate. Linux only.
- **`netring-flow` 0.1.0** (new) — pluggable flow & session tracking,
  cross-platform and **runtime-free** (no tokio, no async deps,
  no Linux-specific code). Pair with any source of `&[u8]` frames:
  pcap, tun-tap, replay, embedded.

The flow stack went through four implementation phases (alpha.0
through alpha.3 — see `plans/INDEX.md` and intermediate tags). What
shipped:

### Workspace + skeleton (was alpha.0)

- Repository is now a Cargo workspace. `netring` and `netring-flow`
  are members; `Cargo.lock` lives at the workspace root.
- `Timestamp` moved from `netring` to `netring-flow`.
  `netring::Timestamp` continues to work via re-export.
- `justfile` recipes and CI workflow updated for the workspace.
- End-user surface (`cargo add netring`, `cargo build`) unchanged.

### Flow extractor + built-ins (was alpha.1)

In `netring-flow`:

- **`PacketView<'a>`** — frame + timestamp; the abstract input to
  every extractor.
- **`FlowExtractor` trait** — implement to define what a flow is in
  your domain. `Send + Sync + 'static`, returns `Extracted<Key>`.
- **`Extracted<K>`** — flow descriptor: key, orientation
  (Forward/Reverse), `Option<L4Proto>`, `Option<TcpInfo>`.
- **`L4Proto`**, **`Orientation`**, **`TcpInfo`**, **`TcpFlags`**.
- **Built-in extractors**: `FiveTuple` (default `bidirectional()`),
  `IpPair`, `MacPair`.
- **Decap combinators**: `StripVlan`, `StripMpls`, `InnerVxlan`
  (default UDP/4789), `InnerGtpU` (default UDP/2152). Compose freely.
- New `extractors` feature (default-on), pulling `etherparse`.

In `netring`:

- **`Packet::view() -> netring_flow::PacketView<'_>`** — zero-cost
  bridge from the existing capture API to the flow types.
- **`netring::flow::*`** — all flow types re-exported under `parse`.
- **`parse`** feature now activates `netring-flow/extractors`.

### Flow tracker + AsyncCapture::flow_stream (was alpha.2)

In `netring-flow`:

- **`FlowTracker<E, S>`** — bidirectional flow tracker generic over
  an extractor and per-flow user state (defaults to `()`).
  Constructors: `new`, `with_config` (for `S: Default`), `with_state`,
  `with_config_and_state` (any `S`).
- **TCP state machine**: `Active → SynSent → SynReceived → Established
  → FinWait → ClosingTcp → Closed` (or `Reset` on RST).
- **Per-protocol idle timeouts** (Suricata defaults: TCP 5min, UDP
  60s, other 30s) with `FlowTracker::sweep(now)`.
- **LRU eviction** on `max_flows` overflow (default 100k) via the
  `lru` crate.
- **`FlowEvent<K>`**: `Started`, `Packet`, `Established`, `StateChange`,
  `Ended` (with reason, stats, history).
- **`FlowSide`** (Initiator/Responder), **`EndReason`**, **`FlowStats`**,
  **`HistoryString`** (Zeek-style `ShAdaFf`, capped at 16 chars).
- New `tracker` feature (default-on); pulls `ahash`, `smallvec`,
  `arrayvec`, `lru`.

In `netring`:

- **`FlowStream<S, E, U, R>`** — `futures_core::Stream<Item =
  Result<FlowEvent<K>, Error>>`. Driven from `AsyncCapture` via
  `AsyncFd::poll_read_ready_mut`.
- **`AsyncCapture::flow_stream(extractor)`** — the headline tokio
  API; consumes the capture and returns a `FlowStream`.
- **`FlowStream::with_state(init)`** — attach per-flow user state.
- **`FlowStream::with_config(config)`** — non-default tracker config.
- **`FlowStream::tracker()` / `tracker_mut()`** — stats / introspection
  / poking user state mid-stream.
- New `flow` feature on `netring`; pulls `parse` + `netring-flow/tracker`.

### Reassembler hooks (was alpha.3)

In `netring-flow` (sync, runtime-free):

- **`Reassembler` trait** — `segment(seq, payload)`, `fin()`, `rst()`.
- **`ReassemblerFactory<K>`** trait (gopacket-style).
- **`BufferedReassembler`** + **`BufferedReassemblerFactory`** —
  in-order accumulator with OOO drop counter.
- **`FlowTracker::track_with_payload<F>(view, F)`** — sync per-segment
  callback, fires before any events are returned.
- **`FlowTracker::extractor()`** accessor.
- **`FlowDriver<E, F, S>`** — sync wrapper bundling a tracker with a
  reassembler factory; manages per-(flow, side) reassemblers and
  cleans them up on `Ended`.
- **`FlowSide`** is now `Hash` (used as part of reassembler-instance keys).
- New `reassembler` feature (default-on, pure std).

In `netring` (gated by `flow + tokio`):

- **`AsyncReassembler` trait** — methods return
  `Pin<Box<dyn Future<Output = ()> + Send + 'static>>`.
- **`AsyncReassemblerFactory<K>`** trait.
- **`ChannelReassembler`** + **`channel_factory<K, F>(F)`** —
  spawn-task-per-flow pattern with `mpsc::Sender<Bytes>` and
  end-to-end backpressure.
- **`FlowStream::with_async_reassembler(factory)`** — type-shifts
  to `FlowStream<S, E, U, AsyncReassemblerSlot<K, F>>`.
- Async `Stream` impl awaits each reassembler future inline before
  yielding the next event — slow consumers backpressure all the way
  to the kernel ring.
- New deps under `flow + tokio`: `bytes`, `ahash`.

### `Conversation<K>` aggregate (plan 30)

A higher-level abstraction in `netring` (gated by `tokio + flow`)
that bundles a flow's two byte streams into a single async iterator.
Sugar over `with_async_reassembler(channel_factory(...))` for the
common "give me all the bytes from this flow" case.

- `Conversation<K>` — owns an mpsc receiver + shared end-reason
  cell. `next_chunk().await` returns `Initiator(Bytes)` /
  `Responder(Bytes)` / `Closed { reason }` / `None`.
- `ConversationStream<S, E>` — `Stream<Item = Result<Conversation<K>>>`,
  yields one conversation per flow.
- `FlowStream::into_conversations()` — entry point; consumes
  `FlowStream<S, E, (), NoReassembler>`.
- `FlowStream::into_conversations_with_capacity(N)` — explicit
  per-conversation channel capacity (default 64).
- `AsyncCapture::flow_conversations(extractor)` — shortcut.
- Implementation uses `Weak<ConvShared>` in the factory's lookup
  map so per-flow state is reclaimed automatically when both
  reassemblers drop — no leak.
- 5 unit tests + 1 example (`async_flow_conversations.rs`) + 1
  doctest.

### `SessionParser` + `DatagramParser` (plan 31, phase 1)

The pre-1.0 strategic abstraction: typed L7 message streams instead
of byte streams. New traits in `netring-flow` (runtime-free):

- **`SessionParser`** — one parser per flow, `feed_initiator` /
  `feed_responder` / `fin_*` / `rst_*` methods returning
  `Vec<Self::Message>`. For stream-based protocols (HTTP/1, TLS,
  DNS-over-TCP).
- **`DatagramParser`** — one parser per flow, `parse(payload, side)
  -> Vec<Self::Message>`. For packet-based protocols (DNS-over-UDP,
  syslog, NTP).
- **`SessionParserFactory<K>` / `DatagramParserFactory<K>`** with
  blanket impls for `Default + Clone` parsers — pass any such
  parser as its own factory; each new flow gets a clone.
- **`SessionEvent<K, M>`** — `Started { key, ts }`,
  `Application { key, side, message, ts }`,
  `Closed { key, reason, stats }`.
- New `session` feature on `netring-flow` (default-on, depends on
  `tracker`).

Async stream adapters in `netring` (gated on `flow + tokio`):

- **`AsyncCapture::flow_stream(...).session_stream(parser)`** —
  yields `SessionEvent<_, P::Message>` driven by a per-flow
  `SessionParser`. Bytes from each TCP segment dispatch to the
  parser; messages buffer in a per-stream `VecDeque` and drain via
  `Stream::poll_next`.
- **`AsyncCapture::flow_stream(...).datagram_stream(parser)`** —
  same shape for UDP. Walks Eth → optional VLAN×2 → IPv4/IPv6 →
  UDP and feeds the L4 payload to the parser. Skips IP fragments
  and IPv6 extension headers.

Trait bridges shipped with this phase:

- **`netring_flow_http::HttpParser`** — `SessionParser` impl
  producing `HttpMessage::{Request, Response}`. Wraps the existing
  `parser::step` / `eof` machinery; holds independent state per
  direction inside one parser. The callback-style `HttpFactory<H>`
  remains; users pick whichever shape fits.
- **`netring_flow_dns::DnsUdpParser`** — `DatagramParser` impl
  producing `DnsMessage::{Query, Response}`. Stateless across
  packets (correlation lives in the separate `Correlator` type).

Out of scope for this phase:
- `TlsParser` and `DnsTcpParser` bridges (the parser shape is
  proven; mechanical follow-up).
- Per-flow parser stats trait (`SessionParserStats`).
- Property tests across all parsers.
- Migration guide.

### `netring-flow-dns` companion crate (plan 24)

Passive DNS observer — UDP/53 only in v0.1. A new `DnsUdpObserver`
type wraps an inner `FlowExtractor` (the "extractor as tap" pattern)
and fires DNS events on every UDP/53 packet, while delegating flow
tracking to the inner extractor. Built on `simple-dns`.

- `parse_message` / `parse_message_at` — standalone DNS message
  parsers; return `DnsParseResult::{Query, Response}`.
- `DnsHandler` trait: `on_query`, `on_response`, `on_unanswered`.
- `Correlator<S>` — bounded `HashMap<(scope, tx_id), DnsQuery>` with
  oldest-first eviction, query/response matching with elapsed time,
  and `sweep(now)` for the configured `query_timeout` (default 30 s).
  Scoping by flow key prevents cross-flow tx-ID collisions.
- Decoded record types: A, AAAA, CNAME, NS, PTR, MX. Everything
  else surfaces as `DnsRdata::Other { rtype, data }`. TXT bodies
  empty for now (current `simple-dns` API limitation).
- Reads `transaction_id` and the flags word directly from the wire
  to avoid `simple-dns` opcode/rcode conversions; exposes accessors
  via `DnsFlags`.
- Internal `peek_udp` walks Ethernet → optional VLAN×2 → IPv4/IPv6
  → UDP without pulling `etherparse`. Fragments and IPv6 extension
  headers are skipped.
- 7 tests covering parse + correlator (match, orphan, sweep).
- Example: `examples/dns_log.rs` — pcap replay logging Q/R/timeouts
  with RTT.
- Out of scope for v0.1: TCP/53 reassembly (zone transfers, large
  responses), DoT/DoH/DoQ, EDNS(0) option decoding, DNSSEC validation.

### `netring-flow-tls` companion crate (plan 23)

A `ReassemblerFactory` that bridges `tls-parser` (rusticata) into
`netring-flow`'s reassembler. Passive observation only — no
decryption, no MITM. User implements `TlsHandler` to receive
`TlsClientHello` / `TlsServerHello` / `TlsAlert` events.

- Surfaced from ClientHello: legacy + record version, random,
  session ID, cipher suites (in order, GREASE-included), compression,
  SNI, ALPN list, `supported_versions` (for TLS 1.3), `supported_groups`,
  full extension-type list (ordered, suitable for fingerprinting).
- Surfaced from ServerHello: legacy + selected version, random,
  session ID, chosen cipher, ALPN selection.
- Alerts: level (Warning / Fatal / Other) + RFC 5246 description code.
- ChangeCipherSpec stops parsing on that direction (records past
  it are encrypted).
- Records spanning multiple TCP segments handled incrementally.
- Optional `ja3` feature: computes the JA3 canonical string +
  MD5 hex digest, fires `TlsHandler::on_ja3`. GREASE values (RFC
  8701) stripped per the upstream reference.
- 6 unit tests + 1 doctest + 1 JA3 test (when feature on) + 2
  fingerprint unit tests.
- Example: `examples/tls_observer.rs` — print SNI/ALPN per
  ClientHello from a pcap.
- README documents what's not surfaced (encrypted records,
  certificate parsing, session resumption details, JA4).

### `netring-flow-http` companion crate (plan 22)

A `ReassemblerFactory` that bridges `httparse`'s zero-copy HTTP/1.x
parser into `netring-flow`'s reassembler. User implements
`HttpHandler` to receive parsed `HttpRequest` / `HttpResponse`
events.

- HTTP/1.0 + HTTP/1.1 request/response lines + headers + body via
  Content-Length.
- Pipelined requests (multiple events per buffer pass).
- `Connection: close` body terminated by FIN (via
  `Reassembler::fin`).
- Messages split across multiple TCP segments handled
  incrementally.
- Configurable `max_buffer` (1 MiB default) and `max_headers`
  (64 default).
- 7 unit tests + 1 integration test against the Plan-12 HTTP fixture
  + 1 doctest.
- Example: `examples/http_log.rs` — log requests + responses from
  a pcap.
- README documents what's deferred (chunked encoding, HTTP/2,
  HEAD-correlation).

### `netring-flow-pcap` companion crate (plan 20)

A new workspace member that wraps `pcap-file` and exposes pcap
files as iterators of `PacketView`s or `FlowEvent`s. Removes ~10
lines of boilerplate from every offline-analysis program.

- `PcapFlowSource::open(path)` — open a pcap on disk.
- `PcapFlowSource::from_reader(R)` — wrap any `Read` (testing).
- `.views()` — `Iterator<Item = Result<OwnedPacketView, Error>>`
- `.with_extractor(extractor)` — `Iterator<Item = Result<FlowEvent<K>, Error>>`,
  drives an internal `FlowTracker` and runs a final far-future
  sweep on pcap exhaustion to flush unfinished flows as
  `Ended { IdleTimeout }`.
- 3 integration tests, 2 doctests, 1 example (`pcap_summary.rs`).
- README documents the relationship to other capture sources.

### Test infrastructure (plan 12)

- **3 pcap fixtures** under `netring-flow/tests/data/`:
  `http_session.pcap` (TCP HTTP/1.1 lifecycle), `dns_queries.pcap`
  (UDP/53 query/response pairs + NXDOMAIN + lone unanswered),
  `mixed_short.pcap` (TCP + UDP + ICMP). All synthetic; ~2 KB total.
- **Fixture generator**: `cargo run -p netring-flow --example
  generate_fixtures --features test-helpers` re-creates them
  deterministically.
- **3 fixture-driven integration tests** in `netring-flow/tests/pcap_fixtures.rs`.
- **10 property-based tests** (`proptest`) in
  `netring-flow/tests/proptest_invariants.rs` covering: 5-tuple
  canonicalization, TCP state machine never panics, tracker
  flow-count invariant, tracker stats balance, "every parser must
  not panic on arbitrary bytes" (5 separate properties: FiveTuple,
  StripVlan, StripMpls, InnerVxlan, InnerGtpU), and "Established
  always after Started." 256 cases per property by default.
- **6 `cargo fuzz` targets** under `netring-flow/fuzz/fuzz_targets/`
  for the 5 built-in extractors. Excluded from the workspace; run
  with `cargo +nightly fuzz run TARGET`. Justfile recipes:
  `just fuzz-build`, `just fuzz-smoke` (30s per target),
  `just fuzz TARGET`.
- **`test-helpers` feature** on `netring-flow` exposes
  `extract::parse::test_frames` (synthetic-frame builders) for
  downstream tests. Also opens `tcp_state` for proptest. Not for
  production use.

### Loopback dedup (plan 10)

- **`Dedup`** primitive in `netring`. Two factory modes:
  - `Dedup::loopback()` — 1ms window, 256-entry ring,
    direction-aware. Drops the kernel's `Outgoing/Host` re-injection
    pair on `lo`. Same-direction repeats (legitimate retransmits)
    are kept.
  - `Dedup::content(window, ring_size)` — generic content-hash
    dedup, direction-agnostic. Use for any capture where
    duplicates aren't loopback-shaped.
- **`AsyncCapture::dedup_stream(Dedup)`** — `Stream<Item = Result<OwnedPacket>>`
  with duplicates filtered. Sync users use the `Dedup::keep(&pkt)`
  loop directly.
- New dep: `xxhash-rust` (xxh3-64 for content hashing, ~zero deps).
- 10 unit tests; 2 integration tests on `lo`.
- Example: `examples/async_lo_dedup.rs`.

### Documentation (this release)

- **`netring-flow/docs/FLOW_GUIDE.md`** — comprehensive cookbook
  covering quick starts (sync + async), built-in extractors,
  encapsulation combinators, custom extractors (3 worked examples),
  per-flow user state, TCP events and history strings, sync + async
  reassembly, backpressure, idle timeouts, performance notes,
  source-agnosticism, `protolens` bridging.
- **`netring-flow/README.md`** — crates.io card.
- Workspace `README.md` — new "Flow & session tracking" section
  near the top.

### Examples added

In `netring-flow`:
- `pcap_flow_keys.rs` — extract 5-tuples from a pcap.
- `pcap_flow_summary.rs` — sync flow tracking over pcap.
- `pcap_buffered_reassembly.rs` — sync TCP reassembly over pcap
  via `FlowDriver`.

In `netring`:
- `async_lo_dedup.rs` — loopback dedup demo with periodic stats.
- `async_flow_keys.rs` — built-in + custom extractor on live capture.
- `async_flow_summary.rs` — Started/Established/Ended events.
- `async_flow_filter.rs` — protocol + port filter.
- `async_flow_history.rs` — Zeek-style `conn.log` output.
- `async_flow_channel.rs` — `channel_factory` + spawned per-flow tasks.

### Tests

- 202 unit + doctests passing across the workspace (was 97 in 0.6.0).
- New: 25 tracker tests, 13 reassembler / driver tests, 25 extractor
  tests, parser, history, TCP state machine.

### Migration from 0.6.0

- `netring::Timestamp` keeps working (re-export). Deep paths like
  `netring::packet::Timestamp` also still resolve.
- No public types or methods removed from `netring`.
- New optional `flow` feature opts into the flow API; existing
  `netring` users see no change unless they enable it.
- Workspace structure: if you depend on netring as a path dependency,
  update the path to `netring/netring/`.

## 0.6.0 — Async first

netring's primary API is now async/tokio. The sync types are still
first-class but the documentation, examples, and recommended patterns
all lead with the async wrappers.

### Added

- **`AsyncXdpSocket`** — async wrapper for AF_XDP, the previously-missing
  piece in the tokio story. Mirrors `AsyncCapture` for RX (three reception
  modes) and `AsyncInjector` for TX (`send().await` awaits `POLLOUT` under
  backpressure). One wrapper covers both directions since `XdpSocket`
  shares one fd. Behind `tokio + af-xdp` features.
  - `AsyncXdpSocket::open(iface)` / `::new(socket)`
  - `readable() → XdpReadableGuard` / `try_recv_batch()` / `recv()`
  - `into_stream() → XdpStream` (`futures_core::Stream`)
  - `send(data).await` / `flush().await` / `wait_drained(timeout).await`
  - `statistics()` (passthrough to `XdpStats`)

- **`AsyncCapture::open(iface)` / `AsyncInjector::open(iface)`** —
  one-liner shortcuts that replace
  `AsyncCapture::new(Capture::open(iface)?)?`. Specialized impls;
  the generic `new()` still works for builder-configured sources.

- **`Bridge::open_pair(a, b)`** — shortcut for
  `Bridge::builder().interface_a(a).interface_b(b).build()`.

- **`docs/ASYNC_GUIDE.md`** — full async guide covering all four
  async types, the three reception modes, `Send`/`!Send` rules,
  Stream + StreamExt usage, and patterns (mpsc fan-out, graceful
  shutdown, periodic stats + metrics integration).

- **Three new examples**:
  - `examples/async_streamext.rs` — `PacketStream` + `futures::StreamExt`
  - `examples/async_xdp.rs` — `AsyncXdpSocket` TX with backpressure
  - `examples/async_metrics.rs` — periodic `tokio::time::interval` +
    metrics integration

### Changed

- **README rewrite** — leads with async (Quick Start), demotes the
  sync API to its own section. Public API table now pairs sync types
  with their async wrappers.
- **Dev-dependency added**: `futures = "0.3"` (used by the
  `async_streamext` example only).

### Internal

- New module `src/async_adapters/tokio_xdp.rs`.

## 0.5.0 — Feature expansion + cleanup

### Breaking

- **Deprecated 0.3.x aliases removed**: `AfPacketRx`, `AfPacketRxBuilder`,
  `AfPacketTx`, `AfPacketTxBuilder` — use `Capture`, `CaptureBuilder`,
  `Injector`, `InjectorBuilder` (introduced in 0.4.0).
- **`XdpSocket::recv_batch` removed**: use `XdpSocket::next_batch` (renamed
  in 0.4.0).
- Both removals are mechanical migrations covered by 0.4.0's CHANGELOG.

### Added

- **`pcap` feature** — exports captured packets to PCAP files via the
  pure-Rust [`pcap-file`] crate. New `netring::pcap::CaptureWriter`
  type with `write_packet` (zero-copy) and `write_owned` (owned)
  entry points. Nanosecond-resolution kernel timestamps. Includes
  `examples/pcap_write.rs`.
- **`metrics` feature** — `netring::metrics::record_capture_delta`
  records three counters (`netring_capture_packets_total`,
  `netring_capture_drops_total`, `netring_capture_freezes_total`)
  via the [`metrics`] façade. Pair with any recorder
  (`metrics-exporter-prometheus`, OTel, statsd, ...).
- **AF_XDP `XDP_SHARED_UMEM` primitive** —
  `XdpSocketBuilder::shared_umem(primary: impl AsFd)` lets a secondary
  socket share an existing UMEM region. Documents the manual-partition
  contract (each socket allocates from its own free list; users are
  responsible for keeping address ranges disjoint). A higher-level
  `SharedUmem` helper that automates partitioning is planned for a
  future release.

### Documentation

- `docs/TUNING_GUIDE.md` updated for 0.4-era surface (rcvbuf,
  reuseport, fill_rxhash, snap_len, cumulative_stats, AF_XDP `XdpMode`,
  metrics integration).
- `docs/AF_XDP_EVALUATION.md` rewritten as a "what we shipped"
  retrospective covering the four-module layout, ring protocol,
  BPF-program requirement, and unfinished extensions.

### Tests + CI

- `tests/bridge.rs` — paired-veth integration tests for `Bridge`
  (idle smoke + into_inner decomposition). Skips gracefully without
  CAP_NET_ADMIN.
- `tests/xdp.rs` — Tx-only AF_XDP smoke test on `lo`. Skips
  gracefully where the kernel doesn't support XDP on the loopback.
- New `tests/helpers.rs::VethPair` RAII fixture.
- CI:
  - `actions/checkout@v4` → `@v5` (Node 20 deprecation).
  - New `cargo-deny` job (license + advisory + source allowlist).
  - New `cargo-machete` job (unused-dep detection).
  - Integration test feature set now includes `af-xdp`.

### Decision: PacketBackend trait deferred

A unified `PacketBackend` trait covering both AF_PACKET and AF_XDP
was scoped but deferred. The AF_PACKET `Packet` exposes metadata
(`direction`, `vlan_tci`, `rxhash`, `status`) that AF_XDP doesn't
surface, and forcing every AF_PACKET caller to unwrap `Option` for
fields they used directly is a worse trade-off than parallel concrete
APIs. Most users pick one backend (AF_PACKET ~500K–1M pps, AF_XDP
10–24M pps) and stay there. Will revisit when there's user code that
demands cross-backend generic handling.

[`pcap-file`]: https://crates.io/crates/pcap-file
[`metrics`]: https://crates.io/crates/metrics

## 0.4.0 — API redesign

The 0.3.0 surface had two parallel layers per direction: a high-level
wrapper (`Capture`/`Injector`) and a low-level type
(`AfPacketRx`/`AfPacketTx`). The wrappers added almost nothing — duplicated
builders, two `stats()`, two `attach_ebpf_filter()`, two ENOMEM-retry paths
to keep in sync. 0.4.0 collapses them.

### Breaking

- **`AfPacketRx` / `Capture` (wrapper) → merged into `Capture`**.
  - The `packets()` flat iterator, `poll_timeout` field, and ENOMEM retry
    move directly onto `Capture` / `CaptureBuilder`.
  - `Capture::into_inner()` is gone (no inner — Capture *is* the source).
  - `Capture::new(iface)` renamed to `Capture::open(iface)` to match
    `File::open` / `TcpStream::connect`.
- **`AfPacketTx` / `Injector` (wrapper) → merged into `Injector`** with
  the same shape; `Injector::open(iface)` is the new shortcut.
- **`AfPacketRxBuilder` / `CaptureBuilder` (wrapper)** → merged into
  `CaptureBuilder`. Same for `InjectorBuilder`.
- **`XdpSocket::recv_batch` → renamed to `XdpSocket::next_batch`** to
  match `Capture::next_batch` (kept as `#[deprecated]` alias for one
  release).
- **`XdpSocket::next_batch` no longer returns `Result`** — `Option`
  matches the AF_PACKET signature; nothing in `recv_batch` could ever
  return `Err` anyway.
- **`AsyncCapture::wait_readable` removed** — was deprecated in 0.3.0;
  use `readable().await?.next_batch()`.
- **`PacketStream::new(cap)` is still available** but `cap.into_stream()`
  is the new fluent shortcut.

### Migration

Old names ship as `#[deprecated]` type aliases so 0.3.0 code keeps
compiling for one release:

```rust
#[deprecated] pub type AfPacketRx        = Capture;
#[deprecated] pub type AfPacketRxBuilder = CaptureBuilder;
#[deprecated] pub type AfPacketTx        = Injector;
#[deprecated] pub type AfPacketTxBuilder = InjectorBuilder;
```

Source-level migration:

```diff
- let mut rx = AfPacketRxBuilder::default().interface("eth0").build()?;
+ let mut rx = Capture::builder().interface("eth0").build()?;

- let mut cap = Capture::new("eth0")?;
+ let mut cap = Capture::open("eth0")?;

- let batch = xdp.recv_batch()?;
+ let batch = xdp.next_batch();

- cap.wait_readable().await?;
- if let Some(b) = cap.get_mut().next_batch() { ... }
+ let mut g = cap.readable().await?;
+ if let Some(b) = g.next_batch() { ... }
```

### Added

- `Capture::open(iface)` / `Injector::open(iface)` / `XdpSocket::open(iface)` —
  one-liner shortcuts.
- `Capture` exposes `next_batch` and `next_batch_blocking` as inherent
  methods so users don't need `use PacketSource;` for the common case.
  `PacketSource` is still implemented and useful for generic code.
- `XdpSocket::next_batch_blocking(timeout)` — blocking RX with poll(2),
  EINTR-safe. Brings AF_XDP to feature parity with AF_PACKET on the
  blocking-receive surface.
- `AsyncCapture::into_stream()` fluent helper (same as `PacketStream::new`).

### Internal

- ~425 net lines removed by collapsing the wrapper layer (1041 deletions
  vs 616 insertions).
- ENOMEM retry logic moved from `CaptureBuilder` (wrapper) to the merged
  `CaptureBuilder` (now uses a private `build_inner` helper).

## 0.3.0

### Breaking

- **`Capture::attach_ebpf_filter` and `AfPacketRx::attach_ebpf_filter`** now take
  `impl AsFd` instead of `RawFd`. Migration:
  ```diff
  - cap.attach_ebpf_filter(prog.fd().as_raw_fd())?;
  + cap.attach_ebpf_filter(prog.fd())?;
  ```
- **`XdpSocket::statistics`** returns the new [`XdpStats`] type instead of
  `libc::xdp_statistics`. Field names are stable and documented; insulates
  downstream from libc churn.
- **`OwnedPacket`** now carries seven additional metadata fields (`status`,
  `direction`, `rxhash`, `vlan_tci`, `vlan_tpid`, `ll_protocol`,
  `source_ll_addr` / `source_ll_addr_len`). Code that constructed
  `OwnedPacket` struct-literally requires those fields. Field-name access
  continues to work.
- **`PacketBatch::iter()`** is no longer `ExactSizeIterator` — `tp_next_offset == 0`
  can terminate the walk early. Use `PacketBatch::len()` for the count.
- Internal: `XdpRing` switched to a token-based API (`PeekToken`,
  `ReserveToken`); affects only crate-internal callers.

### Added

- **AF_XDP zero-copy receive** — `XdpSocket::recv_batch()` returns
  `Option<XdpBatch<'_>>` borrowing directly from UMEM, mirroring the
  AF_PACKET `PacketBatch` lifecycle. New types: `XdpBatch`, `XdpPacket`,
  `XdpBatchIter`. RAII drop releases descriptors and refills the fill ring.
- **`XdpMode`** enum on `XdpSocketBuilder` — `Rx` / `Tx` / `RxTx` /
  `Custom { prefill }`. Fixes a bug where the default prefill drained
  the entire UMEM into the fill ring, leaving zero frames for `send()`.
  TX-only users **must** set `.mode(XdpMode::Tx)`.
- **`XdpSocket::flush`** now honors `XDP_USE_NEED_WAKEUP` — skips the
  `sendto` syscall when the kernel signals it is actively polling.
- **`Bridge::run_async` / `run_iterations_async`** behind `feature = "tokio"` —
  uses `AsyncFd` + `tokio::select!` instead of manual `poll(2)`. Cheaper
  for tokio users.
- **`Bridge` poll(2) wait** — sync `Bridge::run` now blocks on `poll(2)`
  before draining; previously a busy loop. New `BridgeBuilder::poll_timeout`
  setter (default 100 ms).
- **Per-direction `BridgeBuilder` overrides** — `a_block_size`, `a_block_count`,
  `a_frame_size`, `a_block_timeout_ms` and the `b_*` / `tx_*_*` mirrors.
  Asymmetric ring sizing for capture-on-A / forward-on-B with different MTUs.
- **`Bridge::into_inner()`** returns a new `BridgeHandles` struct
  `{ rx_a, tx_b, rx_b, tx_a }` for advanced patterns.
- **`Bridge::stats`** + `BridgeStats` now classifies dropped forwards into
  `*_dropped_too_large` and `*_dropped_ring_full` per direction.
- **`Capture::packets_for(Duration)` / `packets_until(Instant)`** — bounded
  variants of the unbounded `packets()` iterator. Useful for tests and
  time-limited captures.
- **`PacketIter::take_error()`** — inspect the I/O error that terminated
  iteration (previously discarded silently).
- **`AsyncCapture::readable()` / `ReadableGuard`** — single-step zero-copy
  receive without the `wait_readable + next_batch` race window. Also
  `try_recv_batch` for sugar.
- **`PacketStream`** — `futures_core::Stream<Item = Result<Vec<OwnedPacket>, Error>>`
  adapter over `AsyncCapture`. Composes with `StreamExt` combinators and
  is cancel-safe between polls. Pulls in a tiny `futures-core` dep
  gated by the `tokio` feature.
- **`AsyncInjector`** — async TX counterpart to `AsyncCapture`. `send`
  awaits `POLLOUT` when the ring is full instead of returning `None`;
  `wait_drained` blocks until every queued frame has been transmitted.
- **`AsyncPacketSource`** trait now has an impl for `AsyncCapture<S>`.
- **Cancel safety** documented on `readable`, `try_recv_batch`,
  `PacketStream::poll_next`, and all `AsyncInjector` methods.
- New `examples/async_stream.rs` demonstrating the Stream API.
- New `examples/async_inject.rs` — `AsyncInjector` with backpressure.
- New `examples/async_signal.rs` — Ctrl-C graceful shutdown via
  `tokio::signal::ctrl_c` + `tokio::select!`.
- New `examples/async_pipeline.rs` — capture → `tokio::sync::mpsc` →
  N worker tasks, the canonical fan-out pattern.
- New `examples/async_bridge.rs` — `Bridge::run_async` racing against
  Ctrl-C for graceful shutdown.
- **`PacketSource::cumulative_stats`** — monotonic running totals
  (default impl falls back to `stats()`; AF_PACKET overrides to accumulate
  deltas internally). Mirrored on `Capture` and `Bridge`.
- **`AfPacketTx::pending_count` / `wait_drained`** — observability for TX
  completions.
- **`AfPacketTx::available_slots` / `rejected_slots` / `frame_capacity`** —
  finer-grained slot inspection.
- **EINTR-safe syscall helpers** in `src/syscall.rs`. All blocking
  syscalls (`poll`, TX kick `sendto`) now retry on EINTR transparently.
- **`AfPacketRx::attach_fanout_ebpf` / `Capture::attach_fanout_ebpf`** —
  finally wires `FanoutMode::Ebpf` to a callable API.
- **`fill_rxhash` setter** on RX builders.
- **`SO_REUSEPORT`** setter on RX builders.
- **`SO_RCVBUF` / `SO_RCVBUFFORCE`** setters on RX builders.
- **`ChannelCapture::stop_and_drain()`** — graceful shutdown that returns
  buffered packets instead of discarding them.
- **`OwnedPacket::source_ll_addr()`** accessor for the valid prefix.

### Changed

- **`AfPacketTx::flush`** documentation clarified: the returned count is
  *queued*, not *transmitted* (frames may still be in flight or rejected).
  Use the new `pending_count`/`available_slots` accessors for transmission
  progress.
- **`AfPacketTx::Drop`** now logs a warn-level trace event when the
  best-effort flush fails, rather than discarding silently.
- **`MmapRing` MAP_LOCKED retry** logs a cause-specific hint
  (CAP_IPC_LOCK / RLIMIT_MEMLOCK / OOM) on the warn record.
- **`Bridge::stats`** docstring made explicit about the destructive read.
- **`Capture::packets`** rustdoc promoted the soundness warning ("do not
  collect across blocks") from a buried comment to a `# Soundness` section
  with example.
- **`source_ll_addr`** doc now explains the 8-byte cap (kernel
  `sockaddr_ll::sll_addr` size; LLEs longer than 8 are truncated by the
  kernel before reaching us).
- **`interface_info`** logs a debug-level trace when sysfs MTU is missing.

### Deprecated

- `AsyncCapture::wait_readable()` — use `readable().await?.next_batch()`
  instead. The two-step pattern called `clear_ready` eagerly, opening a
  race window between waiting and reading.

### Fixed

- **#1**: AF_XDP TX-only mode was broken. `xdp_send` example silently
  transmitted zero packets because `build()` prefilled the entire UMEM
  into the fill ring. Now `XdpMode::Tx` skips prefill; `RxTx` splits
  half-and-half.
- **#2**: `Bridge::run` busy-looped at 100 % CPU on idle interfaces.
  Now blocks on `poll(2)` over both RX fds.
- **#3**: `BatchIter` re-emitted the last packet repeatedly when given
  a corrupt `num_pkts > actual` count. Now terminates on the
  `tp_next_offset == 0` kernel marker.
- **#4**: `PacketIter` and `BatchIter` had different bounds checks;
  `Packet::direction()` from the high-level iterator could read past
  the bounds-check guarantee. `PacketIter` now delegates to `BatchIter`.
- **#9**: `AfPacketTx::flush` returned an inflated success count
  (queued, not sent). Documented; new accessors expose the truth.
- **#12**: `XdpSocket::recv` validated kernel-supplied `xdp_desc` bounds.
- **#15**: Bridge dropped jumbo packets with the wrong diagnostic;
  classification + counters added.
- **#17**: `PacketIter` swallowed I/O errors silently. `take_error()`
  now exposes the cause.
- **#18**: `Capture::stats(&self)` was destructive despite the immutable
  signature; `cumulative_stats()` provides the non-destructive surface.
- **#20**: `AfPacketTx::allocate` advanced the cursor on dropped slots
  and never reset `WRONG_FORMAT` slots. Now scans forward up to
  `frame_count` and resets rejections.
- **#21**: `XdpRing` callers could read past their peeked range;
  token-based API enforces bounds at runtime.
- **#22**: `XdpSocket` is now provably `Send` but `!Sync` via
  static const assertion + `compile_fail` doctest.
- **#24**: `ChannelCapture::Drop` discarded buffered packets;
  `stop_and_drain` provides the alternative.

### Removed

- Dead `MmapRing::block_size` accessor.
- `#[allow(dead_code)]` on `XdpRing::needs_wakeup` and
  `attach_fanout_ebpf` — both now part of the live API surface.

## 0.2.0

### Added

- **AF_XDP backend** (feature: `af-xdp`) — kernel-bypass packet I/O via XDP sockets
  - `XdpSocket` with `recv()`, `send()`, `flush()`, `poll()`, `statistics()`
  - `XdpSocketBuilder` with `interface()`, `queue_id()`, `frame_size()`, `frame_count()`, `need_wakeup()`
  - Pure Rust implementation using `libc` syscalls (no native C dependencies)
  - UMEM allocation with frame-based free list allocator
  - 4 ring types (Fill, RX, TX, Completion) with lock-free producer/consumer protocol
  - TX works without a BPF program; RX requires an external XDP program (e.g. via `aya`)
  - `xdp_send` example for TX-only usage
- **Bridge / IPS mode** — bidirectional packet forwarding between two interfaces
  - `Bridge`, `BridgeBuilder`, `BridgeAction`, `BridgeDirection`, `BridgeStats`
  - User-supplied filter callback for per-packet forward/drop decisions
- **Interface capability detection** via sysfs
  - `interface_info()` returns `InterfaceInfo` with MTU, speed, driver, queue count, carrier status
  - `RingProfile` presets: `Default`, `LowLatency`, `HighThroughput`, `MemoryConstrained`, `JumboFrames`
  - `InterfaceInfo::suggest_profile()` and `suggest_fanout_threads()`
- **Per-packet metadata** — `PacketDirection`, `PacketStatus` with VLAN, checksum, and flow hash fields
- **eBPF integration** — `BpfFilter`, `BpfInsn` for classic BPF socket filters; `FanoutMode`, `FanoutFlags`
- **Async adapters** — `AsyncCapture` (feature: `tokio`), `ChannelCapture` (feature: `channel`)
- **Packet parsing** — `etherparse` integration (feature: `parse`)
- `Debug` impl for `PacketBatch` and `BatchIter`
- `Send` impl for `XdpSocket`
- `#[must_use]` on `Bridge`
- Crate-root re-exports for `XdpSocket`, `XdpSocketBuilder`, `Bridge`, `BridgeAction`, `BridgeBuilder`, `BridgeDirection`, `BridgeStats`, `AsyncCapture`, `AsyncPacketSource`, `ChannelCapture`

### Changed

- **Breaking:** `XdpSocketBuilder` fields are now private (use setter methods)
- Extracted shared `raw_setsockopt()` helper into `src/sockopt.rs` (deduplicates AF_PACKET and AF_XDP backends)
- Updated `Cargo.toml` description and keywords to reflect AF_XDP support

### Fixed

- Broken rustdoc link to `AsyncPacketSource` in `traits.rs` module docs

## 0.1.0

Initial release.

- AF_PACKET TPACKET_V3 backend with zero-copy mmap ring buffers
- High-level API: `Capture`, `CaptureBuilder`, `Injector`, `InjectorBuilder`
- Low-level API: `AfPacketRx`, `AfPacketTx`, `PacketSource`, `PacketSink` traits
- `Packet` (zero-copy view), `PacketBatch` (RAII block), `OwnedPacket` (heap copy)
- `TxSlot` for frame-level TX with send-or-discard-on-drop semantics
- `CaptureStats` from kernel `PACKET_STATISTICS`
- `Timestamp` with nanosecond precision
