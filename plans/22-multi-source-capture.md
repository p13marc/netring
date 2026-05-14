# Plan 22 — Multi-source capture: workers + interfaces, one type

## Summary

One `AsyncMultiCapture` type that fans in from N captures of two
shapes:

- `open(&["eth0", "eth1"])` — N different interfaces, one capture
  each.
- `open_workers(iface, n, group_id)` — one interface, N captures
  in a `FANOUT_CPU` group.

Both shapes produce the same return type and the same builder
chain. The yielded event type is `TaggedEvent { source_idx, event }`
where `source_idx` is interface index (in the multi-interface case)
or worker index (in the fanout case). One concept, two
constructors.

Companion deliverable: `docs/scaling.md` covering the canonical
multi-core pattern and the `FANOUT_HASH`-on-skewed-traffic
anti-pattern.

Closes des-rs F#5 (multi-interface) and F#6 (scaling docs).

This plan supersedes the earlier draft pair
(`23-scaling-across-cores` + `25-multi-interface`).

## Status

Done — landed in 0.13.0.

**Implementation notes**:

- The plan called for `futures::stream::select_all` to fan in N
  per-source streams. The shipped implementation rolls a custom
  `SelectState<S>` in `multi_streams.rs` instead — a round-robin
  poll over `Vec<Option<S>>` with `None`-out on exhaustion. The
  reason is dep-graph minimalism: `futures-util` would have become
  a non-optional runtime dep for the multi-source feature, and the
  ~50 LoC custom select preserves indices stably for the
  `per_source_capture_stats` accessor (which `select_all` would
  have hidden behind its opaque type).
- Added an `alive_sources()` accessor on each Multi*Stream during
  the post-release audit (decrements as sources hit EOF).

## Prerequisites

- Plan 20 (`StreamCapture` trait) — per-source stats access on the
  merged stream.
- Plan 21 (`open_with_filter`) — for filtered multi-interface and
  multi-worker captures.

## Out of scope

- Cross-interface flow aggregation. Same TCP flow appearing on
  `eth0` (inbound) and `eth1` (outbound) on a routing gateway
  produces **two separate flows** keyed by `(source_idx, FiveTuple)`.
  Merging is a flowscope-side concern; don't bake it in.
- Cross-interface timestamp reordering. Per
  [Packet-Foo's analysis](https://blog.packet-foo.com/2014/08/the-trouble-with-multiple-capture-interfaces/),
  different NICs deliver frames at their own cadence. Emitted
  order is poll order, not timestamp order. Users wanting global
  monotonic timestamps use `with_monotonic_timestamps(true)` on
  the inner streams, or run `reordercap` post-hoc.
- Per-source different BPF filters / configs in `open_workers`.
  Workers share the same socket-build config; if you need
  heterogeneous workers, use `from_captures` with hand-built
  captures.
- A worker-pool runtime (spawn-and-join). Whichever runtime the
  user has (tokio multi-threaded, raw `std::thread`, rayon) is
  theirs; we hand back the multi-capture and let them choose.
- AF_XDP fanout. AF_XDP has its own multi-queue model
  (`XSKMAP` + queue-per-socket); the recipe is different and lives
  in plan 12 follow-ups.

---

## Background — why one type for two shapes

Both scenarios reduce to "N AF_PACKET captures, fan-in to one
event stream, tag each event with the originating source". The
plumbing is identical:

```
N × AsyncCapture<Capture>
        ↓ flow_stream(extractor.clone()) (one per capture)
N × FlowStream<Capture, E>
        ↓ futures::stream::select_all + map(|evt| TaggedEvent { idx, evt })
1 × MultiFlowStream<E>
```

The only difference is how the N captures get constructed —
distinct interfaces or one interface plus a fanout group. So one
type with two constructors.

For DES traffic (per des-rs feedback): one large mediator flow on
`:15987`, plus many short DEP peer flows. **`FANOUT_HASH` is wrong
here** — the mediator dominates, lands on one socket.
**`FANOUT_CPU`** with RSS distributing the mediator's frames
across RX queues is the right answer.

References:
- [`packet(7)`](https://man7.org/linux/man-pages/man7/packet.7.html)
- [Enabling Packet Fan-Out in libpcap (TMA 2017)](https://dl.ifip.org/db/conf/tma/tma2017/tma2017_paper65.pdf)
- [Suricata AF_PACKET docs](https://docs.securityonion.net/en/2.4/af-packet.html)
- [zeek-af_packet-plugin](https://github.com/zeek/zeek-af_packet-plugin/blob/master/README)

---

## Idiomatic design choices

### Why one type for two shapes

Splitting `AsyncWorkers` and `AsyncMultiCapture` would force users
who want the "N workers across `eth0` plus `eth1` to merge" combo
into ad-hoc plumbing. Keeping one type with two constructors lets
that fall out naturally via `from_captures`:

```rust
let eth0_workers = AsyncMultiCapture::open_workers("eth0", 4, 0xDE57)?;
let eth1_workers = AsyncMultiCapture::open_workers("eth1", 4, 0xDE58)?;
let combined = AsyncMultiCapture::from_captures(
    eth0_workers.into_captures().chain(eth1_workers.into_captures()),
    None,  // auto-derive labels
)?;
```

### Why `TaggedEvent` is a struct, not a tuple

`(u16, FlowEvent<K>)` works mechanically but reads worse at use
sites and can't grow new fields without breaking destructuring.
The struct lets future plans add an `rx_queue: Option<u32>`, a
`fanout_worker: Option<u16>`, etc. without source breakage.

### Why `futures::stream::select_all` (not a custom round-robin)

The `futures` crate's `select_all` is well-tested, handles
backpressure via cooperative polling, and is already a dev-dep at
`Cargo.toml:54`. Hand-rolling fan-in is reinvention.

### Why `MultiFlowStream` doesn't implement `Stream<Item = TaggedEvent>` directly

It does — that's the user-facing trait. But the internal `Pin<Box<dyn Stream + Send>>`
trick keeps the N-tuple of concrete inner types hidden from the
public API. Users see `impl Stream<Item = Result<TaggedEvent<K>, Error>>`
and nothing more.

---

## Files

### NEW

```
netring/netring/src/async_adapters/multi_capture.rs  (~500 LoC)
netring/netring/src/async_adapters/multi_streams.rs   (MultiFlowStream + siblings)
netring/netring/docs/scaling.md                       (~250 lines)
netring/netring/examples/async_fanout_workers.rs      (~80 LoC)
netring/netring/examples/async_multi_interface.rs     (~80 LoC)
netring/netring/tests/multi_capture.rs                (~200 LoC)
```

### MODIFY

```
netring/netring/src/async_adapters/mod.rs   (pub mod multi_capture, multi_streams)
netring/netring/src/lib.rs                  (re-exports)
netring/netring/README.md                   (link to docs/scaling.md)
netring/CHANGELOG.md
```

---

## API delta

### `AsyncMultiCapture`

```rust
/// Fan-in over multiple AF_PACKET captures. Two construction
/// modes:
///
/// - [`open`](Self::open) — N distinct interfaces, one capture
///   each. Tag is interface index.
/// - [`open_workers`](Self::open_workers) — one interface, N
///   captures in a fanout group. Tag is worker index.
///
/// Per-source state is independent (separate kernel rings,
/// separate flowscope trackers). Yielded events carry a
/// [`TaggedEvent::source_idx`] for routing.
pub struct AsyncMultiCapture {
    captures: Vec<AsyncCapture<Capture>>,
    labels: Vec<String>,
}

impl AsyncMultiCapture {
    /// Open one AF_PACKET capture per interface.
    pub fn open<I, S>(interfaces: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>;

    /// Open one AF_PACKET capture per interface with a shared
    /// BPF filter applied to every interface.
    pub fn open_with_filter<I, S>(
        interfaces: I,
        filter: BpfFilter,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>;

    /// Open `n` AF_PACKET captures on a single `interface`, all
    /// bound to one fanout group, distributed by [`FanoutMode::Cpu`].
    ///
    /// `group_id` is the fanout group identifier; must be unique
    /// within the process. Stable across reopens.
    ///
    /// Each yielded event's `source_idx` is the worker index
    /// (0..n).
    pub fn open_workers(
        interface: &str,
        n: usize,
        group_id: u16,
    ) -> Result<Self, Error>;

    /// Like [`open_workers`](Self::open_workers) with an explicit
    /// fanout mode. Use [`FanoutMode::LoadBalance`] for round-robin
    /// (breaks per-flow ordering), [`FanoutMode::Cpu`] otherwise.
    pub fn open_workers_with_mode(
        interface: &str,
        n: usize,
        group_id: u16,
        mode: FanoutMode,
    ) -> Result<Self, Error>;

    /// Wrap an already-built set of captures. Use when each source
    /// needs different config (per-interface buffer sizes,
    /// different filters, mixed worker pools).
    ///
    /// If `labels` is `None`, sources are labelled "source-0",
    /// "source-1", ... internally. If `Some`, must have the same
    /// length as `captures`.
    pub fn from_captures(
        captures: Vec<AsyncCapture<Capture>>,
        labels: Option<Vec<String>>,
    ) -> Result<Self, Error>;

    // ── accessors ──
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;

    /// Label for source `i` — interface name for `open` and
    /// `open_with_filter`, "worker-{i}" for `open_workers*`, or
    /// the user-supplied label for `from_captures`.
    pub fn label(&self, i: usize) -> Option<&str>;

    /// Consume the multi-capture and return the underlying
    /// captures + labels for advanced composition.
    pub fn into_captures(self) -> (Vec<AsyncCapture<Capture>>, Vec<String>);
}
```

### Stream constructors

```rust
impl AsyncMultiCapture {
    /// Multi-source equivalent of [`AsyncCapture::flow_stream`].
    /// `extractor` is cloned per source.
    pub fn flow_stream<E>(self, extractor: E) -> MultiFlowStream<E>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Clone + Send + Sync + Unpin + 'static;

    pub fn session_stream<E, F>(
        self,
        extractor: E,
        factory: F,
    ) -> MultiSessionStream<E, F>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Eq + Hash + Clone + Send + Sync + Unpin + 'static,
        F: SessionParserFactory<E::Key> + Clone + Unpin + Send + 'static;

    pub fn datagram_stream<E, F>(
        self,
        extractor: E,
        factory: F,
    ) -> MultiDatagramStream<E, F>
    where /* analogous */ ;
}
```

### `TaggedEvent`

```rust
/// A `FlowEvent` annotated with its source within a multi-capture.
#[derive(Debug, Clone)]
pub struct TaggedEvent<E> {
    /// Index into the multi-capture's source list (0..len).
    pub source_idx: u16,
    /// The underlying event.
    pub event: E,
}

// Convenience: TaggedEvent<FlowEvent<K>>, TaggedEvent<SessionEvent<K, M>>.
```

### Multi-streams

```rust
pub struct MultiFlowStream<E: FlowExtractor> {
    inner: Pin<Box<dyn Stream<Item = Result<TaggedEvent<FlowEvent<E::Key>>, Error>> + Send>>,
    labels: Arc<Vec<String>>,
    capture_handles: Vec<Arc<CaptureHandle>>,  // for capture_stats
}

impl<E: FlowExtractor> Stream for MultiFlowStream<E> {
    type Item = Result<TaggedEvent<FlowEvent<E::Key>>, Error>;
    fn poll_next(...) { … }
}

impl<E: FlowExtractor> MultiFlowStream<E> {
    /// Label for `source_idx`.
    pub fn label(&self, source_idx: u16) -> Option<&str>;

    /// Per-source capture stats. One entry per source; `Err` for
    /// any source whose `getsockopt` failed.
    pub fn per_source_capture_stats(&self) -> Vec<(String, Result<CaptureStats, Error>)>;

    /// Aggregate capture stats across all sources. `packets`,
    /// `drops`, `freeze_count` are summed; sources reporting
    /// `Err` are silently skipped (the per-source method surfaces
    /// them).
    pub fn capture_stats(&self) -> CaptureStats;
}
```

`MultiSessionStream` and `MultiDatagramStream` mirror the shape
with `TaggedEvent<SessionEvent<...>>`.

### Backing struct for capture access

The `Vec<AsyncCapture>` gets consumed into the boxed `select_all`
stream, so per-source stats need a side-channel. `Arc<CaptureHandle>`
where `CaptureHandle` wraps the underlying `Capture` (which is
`Sync` for `&self` operations like `stats()`) lets both the
`select_all` task tree and the user's `stream.capture_stats()` call
share access.

---

## Implementation steps

1. **`multi_capture.rs`**: define `AsyncMultiCapture` + all five
   constructors. Each constructor loops calling
   `AsyncCapture::open` or `AsyncCapture::open_with_filter`
   (plan 21) or `Capture::builder().interface().fanout().build()
   → AsyncCapture::new`.
2. **`multi_capture.rs`**: `into_captures` + label accessors.
3. **`multi_streams.rs`**: define `TaggedEvent` and the three
   `Multi*Stream` types. Each `poll_next` body wraps
   `futures::stream::select_all` over per-source streams, mapping
   each event to `TaggedEvent { source_idx, event }`.
4. **`multi_streams.rs`**: implement `per_source_capture_stats`
   and `capture_stats` via the `Arc<CaptureHandle>` side channel.
5. **`async_adapters/mod.rs`**: `pub mod multi_capture; pub mod multi_streams;`.
6. **`lib.rs`**: re-export `AsyncMultiCapture`, `MultiFlowStream`,
   `MultiSessionStream`, `MultiDatagramStream`, `TaggedEvent`.
7. **`docs/scaling.md`**: ~250-line document with:
   - When you need it
   - Decision matrix: `FanoutMode::Cpu` vs `Hash` vs `LoadBalance`
     vs `QueueMapping` vs `Ebpf`
   - Recipe — `open_workers` + thread pinning
   - Recipe — `open` for multi-interface gateway
   - Recipe — `from_captures` for heterogeneous setups
   - Aggregating stats across sources
   - Anti-patterns (with worked examples):
     - `FanoutMode::Hash` on skewed traffic
     - More workers than RX queues
     - Reading `PACKET_STATISTICS` from only one worker
     - Mixed fanout modes in the same group (kernel rejects)
     - Identical `group_id` across processes
   - Troubleshooting (`/proc/interrupts`, `ethtool -X` / `-L`,
     "Invalid argument" on fanout setsockopt)
   - Cross-references: AF_XDP multi-queue (plan 12 follow-ups);
     `FanoutMode::Ebpf` for custom distribution
8. **`README.md`**: 3-line section linking to `docs/scaling.md`.
9. **Examples**:
   - `async_fanout_workers.rs` — `open_workers` + `core_affinity`
     pinning per worker. ~80 LoC.
   - `async_multi_interface.rs` — `open(&["lo", "eth0"])` with
     skip-if-down on `eth0`. ~80 LoC.
10. **CHANGELOG**: under 0.13.0, "New — `AsyncMultiCapture` and
    scaling recipe".

---

## Tests

### Integration: `tests/multi_capture.rs`

Gated `#[cfg(all(feature = "integration-tests", feature = "tokio", feature = "flow"))]`.

1. **`open(&["lo", "lo"])` opens two captures**. Send a UDP
   packet to `127.0.0.1:port`. Both sources see it. Stream yields
   two `TaggedEvent`s with the same flow key, different `source_idx`
   (0 and 1).
2. **`open_workers("lo", 4, 0xDE57)` opens four captures in one
   fanout group.** Send N packets across varying source ports;
   verify each worker received approximately `N/4` (allow ±20 %
   skew — `FanoutMode::Cpu` on `lo` typically lands all packets on
   one CPU since `lo` has no RSS).
3. **`per_source_capture_stats` returns one entry per source.**
4. **Aggregate `capture_stats` sums per-source counts.**
5. **`from_captures` with explicit labels.** Mixing handcrafted
   captures. Labels survive through to the stream's `label()`
   accessor.
6. **Skip-if-down**: `open(&["lo", "definitely-not-an-iface"])`
   returns `Err`; the test confirms the error surfaces cleanly.

### Unit (in `multi_capture.rs`)

- Constructor argument validation: `open(&[])` returns `Err`
  (no sources). `open_workers("lo", 0, 0)` returns `Err`.
- `labels.len() != captures.len()` in `from_captures` returns
  `Err`.

---

## Acceptance criteria

- [ ] `AsyncMultiCapture::open(&[...])` works.
- [ ] `AsyncMultiCapture::open_workers(iface, n, group_id)` works.
- [ ] `AsyncMultiCapture::open_with_filter(...)` works (uses
      plan 21's `open_with_filter` internally per source).
- [ ] `AsyncMultiCapture::from_captures(...)` accepts pre-built
      captures.
- [ ] `flow_stream` / `session_stream` / `datagram_stream` work
      and yield `TaggedEvent { source_idx, event }`.
- [ ] `per_source_capture_stats()` and aggregate `capture_stats()`
      work on the multi-stream.
- [ ] `docs/scaling.md` exists and is linked from README.
- [ ] Both examples build (`tokio,flow` features).
- [ ] Integration test passes on the `lo, lo` fanout case.
- [ ] `cargo clippy --all-features --examples --tests -- -D warnings`
      passes.
- [ ] CHANGELOG entry under 0.13.0.

---

## Risks

- **`select_all` fairness under skew**. A high-rate source can
  starve a low-rate one between yields. Per-flow timing is fine
  (each flow lives on one source); aggregate event counts have
  mild skew under load. Not a correctness bug; document.
- **`FanoutMode::Cpu` cache-locality assumes RSS/RPS**. On NICs
  without RSS — including `lo`, virtual NICs in some VMs — all RX
  lands on one CPU and `FanoutMode::Cpu` collapses to "worker 0
  gets everything". Documented as troubleshooting step #1 in
  `docs/scaling.md` and via a rustdoc warning on
  `open_workers`.
- **fd budget for many sources**. Each capture is one fd. The
  Linux default `RLIMIT_NOFILE` is typically 1024; multi-iface
  capture across N=100 interfaces wants `prlimit` adjustment.
  Document.
- **Group-ID collisions across processes**. Two unrelated programs
  picking the same `group_id` on the same interface land in the
  same fanout group → chaos. Document: pick a deliberate 16-bit
  constant per process.
- **PCAPNG output for multi-interface**. If pcap-tap (plan 20) is
  applied to a multi-source capture, the writer would mix
  different linktypes/interfaces into one legacy-PCAP file (which
  has one global IDB). For now: `with_pcap_tap` on a `MultiFlowStream`
  is **not** supported (no impl). Users who need
  per-source pcap output construct their own per-source taps
  through `from_captures` + per-stream `with_pcap_tap`. PCAPNG
  multi-interface output is a separate future plan.

---

## Effort

- Code: ~500 LoC (`multi_capture.rs` + `multi_streams.rs`).
- Docs: ~250 lines of markdown.
- Tests: ~200 LoC integration + ~40 LoC unit.
- Examples: ~80 LoC × 2.
- CHANGELOG: 10 lines.
- **Estimate**: 2 days.

---

## Sources

- [`packet(7)` — Linux manual page](https://man7.org/linux/man-pages/man7/packet.7.html)
- [Enabling Packet Fan-Out in libpcap (TMA 2017)](https://dl.ifip.org/db/conf/tma/tma2017/tma2017_paper65.pdf)
- [Security Onion AF-PACKET docs](https://docs.securityonion.net/en/2.4/af-packet.html)
- [zeek-af_packet-plugin README](https://github.com/zeek/zeek-af_packet-plugin/blob/master/README)
- [Linux kernel selftest `psock_fanout.c`](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/net/psock_fanout.c)
- [The trouble with multiple capture interfaces (Packet-Foo)](https://blog.packet-foo.com/2014/08/the-trouble-with-multiple-capture-interfaces/)
- [`futures::stream::select_all`](https://docs.rs/futures/latest/futures/stream/fn.select_all.html)
