# Plan 23 — `AsyncPcapSource` for offline replay

## Summary

An async pcap reader that plugs into the same builder chain as
`AsyncCapture`. Same `flow_stream → session_stream` (or
`datagram_stream`) chain runs offline replay, so the user's
`run_live` and `run_offline` paths collapse into one generic
function.

Two design pivots from the earlier draft:

1. **eventfd-backed readiness** so the source plugs into the
   existing `AsyncCapture<S> → FlowStream<S, E>` hierarchy without
   touching FlowStream's generics. Background task does the sync
   pcap reads.
2. **PCAPNG + legacy PCAP** auto-detected at open. Both formats
   covered — netring writes legacy PCAP (matches `CaptureWriter`),
   but real-world pcaps from tcpdump, Wireshark, or anything
   modern are typically PCAPNG.

Closes des-rs F#4.

This plan supersedes the earlier draft `26-async-pcap-source`.

## Status

Done — landing in 0.13.0.

**Implementation note**: shipped via the simpler design — mpsc
channel + `spawn_blocking` reader — rather than the planned
eventfd-backed `PacketBatch::Owned` refactor. The eventfd design
would require enum-wrapping `PacketBatch<'a>` (which is tied to
mmap memory in the existing AF_PACKET path) and would risk
destabilising the live-capture surface. The mpsc design ships a
distinct `AsyncPcapSource: Stream<Item = OwnedPacket>` plus a
thin `PcapFlowStream` bridge (mirrors `FlowStream`'s builder
methods for the offline-meaningful subset: `with_config`,
`with_idle_timeout_fn`, `tracker()`, `packets_read()`). Live and
offline pipelines unify via a generic consumer over
`Stream<Item = FlowEvent<K>>`. The unified `PacketSource + AsFd`
approach can come in a follow-up plan if real adoption signal
arrives.

## Prerequisites

- Plan 20 (`StreamCapture`) — `stream.capture_stats()` on an
  offline stream returns "read N packets, dropped 0, freeze 0"
  (the offline analog), so plan 20 needs to handle that shape.
  Discussion below.

## Out of scope

- Writing pcap from `AsyncPcapSource`. Write goes through
  `CaptureWriter` + plan 20's `with_pcap_tap`.
- Live + offline merge in one stream. Users who want "replay this
  pcap, then continue live" chain via `Stream::chain` themselves.
- Pre-filtered offline replay via BPF. BPF filters at the kernel
  level don't apply to file reads. Users wanting filtered replay
  use a flowscope-side extractor predicate or `Stream::filter_map`.
- Streaming-write-while-reading (online pcap-style). Open files
  only; FIFO / stdin support is a separate plan if it ever comes up.

---

## Background — the design problem and resolution

`FlowStream<S, E, U, R>` is bound by
`S: PacketSource + std::os::unix::io::AsRawFd`. The `AsRawFd` bound
is for tokio's `AsyncFd` readiness registration.

**Regular files don't support epoll.** Calling `epoll_ctl` on a
regular file fd returns `EPERM` on Linux. So a `File` fd can't go
into `AsyncFd::new` directly.

Three design paths were considered:

### A — synthetic readiness via `eventfd` (chosen)

A `PacketSource + AsFd` impl backed by:

- A sync `pcap_file::pcap::PcapReader<File>` (or `PcapNgReader`)
  on a `tokio::task::spawn_blocking` thread.
- An `eventfd(2)` for tokio readiness.
- An internal `VecDeque<OwnedPacket>` filled by the reader task.
- On consume (`PacketSource::next_batch`), drain the queue into a
  `PacketBatch` view; read from eventfd to clear readiness if
  empty.

**Pros**: stays inside `AsyncCapture<S> → FlowStream<S, E>` type
hierarchy. No refactor.

**Cons**: requires `PacketBatch` to accept owned-data backing,
which needs a small internal generalization (see "Risks" below).

### B — parallel stream hierarchy

A new `PcapFlowStream<E, U, R>` that implements `Stream` directly,
mirroring `FlowStream`'s builder methods. ~400 LoC of near-copy.

Rejected: every future builder method has to be added in two
places.

### C — refactor `FlowStream` to be source-agnostic

A new `PacketStream` trait that abstracts "async-ready + sync
next-batch". `FlowStream<P, E, U, R>` generic over `P: PacketStream`.

Considered. The user said "you are allow to break the backward
compatibility" — so this is on the table.

**Rejected anyway** because the abstraction doesn't pay for itself
yet. `AsyncCapture<S>` already plays the role `PacketStream` would
play, just with concrete-type semantics. Adding the trait
introduces a public abstraction point with one variant
(`AsyncCapture`) and one new variant (`AsyncPcapSource`); the
trait gains nothing over making both implement `PacketSource +
AsFd` directly. Reach for the trait if we add a third source
implementation later.

### Conclusion: path A

The `PacketBatch` owned-backing generalization is small and
isolated. The `AsyncPcapSource` implements `PacketSource + AsFd`
with eventfd-backed readiness. Everything else stays as-is.

---

## Idiomatic design choices

### Why `eventfd` (not a pipe or `tokio::sync::Notify`)

`eventfd(2)` is the kernel-native primitive for "readiness signal
fd". `tokio::sync::Notify` is purely in-process Rust and can't be
exposed as `AsFd` for `AsyncFd::new` integration. A pipe works but
costs two fds per source and 8-byte read/write per signal (same
as eventfd, no advantage).

### Why a background `spawn_blocking` task

`pcap_file::pcap::PcapReader` is sync; its file reads block the
calling thread for disk I/O. Running it on `spawn_blocking` keeps
the tokio runtime healthy. The cost: one blocking-task slot per
source. Tokio's default multi-threaded runtime has 512 slots —
generous.

### Why pacing via `tokio::time::sleep_until` (not interval)

`tokio::time::sleep_until(packet_ts_wall_clock)` is the natural
expression of "deliver this packet at this wall-clock time".
Interval-based pacing would force a regular cadence; pcap
timestamps are irregular.

### Why `AsyncPcapConfig` is a struct (not builder)

The config has three fields. A struct with `Default` and field
assignment matches `FlowTrackerConfig`'s established pattern in
this codebase. No need for a fluent builder.

### Why auto-detect PCAPNG vs PCAP

Real-world pcap files from tcpdump/Wireshark are PCAPNG. Forcing
the user to pick the right reader is a footgun. Sniff magic bytes
at open; pick the backend; surface a single API.

---

## Files

### NEW

```
netring/netring/src/pcap_source.rs                (the source)
netring/netring/src/pcap_source/reader.rs         (sniff + backend trait)
netring/netring/src/pcap_source/legacy.rs         (pcap backend)
netring/netring/src/pcap_source/pcapng.rs         (pcapng backend)
netring/netring/examples/async_pcap_replay.rs     (~80 LoC)
netring/netring/tests/async_pcap_source.rs        (~250 LoC)
```

### MODIFY

```
netring/netring/src/packet.rs                     (PacketBatch::from_owned)
netring/netring/src/lib.rs                        (mod pcap_source; re-exports)
netring/netring/Cargo.toml                        (no new deps; pcap-file already present)
netring/CHANGELOG.md
```

---

## API delta

### `AsyncPcapSource`

```rust
/// Async reader over a pcap file that implements
/// [`PacketSource`] + [`AsFd`]. Wraps in [`AsyncCapture::new`] to
/// run the same builder chain as live capture:
///
/// ```no_run
/// # use futures::StreamExt;
/// # use netring::{AsyncCapture, AsyncPcapSource};
/// # use netring::flow::extract::FiveTuple;
/// # async fn _ex() -> Result<(), netring::Error> {
/// let src = AsyncPcapSource::open("capture.pcap")?;
/// let cap = AsyncCapture::new(src)?;
/// let mut stream = cap.flow_stream(FiveTuple::bidirectional());
/// while let Some(evt) = stream.next().await {
///     let _ = evt?;
///     # break;
/// }
/// # Ok(()) }
/// ```
///
/// Auto-detects PCAPNG vs legacy PCAP at open. Background task
/// reads ahead by `queue_depth` packets; pacing is controlled by
/// [`AsyncPcapConfig::replay_speed`].
pub struct AsyncPcapSource {
    eventfd: OwnedFd,
    inner: Arc<Mutex<PcapSourceInner>>,
    _task: tokio::task::JoinHandle<()>,
}

/// Configuration for [`AsyncPcapSource`].
#[derive(Debug, Clone)]
pub struct AsyncPcapConfig {
    /// Pacing factor: `0.0` = as-fast-as-possible (default).
    /// `1.0` = replay at packet-recorded wire rate.
    /// `0.5` = half speed; `2.0` = double speed; etc.
    pub replay_speed: f32,

    /// Maximum packets buffered ahead of the consumer. Default 64.
    pub queue_depth: usize,

    /// Loop the file at EOF instead of ending the stream.
    /// Default false.
    pub loop_at_eof: bool,
}

impl Default for AsyncPcapConfig {
    fn default() -> Self {
        Self { replay_speed: 0.0, queue_depth: 64, loop_at_eof: false }
    }
}

impl AsyncPcapSource {
    /// Open a pcap or pcapng file for async streaming.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error>;

    /// Open with custom replay config.
    pub fn open_with_config(
        path: impl AsRef<Path>,
        config: AsyncPcapConfig,
    ) -> Result<Self, Error>;

    /// True when the underlying reader has consumed the whole file
    /// (and `loop_at_eof = false`). Subsequent `next_batch` calls
    /// return `None`.
    pub fn is_eof(&self) -> bool;

    /// Format detected at open.
    pub fn format(&self) -> PcapFormat;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapFormat {
    LegacyPcap,
    Pcapng,
}

impl PacketSource for AsyncPcapSource {
    fn next_batch(&mut self) -> Option<PacketBatch<'_>> { … }
    fn next_batch_blocking(&mut self, _: Duration) -> Result<Option<PacketBatch<'_>>, Error> {
        // For async usage. Returns immediately with whatever's in the queue.
        Ok(self.next_batch())
    }
    fn stats(&self) -> Result<CaptureStats, Error> {
        // For offline pcaps: packets = packets read so far, drops = 0, freeze_count = 0.
        // Consistent with plan 20's expectations.
        …
    }
}

impl AsFd for AsyncPcapSource {
    fn as_fd(&self) -> BorrowedFd<'_> { self.eventfd.as_fd() }
}
```

### `PacketBatch::from_owned`

```rust
// netring/src/packet.rs

impl PacketBatch<'_> {
    /// Construct a PacketBatch borrowing from an externally-owned
    /// slice of OwnedPacket. Used by AsyncPcapSource for serving
    /// pcap reads through the same zero-copy iterator surface as
    /// AF_PACKET.
    ///
    /// Internal-use API; constructed by source backends, never by
    /// end users.
    pub(crate) fn from_owned<'a>(packets: &'a [OwnedPacket]) -> PacketBatch<'a> { … }
}
```

This needs careful design — `PacketBatch<'a>` today holds a
borrow into the AF_PACKET mmap ring. A from-owned variant holds a
borrow into a `Vec<OwnedPacket>` arena owned by the source.
Internally `PacketBatch` becomes an enum:

```rust
enum BatchBacking<'a> {
    AfPacket { /* existing mmap ring fields */ },
    Owned { packets: &'a [OwnedPacket] },
}
```

…with the iterator dispatching at the variant level. Hot-path
overhead is one branch per packet — negligible.

---

## Implementation steps

1. **`packet.rs`**: refactor `PacketBatch` to support both
   backings via the `BatchBacking` enum. Existing AF_PACKET code
   keeps working; add the `Owned` variant. Iterator changes are
   internal.
2. **`pcap_source/reader.rs`**: define `PcapBackend` trait —
   `next_packet(&mut self) -> Option<OwnedPacket>`, `is_eof(&self) -> bool`,
   `rewind(&mut self) -> Result<(), Error>` (for loop_at_eof). Plus a
   `fn open(path: &Path) -> Result<Box<dyn PcapBackend>, Error>`
   that sniffs the first 4 bytes (PCAP magic vs PCAPNG magic) and
   returns the right backend.
3. **`pcap_source/legacy.rs`**: `LegacyPcapBackend` wrapping
   `pcap_file::pcap::PcapReader<BufReader<File>>`.
4. **`pcap_source/pcapng.rs`**: `PcapngBackend` wrapping
   `pcap_file::pcapng::PcapNgReader<BufReader<File>>`. Tracks
   per-IDB linktype; converts each `EnhancedPacketBlock` to an
   `OwnedPacket`.
5. **`pcap_source.rs`**: `AsyncPcapSource`, `AsyncPcapConfig`,
   `PcapSourceInner` (the locked queue + state), `PacketSource`
   impl, `AsFd` impl. Background task:
   ```rust
   tokio::task::spawn_blocking(move || {
       let backend = reader::open(&path)?;
       let mut first_ts = None;
       let start = std::time::Instant::now();
       loop {
           // wait for queue space
           let pkt = match backend.next_packet() {
               Some(p) => p,
               None => {
                   if config.loop_at_eof { backend.rewind()?; continue; }
                   set_eof_and_signal();
                   return;
               }
           };
           if config.replay_speed > 0.0 {
               let ts = pkt.timestamp;
               let first = *first_ts.get_or_insert(ts);
               let dt_pcap = ts.duration_since(first);  // or saturating math
               let dt_wall = dt_pcap.div_f32(config.replay_speed);
               let target = start + dt_wall;
               // SAFETY: we're inside spawn_blocking; thread::sleep is fine
               std::thread::sleep(target.saturating_duration_since(Instant::now()));
           }
           push_to_queue_and_signal(pkt);
       }
   })
   ```
6. **`lib.rs`**: `pub mod pcap_source;` + re-export `AsyncPcapSource`,
   `AsyncPcapConfig`, `PcapFormat`.
7. **Example** `examples/async_pcap_replay.rs`: open a fixture
   pcap, drive the same `flow_stream → session_stream` chain as a
   live example, print events. Demonstrates the `run<S>(source: S)`
   pattern that unifies live + offline.
8. **CHANGELOG**: under 0.13.0, "New — `AsyncPcapSource` for
   offline pcap replay".

---

## Tests

### `tests/async_pcap_source.rs`

Gated `#[cfg(all(feature = "tokio", feature = "flow", feature = "pcap"))]`.
**No `integration-tests` needed** — file I/O doesn't require
CAP_NET_RAW. The test creates pcap fixtures in-process via
`CaptureWriter`.

1. **Round-trip legacy PCAP**: write 10 synthetic packets with
   `CaptureWriter::create`, open with `AsyncPcapSource`, drive a
   `flow_stream`, count yielded events.
2. **Round-trip PCAPNG**: same but use a hand-built pcapng
   fixture (or skip if pcapng-write isn't feasible — read a
   committed fixture from `netring/tests/fixtures/sample.pcapng`).
3. **EOF terminates the stream**.
4. **`loop_at_eof = true`** drains forever — run for 30 packets
   across 3 loops.
5. **Pacing**: `replay_speed = 1.0` with packets spaced 100 ms in
   the file → wall-clock duration ≥ N × 100 ms.
6. **Generic `run<S>` function**: define
   `async fn run<S: PacketSource + AsFd + Send + Unpin>(s: S)`,
   call once with `Capture::open("lo")?` (gated on
   `integration-tests`) and once with `AsyncPcapSource::open(...)`
   (always). Same body, both paths exercised.
7. **`capture_stats` on the offline stream returns sensible
   values**: `packets >= number of yielded events`, `drops == 0`,
   `freeze_count == 0`.

---

## Acceptance criteria

- [ ] `AsyncPcapSource::open(path)` works for both legacy PCAP and
      PCAPNG (auto-detected).
- [ ] `format()` accessor returns the detected format.
- [ ] The full builder chain
      `AsyncCapture::new(AsyncPcapSource::open(...)?)?.flow_stream(...).session_stream(...)`
      works unchanged from live capture.
- [ ] Pacing at `replay_speed = 1.0` is observable in wall-clock.
- [ ] EOF terminates the stream cleanly (`None` on
      `next().await`).
- [ ] `loop_at_eof = true` doesn't terminate.
- [ ] `capture_stats()` from plan 20 works for both
      `AsyncCapture<Capture>` and `AsyncCapture<AsyncPcapSource>`.
- [ ] `cargo test --features tokio,flow,pcap` passes (no
      privileges needed).
- [ ] CHANGELOG entry.

---

## Risks

- **`PacketBatch::from_owned` is a real refactor.** The current
  `PacketBatch<'a>` lifetime is tied to mmap ring memory and a
  `&mut PacketSource` borrow. Adding the owned variant means the
  `'a` now potentially borrows from a `Vec<OwnedPacket>` in the
  source instead. The iterator and Drop semantics must stay
  correct for the AF_PACKET case (block return to kernel on
  drop) — the owned variant has no Drop side effect. Use
  `#[non_exhaustive]` on the internal `BatchBacking` to allow
  future variants without semver breaks.
- **PCAPNG with multiple linktypes**. PCAPNG files can have
  multiple Interface Description Blocks each with different
  linktypes (Ethernet on iface 0, Linux SLL on iface 1, etc.).
  flowscope's extractor handles Ethernet; non-Ethernet linktypes
  surface as no-op events. Document.
- **Pacing precision is millisecond-level**. `std::thread::sleep`
  in the blocking task has typically 1–10 ms granularity on
  Linux. Sub-millisecond pacing won't be honored — fine for the
  des-rs case (packets spaced ms apart). Document.
- **Memory cost of `OwnedPacket` queue**. Each packet allocates a
  `Vec<u8>`. With `queue_depth = 64` only 64 are alive at once.
  Pacing controls read-ahead pressure.
- **Thread budget**. One blocking-task slot per source. Tokio's
  default is 512 — plenty for N=10 replays. For N=500, document
  `Runtime::Builder::max_blocking_threads()`.
- **`stats()` semantics divergence**. Offline streams have no
  notion of "drops" (a regular file's kernel buffer can't fill).
  We return `drops: 0` always. Document in plan 20's `capture_stats`
  rustdoc that offline sources return this consistent shape.

---

## Effort

- Code: ~600 LoC across `pcap_source/` (source + 2 backends +
  reader) + `packet.rs` refactor.
- Test: ~250 LoC.
- Example: ~80 LoC.
- CHANGELOG: 8 lines.
- **Estimate**: 2 days. The trickiest piece is the
  `PacketBatch::from_owned` refactor — depending on how invasive
  it ends up on the existing `PacketBatch`'s lifetime story, this
  could grow.

---

## Sources

- [`epoll(7)` — Linux manual page](https://man7.org/linux/man-pages/man7/epoll.7.html)
  (regular files not supported)
- [`eventfd(2)` — Linux manual page](https://man7.org/linux/man-pages/man2/eventfd.2.html)
- [rust-pcap issue #341: PacketStream and Offline Capture](https://github.com/rust-pcap/pcap/issues/341)
- [Tokio streams tutorial](https://tokio.rs/tokio/tutorial/streams)
- [`pcap_file` crate](https://crates.io/crates/pcap-file)
