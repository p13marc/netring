# Plan 24 — Stream API completion: StreamCapture defaults, tracker_stats, snaplen, busy-poll

## Summary

Five small additions that close the remaining "operator-visible
knob" gaps on netring's async stream surface, consolidated into one
0.15.0 ship. From the simple-nms 2026-08-XX wishlist:

1. **`StreamCapture::set_filter`** as a default method on the sealed
   trait — gated to AF_PACKET-backed sources via `PacketSetFilter`.
   Replaces simple-nms's N1.3 ask for a `flow_stream(...).with_bpf_filter(filter)`
   builder, which had ambiguous timing semantics (apply at open
   vs. apply post-build).
2. **`StreamCapture::dedup` / `dedup_mut`** as default methods,
   returning `Option<&Dedup>` / `Option<&mut Dedup>`. Currently only
   `FlowStream` and `DedupStream` expose this; `SessionStream` and
   `DatagramStream` are missing it (N1.5).
3. **`tracker_stats() -> &FlowTrackerStats` + `active_flows() -> usize`**
   accessors on `FlowStream`, `SessionStream`, `DatagramStream`,
   `PcapFlowStream`, plus the three Multi*Stream types (N1.1). One
   call replaces today's "iterate `snapshot_flow_stats()` and count".
4. **`with_pcap_tap_snaplen(n)`** on each of the four stream types
   plus a `snaplen: Option<u32>` field on `PcapTap` (N1.4).
   Truncates recorded frames to `n` bytes before they hit the
   writer.
5. **`Capture::busy_poll_config() -> BusyPollConfig`** + a
   `tracing::info!` when the busy-poll trio is applied at socket
   build time (N1.7). Reachable from a built stream via
   `stream.capture().get_ref().busy_poll_config()`.

Closes simple-nms wishlist items **N1.1, N1.3-redirect, N1.4, N1.5,
N1.7**. N1.6 (`BpfFilter::to_human()`) is its own plan (25). N2.1
(multi-source builder parity) is its own plan (26). N1.2
(`SkipEndpoints` extractor) is a flowscope plan, not netring's.

## Status

Planned — targets 0.15.0.

## Prerequisites

- None. All additions are on existing types.

## Out of scope

- **`flow_stream(...).with_bpf_filter(filter)` chained builder.**
  Considered and rejected. The simple-nms ask conflates two
  semantics (filter-at-open vs. post-build set_filter swap); the
  `with_*` naming implies stream-build-time application, but
  internally it would have to call `capture().set_filter()` — a
  reader-trap. The right answer is a verb that explicitly says
  "swap": `stream.set_filter(filter)?` via the `StreamCapture`
  default method. `AsyncCapture::open_with_filter(iface, filter)`
  remains the answer for true filter-at-open.
- **A `StreamHealth { active_flows, last_sweep_at, sweep_count }`
  return type.** Considered and rejected. simple-nms can derive
  `last_sweep_at` from their tick clock and `sweep_count` from
  `FlowTrackerStats::flows_ended + flows_evicted` if they really
  need it. A new dedicated struct duplicates surface for marginal
  ergonomic gain.
- **`BusyPollProfile` enum.** Considered and rejected. The simple-nms
  ask was for a typed enum to publish under `info`; a plain
  `BusyPollConfig` struct (the three `Option`s) is more direct, and
  enum classification ("aggressive" vs. "default") belongs in
  simple-nms's domain, not netring's.
- **Per-`MultiCapture` aggregate `tracker_stats()` summing across
  sources.** Out of scope for this plan; revisit if a real ops
  workflow asks. For 0.15.0, each Multi*Stream exposes the inner
  per-source tracker accessor (same shape as
  `per_source_capture_stats`).

---

## Background — design choices

### Why `set_filter` is a `StreamCapture` default method, not a `with_*` builder

The sealed `StreamCapture` trait already gives all four stream
types a uniform `capture()` accessor. Adding a default method that
proxies to `self.capture().set_filter(filter)` requires zero
per-type code:

```rust
impl<S: PacketSetFilter> /* sealed bound only */ for FlowStream { … }
```

But the default method has to be visible **only** when the
underlying source supports `PacketSetFilter`. The cleanest Rust
shape is two traits:

```rust
pub trait StreamCapture { type Source: …; fn capture(&self) -> &AsyncCapture<Self::Source>; … }

pub trait StreamSetFilter: StreamCapture
where Self::Source: PacketSetFilter,
{
    fn set_filter(&self, filter: &BpfFilter) -> Result<(), Error> {
        self.capture().set_filter(filter)
    }
}

impl<T> StreamSetFilter for T
where T: StreamCapture,
      T::Source: PacketSetFilter, { }
```

The blanket impl means `set_filter` appears on every stream type
whose source is AF_PACKET-backed, automatically. `AsyncCapture<XdpSocket>`-
backed streams don't get it — matching the existing
`AsyncCapture::set_filter` constraint shape.

### Why `dedup()` / `dedup_mut()` go on `StreamCapture` (not a new trait)

The current state: `FlowStream` and `DedupStream` expose
`dedup()` / `dedup_mut()` returning `Option<&Dedup>` /
`Option<&mut Dedup>`. `SessionStream` and `DatagramStream` don't —
even though both have a `dedup: Option<Dedup>` field internally
(plumbed from `FlowStream::with_dedup`).

Add as `StreamCapture` default methods that return `None`, then
override on `FlowStream`, `SessionStream`, `DatagramStream`,
`DedupStream` to return the actual field. The trait's default
covers any future stream type that doesn't carry a dedup.

### Why `tracker_stats()` is a thin accessor, not a typed wrapper

`FlowTrackerStats` already exists in flowscope as a 4-field struct
(`flows_created`, `flows_ended`, `flows_evicted`, `packets_unmatched`).
Surfacing it is one method per stream type. Adding a
`StreamHealth` wrapper would force simple-nms to translate twice
(internal struct → wrapper → Zenoh payload).

`active_flows()` is the only computed accessor: `tracker.flows().count()`.
That's an `O(n)` walk but cheap; the LRU's iterator is hash-table-bound.

### Why `with_pcap_tap_snaplen(n)` is a separate builder (not a `PcapTap` field constructor)

The existing builders are `with_pcap_tap(writer)` and
`with_pcap_tap_policy(writer, policy)`. Adding
`with_pcap_tap_snaplen(n)` matches that style: per-knob `with_*`
that updates a single field. Implementation: `PcapTap` gains a
`snaplen: Option<u32>` field defaulting to `None` (unlimited), and
`write_or_handle` truncates the packet data slice to `snaplen` if
set before calling the inner writer.

Alternative considered: `with_pcap_tap_full(writer, policy, snaplen)`
all-in-one. Rejected — too coarse, breaks the existing per-knob
shape.

### Why `Capture::busy_poll_config()` adds fields to `Capture`

Today the three busy-poll values (`busy_poll_us`,
`prefer_busy_poll`, `busy_poll_budget`) are passed through
`CaptureBuilder`'s build path to `setsockopt`, then discarded.
For the accessor to work post-build, store the trio as
`busy_poll: BusyPollConfig` on `Capture`.

`BusyPollConfig` is a plain struct with three `Option<*>` fields,
deriving `Debug, Clone, Copy, Default, PartialEq, Eq`. No new
enums.

The `tracing::info!` fires inside `Capture::builder().build()`
when at least one busy-poll knob is set, **once per built
capture**:

```rust
tracing::info!(
    target: "netring::capture::busy_poll",
    busy_poll_us = ?cfg.busy_poll_us,
    prefer_busy_poll = ?cfg.prefer_busy_poll,
    busy_poll_budget = ?cfg.busy_poll_budget,
    interface = %iface,
    "busy-poll trio applied",
);
```

Consumers can subscribe via `target: "netring::capture::busy_poll"`
or just match the static target.

---

## Files

### NEW

```
netring/netring/src/config/busy_poll.rs              (BusyPollConfig struct)
netring/netring/tests/stream_api_completion.rs       (integration)
```

### MODIFY

```
netring/netring/src/config/mod.rs                    (mod busy_poll + re-export)
netring/netring/src/lib.rs                           (re-exports)
netring/netring/src/afpacket/rx.rs                   (Capture::busy_poll_config + tracing::info)
netring/netring/src/async_adapters/stream_capture.rs (StreamSetFilter, dedup defaults)
netring/netring/src/async_adapters/flow_stream.rs    (tracker_stats, active_flows, dedup overrides, snaplen builder)
netring/netring/src/async_adapters/session_stream.rs (tracker_stats, active_flows, dedup overrides, snaplen builder)
netring/netring/src/async_adapters/datagram_stream.rs(tracker_stats, active_flows, dedup overrides, snaplen builder)
netring/netring/src/async_adapters/dedup_stream.rs   (snaplen builder)
netring/netring/src/pcap_flow.rs                     (tracker_stats, active_flows)
netring/netring/src/async_adapters/multi_streams.rs  (per_source_tracker_stats, total_active_flows)
netring/netring/src/pcap_tap.rs                      (snaplen field + truncation)
netring/CHANGELOG.md
```

---

## API delta

### `StreamSetFilter` — new sub-trait

```rust
// netring/src/async_adapters/stream_capture.rs

pub trait StreamSetFilter: StreamCapture
where Self::Source: PacketSetFilter,
{
    /// Atomically replace the BPF filter on the underlying capture
    /// without tearing down the kernel ring. Equivalent to
    /// `self.capture().set_filter(filter)`.
    ///
    /// In-flight packets in the ring at swap time were captured
    /// under the old filter. Drain a couple of polls if a clean
    /// cutover is needed.
    fn set_filter(&self, filter: &BpfFilter) -> Result<(), Error> {
        self.capture().set_filter(filter)
    }
}

impl<T> StreamSetFilter for T
where T: StreamCapture,
      T::Source: PacketSetFilter, { }
```

Auto-implemented for every stream type whose source supports
`PacketSetFilter`. `AsyncCapture<XdpSocket>`-backed streams
silently lack it (compile error if called — same shape as
`AsyncCapture::set_filter` today).

### `StreamCapture::dedup` / `dedup_mut` — default methods

```rust
pub trait StreamCapture: Sealed {
    type Source: PacketSource + AsRawFd;
    fn capture(&self) -> &AsyncCapture<Self::Source>;

    fn capture_stats(&self) -> Result<CaptureStats, Error> { … }
    fn capture_cumulative_stats(&self) -> Result<CaptureStats, Error> { … }

    /// Borrow the embedded loopback dedup, if one was attached via
    /// `with_dedup(...)`. Defaults to `None`; overridden by stream
    /// types that carry a dedup.
    fn dedup(&self) -> Option<&Dedup> { None }

    /// Mutable counterpart of [`dedup`](Self::dedup) — useful for
    /// inspecting `dropped()` / `seen()` counters.
    fn dedup_mut(&mut self) -> Option<&mut Dedup> { None }
}
```

`FlowStream`, `SessionStream`, `DatagramStream`, `DedupStream` all
override to return their `dedup: Option<Dedup>` field.

### `tracker_stats` + `active_flows`

Per-stream-type inherent methods (because `StreamCapture` doesn't
know about the tracker's key type):

```rust
impl<S, E, U, R> FlowStream<S, E, U, R> {
    pub fn tracker_stats(&self) -> &FlowTrackerStats {
        self.tracker.stats()
    }

    /// Count of live flow entries (current LRU size). O(n) walk.
    pub fn active_flows(&self) -> usize {
        self.tracker.flows().count()
    }
}
```

Same shape on `SessionStream<S, E, F>`, `DatagramStream<S, E, F>`,
`PcapFlowStream<E>`. The Multi*Streams get fan-in versions:

```rust
impl<E> MultiFlowStream<E> {
    /// Per-source tracker stats. One entry per source; `None` if
    /// the source has been exhausted.
    pub fn per_source_tracker_stats(&self) -> Vec<(String, Option<&FlowTrackerStats>)>;

    /// Sum of live flow counts across all sources.
    pub fn total_active_flows(&self) -> usize;
}
```

### `with_pcap_tap_snaplen` + truncation

```rust
impl<S, E, U, R> FlowStream<S, E, U, R> {
    /// Cap the recorded frame size on the pcap tap, in bytes.
    /// Default unlimited. No-op if no tap is attached.
    pub fn with_pcap_tap_snaplen(mut self, snaplen: u32) -> Self {
        if let Some(tap) = self.tap.as_mut() {
            tap.set_snaplen(snaplen);
        }
        self
    }
}
```

Same on the other three. Internally:

```rust
// pcap_tap.rs
pub struct PcapTap {
    inner: Box<dyn TapWriter>,
    policy: TapErrorPolicy,
    snaplen: Option<u32>,   // NEW
    dropped: bool,
}

impl PcapTap {
    pub(crate) fn set_snaplen(&mut self, snaplen: u32) { self.snaplen = Some(snaplen); }
}

impl TapWriter for CaptureWriter<W> {
    fn write(&mut self, pkt: &Packet<'_>, snaplen: Option<u32>) -> Result<(), pcap_file::PcapError> {
        match snaplen {
            Some(cap) if (pkt.data().len() as u32) > cap => {
                // Truncate before write; pcap keeps original_len for the wire.
                let truncated = &pkt.data()[..cap as usize];
                self.write_packet_truncated(pkt, truncated)
            }
            _ => self.write_packet(pkt),
        }
    }
}
```

`CaptureWriter::write_packet_truncated(pkt, slice)` is a new
inherent helper that writes the same `PcapPacket::new_owned` with
the truncated body but preserves the original `pkt.original_len()`
in the pcap record header. Standard pcap convention: `caplen <
orig_len` flags truncation.

### `BusyPollConfig` + `Capture::busy_poll_config`

```rust
// netring/src/config/busy_poll.rs

/// Busy-poll trio applied to the capture socket. Empty by default
/// (no busy-polling). Populated via
/// [`CaptureBuilder::busy_poll_us`], [`prefer_busy_poll`],
/// [`busy_poll_budget`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BusyPollConfig {
    pub busy_poll_us: Option<u32>,
    pub prefer_busy_poll: Option<bool>,
    pub busy_poll_budget: Option<u16>,
}

impl BusyPollConfig {
    /// True if any of the three knobs is set.
    pub fn is_active(&self) -> bool {
        self.busy_poll_us.is_some()
            || self.prefer_busy_poll.is_some()
            || self.busy_poll_budget.is_some()
    }
}
```

```rust
// rx.rs

pub struct Capture {
    // … existing fields …
    busy_poll: BusyPollConfig,   // NEW
}

impl Capture {
    pub fn busy_poll_config(&self) -> &BusyPollConfig {
        &self.busy_poll
    }
}

impl CaptureBuilder {
    pub fn build(self) -> Result<Capture, Error> {
        // … existing setup …

        let busy_poll = BusyPollConfig {
            busy_poll_us: self.busy_poll_us,
            prefer_busy_poll: self.prefer_busy_poll,
            busy_poll_budget: self.busy_poll_budget,
        };
        if busy_poll.is_active() {
            tracing::info!(
                target: "netring::capture::busy_poll",
                ?busy_poll,
                interface = %self.interface,
                "busy-poll trio applied",
            );
        }

        Ok(Capture { /* … */ busy_poll })
    }
}
```

Reachable from a stream:

```rust
let cfg = stream.capture().get_ref().busy_poll_config().clone();
```

`AsyncCapture::busy_poll_config()` is **not** added — `get_ref()`
+ method call is one extra hop but keeps the busy-poll API scoped
to `Capture` only.

---

## Implementation steps

1. **`config/busy_poll.rs`**: define `BusyPollConfig` + `is_active`.
2. **`config/mod.rs`**: `mod busy_poll; pub use busy_poll::BusyPollConfig;`.
3. **`lib.rs`**: re-export `BusyPollConfig` and `StreamSetFilter`.
4. **`rx.rs`**: add `busy_poll: BusyPollConfig` to `Capture`,
   populate in `build()`, add `busy_poll_config()` accessor, emit
   `tracing::info!` on apply.
5. **`stream_capture.rs`**: add `dedup` / `dedup_mut` default
   methods returning `None`. Add `StreamSetFilter` sub-trait with
   blanket impl.
6. **Per-stream `dedup` overrides**: `FlowStream`, `SessionStream`,
   `DatagramStream`, `DedupStream` override `dedup()` / `dedup_mut()`
   to return the field.
7. **Per-stream `tracker_stats` / `active_flows`**: add inherent
   methods on `FlowStream`, `SessionStream`, `DatagramStream`,
   `PcapFlowStream`. Each is two lines.
8. **`pcap_tap.rs`**: add `snaplen: Option<u32>` field +
   `set_snaplen` setter; update `TapWriter::write` to accept
   `snaplen`; `CaptureWriter` blanket impl truncates if cap
   exceeded.
9. **`pcap.rs`**: add `CaptureWriter::write_packet_truncated(pkt, &[u8])`
   inherent helper.
10. **Per-stream `with_pcap_tap_snaplen`**: add builder method on
    each of the four stream types.
11. **Multi*Stream**: add `per_source_tracker_stats` +
    `total_active_flows` on each of the three Multi*Streams. Same
    side-channel pattern as `per_source_capture_stats`.
12. **CHANGELOG**: under 0.15.0, group by item (5 bullets).
13. **Integration test** (see below).

---

## Tests

### Integration: `tests/stream_api_completion.rs`

Gated `#[cfg(all(feature = "integration-tests", feature = "tokio", feature = "flow", feature = "pcap"))]`.

1. **`set_filter` via `StreamSetFilter` blanket impl**. Open a
   capture on `lo`, build a `FlowStream`, call
   `stream.set_filter(...)`, send a packet matching the new filter,
   confirm a `FlowEvent::Started` arrives.
2. **`dedup` accessor parity**. Build
   `flow_stream → with_dedup → session_stream`. Confirm
   `stream.dedup().is_some()` and the counters reflect feeds.
3. **`tracker_stats` returns expected counts after one flow**.
4. **`active_flows() == 1`** after one in-progress flow; `== 0`
   after sweep with idle.
5. **`with_pcap_tap_snaplen(64)`** records only 64 bytes per
   packet; round-trip via `PcapReader` confirms `data.len() == 64`
   and `orig_len > 64`.
6. **`busy_poll_config().is_active()`** matches the builder knobs.

### Unit (in `pcap_tap.rs`)

`PcapTap::set_snaplen` truncation policy — does the right thing
when no tap is attached, when snaplen is set, when packet is
smaller than snaplen, when packet is larger.

### Unit (in `busy_poll.rs`)

`is_active()` — covers all 8 combinations.

---

## Acceptance criteria

- [ ] `stream.set_filter(&filter)` compiles on `FlowStream`,
      `SessionStream`, `DatagramStream`, `DedupStream`,
      `PcapFlowStream` for AF_PACKET-backed sources only.
- [ ] `stream.dedup()` / `dedup_mut()` exist on all four async
      stream types and return `Some` after `with_dedup`.
- [ ] `tracker_stats()` exists on `FlowStream`, `SessionStream`,
      `DatagramStream`, `PcapFlowStream`, and the three
      Multi*Stream variants.
- [ ] `active_flows()` / `total_active_flows()` available.
- [ ] `with_pcap_tap_snaplen(n)` truncates recorded frames; PCAP
      orig_len preserved.
- [ ] `Capture::busy_poll_config() -> &BusyPollConfig` exists.
- [ ] `tracing::info!` fires once per built capture when busy-poll
      is active.
- [ ] `cargo test --all-features` passes (unit + integration).
- [ ] `cargo clippy --all-features --tests -- -D warnings` clean.
- [ ] CHANGELOG entry under 0.15.0.

---

## Risks

- **`set_filter` swap leaves pre-filter packets in the ring.**
  Same as today's `AsyncCapture::set_filter`. Documented on the
  trait method.
- **`active_flows()` is O(n).** Walks the LRU. For tables of 100k+
  flows this is a few µs — well below a metrics-tick budget but
  not free. Call from a periodic publisher, not every poll.
- **`BusyPollConfig` on `Capture` adds 12 bytes per capture.**
  Negligible. The struct is `Copy`.
- **`tracing::info!` may be noisy** for callers building many
  short-lived captures with busy-poll. The `target` filter mutes
  it (`RUST_LOG=netring::capture::busy_poll=off`). Document.
- **Snaplen truncation drops bytes the reassembler would have used.**
  If a user wraps `with_pcap_tap_snaplen(64).session_stream(...)`,
  the **flow** path still sees full frames — only the recorded
  pcap is truncated. Same semantic as `tcpdump -s 64`.

---

## Effort

- Code: ~250 LoC across 8 files (most ~20 LoC each).
- Test: ~200 LoC integration + ~40 LoC unit.
- CHANGELOG: 10 lines.
- **Estimate**: 1.5 days.
