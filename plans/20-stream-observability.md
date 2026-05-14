# Plan 20 — Stream observability: `StreamCapture` trait + pcap tap

## Summary

Two parts of one cohesive observability story for the async-stream
chain:

1. A sealed `StreamCapture` trait that gives `FlowStream`,
   `SessionStream`, `DatagramStream`, and `DedupStream` a uniform
   `capture()` accessor exposing `&AsyncCapture<S>`. Default-methoded
   `capture_stats()` / `capture_cumulative_stats()` fall out for
   free. Lays the foundation for plan 21's `set_filter` access from
   inside a running stream.
2. A `with_pcap_tap(writer)` builder on all four stream types that
   copies every captured packet to a `CaptureWriter<W>` *before*
   the flow tracker sees it. Three error policies for disk-full /
   I/O-glitch handling.

Closes des-rs F#2 (drop/freeze counters) and F#3 (raw-frame tap).

This plan supersedes the earlier draft pair (`20-stream-capture-stats`
+ `22-pcap-tap`).

## Status

Done — landed in 0.13.0.

## Prerequisites

- None.

## Out of scope

- Periodic `SessionEvent::CaptureStats` variant inlined into the
  data stream. Considered; rejected. Mixing control telemetry with
  data records forces the consumer to co-locate two concerns and
  re-handle a variant they don't care about. Out-of-band query via
  `stream.capture_stats()` is cleaner.
- A generic `with_tap<F>(F: FnMut(&Packet<'_>))` closure variant.
  Considered; deferred. The pcap shape covers the documented use
  case and lets us own the writer's lifecycle. A generic-tap can
  come later if a second consumer surfaces.
- Rotating-file pcap. Wrap `CaptureWriter` in a rotating `Write`
  adapter outside netring; or use `tcpdump -w` for that case.
- Tap on owned-packet streams (`PacketStream` from `into_stream`).
  Different ownership pattern (cloning `Vec<u8>` rather than
  borrowing); YAGNI until asked.
- Disk-write blocking on tap. `CaptureWriter::write_packet` is sync;
  users wanting non-blocking record paths wrap their writer in
  `BufWriter` (recommended for any sustained capture) or run the
  writer on a dedicated thread fed by an mpsc. Don't make the tap
  async-by-default — it doubles surface for the 1 % case.

---

## Background

`AsyncCapture::stats()` / `cumulative_stats()` already exist at
`tokio_adapter.rs:307` / `:313` and read
`getsockopt(PACKET_STATISTICS)`. The four async-adapter types each
own an `AsyncCapture<S>` field named `cap`. The accessors are
behind a private struct field today.

`CaptureWriter` exists at `pcap.rs:42` and exposes
`write_packet(&Packet<'_>)` / `write_owned(&OwnedPacket)`. Each
write copies into a fresh `PcapPacket::new_owned` — the tap can
safely sit before the tracker pipeline without disturbing zero-copy
semantics on the tracker side.

---

## Idiomatic design choices

### Why a sealed trait instead of N inherent methods

The naive approach is 4 stream types × 2 stats methods = 8 inherent
methods of identical body. Idiomatic Rust factors that through a
trait with default methods, where each impl provides only the
"hook" — here, the `capture()` accessor. The trait is **sealed**
(an unnameable supertrait in a private module) so external code
can't add weird impls but rustdoc still surfaces it under each
stream type.

This pattern also serves plan 21: once `stream.capture()` returns
`&AsyncCapture<S>`, every method on `AsyncCapture` becomes
addressable from inside a running stream without per-method
proxying. `stream.capture().set_filter(filter)` works for free.

### Why the tap stays generic over W via boxed-dyn

Putting `W: Write` on every stream type would proliferate generics
through the whole adapter graph (`FlowStream<S, E, U, R, W>`,
`SessionStream<S, E, F, W>`, etc.). The disk-write hot path's
overhead is dominated by syscall cost, not virtual dispatch — one
boxed-dyn call per packet is invisible. Streams stay generic in
`S, E, U, R / F` only; the tap is `Option<PcapTap>`.

### Why `TapErrorPolicy` is an enum (not a closure)

A closure `FnMut(io::Error) -> ControlFlow<...>` is more flexible
but invites complex error-recovery logic in user code. The 3-arm
enum (`Continue`, `DropTap`, `FailStream`) covers the three
operational stances; users with stranger needs can build them on
top.

---

## Files

### NEW

```
netring/netring/src/async_adapters/stream_capture.rs  (trait + sealed marker)
netring/netring/src/pcap_tap.rs                       (PcapTap + TapErrorPolicy)
netring/netring/tests/stream_observability.rs         (integration tests)
netring/netring/examples/async_flow_with_tap.rs       (~80 LoC demo)
```

### MODIFY

```
netring/netring/src/async_adapters/mod.rs        (pub mod stream_capture)
netring/netring/src/async_adapters/flow_stream.rs    (impl + tap hook)
netring/netring/src/async_adapters/session_stream.rs  (impl + tap hook)
netring/netring/src/async_adapters/datagram_stream.rs (impl + tap hook)
netring/netring/src/async_adapters/dedup_stream.rs   (impl + tap hook)
netring/netring/src/lib.rs                            (re-exports)
netring/CHANGELOG.md
```

---

## API delta

### `StreamCapture` trait

```rust
// netring/src/async_adapters/stream_capture.rs

mod sealed {
    pub trait Sealed {}
}

/// Uniform read-access to the underlying capture for an async
/// stream type. Sealed — implemented only by netring's own stream
/// adapters (`FlowStream`, `SessionStream`, `DatagramStream`,
/// `DedupStream`).
///
/// Useful for out-of-band operations on a running stream:
///
/// ```no_run
/// # use netring::{AsyncCapture, StreamCapture, BpfFilter};
/// # use netring::flow::extract::FiveTuple;
/// # async fn _ex() -> Result<(), netring::Error> {
/// let cap = AsyncCapture::open("eth0")?;
/// let stream = cap.flow_stream(FiveTuple::bidirectional());
///
/// // poll kernel ring stats:
/// let stats = stream.capture_stats()?;
///
/// // swap the BPF filter without tearing down the ring:
/// let new_filter = BpfFilter::builder().tcp().dst_port(443).build()?;
/// stream.capture().set_filter(&new_filter)?;
///
/// # let _ = stats; Ok(()) }
/// ```
pub trait StreamCapture: sealed::Sealed {
    /// The underlying packet source type.
    type Source: crate::PacketSource;

    /// Borrow the underlying capture.
    fn capture(&self) -> &crate::AsyncCapture<Self::Source>;

    /// Kernel ring statistics for the underlying capture.
    ///
    /// **Resets the kernel counters** on read (AF_PACKET semantics).
    /// Pair with [`capture_cumulative_stats`](Self::capture_cumulative_stats)
    /// for monotonic totals.
    fn capture_stats(&self) -> Result<crate::stats::CaptureStats, crate::Error> {
        self.capture().stats()
    }

    /// Monotonic counterpart of [`capture_stats`](Self::capture_stats).
    fn capture_cumulative_stats(&self) -> Result<crate::stats::CaptureStats, crate::Error> {
        self.capture().cumulative_stats()
    }
}
```

Each stream type's impl is one line:

```rust
impl<S, E, U, R> sealed::Sealed for FlowStream<S, E, U, R>
where S: PacketSource + AsRawFd { }

impl<S, E, U, R> StreamCapture for FlowStream<S, E, U, R>
where S: PacketSource + AsRawFd {
    type Source = S;
    fn capture(&self) -> &AsyncCapture<S> { &self.cap }
}
```

Same shape for `SessionStream`, `DatagramStream`, `DedupStream`.

### Pcap tap

```rust
// netring/src/pcap_tap.rs

/// What to do when a pcap tap encounters a write error mid-capture.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TapErrorPolicy {
    /// Log the error via `tracing::warn!` and continue capturing.
    /// Subsequent packets are still tapped (until the next error).
    /// Default — appropriate for opportunistic recording.
    #[default]
    Continue,
    /// Drop the tap on first error (no further packets written),
    /// but keep the flow stream running.
    DropTap,
    /// Fail the next stream poll with `Error::Io`. The flow stream
    /// terminates. Recommended for evidence-recording pipelines.
    FailStream,
}

/// Boxed tap-writer plus its error policy. Owned by stream types
/// via an `Option<PcapTap>` field; not directly constructible by
/// users.
pub struct PcapTap {
    writer: Box<dyn TapWriter>,
    policy: TapErrorPolicy,
    dropped: bool,
}

impl PcapTap {
    pub(crate) fn new<W: std::io::Write + Send + 'static>(
        writer: CaptureWriter<W>,
        policy: TapErrorPolicy,
    ) -> Self { … }

    /// Write `pkt`, honouring the policy. Returns `Some(err)` only
    /// for `FailStream` policy on a write failure.
    pub(crate) fn write_or_handle(
        &mut self,
        pkt: &Packet<'_>,
    ) -> Option<crate::Error> { … }
}

// Sealed trait so we can erase the W parameter.
trait TapWriter: Send {
    fn write(&mut self, pkt: &Packet<'_>) -> Result<(), pcap_file::PcapError>;
}

impl<W: std::io::Write + Send + 'static> TapWriter for CaptureWriter<W> {
    fn write(&mut self, pkt: &Packet<'_>) -> Result<(), pcap_file::PcapError> {
        self.write_packet(pkt)
    }
}
```

### Builder method on each stream

```rust
impl<S, E, U, R> FlowStream<S, E, U, R>
where S: PacketSource + AsRawFd,
{
    /// Tap every captured packet into `writer` before passing it
    /// to the flow tracker. Default error policy: [`TapErrorPolicy::Continue`].
    pub fn with_pcap_tap<W>(self, writer: CaptureWriter<W>) -> Self
    where W: std::io::Write + Send + 'static,
    {
        self.with_pcap_tap_policy(writer, TapErrorPolicy::default())
    }

    /// Variant with an explicit error policy.
    pub fn with_pcap_tap_policy<W>(
        mut self,
        writer: CaptureWriter<W>,
        policy: TapErrorPolicy,
    ) -> Self
    where W: std::io::Write + Send + 'static,
    {
        self.tap = Some(PcapTap::new(writer, policy));
        self
    }
}
```

Mirrored on `SessionStream`, `DatagramStream`, `DedupStream`. The
`tap: Option<PcapTap>` field is preserved across `session_stream` /
`datagram_stream` / `with_async_reassembler` / `with_state`
conversions, the same way `with_dedup` plumbing works today.

---

## Implementation steps

1. **`stream_capture.rs`**: define the sealed marker and trait.
2. **`pcap_tap.rs`**: define `TapErrorPolicy`, `PcapTap`, the
   sealed `TapWriter` trait, and the blanket impl for `CaptureWriter<W>`.
   `write_or_handle` honours the policy; on `Continue` it emits a
   `tracing::warn!(target: "netring::pcap_tap", ?err, "tap write failed")`
   and returns `None`.
3. **`flow_stream.rs`**:
   - Add `tap: Option<PcapTap>` field.
   - Add `with_pcap_tap` / `with_pcap_tap_policy` builder methods.
   - In `poll_next`, after the packet view is materialized but
     before `tracker.track(view)`:
     ```rust
     if let Some(tap) = &mut this.tap {
         if let Some(err) = tap.write_or_handle(&pkt) {
             return Poll::Ready(Some(Err(err)));
         }
     }
     ```
   - Thread the `tap` through `with_state`, `with_async_reassembler`,
     `session_stream`, `datagram_stream` conversions (same shape as
     existing `dedup` and `monotonic_ts` plumbing).
   - Impl `Sealed` + `StreamCapture`.
4. **`session_stream.rs`**: same — tap field, hooks, builder, impl.
5. **`datagram_stream.rs`**: same.
6. **`dedup_stream.rs`**: same.
7. **`async_adapters/mod.rs`**: `pub mod stream_capture;`.
8. **`lib.rs`**: re-export `StreamCapture`, `PcapTap`,
   `TapErrorPolicy`.
9. **CHANGELOG**: under 0.13.0, two bullet groups — "New —
   `StreamCapture` trait" and "New — pcap tap on async streams".

---

## Tests

### Unit (in `stream_capture.rs`)

A trait-bound smoke test: a generic function `fn assert_stream<S: StreamCapture>(_: &S)`
is instantiated with each of the four stream types in a `compile_pass!`
macro (or just a `#[test]` that calls it). Confirms the trait is
auto-derived correctly through type-inference.

### Integration: `tests/stream_observability.rs`

Gated `#[cfg(all(feature = "integration-tests", feature = "tokio", feature = "flow", feature = "pcap"))]`.

1. **`capture_stats` on a fresh `flow_stream` returns zero packets,
   zero drops, zero freeze.**
2. **`capture_stats` survives the `with_dedup → session_stream`
   conversion.** Build the full chain, retrieve stats on the final
   `SessionStream`, assert valid `CaptureStats`.
3. **`capture_cumulative_stats` is monotonic across two reads.**
4. **`capture()` accessor gives the same `&AsyncCapture` reference
   each call.**
5. **Pcap tap captures what `flow_stream` sees.** Send a known UDP
   datagram, drain a few events, read back the temp file with
   `PcapReader`; assert the marker bytes are present.
6. **Tap is preserved across `session_stream` conversion.**
7. **`FailStream` policy surfaces an error on the next poll** after
   a failing write. Use a writer over a `BrokenWriter` (always
   `io::ErrorKind::Other`).
8. **`DropTap` policy keeps the stream alive** but stops recording
   after the first failure.

### Example

`examples/async_flow_with_tap.rs` — full chain demoing
`flow_stream → with_dedup → with_pcap_tap → session_stream` with
periodic `capture_stats()` printout via a sibling `tokio::spawn`
that holds `&stream` through an `Arc<Mutex<…>>` (or simpler, the
stats are read between poll iterations).

---

## Acceptance criteria

- [ ] `StreamCapture` trait exists and is implemented for all four
      stream types.
- [ ] `stream.capture()`, `stream.capture_stats()`,
      `stream.capture_cumulative_stats()` all compile for each of
      the four stream types.
- [ ] `with_pcap_tap` / `with_pcap_tap_policy` exist on all four
      stream types.
- [ ] Tap survives `session_stream` / `datagram_stream` conversion.
- [ ] All three `TapErrorPolicy` arms exhibit the expected behaviour.
- [ ] `cargo test --features integration-tests,tokio,flow,pcap`
      passes (under `just setcap`).
- [ ] `cargo clippy --all-features --tests --examples -- -D warnings`
      passes.
- [ ] CHANGELOG entry under 0.13.0.

---

## Risks

- **`getsockopt(PACKET_STATISTICS)` is destructive.** Document on
  `capture_stats()`: monotonic totals come from
  `capture_cumulative_stats()`. Same caveat as today's
  `AsyncCapture::stats()`.
- **Pcap linktype mismatch.** AF_PACKET on `lo` is DLT_EN10MB,
  matching `CaptureWriter::create` default. Real NICs are usually
  Ethernet too, but Linux SLL (113) or others appear in some
  configurations. Document: use `new_with_linktype` for
  non-Ethernet captures.
- **`tracing::warn!` from the `Continue` policy** can be loud under
  a sustained disk-full condition. Acceptable — the tracing
  filter `RUST_LOG=netring::pcap_tap=error` mutes it. Document.
- **Sealed trait visibility.** External crates can't implement
  `StreamCapture`. That's the point. Rustdoc surfaces the trait
  under each stream type so users discover the methods.
- **Streams must compose forward.** If a future plan adds a fifth
  stream type, it must implement `StreamCapture` (and `Sealed`).
  Add this to plan-template / CLAUDE.md notes.

---

## Effort

- Code: ~200 LoC across the new modules + the hooks in the four
  stream types.
- Test: ~250 LoC (integration + unit + example).
- CHANGELOG: 14 lines.
- **Estimate**: 1.5 days.
