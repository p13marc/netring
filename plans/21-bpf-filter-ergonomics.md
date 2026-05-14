# Plan 21 — BPF filter API completion

## Summary

Round out the BPF filter API surface introduced in 0.11.0 with two
ergonomic additions:

1. **`AsyncCapture::open_with_filter(iface, filter)`** — one-call
   constructor that attaches a typed BPF filter at socket build
   time. Removes the three-line `Capture::builder().interface().bpf_filter().build() → AsyncCapture::new()`
   boilerplate.
2. **`Capture::set_filter(&filter)` + `AsyncCapture::set_filter`** —
   atomic in-kernel filter swap on a running capture, without
   tearing down the ring or losing in-flight flow state. Reachable
   from inside a running stream via plan 20's `stream.capture()`
   accessor: `stream.capture().set_filter(&new_filter)?`.

Closes des-rs F#1 (live-stream BPF ergonomic; their 10-GbE DES
sniffer goes from ~30 % to ~1 % CPU with kernel-side filtering) and
F#7 (dynamic filter swap).

This plan supersedes the earlier draft pair
(`21-async-capture-open-with-filter` + `24-dynamic-bpf-filter`).

## Status

Planned — targets 0.13.0.

## Prerequisites

- Plan 18 (`BpfFilter::builder()`) — already shipped in 0.11.0.
- Plan 20 (`StreamCapture` trait) — provides `stream.capture()` so
  filter swaps from inside a stream are one-liners.

## Out of scope

- A `flow_stream(...).with_bpf_filter(filter)` builder method.
  Considered; rejected. The filter must attach **before** the
  kernel ring starts collecting, otherwise the first batch leaks
  unfiltered traffic. The stream-layer builder is the wrong place.
  Users who want runtime filter swaps after the stream is built
  use `stream.capture().set_filter(...)`.
- Per-CPU different filters within one fanout group. AF_PACKET
  fanout sockets each have their own filter — so per-CPU swap is
  implicit via plan 22's `open_workers` + per-worker
  `worker.set_filter(...)`. Not separate work.
- Filter swap on AF_XDP. AF_XDP has no `SO_ATTACH_FILTER`; the
  filtering happens in the XDP program itself. The `PacketSetFilter`
  trait is bounded on AF_PACKET-backed captures specifically.

---

## Background

`netring::afpacket::filter::attach_bpf_filter` (`filter.rs:15`)
is `pub(crate)` today and calls `setsockopt(SO_ATTACH_FILTER, prog)`
on a `BorrowedFd`. The kernel replaces any existing filter
atomically — no race window, no manual detach needed. The plumbing
exists; only the public surface is missing.

`AsyncCapture::open(interface)` is sugar for
`AsyncCapture::new(Capture::open(interface)?)`. The
`open_with_filter` constructor follows the same shape with one
extra builder call inside.

---

## Idiomatic design choices

### Why `PacketSetFilter` is a trait

`set_filter` only makes sense for AF_PACKET-backed captures.
`AsyncCapture<S>` is generic over any `PacketSource`, including
`XdpSocket`. The Rust-idiomatic way to scope a method to a subset
of `S` types is a trait bound:

```rust
impl<S: PacketSource + AsRawFd + PacketSetFilter> AsyncCapture<S> { … }
```

`PacketSetFilter` is implemented only for `Capture`. Users with an
`AsyncCapture<XdpSocket>` won't see `set_filter` — the method
simply isn't there. No runtime error, no `unimplemented!()`, no
trait-object slot for a no-op.

### Why two methods (`open` + `open_with_filter`) instead of an
### `Option<BpfFilter>` parameter

`fn open(interface: &str, filter: Option<BpfFilter>)` is briefer
in the signature but worse in use: callers always pass `None` for
the no-filter case, and `Some(filter)` for the filter case. The
two-method form reads better at call sites and rustdoc lists them
side-by-side. Idiomatic Rust prefers explicit naming over magic
parameters when the cardinality is small.

### Why `set_filter(&BpfFilter)` takes a reference (not by value)

`BpfFilter` is a thin wrapper around `Vec<BpfInsn>` (variable-size).
Re-attaching the same filter shouldn't require a clone. Taking
`&BpfFilter` lets callers keep their filter object alive across
swaps and replays.

---

## Files

### NEW

```
netring/netring/tests/bpf_filter_lifecycle.rs   (integration test)
netring/netring/examples/async_filter.rs        (~40 LoC demo)
```

### MODIFY

```
netring/netring/src/traits.rs                          (PacketSetFilter trait)
netring/netring/src/afpacket/rx.rs                     (Capture::set_filter)
netring/netring/src/async_adapters/tokio_adapter.rs    (open_with_filter, set_filter)
netring/netring/src/lib.rs                             (re-exports if any)
netring/CHANGELOG.md
```

---

## API delta

### `PacketSetFilter` trait

```rust
// netring/src/traits.rs

/// Packet sources that support atomic BPF filter replacement on a
/// running socket (AF_PACKET semantics: `setsockopt(SO_ATTACH_FILTER)`).
///
/// Implemented for [`Capture`]. **Not** implemented for AF_XDP
/// sockets — XDP filtering is done in the XDP program, not via
/// `SO_ATTACH_FILTER`.
pub trait PacketSetFilter {
    /// Replace the BPF filter on this source without disturbing
    /// the ring buffer or the user-space stream.
    fn set_filter(&self, filter: &BpfFilter) -> Result<(), Error>;
}
```

### `Capture::set_filter`

```rust
impl Capture {
    /// Replace the BPF filter on this capture. Atomic at the kernel
    /// level: there's no window where the previous filter has been
    /// removed and the new one not yet installed.
    ///
    /// To remove a filter without replacing it, use
    /// [`detach_filter`](Self::detach_filter).
    pub fn set_filter(&self, filter: &BpfFilter) -> Result<(), Error> {
        crate::afpacket::filter::attach_bpf_filter(self.as_fd(), filter)
    }
}

impl PacketSetFilter for Capture {
    fn set_filter(&self, filter: &BpfFilter) -> Result<(), Error> {
        Capture::set_filter(self, filter)
    }
}
```

### `AsyncCapture` additions

```rust
impl AsyncCapture<crate::Capture> {
    /// Open an AF_PACKET capture on `interface` with `filter`
    /// installed before the first batch hits the ring.
    ///
    /// One-call equivalent of:
    ///
    /// ```ignore
    /// AsyncCapture::new(
    ///     Capture::builder()
    ///         .interface(interface)
    ///         .bpf_filter(filter)
    ///         .build()?
    /// )
    /// ```
    ///
    /// For non-default block sizes, fanout, busy-poll, or other
    /// builder knobs, fall back to the full builder path.
    pub fn open_with_filter(
        interface: &str,
        filter: BpfFilter,
    ) -> Result<Self, Error> {
        let rx = crate::Capture::builder()
            .interface(interface)
            .bpf_filter(filter)
            .build()?;
        Self::new(rx)
    }
}

impl<S> AsyncCapture<S>
where S: PacketSource + AsRawFd + PacketSetFilter,
{
    /// Replace the BPF filter on the underlying source. Atomic
    /// at the kernel level.
    ///
    /// Available for AF_PACKET-backed captures only.
    pub fn set_filter(&self, filter: &BpfFilter) -> Result<(), Error> {
        self.inner.get_ref().set_filter(filter)
    }
}
```

### Composes with plan 20

Once both plans land:

```rust
let cap = AsyncCapture::open_with_filter("eth0", filter)?;
let stream = cap.flow_stream(FiveTuple::bidirectional())
    .with_config(cfg)
    .with_pcap_tap(writer)
    .session_stream(parser);

// later, from anywhere holding &stream:
let new_filter = BpfFilter::builder().tcp().dst_port(8443).build()?;
stream.capture().set_filter(&new_filter)?;
```

`stream.capture()` from plan 20 returns `&AsyncCapture<Capture>`,
which exposes `set_filter` from this plan. No proxy methods, no
inner-mutability dance.

---

## Implementation steps

1. **`traits.rs`**: define `PacketSetFilter`. Place it near
   `PacketSource` for discoverability.
2. **`rx.rs`**: add `Capture::set_filter` near `detach_filter`
   (around line 189). One-line body. Add `impl PacketSetFilter for Capture`.
3. **`tokio_adapter.rs`**:
   - Add `AsyncCapture::open_with_filter` right after `open`
     (around line 109).
   - Add `AsyncCapture::set_filter` constrained on
     `S: PacketSetFilter`.
4. **CHANGELOG entry** under 0.13.0:
   - "New — `AsyncCapture::open_with_filter`"
   - "New — `Capture::set_filter` / `AsyncCapture::set_filter`
     for dynamic BPF swap"
   - "New — `PacketSetFilter` trait"
5. **Example**: `examples/async_filter.rs` showing the one-liner
   plus a runtime swap halfway through.

---

## Tests

### Integration: `tests/bpf_filter_lifecycle.rs`

Gated `#[cfg(all(feature = "integration-tests", feature = "tokio"))]`.

1. **`open_with_filter` attaches the filter before the first
   packet.** Open on `lo` with `dst_port(A)`. Send to port B (no
   match). Drain for 200 ms. Assert zero packets received.
2. **Filter swap takes effect.** Same `open_with_filter`. Send to
   port B → no packet seen. `set_filter(dst_port(B))`. Send to
   port B → packet seen.
3. **Filter swap from inside a running stream.** Build a
   `flow_stream`, swap filter via `stream.capture().set_filter(...)`,
   confirm subsequent traffic matches the new filter.
4. **AF_XDP doesn't expose `set_filter`.** Compile-fail test (via
   `compile_fail` doctest or `trybuild`) showing that
   `cap.set_filter(...)` on an `AsyncCapture<XdpSocket>` doesn't
   compile.

Helper: `helpers::send_udp_to_loopback(port, marker, count)`
already exists in `tests/helpers.rs`.

### Doctest

A short doctest on `open_with_filter` and on `set_filter` showing
the canonical use.

---

## Acceptance criteria

- [ ] `AsyncCapture::open_with_filter(iface, BpfFilter) -> Result<Self, Error>`
      compiles and links.
- [ ] `Capture::set_filter(&BpfFilter) -> Result<(), Error>` exists
      and atomically replaces the filter.
- [ ] `AsyncCapture::set_filter` exists for AF_PACKET-backed
      captures, gated by the `PacketSetFilter` trait.
- [ ] `AsyncCapture<XdpSocket>` does **not** expose `set_filter`
      (trait bound prevents it).
- [ ] Integration test: filter swap takes effect on the next packet.
- [ ] `stream.capture().set_filter(...)` chain works (relies on plan 20).
- [ ] `cargo clippy --all-features --tests --examples -- -D warnings`
      passes.
- [ ] CHANGELOG entry under 0.13.0.

---

## Risks

- **In-flight packets in the ring at swap time were captured under
  the old filter.** Document on `set_filter`: the ring contains
  pre-swap matches for a brief window after the call. Users
  wanting clean cutover should drain the ring (poll a few times),
  or set up the new filter as `(old OR new)` first, drain old
  matches, then narrow.
- **Filter validation is repeated on each swap.** `attach_bpf_filter`
  rejects empty or oversized filters. Wrong filters never make it
  to the kernel.
- **PacketSetFilter naming collision.** No existing trait by that
  name in netring. Single canonical home in `traits.rs`.

---

## Effort

- Code: ~30 LoC (trait + 2 methods + Capture::set_filter).
- Test: ~150 LoC.
- Example: ~40 LoC.
- CHANGELOG: 6 lines.
- **Estimate**: 3 hours.
