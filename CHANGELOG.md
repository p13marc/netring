# Changelog

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
