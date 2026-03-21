# Changelog

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
