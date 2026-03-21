# netring — High-Performance Packet I/O for Rust

> Edition 2024 · MSRV 1.85 · Linux only · Zero-copy · Pure Rust

## 1. Overview

`netring` is a pure Rust library for zero-copy packet capture and injection on Linux,
built on AF_PACKET with TPACKET_V3 (block-based mmap ring buffers). It exposes both a
**high-level ergonomic API** and a **low-level batch API** for maximum flexibility.

### Goals

- Zero-copy packet access via mmap shared ring buffers
- Pure Rust — `nix` + `libc` for syscalls, no C library dependencies
- High-level API: builder-configured, iterator-based, hard to misuse
- Low-level API: batch-oriented block access for maximum throughput
- Compile-time safety: lifetimes enforce zero-copy validity, RAII for all resources
- Async-native: `async fn` in traits (stable), `AsyncFd` integration, future `gen` blocks
- Extensible to AF_XDP via trait abstraction

### Non-Goals

- Packet parsing (use `etherparse`, `pnet_packet`, etc.)
- Built-in async runtime
- Cross-platform — Linux only (kernel 3.2+)

### Rust 2026 Features Leveraged

| Feature | Stable Since | How We Use It |
|---------|-------------|---------------|
| Edition 2024 | 1.85 | Explicit `unsafe {}` in unsafe fns, `unsafe extern`, RPIT lifetime capture |
| `async fn` in traits | 1.75 | `AsyncPacketSource` trait — no `async-trait` crate needed |
| RPITIT | 1.75 | `fn packets(&mut self) -> impl Iterator<Item = Packet<'_>>` in traits |
| Strict provenance | 1.84 | `ptr.map_addr()`, `ptr.with_addr()` for all mmap pointer math |
| I/O safety (`OwnedFd`) | 1.63 | Socket ownership, `AsFd` / `BorrowedFd` in all public APIs |
| `#[diagnostic::on_unimplemented]` | 1.78 | User-friendly errors when trait bounds aren't met |
| `let`-`else` | 1.65 | Cleaner validation in builders |
| `if let` chains | 1.87 | Config validation |

---

## 2. Prior Art

### Comparison with Existing Implementations

| Implementation | Language | TPACKET | Zero-copy | Batch API | Fanout | Limitations |
|----------------|----------|---------|-----------|-----------|--------|-------------|
| **gopacket/afpacket** | Go | V3 | Yes* | Hidden | Yes | `interface{}` opts; zero-copy contract unenforceable; mutex per read |
| **libpcap** | C | V3 | Callback | Hidden | No | Callback-based; block batching hidden; auto-tunes but no user control |
| **netsniff-ng** | C | V3 | Yes | Manual | Yes | Tool, not library; hardcoded timeouts; no API abstraction |
| **DPDK af_packet PMD** | C | V2 | No** | Batch | Yes | Always copies into mbuf despite mmap; V2 only |
| **PF_RING** | C | Custom | Yes | Batch | Custom | Proprietary kernel module |
| **af_packet** (0.3.1) | Rust | V3 | Yes | Hidden | No | Own struct defs (not libc), nom parser, raw `*mut u8`, no NonNull/provenance, no TX |
| **afpacket** (0.2.3) | Rust | None | No | No | No | Plain `read()`/`write()` — no mmap at all; stale |
| **pnet** (0.35) | Rust | None | No | No | No | Per-packet syscall; cross-platform LCD |
| **pcap** (2.4) | Rust | Via libpcap | Callback | No | No | C dependency; no direct ring access |
| **xsk-rs** (0.8) | Rust | — | AF_XDP | Yes | — | AF_XDP only; requires eBPF + driver support |

\* gopacket zero-copy: "previous call invalidates the slice" is documentation-only.
\** DPDK maps the ring but copies every packet into an `rte_mbuf`.

**Gap**: No modern, maintained, pure-Rust crate implements TPACKET_V3 with zero-copy
batch access, fanout, correct memory ordering, async support, and edition 2024 idioms.

### Lessons Applied

| Lesson | Source | netring |
|--------|--------|---------|
| Builder pattern | `io-uring` 0.7 | Type-safe builder, validated at `build()`, ENOMEM retry |
| Expose block batching | gopacket/libpcap hide it | Two-level API: `PacketBatch` + flat `Iterator` |
| Lifetime-enforced zero-copy | Go/C can't do this | `Packet<'a>` borrows from `PacketBatch<'a>` — compile-time enforced |
| Separate RX/TX | `afxdp-rs`, `io-uring` | Different kernel semantics warrant separate types |
| RAII for kernel resources | `io-uring` `Mmap` | `Drop` for mmap, block return, fd close |
| State-machine ownership | Embedded DMA patterns | Block lifecycle: `KernelOwned → UserOwned → KernelOwned` |
| I/O safety | `nix` 0.31 | `OwnedFd` / `BorrowedFd` everywhere — no raw fd in public API |
| Strict provenance | Rust 1.84+ | `ptr.map_addr()` for all mmap pointer arithmetic |
| `async fn in traits` | Rust 1.75+ | Native `AsyncPacketSource` trait — no proc-macro overhead |

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────┐
│                  User Application                    │
├──────────────────┬──────────────────────────────────┤
│  High-Level API  │  Low-Level API                    │
│  Capture         │  PacketSource / PacketSink traits │
│  (iterator)      │  PacketBatch (block access)       │
├──────────────────┴──────────────────────────────────┤
│              Backends (trait impls)                   │
│  ┌───────────────────┐  ┌────────────────────────┐  │
│  │ AF_PACKET          │  │ AF_XDP (future)        │  │
│  │ TPACKET_V3 mmap   │  │ UMEM + eBPF            │  │
│  └───────────────────┘  └────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│  nix 0.31 (socket, mmap, poll) + libc (TPACKET FFI) │
├─────────────────────────────────────────────────────┤
│              Linux Kernel                            │
└─────────────────────────────────────────────────────┘
```

### Module Layout

```
netring/
├── src/
│   ├── lib.rs                # #[doc = include_str!("../README.md")], re-exports
│   ├── capture.rs            # High-level Capture + CaptureBuilder
│   ├── inject.rs             # High-level Injector + InjectorBuilder
│   ├── traits.rs             # PacketSource, PacketSink, AsyncPacketSource
│   ├── packet.rs             # Packet, OwnedPacket, PacketBatch, BatchIter
│   ├── config.rs             # FanoutMode, FanoutFlags, TimestampSource
│   ├── stats.rs              # CaptureStats
│   ├── error.rs              # Error enum (thiserror 2.x)
│   ├── afpacket/
│   │   ├── mod.rs
│   │   ├── rx.rs             # AfPacketRx: PacketSource impl
│   │   ├── tx.rs             # AfPacketTx: PacketSink impl
│   │   ├── ring.rs           # MmapRing (mmap lifecycle, strict provenance)
│   │   ├── socket.rs         # Socket setup via nix + libc
│   │   ├── fanout.rs         # Fanout join/leave
│   │   ├── filter.rs         # BPF filter attachment
│   │   └── ffi.rs            # #[repr(C)] kernel structs, constants
│   └── async/
│       ├── mod.rs
│       ├── tokio.rs          # AsyncFd adapter (feature: "tokio")
│       └── channel.rs        # Thread + channel adapter (feature: "channel")
├── benches/
│   ├── poll_throughput.rs    # divan microbenchmarks
│   └── e2e_capture.rs        # criterion end-to-end benchmarks
├── Cargo.toml
└── examples/
    ├── capture.rs
    ├── fanout.rs
    └── inject.rs
```

---

## 4. High-Level API

### 4.1 `Capture` — Builder + Iterator

```rust
use netring::Capture;

// Minimal — all defaults
let mut cap = Capture::new("eth0")?;

// Configured via builder
let mut cap = Capture::builder()
    .interface("eth0")
    .promiscuous(true)
    .block_size(1 << 22)
    .block_count(64)
    .block_timeout_ms(60)
    .ignore_outgoing(true)
    .busy_poll_us(50)
    .build()?;

// Flat iterator — blocks until packets arrive, handles block retirement
for packet in cap.packets() {
    println!("[{}.{:09}] {} bytes",
        packet.timestamp().sec, packet.timestamp().nsec, packet.len());

    // Zero-copy: data() borrows from the mmap ring
    let _eth_header = &packet.data()[..14];

    // Escape hatch: copy out for long-lived storage
    let _owned = packet.to_owned();
}
```

### 4.2 Type Definitions

```rust
/// High-level packet capture handle.
///
/// Wraps [`AfPacketRx`] and provides a flat packet iterator that
/// manages block retirement automatically.
///
/// For batch-level control, use [`AfPacketRx`] directly via [`into_inner()`].
///
/// # Examples
///
/// ```no_run
/// let mut cap = netring::Capture::new("lo")?;
/// for pkt in cap.packets().take(10) {
///     println!("{} bytes", pkt.len());
/// }
/// # Ok::<(), netring::Error>(())
/// ```
#[must_use]
pub struct Capture {
    rx: AfPacketRx,
    timeout: Duration,
}

impl Capture {
    /// Open capture on the named interface with default settings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InterfaceNotFound`] if the interface doesn't exist,
    /// [`Error::PermissionDenied`] without `CAP_NET_RAW`.
    pub fn new(interface: &str) -> Result<Self, Error>;

    /// Start building a capture with custom configuration.
    pub fn builder() -> CaptureBuilder;

    /// Blocking iterator over received packets.
    ///
    /// Handles block advancement and retirement automatically.
    /// Each [`Packet`] is a zero-copy view — valid until the iterator
    /// advances past its block.
    pub fn packets(&mut self) -> impl Iterator<Item = Packet<'_>>;

    /// Capture statistics. Resets kernel counters on read.
    pub fn stats(&self) -> Result<CaptureStats, Error>;

    /// Unwrap into the low-level [`AfPacketRx`].
    pub fn into_inner(self) -> AfPacketRx;

    /// Borrow the underlying fd for external use (e.g., attaching eBPF via `aya`).
    pub fn as_fd(&self) -> BorrowedFd<'_>;
}

impl AsFd for Capture {
    fn as_fd(&self) -> BorrowedFd<'_>;
}
```

### 4.3 `CaptureBuilder`

```rust
/// Builder for [`Capture`] with sensible defaults.
///
/// Validates all parameters at [`build()`](CaptureBuilder::build). On `ENOMEM`,
/// retries with progressively smaller ring sizes (down to 25% of requested)
/// before returning an error.
///
/// # Examples
///
/// ```no_run
/// let cap = netring::Capture::builder()
///     .interface("eth0")
///     .promiscuous(true)
///     .block_size(1 << 20)   // 1 MiB
///     .block_count(32)
///     .build()?;
/// # Ok::<(), netring::Error>(())
/// ```
#[must_use]
pub struct CaptureBuilder { /* ... */ }

impl CaptureBuilder {
    // Required
    pub fn interface(self, name: &str) -> Self;

    // Ring tuning (defaults: 4 MiB blocks, 64 blocks, 2048 frame_size, 60ms timeout)
    pub fn block_size(self, bytes: usize) -> Self;
    pub fn block_count(self, n: usize) -> Self;
    pub fn frame_size(self, bytes: usize) -> Self;
    pub fn block_timeout_ms(self, ms: u32) -> Self;

    // Socket options
    pub fn promiscuous(self, enable: bool) -> Self;
    pub fn ignore_outgoing(self, enable: bool) -> Self;
    pub fn busy_poll_us(self, us: u32) -> Self;
    pub fn timestamp_source(self, source: TimestampSource) -> Self;
    pub fn poll_timeout(self, timeout: Duration) -> Self;

    // Fanout
    pub fn fanout(self, mode: FanoutMode, group_id: u16) -> Self;
    pub fn fanout_flags(self, flags: FanoutFlags) -> Self;

    // BPF filter (raw instructions — generate with `tcpdump -dd`)
    pub fn bpf_filter(self, insns: Vec<BpfInsn>) -> Self;

    /// Validate configuration and create the capture.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`] if parameters are invalid (block_size not power of 2, etc.)
    /// - [`Error::PermissionDenied`] without `CAP_NET_RAW`
    /// - [`Error::Mmap`] if ring allocation fails after ENOMEM retries
    pub fn build(self) -> Result<Capture, Error>;
}
```

### 4.4 `Injector` — TX Path

```rust
/// High-level packet injection handle.
///
/// TPACKET_V3 TX uses V1 frame-based semantics (not block-based).
/// Each frame is submitted individually, then [`flush()`](Injector::flush)
/// triggers kernel transmission.
///
/// # Examples
///
/// ```no_run
/// let mut tx = netring::Injector::builder()
///     .interface("eth0")
///     .qdisc_bypass(true)
///     .build()?;
///
/// if let Some(mut slot) = tx.allocate(64) {
///     slot.data_mut()[0..6].copy_from_slice(&[0xff; 6]); // dst MAC
///     slot.set_len(64);
///     slot.send();
/// }
/// tx.flush()?;
/// # Ok::<(), netring::Error>(())
/// ```
#[must_use]
pub struct Injector {
    tx: AfPacketTx,
}

impl Injector {
    pub fn builder() -> InjectorBuilder;
    pub fn allocate(&mut self, len: usize) -> Option<TxSlot<'_>>;
    pub fn flush(&mut self) -> Result<usize, Error>;
    pub fn into_inner(self) -> AfPacketTx;
    pub fn as_fd(&self) -> BorrowedFd<'_>;
}

impl AsFd for Injector { /* ... */ }
```

---

## 5. Low-Level API

### 5.1 Core Traits

```rust
/// A source of packet batches (RX path).
///
/// Implement this trait to add new backends (AF_XDP, mock sources, pcap replay).
///
/// # Examples
///
/// ```no_run
/// use netring::{AfPacketRx, PacketSource};
/// use std::time::Duration;
///
/// let mut rx = AfPacketRx::builder().interface("lo").build()?;
/// while let Some(batch) = rx.next_batch_blocking(Duration::from_millis(100))? {
///     for pkt in &batch {
///         println!("{} bytes", pkt.len());
///     }
///     // batch dropped → block returned to kernel
/// }
/// # Ok::<(), netring::Error>(())
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be used as a packet source",
    label = "this type does not implement `PacketSource`",
    note = "consider using `AfPacketRx` or implementing this trait for your backend"
)]
pub trait PacketSource: AsFd {
    /// Non-blocking poll. Returns `None` if no block is retired.
    fn next_batch(&mut self) -> Option<PacketBatch<'_>>;

    /// Block until a batch is available or timeout expires.
    fn next_batch_blocking(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<PacketBatch<'_>>, Error>;

    /// Capture statistics since last read. Resets kernel counters.
    fn stats(&self) -> Result<CaptureStats, Error>;
}

/// A sink for outgoing packets (TX path).
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be used as a packet sink",
    note = "consider using `AfPacketTx` or implementing this trait for your backend"
)]
pub trait PacketSink: AsFd {
    /// Allocate a mutable frame. Returns `None` if ring is full.
    fn allocate(&mut self, len: usize) -> Option<TxSlot<'_>>;

    /// Flush pending frames to the wire. Returns count sent.
    fn flush(&mut self) -> Result<usize, Error>;
}

/// Async packet source. Uses native `async fn` in traits (stable since 1.75).
///
/// Feature-gated behind `tokio`. No `#[async_trait]` proc macro needed.
#[cfg(feature = "tokio")]
pub trait AsyncPacketSource: AsFd {
    /// Await the next packet batch.
    async fn next_batch(&mut self) -> Result<PacketBatch<'_>, Error>;
}
```

### 5.2 Packet Types

```rust
/// Zero-copy view of a received packet.
///
/// Borrows from the mmap ring via its parent [`PacketBatch`].
/// The borrow checker enforces that this reference cannot outlive the batch —
/// unlike Go's `gopacket` where the invalidation contract is documentation-only.
///
/// Call [`to_owned()`](Packet::to_owned) to copy data out of the ring.
pub struct Packet<'a> {
    data: &'a [u8],
    hdr: &'a tpacket3_hdr,
}

impl<'a> Packet<'a> {
    /// Raw packet bytes starting from the MAC header.
    pub fn data(&self) -> &'a [u8];

    /// Kernel timestamp (nanosecond precision).
    pub fn timestamp(&self) -> Timestamp;

    /// Captured length (may be < `original_len` if truncated).
    pub fn len(&self) -> usize;

    /// Original packet length on the wire.
    pub fn original_len(&self) -> usize;

    /// Per-packet status flags.
    pub fn status(&self) -> PacketStatus;

    /// RX flow hash (requires `fill_rxhash` — enabled by default).
    pub fn rxhash(&self) -> u32;

    /// Raw VLAN TCI from kernel header. Check `status().vlan_valid` first.
    pub fn vlan_tci(&self) -> u16;

    /// Raw VLAN TPID from kernel header. Check `status().vlan_tpid_valid` first.
    pub fn vlan_tpid(&self) -> u16;

    /// Copy packet data out of the ring for long-lived storage.
    pub fn to_owned(&self) -> OwnedPacket;
}

/// Owned copy of a packet, independent of the ring buffer.
#[derive(Debug, Clone)]
pub struct OwnedPacket {
    pub data: Vec<u8>,
    pub timestamp: Timestamp,
    pub original_len: usize,
}

/// Nanosecond-precision kernel timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    pub sec: u32,
    pub nsec: u32,
}

impl Timestamp {
    pub fn to_system_time(self) -> SystemTime;
    pub fn to_duration(self) -> Duration;
}

impl From<Timestamp> for SystemTime { /* ... */ }
impl From<Timestamp> for Duration { /* ... */ }

/// Decoded per-packet status flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacketStatus {
    pub truncated: bool,
    pub losing: bool,
    pub vlan_valid: bool,
    pub vlan_tpid_valid: bool,
    pub csum_valid: bool,
    pub csum_not_ready: bool,
    pub gso_tcp: bool,
}
```

---

## 5. Low-Level API

### 5.1 `PacketBatch` — Block-Level Access

```rust
/// A batch of packets from a single retired kernel block.
///
/// **RAII**: dropping the batch writes `TP_STATUS_KERNEL` to return the
/// block to the kernel. The `Release` fence ensures all reads complete first.
///
/// Only one batch can be live at a time per `AfPacketRx` (enforced by
/// `&mut self` on [`next_batch()`]).
///
/// # Iteration
///
/// ```no_run
/// # let batch: netring::PacketBatch = todo!();
/// // Via IntoIterator
/// for pkt in &batch {
///     println!("{} bytes", pkt.len());
/// }
///
/// // Via explicit iter
/// let large: Vec<_> = batch.iter()
///     .filter(|p| p.len() > 1000)
///     .map(|p| p.to_owned())
///     .collect();
/// ```
pub struct PacketBatch<'a> { /* ... */ }

impl<'a> PacketBatch<'a> {
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;

    /// Whether the block was retired via timeout (partially filled).
    pub fn timed_out(&self) -> bool;

    /// Monotonic block sequence number. Gaps indicate dropped blocks.
    pub fn seq_num(&self) -> u64;

    pub fn ts_first(&self) -> Timestamp;
    pub fn ts_last(&self) -> Timestamp;

    pub fn iter(&self) -> BatchIter<'a>;
}

impl<'a> IntoIterator for &'a PacketBatch<'a> {
    type Item = Packet<'a>;
    type IntoIter = BatchIter<'a>;
}

impl Drop for PacketBatch<'_> {
    fn drop(&mut self) {
        // fence(Ordering::Release);
        // write_volatile(&mut block_status, TP_STATUS_KERNEL);
    }
}
```

### 5.2 TX Slot

```rust
/// A mutable frame in the TX ring.
///
/// Calling [`send()`](TxSlot::send) marks the frame for transmission.
/// Dropping without calling `send()` discards the frame.
pub struct TxSlot<'a> { /* ... */ }

impl<'a> TxSlot<'a> {
    pub fn data_mut(&mut self) -> &mut [u8];
    pub fn set_len(&mut self, len: usize);

    /// Mark frame for transmission and release the slot.
    pub fn send(self);
}
```

### 5.3 Backend Types

```rust
/// AF_PACKET TPACKET_V3 RX ring.
///
/// Implements [`PacketSource`] and [`AsFd`].
/// Use [`AfPacketRx::builder()`] to construct.
pub struct AfPacketRx { /* OwnedFd, MmapRing, block cursor, seq tracker */ }

impl AfPacketRx {
    pub fn builder() -> AfPacketRxBuilder;

    /// Expose the mmap base pointer for advanced use (e.g., `madvise`).
    ///
    /// # Safety
    ///
    /// The caller must not write to the returned pointer region or
    /// interfere with block status fields.
    pub unsafe fn ring_ptr(&self) -> *const u8;
    pub fn ring_len(&self) -> usize;
}

impl PacketSource for AfPacketRx { /* ... */ }
impl AsFd for AfPacketRx { /* ... */ }
impl Drop for AfPacketRx { /* munmap + close */ }

// Send: AfPacketRx owns its fd and ring — safe to move across threads.
// !Sync: mutable state (block cursor) requires exclusive access.
unsafe impl Send for AfPacketRx {}


/// AF_PACKET TX ring (V1 frame-based semantics).
///
/// Implements [`PacketSink`] and [`AsFd`].
pub struct AfPacketTx { /* OwnedFd, MmapRing, frame cursor, pending count */ }

impl AfPacketTx {
    pub fn builder() -> AfPacketTxBuilder;
}

impl PacketSink for AfPacketTx { /* ... */ }
impl AsFd for AfPacketTx { /* ... */ }
impl Drop for AfPacketTx { /* munmap + close */ }

unsafe impl Send for AfPacketTx {}
```

---

## 6. Async Integration

### 6.1 tokio `AsyncFd` (feature: `tokio`)

Uses native `async fn` in traits — no `#[async_trait]` proc macro.

```rust
use netring::{Capture, r#async::AsyncCapture};

#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    let cap = Capture::builder().interface("eth0").build()?;
    let mut async_cap = AsyncCapture::new(cap)?;

    loop {
        let batch = async_cap.recv().await?;
        for pkt in &batch {
            handle(pkt.data()).await;
        }
    }
}
```

```rust
/// Async capture using tokio [`AsyncFd`].
///
/// Wraps a [`Capture`] (or any [`PacketSource`]) and provides async batch retrieval.
pub struct AsyncCapture<S: PacketSource = AfPacketRx> {
    inner: AsyncFd<S>,
}

impl<S: PacketSource> AsyncCapture<S> {
    pub fn new(source: S) -> Result<Self, Error>;

    /// Await the next packet batch.
    pub async fn recv(&mut self) -> Result<PacketBatch<'_>, Error> {
        loop {
            if let Some(batch) = self.inner.get_mut().next_batch() {
                return Ok(batch);
            }
            let mut guard = self.inner.readable().await?;
            guard.clear_ready();
        }
    }
}

// Also implements AsyncPacketSource
#[cfg(feature = "tokio")]
impl<S: PacketSource> AsyncPacketSource for AsyncCapture<S> {
    async fn next_batch(&mut self) -> Result<PacketBatch<'_>, Error> {
        self.recv().await
    }
}
```

### 6.2 Thread + Channel (feature: `channel`)

```rust
use netring::channel::ChannelCapture;

let rx = ChannelCapture::spawn("eth0", 4096)?;

// Implements Iterator
for packet in &rx {
    process(&packet.data);
}
```

```rust
/// Capture thread sending owned packets over a bounded channel.
///
/// Not zero-copy across the channel (packets copied out of ring).
/// Useful for runtime-agnostic async or multi-consumer patterns.
pub struct ChannelCapture { /* receiver, join handle, stop flag */ }

impl ChannelCapture {
    pub fn spawn(interface: &str, capacity: usize) -> Result<Self, Error>;
    pub fn recv(&self) -> Result<OwnedPacket, RecvError>;
    pub fn try_recv(&self) -> Result<OwnedPacket, TryRecvError>;
}

impl Iterator for &ChannelCapture {
    type Item = OwnedPacket;
}

impl Drop for ChannelCapture {
    fn drop(&mut self) { /* signal stop, join thread */ }
}
```

### 6.3 Future: `gen` Blocks (feature: `nightly`)

When Rust stabilizes generator blocks, netring will provide:

```rust
// Behind #![feature(gen_blocks)] — nightly only for now
#[cfg(feature = "nightly")]
impl Capture {
    pub fn packets_gen(&mut self) -> impl Generator<Yield = Packet<'_>> {
        gen {
            loop {
                if let Some(batch) = self.rx.next_batch_blocking(self.timeout)? {
                    for pkt in &batch {
                        yield pkt;
                    }
                }
            }
        }
    }
}
```

This is the natural fit for packet iteration — the generator suspends between
batches while preserving the batch lifetime. Tracked for post-stabilization.

---

## 7. Configuration Types

### 7.1 Fanout

```rust
/// Fanout distribution mode for multi-socket packet sharing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FanoutMode {
    /// Distribute by flow hash (src/dst IP+port).
    Hash,
    /// Round-robin across sockets.
    LoadBalance,
    /// Route to the CPU that received the NIC interrupt.
    Cpu,
    /// Fill one socket, overflow when backlogged.
    Rollover,
    /// Random distribution.
    Random,
    /// Based on `skb->queue_mapping`.
    QueueMapping,
}

bitflags::bitflags! {
    /// Flags OR'd with the fanout mode.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FanoutFlags: u16 {
        const ROLLOVER        = 0x1000;
        const UNIQUE_ID       = 0x2000;
        const IGNORE_OUTGOING = 0x4000;
        const DEFRAG          = 0x8000;
    }
}
```

### 7.2 BPF Filter

```rust
/// Classic BPF filter for kernel-level packet filtering.
///
/// Generate instructions with `tcpdump -dd "expression"` or programmatically.
/// Attach to capture via builder: `.bpf_filter(insns)`.
///
/// For eBPF, use `aya` and attach to the socket fd via [`Capture::as_fd()`].
pub struct BpfFilter {
    instructions: Vec<BpfInsn>,
}

impl BpfFilter {
    pub fn new(insns: Vec<BpfInsn>) -> Self;
    pub fn instructions(&self) -> &[BpfInsn];
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}
```

### 7.3 Other

```rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TimestampSource {
    #[default]
    Software,
    RawHardware,
    SysHardware,
}

/// Capture statistics. Reading resets kernel counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureStats {
    pub packets: u32,
    pub drops: u32,
    pub freeze_count: u32,
}
```

### 7.4 Errors

```rust
/// All errors returned by netring.
///
/// Uses `thiserror` 2.x. Each variant wraps the underlying `std::io::Error`
/// where applicable, preserving the OS errno for diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("socket creation failed")]
    Socket(#[source] std::io::Error),

    #[error("mmap failed")]
    Mmap(#[source] std::io::Error),

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("bind failed")]
    Bind(#[source] std::io::Error),

    #[error("setsockopt({option}) failed")]
    SockOpt {
        option: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("insufficient privileges (need CAP_NET_RAW)")]
    PermissionDenied,

    #[error(transparent)]
    Io(std::io::Error),
}
```

---

## 8. Internal: Ring Buffer Implementation

### 8.1 `MmapRing` — Strict Provenance

```rust
/// RAII wrapper for the mmap'd ring buffer region.
///
/// Uses strict provenance APIs (`ptr.map_addr()`) for all pointer
/// arithmetic — never casts `*mut u8` to `usize` and back.
struct MmapRing {
    /// Base pointer into the mmap region. Preserves provenance.
    base: NonNull<u8>,
    size: usize,
    block_size: usize,
    block_count: usize,
}

impl MmapRing {
    /// Create a new ring via `nix::sys::mman::mmap`.
    ///
    /// nix 0.31 signature: `mmap<F: AsFd>(addr, length, prot, flags, f, offset)`.
    /// Returns `Result<NonNull<c_void>>`. Takes `F: AsFd` directly (not Option).
    /// On EPERM for MAP_LOCKED, retries without it and logs a warning.
    fn new(fd: BorrowedFd<'_>, size: usize, block_size: usize) -> Result<Self, Error>;

    /// Get pointer to block `index` using strict provenance.
    fn block_ptr(&self, index: usize) -> NonNull<tpacket_block_desc> {
        let offset = index * self.block_size;
        // Strict provenance: preserves the mmap allocation's provenance
        let ptr = self.base.as_ptr().map_addr(|a| a + offset);
        // SAFETY: offset is within the mmap region (index < block_count)
        unsafe { NonNull::new_unchecked(ptr.cast::<tpacket_block_desc>()) }
    }
}

impl Drop for MmapRing {
    fn drop(&mut self) {
        // SAFETY: self.base was returned by mmap, self.size matches.
        unsafe { nix::sys::mman::munmap(self.base, self.size).ok(); }
    }
}
```

### 8.2 Block Status — Atomic Access

```rust
/// Read block status with proper memory ordering.
///
/// The kernel writes `TP_STATUS_USER` with a store-release; we read with
/// load-acquire to see all packet data the kernel wrote before retiring.
fn read_block_status(bd: NonNull<tpacket_block_desc>) -> u32 {
    // SAFETY: block_status is a u32 at a known offset, naturally aligned.
    let status_ptr = unsafe {
        &*(bd.as_ptr().cast::<u8>()
            .add(offset_of!(tpacket_block_desc, hdr.bh1.block_status))
            .cast::<AtomicU32>())
    };
    status_ptr.load(Ordering::Acquire)
}

/// Return block to kernel with store-release ordering.
fn release_block(bd: NonNull<tpacket_block_desc>) {
    let status_ptr = unsafe {
        &*(bd.as_ptr().cast::<u8>()
            .add(offset_of!(tpacket_block_desc, hdr.bh1.block_status))
            .cast::<AtomicU32>())
    };
    status_ptr.store(TP_STATUS_KERNEL, Ordering::Release);
}
```

### 8.3 Poll Algorithm

```rust
impl PacketSource for AfPacketRx {
    fn next_batch(&mut self) -> Option<PacketBatch<'_>> {
        let bd = self.ring.block_ptr(self.current_block);
        let status = read_block_status(bd);

        if status & TP_STATUS_USER == 0 {
            return None;
        }

        // Sequence gap detection
        let seq = unsafe { (*bd.as_ptr()).hdr.bh1.seq_num };
        if seq != self.expected_seq && self.expected_seq != 0 {
            log::warn!("block sequence gap: expected {}, got {}", self.expected_seq, seq);
        }
        self.expected_seq = seq + 1;

        let batch = PacketBatch::new(bd, &self.ring);
        self.current_block = (self.current_block + 1) % self.ring.block_count;
        Some(batch)
    }

    fn next_batch_blocking(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<PacketBatch<'_>>, Error> {
        if let Some(batch) = self.next_batch() {
            return Ok(Some(batch));
        }
        // nix::poll::poll() — safe wrapper, no raw libc needed
        let mut pfd = nix::poll::PollFd::new(self.as_fd(), nix::poll::PollFlags::POLLIN);
        nix::poll::poll(&mut [pfd], timeout.as_millis() as i32)?;
        Ok(self.next_batch())
    }
}
```

---

## 9. Safety

### Unsafe Boundaries

| Operation | Module | Reason |
|-----------|--------|--------|
| `nix::sys::mman::mmap` / `munmap` | `ring.rs` | Kernel shared memory |
| `AtomicU32` cast on block status | `ring.rs` | Shared-memory synchronization |
| Pointer arithmetic in blocks | `packet.rs` | Walking packet linked list |
| `libc::setsockopt` (TPACKET opts) | `socket.rs` | FFI for AF_PACKET-specific options |
| `*mut u8` → `#[repr(C)]` struct cast | `ffi.rs` | Interpreting kernel structures |

### Invariants

1. **Lifetime chain**: `Packet<'a>` → `PacketBatch<'a>` → `AfPacketRx`. Compiler-enforced — block cannot be returned while any packet reference exists.

2. **Block state machine**: `KernelOwned` → (kernel fills, sets `TP_STATUS_USER`) → `UserOwned` → (user reads, drop sets `TP_STATUS_KERNEL`) → `KernelOwned`. Single owner at all times.

3. **Atomic ordering**: `Acquire` on status read (see kernel's stores to block data); `Release` on status write (flush our reads before kernel reclaims).

4. **Bounds checking**: `BatchIter` validates `tp_next_offset` and `tp_snaplen` against block boundaries before constructing slices.

5. **Drop ordering**: `MmapRing` → `munmap`; `OwnedFd` → `close`. Struct field declaration order guarantees drop order.

6. **Provenance**: All pointer arithmetic uses strict provenance (`map_addr`). No `ptr as usize` round-trips.

### Edition 2024: Explicit Unsafe

All `unsafe fn` bodies use explicit `unsafe {}` blocks per edition 2024 semantics:

```rust
// Edition 2024: body of unsafe fn is *not* implicitly unsafe
unsafe fn block_data(bd: NonNull<tpacket_block_desc>) -> &[u8] {
    let len = unsafe { (*bd.as_ptr()).hdr.bh1.blk_len as usize };
    unsafe { core::slice::from_raw_parts(bd.as_ptr().cast(), len) }
}
```

---

## 10. Performance

### Defaults

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `block_size` | 4 MiB | Throughput/latency balance |
| `block_count` | 64 | 256 MiB total buffer |
| `frame_size` | 2048 | 1500 MTU + headers |
| `block_timeout_ms` | 60 | Responsive on sparse traffic |
| `fill_rxhash` | true | Useful for flow tracking |

### Tuning Profiles

| Profile | block_size | block_count | timeout_ms | busy_poll | Notes |
|---------|-----------|-------------|------------|-----------|-------|
| High throughput | 4 MiB | 128–256 | 60 | off | + `FanoutMode::Cpu` + thread pinning |
| Low latency | 256 KiB | 64 | 1–10 | 50 µs | Smaller blocks retire faster |
| Memory-constrained | 1 MiB | 16 | 100 | off | 16 MiB total |
| Jumbo frames | 4 MiB | 64 | 60 | off | `frame_size` = 65536 |

### System Requirements

```bash
ulimit -l unlimited                        # MAP_LOCKED
sysctl -w net.core.rmem_max=268435456      # socket buffer
ethtool -L eth0 combined 8                 # NIC RSS for fanout
```

| Capability | Required For |
|------------|-------------|
| `CAP_NET_RAW` | AF_PACKET sockets |
| `CAP_IPC_LOCK` | `MAP_LOCKED` (or sufficient `RLIMIT_MEMLOCK`) |
| `CAP_NET_ADMIN` | Promiscuous mode |

---

## 11. Feature Flags

| Feature | Default | Dependencies | Description |
|---------|---------|-------------|-------------|
| (core) | — | `libc`, `nix`, `thiserror` 2.x, `log`, `bitflags` 2.x | `Capture`, `Injector`, `AfPacketRx/Tx` |
| `tokio` | off | `tokio` 1.x (io-util, net) | `AsyncCapture`, `AsyncPacketSource` |
| `channel` | off | `crossbeam-channel` | `ChannelCapture` thread adapter |
| `nightly` | off | nightly compiler | `gen` block iterators (when stabilized) |

---

## 12. Examples

### Basic Capture

```rust
use netring::Capture;

fn main() -> Result<(), netring::Error> {
    let mut cap = Capture::builder()
        .interface("eth0")
        .promiscuous(true)
        .ignore_outgoing(true)
        .build()?;

    for pkt in cap.packets().take(1000) {
        println!("[{}.{:09}] {} bytes",
            pkt.timestamp().sec, pkt.timestamp().nsec, pkt.len());
    }

    println!("{:?}", cap.stats()?);
    Ok(())
}
```

### Batch Processing

```rust
use netring::{AfPacketRx, PacketSource};
use std::time::Duration;

fn main() -> Result<(), netring::Error> {
    let mut rx = AfPacketRx::builder()
        .interface("eth0")
        .block_size(1 << 22)
        .block_count(128)
        .build()?;

    let mut last_seq = 0u64;
    loop {
        let Some(batch) = rx.next_batch_blocking(Duration::from_millis(100))? else {
            continue;
        };

        if batch.seq_num() != last_seq + 1 && last_seq != 0 {
            eprintln!("dropped blocks: {} → {}", last_seq, batch.seq_num());
        }
        last_seq = batch.seq_num();

        for pkt in &batch {
            process(pkt.data());
        }
    }
}
```

### Fanout

```rust
use netring::{Capture, FanoutMode, FanoutFlags};
use std::thread;

fn main() -> Result<(), netring::Error> {
    let cpus = thread::available_parallelism()?.get();

    let handles: Vec<_> = (0..cpus).map(|_| {
        thread::spawn(|| {
            let mut cap = Capture::builder()
                .interface("eth0")
                .fanout(FanoutMode::Cpu, 42)
                .fanout_flags(FanoutFlags::ROLLOVER | FanoutFlags::DEFRAG)
                .ignore_outgoing(true)
                .build()
                .unwrap();

            for pkt in cap.packets() {
                process(pkt.data());
            }
        })
    }).collect();

    for h in handles { h.join().unwrap(); }
    Ok(())
}
```

### Async (tokio)

```rust
use netring::{Capture, r#async::AsyncCapture};

#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    let cap = Capture::builder().interface("eth0").build()?;
    let mut async_cap = AsyncCapture::new(cap)?;

    loop {
        let batch = async_cap.recv().await?;
        for pkt in &batch {
            handle(pkt.data()).await;
        }
    }
}
```

### Injection

```rust
use netring::Injector;

fn main() -> Result<(), netring::Error> {
    let mut tx = Injector::builder()
        .interface("eth0")
        .qdisc_bypass(true)
        .build()?;

    for i in 0u16..1000 {
        if let Some(mut slot) = tx.allocate(64) {
            let buf = slot.data_mut();
            buf[0..6].copy_from_slice(&[0xff; 6]);        // broadcast dst
            buf[6..12].copy_from_slice(&[0x00; 6]);       // src
            buf[12..14].copy_from_slice(&(0x0800u16).to_be_bytes());
            slot.set_len(64);
            slot.send();
        }
    }
    tx.flush()?;
    Ok(())
}
```

### eBPF Integration (via `aya`)

```rust
// Users attach their own eBPF programs via the exposed fd
use aya::programs::SocketFilter;

let mut cap = netring::Capture::new("eth0")?;
let prog: &mut SocketFilter = bpf.program_mut("my_filter")?.try_into()?;
prog.load()?;
prog.attach(cap.as_fd())?;  // AsFd — no raw fd needed

for pkt in cap.packets() {
    // Only packets passing the eBPF filter arrive here
}
```

---

## 13. Testing

### Unit Tests (no privileges)

- Config validation: block_size power-of-2, frame_size alignment, frame_nr calculation
- FFI struct layout: `size_of`, `offset_of` assertions against kernel constants
- `BatchIter`: synthetic block data, linked list walk, bounds checking
- BPF instruction encoding
- Timestamp conversions
- Builder validation: missing interface, invalid combos

### Integration Tests (`CAP_NET_RAW` required)

- Loopback: send known packets via raw socket, capture with netring, verify content
- Block timeout: verify partial blocks retire after configured timeout
- Fanout: N sockets in group, verify each receives a subset
- Statistics: inject N packets, verify `CaptureStats` counts
- Sequence gaps: intentionally slow consumer, verify gap detection
- ENOMEM retry: request absurd ring size, verify graceful degradation

### Benchmarks

- `divan`: microbenchmarks for `next_batch()`, `BatchIter`, `to_owned()`
- `criterion`: end-to-end throughput (Mpps) vs ring size, block size

---

## 14. Dependencies

| Crate | Version | Purpose | Required |
|-------|---------|---------|----------|
| `libc` | 0.2 | TPACKET structs, AF_PACKET constants | Yes |
| `nix` | 0.31 | Safe syscall wrappers (socket, mmap, poll, bind) | Yes |
| `thiserror` | 2.x | Error derivation | Yes |
| `log` | 0.4 | Warnings (sequence gaps, ENOMEM retries) | Yes |
| `bitflags` | 2.x | `FanoutFlags` | Yes |
| `tokio` | 1.x | `AsyncFd` adapter | Feature `tokio` |
| `crossbeam-channel` | 0.5 | Channel adapter | Feature `channel` |
| `divan` | 0.1 | Microbenchmarks | Dev |
| `criterion` | 0.5 | E2E benchmarks | Dev |

---

## 15. Design Decisions

1. **Two API levels**: `Capture` (flat iterator, simple) and `AfPacketRx` (batch, maximum control). Unlike gopacket (per-packet only) or libpcap (callback only).

2. **Builder pattern**: Type-safe, validated at `build()`, ENOMEM retry. `#[must_use]` prevents silent drops.

3. **Lifetime-enforced zero-copy**: `Packet<'a>` → `PacketBatch<'a>` — compile-time enforced. The key advantage over Go/C.

4. **`async fn` in traits**: Native since Rust 1.75 — `AsyncPacketSource` needs no proc macro.

5. **Strict provenance**: `ptr.map_addr()` for all mmap pointer math. No `ptr as usize` casts.

6. **I/O safety**: `OwnedFd` / `BorrowedFd` / `AsFd` throughout — no raw fd in public API. Enables safe interop with `aya`, `tokio`, etc.

7. **`nix` + `libc`**: `nix` 0.31 for standard syscalls (safe wrappers); raw `libc` only for TPACKET-specific structs/constants that `nix` doesn't wrap.

8. **Separate RX/TX**: Different kernel semantics (V3 blocks vs V1 frames), independent configuration, no contention.

9. **TX now**: V1-style TX through `Injector` — imperfect but usable without waiting for AF_XDP.

10. **Raw VLAN fields**: Users decode `vlan_tci()` / `vlan_tpid()` themselves.

11. **No auto huge pages**: Users call `madvise` on `ring_ptr()` if they want THP.

12. **`SO_BUSY_POLL`**: Builder accepts `busy_poll_us()` for latency-sensitive workloads.

13. **ENOMEM retry**: Shrinks ring to 25% before failing — adopted from libpcap.

14. **`#[diagnostic::on_unimplemented]`**: Custom error messages when users misuse `PacketSource`/`PacketSink`.

15. **`AsFd` on all handles**: Enables external eBPF attachment via `aya` without exposing raw fds.

---

## Appendix A: TPACKET_V3 Kernel Reference

### Memory Layout

```
Ring (mmap'd, block_size × block_count bytes):
┌────────────────┬────────────────┬───┐
│    Block 0     │    Block 1     │...│
└────────────────┴────────────────┴───┘

Block (block_size bytes):
┌──────────────────────────────────────────────┐
│ tpacket_block_desc (48 bytes)                │
│   block_status: u32, num_pkts: u32           │
│   offset_to_first_pkt: u32, blk_len: u32    │
│   seq_num: u64, ts_first, ts_last            │
├──────────────────────────────────────────────┤
│ tpacket3_hdr + sockaddr_ll (≥68 bytes)       │
│   tp_next_offset → next pkt (0 = last)       │
│   tp_sec, tp_nsec, tp_snaplen, tp_len        │
│   tp_status, tp_mac, tp_net                  │
│   hv1: { rxhash, vlan_tci, vlan_tpid }      │
│ [packet data: tp_snaplen bytes]              │
│ [padding to 16-byte alignment]               │
├──────────────────────────────────────────────┤
│ ... more packets ...                         │
├──────────────────────────────────────────────┤
│ [unused space]                               │
└──────────────────────────────────────────────┘
```

### Setup Sequence

```
1. socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
2. setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V3)
3. setsockopt(SOL_PACKET, PACKET_RX_RING, &tpacket_req3)
4. [opt] setsockopt(SOL_PACKET, PACKET_TX_RING, &tpacket_req3)
5. mmap(MAP_SHARED | MAP_LOCKED | MAP_POPULATE)
6. bind(&sockaddr_ll)
7. [opt] PACKET_ADD_MEMBERSHIP (promisc)
8. [opt] PACKET_FANOUT
9. [opt] SO_ATTACH_FILTER
```

### `tpacket_req3` Constraints

- `tp_block_size`: power of 2, multiple of `PAGE_SIZE` (4096)
- `tp_frame_size`: multiple of 16, ≥ 68 (`TPACKET3_HDRLEN`)
- `tp_frame_nr` = `(block_size / frame_size) × block_nr`
- `tp_retire_blk_tov`: block timeout in ms (0 = disabled)

### Status Flags

| Flag | Value | Context |
|------|-------|---------|
| `TP_STATUS_KERNEL` | `0x00` | Block: kernel-owned |
| `TP_STATUS_USER` | `0x01` | Block: user-owned |
| `TP_STATUS_BLK_TMO` | `0x20` | Block: timeout-retired |
| `TP_STATUS_COPY` | `0x02` | Packet: truncated |
| `TP_STATUS_LOSING` | `0x04` | Packet: drops occurring |
| `TP_STATUS_VLAN_VALID` | `0x10` | Packet: VLAN TCI valid |
| `TP_STATUS_VLAN_TPID_VALID` | `0x40` | Packet: VLAN TPID valid |
| `TP_STATUS_CSUM_VALID` | `0x80` | Packet: HW checksum OK |
| `TP_STATUS_GSO_TCP` | `0x100` | Packet: TCP GSO segment |

### Constants

| Constant | Value |
|----------|-------|
| `SOL_PACKET` | 263 |
| `PACKET_VERSION` | 10 |
| `PACKET_RX_RING` | 5 |
| `PACKET_TX_RING` | 13 |
| `PACKET_FANOUT` | 18 |
| `PACKET_STATISTICS` | 6 |
| `PACKET_ADD_MEMBERSHIP` | 1 |
| `PACKET_MR_PROMISC` | 1 |
| `PACKET_QDISC_BYPASS` | 20 |
| `PACKET_IGNORE_OUTGOING` | 23 |
| `PACKET_TIMESTAMP` | 17 |
| `ETH_P_ALL` | 0x0003 |
| `TPACKET_V3` | 2 |
| `TPACKET_ALIGNMENT` | 16 |
| `TPACKET3_HDRLEN` | 68 |
| `TP_FT_REQ_FILL_RXHASH` | 0x01 |
| `PACKET_FANOUT_HASH` | 0 |
| `PACKET_FANOUT_LB` | 1 |
| `PACKET_FANOUT_CPU` | 2 |
| `PACKET_FANOUT_ROLLOVER` | 3 |
| `PACKET_FANOUT_RND` | 4 |
| `PACKET_FANOUT_QM` | 5 |

---

## Appendix B: `libc` and `nix` Crate Notes

### `libc` 0.2.183 — All TPACKET_V3 Types Available

`libc` exports all required TPACKET_V3 `#[repr(C)]` structs. The `ffi.rs` module
should **re-export from libc**, not redefine them:

| libc Type | Size | Notes |
|-----------|------|-------|
| `tpacket_req3` | 28 B | All 7 fields public |
| `tpacket3_hdr` | 48 B | `hv1` is a struct field (not union) |
| `tpacket_block_desc` | 48 B | Contains `hdr: tpacket_bd_header_u` (union) |
| `tpacket_hdr_v1` | 40 B | `#[repr(align(8))]` |
| `tpacket_bd_ts` | 8 B | **Caveat: field is `ts_usec`, not `ts_nsec`** |
| `tpacket_hdr_variant1` | 12 B | `tp_rxhash`, `tp_vlan_tci`, `tp_vlan_tpid` |
| `tpacket_stats_v3` | 12 B | `tp_packets`, `tp_drops`, `tp_freeze_q_cnt` |
| `sockaddr_ll` | 20 B | Standard |
| `sock_filter` | 8 B | Matches `BpfInsn` layout |

**`tpacket_bd_ts.ts_usec` caveat**: The kernel header has a union of `ts_usec`/`ts_nsec`.
`libc` flattened it to `ts_usec`. Since TPACKET_V3 always provides nanosecond resolution,
read `ts_usec` and interpret as nanoseconds. Add a wrapper type or doc note for clarity.

**`TPACKET_V3` constant**: Available as `libc::tpacket_versions::TPACKET_V3` (enum variant).
Define a convenience constant: `const TPACKET_V3_INT: c_int = 2;` for `setsockopt`.

**Constants NOT in `libc`** (define in `ffi.rs`):
- `TP_STATUS_GSO_TCP: u32 = 0x100`
- TX status constants: `TP_STATUS_AVAILABLE`, `TP_STATUS_SEND_REQUEST`, `TP_STATUS_SENDING`, `TP_STATUS_WRONG_FORMAT`

### `nix` 0.31 — Safe Syscall Wrappers

**mmap signature** (nix 0.31):
```rust
pub unsafe fn mmap<F: AsFd>(
    addr: Option<NonZeroUsize>,
    length: NonZeroUsize,
    prot: ProtFlags,
    flags: MapFlags,  // MAP_SHARED | MAP_LOCKED | MAP_POPULATE all available
    f: F,             // Takes AsFd directly — pass BorrowedFd
    offset: off_t,
) -> Result<NonNull<c_void>>
```

**Use nix for**: `mmap`, `munmap`, `poll`, `if_nametoindex`, `close` (via `OwnedFd`)
**Use raw libc for**: `setsockopt` with `SOL_PACKET` options, `bind` with `sockaddr_ll`,
`sendto(fd, NULL, 0, 0, NULL, 0)` for TX flush

---

## Appendix C: Implementation Plan

### Phase Overview

| Phase | Name | Key Deliverables |
|-------|------|-----------------|
| 1 | FFI & Foundations | Cargo.toml, `error.rs`, `ffi.rs` (re-exports + layout tests), `config.rs`, `stats.rs`, `packet.rs` (value types) |
| 2 | Socket & MmapRing | `socket.rs` (all setsockopt), `ring.rs` (MmapRing + strict provenance + AtomicU32), `filter.rs`, `fanout.rs` |
| 3 | RX Path | `traits.rs` (PacketSource), `Packet<'a>`, `PacketBatch` (RAII), `BatchIter`, `AfPacketRx` + builder |
| 4 | TX Path | `PacketSink` trait, `TxSlot`, `AfPacketTx` + builder, `Injector` |
| 5 | High-Level API | `Capture` + `CaptureBuilder`, flat packet iterator, ENOMEM retry |
| 6 | Async & Channel | `AsyncCapture` (tokio `AsyncFd`), `ChannelCapture` (crossbeam), `AsyncPacketSource` |
| 7 | Tests & Docs | FFI layout assertions, synthetic BatchIter tests, integration tests, benchmarks, examples, README |

### Phase Dependencies

```
Phase 1 ──→ Phase 2 ──→ Phase 3 ──→ Phase 5 ──→ Phase 6 ──→ Phase 7
                    └──→ Phase 4 ──┘
```

### Key Implementation Notes

**1. Field declaration order matters for Drop:**
```rust
pub struct AfPacketRx {
    ring: MmapRing,      // dropped first → munmap
    fd: OwnedFd,         // dropped second → close
    current_block: usize,
    expected_seq: u64,
}
```

**2. `AsFd` must be implemented on all public handles:**
- `Capture`, `Injector`, `AfPacketRx`, `AfPacketTx`, `AsyncCapture`
- Enables external eBPF attachment via `aya` (see Examples section)

**3. Flat packet iterator (Phase 5) requires unsafe:**
`LendingIterator` is not stabilized. The `packets()` method returns
`impl Iterator<Item = Packet<'_>>` using a raw pointer to `AfPacketRx`
with lifetime erasure on `PacketBatch`. Blocks are released lazily at
the start of the next `next()` call. Documented for `for`-loop consumption only.

**4. TX uses V1 frame-based semantics:**
TPACKET_V3 TX falls back to V1. Frames are walked by index with `frame_size`
stride, not by `tp_next_offset`. Status flow:
`TP_STATUS_AVAILABLE (0) → TP_STATUS_SEND_REQUEST (1) → kernel sends → TP_STATUS_AVAILABLE`

**5. `r#async` module naming:**
`async` is a keyword. The module uses `pub mod r#async;` and is accessed as
`netring::r#async::AsyncCapture` or via convenience re-export `netring::channel::ChannelCapture`.

**6. ENOMEM retry in CaptureBuilder::build():**
On `ENOMEM` from `setsockopt(PACKET_RX_RING)` or `mmap`, shrink `block_count`
by 25% per attempt, down to 25% of original. Log each retry via `log::warn!`.

**7. Poll timeout clamping:**
`Duration::as_millis()` returns `u128`. Clamp to `i32::MAX` for `nix::poll::poll`:
`i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX)`

**8. `gen` blocks (nightly only):**
Not stabilized as of Rust 1.93. The `nightly` feature flag is reserved for
future `gen`-block-based iteration when stabilized. No implementation in initial release.

### Detailed plans

See `plans/` directory for per-phase file-level implementation plans:
- `plans/01-ffi-foundations.md` — every struct, constant, and FFI layout test
- `plans/02-socket-mmap.md` — every setsockopt wrapper, MmapRing, block status helpers
- `plans/03-rx-path.md` — lifetime model, BatchIter pointer walking, AfPacketRx builder
- `plans/04-tx-path.md` — V1 frame semantics, TxSlot send/drop, AfPacketTx builder
- `plans/05-high-level-api.md` — flat iterator design (raw pointer + lifetime erasure)
- `plans/06-async-channel.md` — AsyncFd loop, channel thread, feature gates
- `plans/07-tests-docs.md` — every test function, benchmark, example, doc requirement
