# API Overview

netring exposes one type per role. There is no high-level/low-level split —
the type you see is the type you use.

## At a glance

| Concept | Type | Backend | Feature |
|---------|------|---------|---------|
| Receive packets | `Capture` | AF_PACKET | core |
| Inject packets | `Injector` | AF_PACKET | core |
| Receive + inject (one fd) | `XdpSocket` | AF_XDP | `af-xdp` |
| Bridge two interfaces | `Bridge` | AF_PACKET | core |
| Async capture | `AsyncCapture<S>` | any | `tokio` |
| Async inject | `AsyncInjector` | AF_PACKET | `tokio` |
| Async stream | `PacketStream<S>` | wraps `AsyncCapture` | `tokio` |
| Channel adapter | `ChannelCapture` | AF_PACKET | `channel` |

Every type with a backing kernel resource has both:

- `Type::open(iface)` — one-liner with defaults
- `Type::builder()` — fluent configuration

## Capture (RX)

```rust,no_run
use netring::Capture;

// Simplest form.
let mut cap = Capture::open("eth0")?;

// Configured.
let mut cap = Capture::builder()
    .interface("eth0")
    .promiscuous(true)
    .block_timeout_ms(60)
    .ignore_outgoing(true)
    .build()?;
# Ok::<(), netring::Error>(())
```

### Three reception modes

```rust,no_run
# use netring::Capture;
# use std::time::Duration;
# let mut cap = Capture::open("eth0")?;
// 1. Flat iterator (zero-copy, blocks indefinitely)
for pkt in cap.packets().take(1000) {
    let data: &[u8] = pkt.data();        // borrows from ring
    let _ts = pkt.timestamp();           // nanosecond kernel timestamp
    let _owned = pkt.to_owned();         // copy out for long-lived storage
}

// 2. Bounded iterator
for pkt in cap.packets_for(Duration::from_secs(5)) { /* ... */ }

// 3. Block-level batches with sequence-gap detection
while let Some(batch) = cap.next_batch_blocking(Duration::from_millis(100))? {
    println!("seq={} pkts={} timed_out={}",
        batch.seq_num(), batch.len(), batch.timed_out());
    for pkt in &batch { /* ... */ }
    // batch dropped → block returned to kernel
}
# Ok::<(), netring::Error>(())
```

### Stats

```rust,no_run
# let cap = netring::Capture::open("eth0")?;
let s = cap.stats()?;             // since last call (resets kernel counters)
let s2 = cap.cumulative_stats()?; // since open (monotonic)
# Ok::<(), netring::Error>(())
```

## Injector (TX)

```rust,no_run
use netring::Injector;

let mut tx = Injector::builder()
    .interface("eth0")
    .qdisc_bypass(true)    // skip qdisc for lower latency
    .build()?;

if let Some(mut slot) = tx.allocate(64) {
    slot.data_mut()[0..6].copy_from_slice(&[0xff; 6]);  // dst MAC
    slot.set_len(64);
    slot.send();           // mark for transmission
}
tx.flush()?;               // kick kernel to send

// Observability accessors:
let _ = tx.frame_capacity();
let _ = tx.pending_count();
let _ = tx.available_slots();
let _ = tx.rejected_slots();
# Ok::<(), netring::Error>(())
```

## AF_XDP (`af-xdp` feature)

Kernel-bypass packet I/O via XDP sockets. Pure-Rust `libc` syscalls — no
native C deps. Method names mirror `Capture` for naming parity.

```rust,no_run,ignore
use netring::{XdpMode, XdpSocket};
use std::time::Duration;

// TX-only — no BPF program required. **Must** set XdpMode::Tx, otherwise
// the default (RxTx) prefills half the UMEM and starves the TX path.
let mut xdp = XdpSocket::builder()
    .interface("eth0")
    .queue_id(0)
    .mode(XdpMode::Tx)
    .build()?;

xdp.send(&frame)?;
xdp.flush()?;

// RX (requires an attached XDP program — see `aya`).
if let Some(batch) = xdp.next_batch_blocking(Duration::from_millis(100))? {
    for pkt in &batch {
        println!("{} bytes", pkt.data().len());
    }
}
# Ok::<(), netring::Error>(())
```

## Bridge

```rust,no_run
use netring::bridge::{Bridge, BridgeAction};

let mut bridge = Bridge::builder()
    .interface_a("eth0")
    .interface_b("eth1")
    .build()?;

bridge.run(|_pkt, _dir| BridgeAction::Forward)?;
# Ok::<(), netring::Error>(())
```

Async variant under `tokio` feature:

```rust,no_run,ignore
bridge.run_async(|_pkt, _dir| BridgeAction::Forward).await?;
```

## Async (`tokio` feature)

### `AsyncCapture<S>` — three reception entry points

```rust,no_run
# async fn _ex() -> Result<(), netring::Error> {
use netring::{AsyncCapture, Capture};

let mut cap = AsyncCapture::new(Capture::open("eth0")?)?;

// Guarded zero-copy (recommended).
let mut guard = cap.readable().await?;
if let Some(batch) = guard.next_batch() {
    for pkt in &batch { /* ... */ }
}

// Single-call zero-copy.
let batch = cap.try_recv_batch().await?;

// Owned copies — use when the future must be Send (tokio::spawn etc.).
let packets = cap.recv().await?;
# Ok(()) }
```

### `PacketStream` — futures-compatible

```rust,no_run
# async fn _ex() -> Result<(), netring::Error> {
use netring::{AsyncCapture, Capture};

let stream = AsyncCapture::new(Capture::open("eth0")?)?.into_stream();
// Use with `futures::StreamExt::next` or `tokio_stream`.
# let _ = stream;
# Ok(()) }
```

### `AsyncInjector` — TX with backpressure

```rust,no_run
# async fn _ex() -> Result<(), netring::Error> {
use netring::{AsyncInjector, Injector};

let mut tx = AsyncInjector::new(Injector::open("eth0")?)?;
tx.send(&[0xff; 64]).await?;          // awaits POLLOUT if ring is full
tx.flush().await?;
tx.wait_drained(std::time::Duration::from_secs(1)).await?;
# Ok(()) }
```

### `ChannelCapture` (runtime-agnostic)

```rust,no_run
use netring::async_adapters::channel::ChannelCapture;

let rx = ChannelCapture::spawn("eth0", 4096)?;
for pkt in &rx {
    println!("{} bytes", pkt.data.len());
}
# Ok::<(), netring::Error>(())
```

## Configuration reference

### CaptureBuilder

| Method | Default | Description |
|--------|---------|-------------|
| `.interface(name)` | required | Network interface |
| `.profile(...)` | Default | Apply a [`RingProfile`] preset |
| `.block_size(bytes)` | 4 MiB | Block size (power of 2, multiple of PAGE_SIZE) |
| `.block_count(n)` | 64 | Number of blocks |
| `.frame_size(bytes)` | 2048 | Min frame size (multiple of 16, ≥ 68) |
| `.snap_len(bytes)` | unset | Shortcut: sets frame_size to fit only the first N bytes |
| `.block_timeout_ms(ms)` | 60 | Block retirement timeout |
| `.fill_rxhash(bool)` | true | Kernel populates `tp_rxhash` |
| `.promiscuous(bool)` | false | Promiscuous mode |
| `.ignore_outgoing(bool)` | false | Skip outgoing packets |
| `.busy_poll_us(us)` | disabled | Kernel NIC polling timeout |
| `.reuseport(bool)` | false | `SO_REUSEPORT` |
| `.rcvbuf(bytes)` | unset | `SO_RCVBUF` (or `SO_RCVBUFFORCE` if `rcvbuf_force`) |
| `.timestamp_source(src)` | Software | Timestamp source |
| `.poll_timeout(dur)` | 100ms | Iterator poll timeout |
| `.fanout(mode, id)` | disabled | Join fanout group |
| `.fanout_flags(flags)` | empty | Fanout options |
| `.bpf_filter(insns)` | disabled | Classic BPF filter |

### InjectorBuilder

| Method | Default | Description |
|--------|---------|-------------|
| `.interface(name)` | required | Network interface |
| `.frame_size(bytes)` | 2048 | TX frame size |
| `.frame_count(n)` | 256 | Number of TX frames |
| `.qdisc_bypass(bool)` | false | Skip qdisc layer |

### XdpSocketBuilder

| Method | Default | Description |
|--------|---------|-------------|
| `.interface(name)` | required | Network interface |
| `.queue_id(id)` | 0 | NIC queue to bind |
| `.frame_size(size)` | 4096 | UMEM frame size |
| `.frame_count(count)` | 4096 | UMEM frame count |
| `.mode(mode)` | RxTx | RX/TX/RxTx/Custom split |
| `.need_wakeup(bool)` | true | `XDP_USE_NEED_WAKEUP` optimization |

## Error handling

All errors are `netring::Error`:

| Variant | Cause |
|---------|-------|
| `PermissionDenied` | Missing `CAP_NET_RAW` |
| `InterfaceNotFound(name)` | Interface doesn't exist |
| `Config(msg)` | Invalid builder parameters |
| `Socket(io)` | Socket creation failed |
| `Mmap(io)` | Ring buffer mmap failed |
| `Bind(io)` | Interface bind failed |
| `SockOpt { option, source }` | setsockopt failed |
| `Io(io)` | Generic I/O error |

## eBPF integration

All handles implement `AsFd`. Use with `aya`, `libbpf-rs`, etc.:

```rust,no_run
use std::os::fd::AsFd;
let cap = netring::Capture::open("eth0")?;
let _fd = cap.as_fd();
# Ok::<(), netring::Error>(())
```

For socket-filter attachment, prefer the inherent helpers:

```rust,no_run,ignore
cap.attach_ebpf_filter(prog.fd())?;
cap.attach_fanout_ebpf(prog.fd())?;  // if FanoutMode::Ebpf was selected
cap.detach_filter()?;
```

## Migrating from 0.3.x

| 0.3.x | 0.4.x |
|-------|-------|
| `AfPacketRx` | `Capture` |
| `AfPacketRxBuilder` | `CaptureBuilder` |
| `AfPacketTx` | `Injector` |
| `AfPacketTxBuilder` | `InjectorBuilder` |
| `Capture::new(iface)` | `Capture::open(iface)` |
| `XdpSocket::recv_batch()` | `XdpSocket::next_batch()` |
| `cap.wait_readable() + cap.get_mut().next_batch()` | `let g = cap.readable().await?; g.next_batch()` |

The old type names ship as `#[deprecated]` aliases for one release.
