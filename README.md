# netring

High-performance zero-copy packet I/O for Linux.

`netring` provides packet capture and injection via AF_PACKET (TPACKET_V3
block-based mmap ring buffers) and AF_XDP (kernel-bypass via XDP sockets).
One type per role — use it directly, no wrappers, no extra layers.

## Quick Start

```rust,no_run
// Flat packet iterator — the simplest path.
let mut cap = netring::Capture::open("eth0").unwrap();
for pkt in cap.packets().take(100) {
    println!("[{}] {} bytes", pkt.timestamp(), pkt.len());
}
```

```rust,no_run
// Batch processing with sequence-gap detection.
use netring::Capture;
use std::time::Duration;

let mut cap = Capture::builder()
    .interface("eth0")
    .block_size(1 << 22)
    .build()
    .unwrap();

while let Some(batch) = cap.next_batch_blocking(Duration::from_millis(100)).unwrap() {
    println!("seq={} pkts={} timed_out={}",
        batch.seq_num(), batch.len(), batch.timed_out());
    for pkt in &batch {
        process(pkt.data());
    }
    // batch dropped → block returned to kernel
}
# fn process(_: &[u8]) {}
```

```rust,no_run
// Async with tokio: zero-copy zero-overhead readiness via AsyncFd.
# async fn _ex() -> Result<(), netring::Error> {
use netring::{AsyncCapture, Capture};

let mut cap = AsyncCapture::new(Capture::open("eth0")?)?;

loop {
    let mut guard = cap.readable().await?;
    if let Some(batch) = guard.next_batch() {
        for pkt in &batch {
            handle(pkt.data()).await;
        }
    }
}
# async fn handle(_: &[u8]) {}
# }
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `af-xdp` | off | AF_XDP kernel-bypass packet I/O (pure Rust, no native deps) |
| `tokio` | off | Async capture/inject via `AsyncFd`, `Stream` impl, async `Bridge` |
| `channel` | off | Thread + bounded channel adapter (runtime-agnostic) |
| `parse` | off | Packet header parsing via `etherparse` |

## Public API

One type per role:

| Concept | Type | Backend |
|---------|------|---------|
| Receive packets | `Capture` | AF_PACKET |
| Inject packets | `Injector` | AF_PACKET |
| Receive + inject (single fd) | `XdpSocket` | AF_XDP (feature: `af-xdp`) |
| Bridge two interfaces | `Bridge` | AF_PACKET |
| Async capture | `AsyncCapture<S>` | any (feature: `tokio`) |
| Async inject | `AsyncInjector` | AF_PACKET (feature: `tokio`) |
| Async stream | `PacketStream` | wraps `AsyncCapture` (feature: `tokio`) |
| Channel adapter | `ChannelCapture` | AF_PACKET (feature: `channel`) |

Each type has both a `::open(iface)` shortcut and a `::builder()` for full
configuration.

## Default Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `block_size` | 4 MiB | Ring buffer block size |
| `block_count` | 64 | Number of blocks (256 MiB total) |
| `frame_size` | 2048 | Minimum frame size |
| `block_timeout_ms` | 60 | Block retirement timeout |
| `fill_rxhash` | true | Kernel fills RX flow hash |

## Performance Tuning

| Profile | block_size | block_count | timeout_ms | Notes |
|---------|-----------|-------------|------------|-------|
| High throughput | 4 MiB | 128–256 | 60 | + `FanoutMode::Cpu` + thread pinning |
| Low latency | 256 KiB | 64 | 1–10 | + `busy_poll_us(50)` |
| Memory-constrained | 1 MiB | 16 | 100 | 16 MiB total ring |
| Jumbo frames | 4 MiB | 64 | 60 | `frame_size(65536)` |

See [docs/TUNING_GUIDE.md](docs/TUNING_GUIDE.md) for detailed tuning advice.

## Fanout Modes

Distribute packets across multiple sockets for multi-threaded capture:

| Mode | Strategy |
|------|----------|
| `Hash` | Flow hash (same flow → same socket) |
| `Cpu` | Route to CPU that received the NIC interrupt |
| `LoadBalance` | Round-robin |
| `Rollover` | Fill one socket, overflow to next |
| `Random` | Random distribution |
| `QueueMapping` | NIC hardware queue mapping |

```rust,no_run
use netring::{Capture, FanoutMode, FanoutFlags};

let cap = Capture::builder()
    .interface("eth0")
    .fanout(FanoutMode::Cpu, 42)
    .fanout_flags(FanoutFlags::ROLLOVER | FanoutFlags::DEFRAG)
    .build()
    .unwrap();
```

## Statistics

```rust,no_run
# let cap = netring::Capture::open("lo").unwrap();
let stats = cap.stats().unwrap();
println!("received: {}, dropped: {}, frozen: {}",
    stats.packets, stats.drops, stats.freeze_count);
```

Reading stats resets the kernel counters — call periodically for rate calculation.

## System Requirements

- **Linux** kernel 3.2+ (for TPACKET_V3), 5.4+ (for AF_XDP)
- **Rust** 1.85+ (edition 2024)

### Capabilities

| Capability | Required For |
|------------|-------------|
| `CAP_NET_RAW` | Creating AF_PACKET / AF_XDP sockets |
| `CAP_IPC_LOCK` | `MAP_LOCKED` (or sufficient `RLIMIT_MEMLOCK`) |
| `CAP_NET_ADMIN` | Promiscuous mode |

```bash
# Recommended: use justfile (sudo only once for setcap)
just setcap          # grants CAP_NET_RAW on all binaries
just test            # runs without sudo
just capture eth0    # runs without sudo

# Manual alternative
sudo setcap cap_net_raw+ep target/release/examples/capture
```

## Examples

```bash
just setcap                  # grant capabilities once (needs sudo)
just capture eth0            # basic packet capture
just batch eth0              # low-level batch API with sequence gap detection
just fanout eth0 4           # multi-threaded fanout capture
just inject lo               # packet injection
just stats eth0              # live statistics monitor (pkt/s, drops)
just low-latency eth0        # low-latency tuning demo
just dpi eth0                # deep packet inspection (HTTP/TLS/DNS/SSH detection)
just channel eth0            # channel adapter (runtime-agnostic)
just async eth0              # async capture with tokio (readable() pattern)
just async-stream eth0       # async capture as a futures::Stream
just async-inject lo 1000    # async TX with backpressure (AsyncInjector)
just async-signal eth0       # async capture with Ctrl-C graceful shutdown
just async-pipeline eth0 4   # async capture → tokio::mpsc → 4 worker tasks
just async-bridge eth0 eth1  # async transparent bridge (Bridge::run_async)
just ebpf                    # eBPF/aya integration demo (AsFd verification)
cargo run --example xdp_send --features af-xdp -- lo  # AF_XDP TX-only (uses XdpMode::Tx)
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — system design, lifetime model, ring layout
- [API Overview](docs/API_OVERVIEW.md) — all types, methods, and configuration
- [Tuning Guide](docs/TUNING_GUIDE.md) — performance profiles, system tuning, monitoring
- [Troubleshooting](docs/TROUBLESHOOTING.md) — common errors and fixes

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT License](LICENSE-MIT) at your option.
