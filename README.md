# netring

High-performance zero-copy packet I/O for Linux.

`netring` provides packet capture and injection via AF_PACKET with TPACKET_V3
(block-based mmap ring buffers). It offers both a high-level ergonomic API
and a low-level batch API for maximum throughput.

## Quick Start

```rust,no_run
// High-level: flat packet iterator
let mut cap = netring::Capture::new("eth0").unwrap();
for pkt in cap.packets().take(100) {
    println!("[{}] {} bytes", pkt.timestamp(), pkt.len());
}
```

```rust,no_run
// Low-level: batch processing with sequence gap detection
use netring::{AfPacketRxBuilder, PacketSource};
use std::time::Duration;

let mut rx = AfPacketRxBuilder::default()
    .interface("eth0")
    .block_size(1 << 22)
    .build()
    .unwrap();

while let Some(batch) = rx.next_batch_blocking(Duration::from_millis(100)).unwrap() {
    println!("seq={} pkts={} timed_out={}",
        batch.seq_num(), batch.len(), batch.timed_out());
    for pkt in &batch {
        process(pkt.data());
    }
    // batch dropped → block returned to kernel
}
# fn process(_: &[u8]) {}
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `tokio` | off | Async capture via `AsyncFd` (wait_readable + next_batch) |
| `channel` | off | Thread + bounded channel adapter (runtime-agnostic) |

## API Levels

| Level | Types | When to Use |
|-------|-------|-------------|
| **High** | `Capture`, `Injector` | Simple capture/inject with iterators and builders |
| **Low** | `AfPacketRx`, `AfPacketTx` | Batch processing, sequence tracking, custom poll logic |
| **Async** | `AsyncCapture`, `ChannelCapture` | Integration with tokio or any async runtime |

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
# let cap = netring::Capture::new("lo").unwrap();
let stats = cap.stats().unwrap();
println!("received: {}, dropped: {}, frozen: {}",
    stats.packets, stats.drops, stats.freeze_count);
```

Reading stats resets the kernel counters — call periodically for rate calculation.

## System Requirements

- **Linux** kernel 3.2+ (for TPACKET_V3)
- **Rust** 1.85+ (edition 2024)

### Capabilities

| Capability | Required For |
|------------|-------------|
| `CAP_NET_RAW` | Creating AF_PACKET sockets |
| `CAP_IPC_LOCK` | `MAP_LOCKED` (or sufficient `RLIMIT_MEMLOCK`) |
| `CAP_NET_ADMIN` | Promiscuous mode |

```bash
# Option 1: run as root
sudo cargo run --example capture

# Option 2: set capability on binary
sudo setcap cap_net_raw+ep target/release/examples/capture
```

## Examples

```bash
cargo run --example capture -- eth0           # basic capture
cargo run --example batch_processing -- eth0  # low-level batch API
cargo run --example fanout -- eth0 4          # multi-threaded fanout
cargo run --example inject -- lo              # packet injection
cargo run --example stats_monitor -- eth0     # live statistics
cargo run --example low_latency -- eth0       # low-latency tuning
cargo run --example channel_consumer --features channel -- eth0
cargo run --example async_capture --features tokio -- eth0
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — system design, lifetime model, ring layout
- [API Overview](docs/API_OVERVIEW.md) — all types, methods, and configuration
- [Tuning Guide](docs/TUNING_GUIDE.md) — performance profiles, system tuning, monitoring
- [Troubleshooting](docs/TROUBLESHOOTING.md) — common errors and fixes

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT License](LICENSE-MIT) at your option.
