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
// Low-level: batch processing
use netring::{AfPacketRxBuilder, PacketSource};
use std::time::Duration;

let mut rx = AfPacketRxBuilder::default()
    .interface("eth0")
    .block_size(1 << 22)
    .build()
    .unwrap();

while let Some(batch) = rx.next_batch_blocking(Duration::from_millis(100)).unwrap() {
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
| `tokio` | off | Async capture via `AsyncFd` |
| `channel` | off | Thread + channel adapter |

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
# Alternative: set capability on binary
sudo setcap cap_net_raw+ep target/release/examples/capture
```

## Performance Tuning

| Profile | block_size | block_count | timeout_ms | Notes |
|---------|-----------|-------------|------------|-------|
| High throughput | 4 MiB | 128–256 | 60 | + `FanoutMode::Cpu` + thread pinning |
| Low latency | 256 KiB | 64 | 1–10 | + `busy_poll_us(50)` |
| Memory-constrained | 1 MiB | 16 | 100 | 16 MiB total |

```bash
# System tuning
ulimit -l unlimited
sudo sysctl -w net.core.rmem_max=268435456
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT License](LICENSE-MIT) at your option.
