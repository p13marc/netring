# Performance Tuning Guide

## Default Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `block_size` | 4 MiB (1 << 22) | Size of each ring buffer block |
| `block_count` | 64 | Number of blocks (total ring: 256 MiB) |
| `frame_size` | 2048 | Minimum frame size (1500 MTU + headers) |
| `block_timeout_ms` | 60 | Block retirement timeout |
| `fill_rxhash` | true | Kernel fills RX flow hash |

## Tuning Profiles

### High Throughput (>1 Mpps)

```rust
Capture::builder()
    .interface("eth0")
    .block_size(1 << 22)      // 4 MiB blocks
    .block_count(256)          // 1 GiB total ring
    .block_timeout_ms(60)
    .ignore_outgoing(true)
    .fanout(FanoutMode::Cpu, 42)
    .fanout_flags(FanoutFlags::ROLLOVER | FanoutFlags::DEFRAG)
    .build()?;
```

- Use `FanoutMode::Cpu` with one capture thread per CPU core
- Pin threads to CPUs with `core_affinity`
- Configure NIC RSS: `ethtool -L eth0 combined N`
- Large ring (256+ blocks) tolerates processing stalls

### Low Latency

```rust
Capture::builder()
    .interface("eth0")
    .block_size(256 * 1024)    // 256 KiB — smaller blocks retire faster
    .block_count(64)
    .block_timeout_ms(1)       // 1 ms — retire partial blocks quickly
    .busy_poll_us(50)          // kernel polls NIC for 50µs before sleeping
    .build()?;
```

- Small blocks: less data buffered before retirement
- Short timeout: partial blocks handed to userspace quickly
- `busy_poll_us`: kernel spins on NIC driver, avoiding interrupt latency
- Trade-off: higher CPU usage for lower tail latency

### Memory-Constrained

```rust
Capture::builder()
    .interface("eth0")
    .block_size(1 << 20)      // 1 MiB blocks
    .block_count(16)           // 16 MiB total
    .block_timeout_ms(100)
    .build()?;
```

### Jumbo Frames (MTU 9000)

```rust
Capture::builder()
    .interface("eth0")
    .frame_size(65536)         // accommodate jumbo frames + GSO
    .block_size(1 << 22)
    .build()?;
```

## System Tuning

### Locked Memory

`MAP_LOCKED` prevents ring pages from being swapped. Without `CAP_IPC_LOCK`,
the library falls back to `MAP_POPULATE` (pre-faults but doesn't lock).

```bash
# Per-session
ulimit -l unlimited

# Permanent: /etc/security/limits.conf
username  hard  memlock  unlimited
```

### Socket Buffers

```bash
sudo sysctl -w net.core.rmem_max=268435456
sudo sysctl -w net.core.rmem_default=268435456
sudo sysctl -w net.core.netdev_max_backlog=50000
```

### NIC Configuration

```bash
# Enable RSS (Receive Side Scaling) for fanout
sudo ethtool -L eth0 combined 8

# Tune interrupt coalescing
sudo ethtool -C eth0 rx-usecs 50 rx-frames 64

# Enable hardware timestamping (if supported)
sudo ethtool -T eth0
```

## Monitoring

### Capture Statistics

```rust
let stats = cap.stats()?;
println!("{}", stats);
// Output: "packets: 12345, drops: 0, freezes: 0"
```

| Field | Meaning |
|-------|---------|
| `packets` | Total packets received (passed BPF filter) |
| `drops` | Packets dropped because ring was full |
| `freeze_count` | Times the ring was frozen (queue depth exceeded) |

**Reading stats resets kernel counters.** Call periodically for rate calculation.

### Sequence Gap Detection

The low-level API provides `PacketBatch::seq_num()` — a monotonically increasing
block sequence number. Gaps indicate the kernel dropped entire blocks:

```rust
if batch.seq_num() != expected_seq {
    eprintln!("dropped {} blocks", batch.seq_num() - expected_seq);
}
```

## Reducing Drops

1. **Increase ring size**: more blocks = more buffer against processing stalls
2. **Use fanout**: distribute load across CPU cores
3. **Attach BPF filter**: drop unwanted packets in kernel before they reach the ring
4. **Minimize processing in the poll loop**: copy/enqueue and process elsewhere
5. **Use `ignore_outgoing(true)`**: skip TX packets you don't need
6. **Pin to NUMA node**: ensure ring memory is local to the NIC

## Fanout Modes

| Mode | Best For |
|------|----------|
| `Hash` | Flow-consistent distribution (same flow → same socket) |
| `Cpu` | Match packet delivery to interrupt-handling CPU |
| `LoadBalance` | Even round-robin distribution |
| `Rollover` | Fill one socket, overflow to next (simple load shedding) |
| `Random` | Statistical distribution without flow affinity |
| `QueueMapping` | NIC hardware queue-aware distribution |

**Flags:**
- `DEFRAG`: reassemble IP fragments before hashing (prevents flow splitting)
- `ROLLOVER`: overflow to next socket when selected one is full
- `IGNORE_OUTGOING`: skip outgoing packets in fanout group
