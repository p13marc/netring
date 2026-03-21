# API Overview

## Choosing Your API Level

```
Do you need batch-level control?
  │
  ├── No → Use Capture (high-level, simple)
  │         cap.packets() → flat iterator
  │
  └── Yes → Use AfPacketRx (low-level, maximum control)
              rx.next_batch() → PacketBatch with metadata
```

## High-Level API

### Capture (RX)

```rust
use netring::Capture;

// Minimal
let mut cap = Capture::new("eth0")?;

// Configured
let mut cap = Capture::builder()
    .interface("eth0")
    .promiscuous(true)
    .block_timeout_ms(60)
    .ignore_outgoing(true)
    .build()?;

// Iterate packets (blocks until available)
for pkt in cap.packets().take(1000) {
    let data: &[u8] = pkt.data();        // zero-copy, borrows from ring
    let ts = pkt.timestamp();              // nanosecond kernel timestamp
    let owned = pkt.to_owned();            // copy out for long-lived storage
}

// Statistics (resets kernel counters)
let stats = cap.stats()?;
```

### Injector (TX)

```rust
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
```

## Low-Level API

### PacketSource Trait

```rust
use netring::{AfPacketRx, AfPacketRxBuilder, PacketSource};
use std::time::Duration;

let mut rx = AfPacketRxBuilder::default()
    .interface("eth0")
    .block_size(1 << 22)
    .block_count(128)
    .build()?;

loop {
    // next_batch() is non-blocking; next_batch_blocking() waits
    let Some(batch) = rx.next_batch_blocking(Duration::from_millis(100))? else {
        continue;
    };

    // Batch metadata
    println!("seq={} pkts={} timed_out={}",
        batch.seq_num(), batch.len(), batch.timed_out());

    // Iterate packets within the block
    for pkt in &batch {
        process(pkt.data());
    }
    // batch dropped here → block returned to kernel
}
```

### PacketSink Trait

```rust
use netring::{AfPacketTx, AfPacketTxBuilder, PacketSink};

let mut tx = AfPacketTxBuilder::default()
    .interface("eth0")
    .frame_count(256)
    .build()?;

// allocate() + send() + flush()
```

## Key Types

| Type | Description |
|------|-------------|
| `Capture` | High-level RX handle (builder + flat iterator) |
| `Injector` | High-level TX handle (builder + allocate/flush) |
| `AfPacketRx` | Low-level RX (implements `PacketSource`) |
| `AfPacketTx` | Low-level TX (implements `PacketSink`) |
| `Packet<'a>` | Zero-copy packet view (borrows from ring) |
| `PacketBatch<'a>` | Block of packets (RAII: returns block on drop) |
| `OwnedPacket` | Owned copy (heap-allocated, no lifetime) |
| `TxSlot<'a>` | Mutable TX frame (send or discard on drop) |
| `XdpSocket` | AF_XDP socket (feature: `af-xdp`) |
| `XdpSocketBuilder` | Builder for AF_XDP sockets |
| `CaptureStats` | Packets received, dropped, frozen |
| `Timestamp` | Nanosecond kernel timestamp |

## Async Integration

### tokio (`AsyncCapture`)

```rust
use netring::{AfPacketRxBuilder, PacketSource};
use netring::async_adapters::tokio_adapter::AsyncCapture;

let rx = AfPacketRxBuilder::default().interface("eth0").build()?;
let mut async_cap = AsyncCapture::new(rx)?;

loop {
    async_cap.wait_readable().await?;  // epoll-based wait
    if let Some(batch) = async_cap.get_mut().next_batch() {
        for pkt in &batch { /* ... */ }
    }
}
```

### Channel (`ChannelCapture`)

```rust
use netring::async_adapters::channel::ChannelCapture;

let rx = ChannelCapture::spawn("eth0", 4096)?;  // background thread
for pkt in &rx {                                  // OwnedPacket via channel
    println!("{} bytes", pkt.data.len());
}
// rx dropped → thread stops
```

## Configuration Reference

### CaptureBuilder Methods

| Method | Default | Description |
|--------|---------|-------------|
| `.interface(name)` | required | Network interface |
| `.block_size(bytes)` | 4 MiB | Block size (power of 2, multiple of PAGE_SIZE) |
| `.block_count(n)` | 64 | Number of blocks |
| `.frame_size(bytes)` | 2048 | Min frame size (multiple of 16, ≥ 68) |
| `.block_timeout_ms(ms)` | 60 | Block retirement timeout |
| `.promiscuous(bool)` | false | Promiscuous mode |
| `.ignore_outgoing(bool)` | false | Skip outgoing packets |
| `.busy_poll_us(us)` | disabled | Kernel NIC polling timeout |
| `.timestamp_source(src)` | Software | Timestamp source |
| `.poll_timeout(dur)` | 100ms | Iterator poll timeout |
| `.fanout(mode, id)` | disabled | Join fanout group |
| `.fanout_flags(flags)` | empty | Fanout options |
| `.bpf_filter(insns)` | disabled | Kernel-level BPF filter |

## Error Handling

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

## External eBPF Integration

All handles implement `AsFd`, enabling external eBPF attachment:

```rust
use std::os::fd::AsFd;

let cap = Capture::new("eth0")?;
let fd = cap.as_fd();  // use with aya, libbpf-rs, etc.
```
