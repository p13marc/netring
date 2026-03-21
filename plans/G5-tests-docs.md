# Phase G.5: AF_XDP Tests, Example, Documentation

## Tests

### Unit tests (no privileges)

**ffi.rs:**
- Constant values: `AF_XDP == 44`, `SOL_XDP == 283`, etc.
- Struct sizes: `xdp_umem_reg == 32`, `sockaddr_xdp == 16`, `xdp_desc == 16`,
  `xdp_mmap_offsets == 128`, `xdp_ring_offset == 32`

**umem.rs:**
- `Umem::new(4096, 16)` — creates 16 frames, `available() == 16`
- `alloc_frame()` returns sequential offsets
- `alloc_frame()` returns `None` when exhausted
- `free_frame()` + `alloc_frame()` recycles correctly
- `as_reg()` returns correct `xdp_umem_reg`

**ring.rs:**
- Producer/consumer with synthetic data (mock ring in a `Vec<u8>`)
- `producer_reserve()` returns None when full
- `consumer_peek()` returns 0 when empty
- Index masking wraps correctly at ring_size boundary
- `needs_wakeup()` reads flag correctly

**mod.rs (builder):**
- Builder rejects missing interface
- Builder rejects zero frame_size/count
- Builder validate() works
- Builder defaults correct

### Integration tests (needs CAP_NET_RAW + CAP_BPF + XDP NIC)

These cannot run in CI without a privileged environment with XDP-capable NIC.
Document as manual tests.

- TX-only: create XdpSocket, `send()` a packet, `flush()` — no BPF needed
- RX: requires external XDP program (aya), out of scope for automated tests

## Example

### `examples/xdp_send.rs`

TX-only example (no BPF program needed):

```rust
//! AF_XDP TX-only example — send packets without a BPF program.
//!
//! Usage: cargo run --example xdp_send --features af-xdp -- <interface>
//! Requires CAP_NET_RAW + CAP_BPF.

use netring::afxdp::XdpSocketBuilder;

fn main() -> Result<(), netring::Error> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let mut xdp = XdpSocketBuilder::default()
        .interface(&iface)
        .queue_id(0)
        .build()?;

    // Send 10 raw Ethernet frames
    for i in 0u16..10 {
        let mut frame = vec![0u8; 64];
        frame[0..6].copy_from_slice(&[0xff; 6]); // broadcast
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14..16].copy_from_slice(&i.to_be_bytes());
        xdp.send(&frame)?;
    }
    xdp.flush()?;
    eprintln!("Sent 10 frames via AF_XDP");
    Ok(())
}
```

## Documentation

### Update `docs/ARCHITECTURE.md`

Add AF_XDP section:
```
## AF_XDP Backend (feature: af-xdp)

Uses direct AF_XDP syscalls (socket, setsockopt, mmap, bind) via libc.
Same pure Rust approach as AF_PACKET — no C library dependencies.

Ring model: 4 shared rings (Fill, RX, TX, Completion) over UMEM.
Producer/consumer protocol with AtomicU32 (Acquire/Release ordering).

Requires: Linux 5.4+, XDP-capable NIC driver, external XDP BPF program for RX.
```

### Update `docs/API_OVERVIEW.md`

Add `XdpSocket` to the key types table.

### Update `README.md`

Add `af-xdp` to feature flags table.
Add AF_XDP to the comparison table in the evaluation doc.

### Update `CLAUDE.md`

Note AF_XDP implementation status.
