# Phase C: Per-Packet Direction

## Goal

Expose the packet direction (host/broadcast/multicast/otherhost/outgoing) that
the kernel provides via `sockaddr_ll.sll_pkttype` in the TPACKET_V3 ring.

## Background

Each packet in the ring has a `sockaddr_ll` structure after the `tpacket3_hdr`.
The `sll_pkttype` field indicates:

| Value | Constant | Meaning |
|-------|----------|---------|
| 0 | `libc::PACKET_HOST` | Addressed to this host |
| 1 | `libc::PACKET_BROADCAST` | Broadcast frame |
| 2 | `libc::PACKET_MULTICAST` | Multicast frame |
| 3 | `libc::PACKET_OTHERHOST` | Destined for another host (promiscuous mode) |
| 4 | `libc::PACKET_OUTGOING` | Originated from this host |

All constants are in `libc 0.2.183` (type `c_uchar`). Re-export in `ffi.rs`.

The `sockaddr_ll` is placed after `tpacket3_hdr` at offset
`TPACKET_ALIGN(sizeof(tpacket3_hdr))` from the packet header start.
We access it via the gap between the tpacket3_hdr and `tp_mac`.

## Implementation

### 1. PacketDirection enum

Location: `src/packet.rs`

```rust
/// Direction of a captured packet relative to the capturing host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketDirection {
    /// Addressed to this host.
    Host,
    /// Link-layer broadcast.
    Broadcast,
    /// Link-layer multicast.
    Multicast,
    /// Destined for another host (captured in promiscuous mode).
    OtherHost,
    /// Originated from this host.
    Outgoing,
    /// Unknown direction.
    Unknown(u8),
}
```

### 2. Packet::direction() method

```rust
impl<'a> Packet<'a> {
    /// Packet direction relative to the capturing host.
    ///
    /// Decoded from the `sockaddr_ll.sll_pkttype` field in the ring buffer.
    pub fn direction(&self) -> PacketDirection;
}
```

Implementation: the `sockaddr_ll` is at a known offset after the `tpacket3_hdr`.
Read `sll_pkttype` from `hdr_ptr + sizeof(tpacket3_hdr)` (aligned), cast to
`&sockaddr_ll`, read `sll_pkttype`.

This requires storing the `sockaddr_ll` pointer in `Packet` or computing it from
`hdr`. Since the `sockaddr_ll` is at `TPACKET_ALIGN(sizeof(tpacket3_hdr))` after
the header start, we can compute it:

```rust
let sll_offset = ffi::tpacket_align(std::mem::size_of::<ffi::tpacket3_hdr>());
let sll_ptr = (self.hdr as *const _ as *const u8).map_addr(|a| a + sll_offset);
let sll = unsafe { &*(sll_ptr as *const ffi::sockaddr_ll) };
```

### 3. Packet::link_layer_address() method (bonus)

While we have the `sockaddr_ll`, also expose:

```rust
/// Source MAC address from the link-layer header metadata.
pub fn source_mac(&self) -> [u8; 6];

/// EtherType / protocol from link-layer metadata.
pub fn protocol(&self) -> u16;
```

These come from `sll_addr` and `sll_protocol` respectively.

### 4. Bounds checking for sockaddr_ll

The `Packet` struct doesn't hold `block_end`, so it can't validate sockaddr_ll
bounds in `direction()`. Two approaches:

**Preferred**: Validate in `BatchIter::next()` before constructing the Packet.
Add a bounds check: `hdr_ptr + sll_offset + sizeof(sockaddr_ll) <= block_end`.
If it fails, skip the packet (same as existing tp_snaplen check).

**Alternative**: Store `block_end` in `Packet` (adds 8 bytes per packet, slightly
less clean but allows lazy bounds checking in `direction()`).

## Tests

- Unit: synthetic block with sockaddr_ll written at correct offset, verify direction()
- Unit: verify each PacketDirection variant maps from correct sll_pkttype value
- Integration: capture on loopback with `ignore_outgoing(false)`, verify we see
  both `Host` and `Outgoing` directions

## Exports

- Add `PacketDirection` to `lib.rs` re-exports
- Add to `docs/API_OVERVIEW.md`
