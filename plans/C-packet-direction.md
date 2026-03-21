# Phase C: Per-Packet Direction

## Goal

Expose the packet direction (host/broadcast/multicast/otherhost/outgoing) that
the kernel provides via `sockaddr_ll.sll_pkttype` in the TPACKET_V3 ring.

## Background

Each packet in the ring has a `sockaddr_ll` structure after the `tpacket3_hdr`.
The `sll_pkttype` field indicates:

| Value | Constant | Meaning |
|-------|----------|---------|
| 0 | `PACKET_HOST` | Addressed to this host |
| 1 | `PACKET_BROADCAST` | Broadcast frame |
| 2 | `PACKET_MULTICAST` | Multicast frame |
| 3 | `PACKET_OTHERHOST` | Destined for another host (promiscuous mode) |
| 4 | `PACKET_OUTGOING` | Originated from this host |

The `sockaddr_ll` is located at offset `tp_mac - sizeof(sockaddr_ll)` from the
`tpacket3_hdr`, or more precisely, between the `tpacket3_hdr` and the actual
packet data at `tp_mac`.

Actually, in TPACKET_V3, the `sockaddr_ll` is placed right after `tpacket3_hdr`
(at `tpacket3_hdr + TPACKET_ALIGN(sizeof(tpacket3_hdr))`). The field
`tp_net - tp_mac` gives the link-layer header size, and `sll_pkttype` is in the
`sockaddr_ll` that precedes `tp_mac`.

We can access it via the gap between the tpacket3_hdr and tp_mac offset.

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

### 4. Update BatchIter bounds checking

When constructing a `Packet`, verify that the `sockaddr_ll` also fits within the
block bounds (it's between tpacket3_hdr and tp_mac).

## Tests

- Unit: synthetic block with sockaddr_ll written at correct offset, verify direction()
- Unit: verify each PacketDirection variant maps from correct sll_pkttype value
- Integration: capture on loopback with `ignore_outgoing(false)`, verify we see
  both `Host` and `Outgoing` directions

## Exports

- Add `PacketDirection` to `lib.rs` re-exports
- Add to `docs/API_OVERVIEW.md`
