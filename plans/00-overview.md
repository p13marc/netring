# Implementation Plans — v0.2 Roadmap

## Phases

| Phase | Name | Effort | Dependencies |
|-------|------|--------|-------------|
| A | Code Quality + New Dependencies | Small | None |
| B | Ring Presets & Snap Length | Small | None |
| C | Per-Packet Direction | Small | A (inline) |
| D | eBPF Fanout & Socket Filter | Medium | A (ffi constants) |
| E | Interface Capability Detection | Medium | B (RingProfile) |
| F | Bridge / IPS Mode | Large | A, B |
| G | AF_XDP Backend | Large | A |

## Dependency Graph

```
Phase A ──→ Phase C (inline + bounds check interaction)
       ──→ Phase D (ffi constants for PACKET_FANOUT_EBPF)
       ──→ Phase F (TX block_size fix)
       ──→ Phase G (clean trait abstraction)

Phase B ──→ Phase E (InterfaceInfo::suggest_profile() returns RingProfile)
       ──→ Phase F (BridgeBuilder::profile() uses RingProfile)

Phases C and D are independent of each other.
```

## Versioning

- Phases A–E → **v0.2.0**
- Phase F (bridge) → **v0.3.0**
- Phase G (AF_XDP) → **v0.4.0** (behind `af-xdp` feature flag)

## New Dependencies Summary

| Crate | Type | Feature Flag | Phase |
|-------|------|-------------|-------|
| `tracing` 0.1 | Required (replaces `log`) | — | A |
| `etherparse` 0.16 | Optional | `parse` | A |
| `core_affinity` 0.8 | Dev-dependency | — | A |
| `nlink` 0.9 | Optional | `nlink` | E |
| `xsk-rs` 0.8 | Optional | `af-xdp` | G |

## Verified Constants (libc 0.2.183)

All needed constants are exported by libc — no manual definitions needed:
- `PACKET_FANOUT_CBPF` (6), `PACKET_FANOUT_EBPF` (7), `PACKET_FANOUT_DATA` (22)
- `SO_ATTACH_BPF` (50)
- `PACKET_HOST` (0), `PACKET_BROADCAST` (1), `PACKET_MULTICAST` (2), `PACKET_OTHERHOST` (3), `PACKET_OUTGOING` (4)

## Known Limitations

- **Plan G (AF_XDP)**: `XdpRx` will NOT implement `PacketSource` in v0.4 (standalone API).
  Bridge (Plan F) requires `PacketSource` — AF_XDP + Bridge is not supported until
  a future GAT-based trait redesign.
