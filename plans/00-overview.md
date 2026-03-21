# Implementation Plans — v0.2 Roadmap

## Phases

| Phase | Name | Effort | Dependencies |
|-------|------|--------|-------------|
| A | Code Quality Fixes | Small | None |
| B | Ring Presets & Snap Length | Small | None |
| C | Per-Packet Direction | Small | None |
| D | eBPF Fanout & Socket Filter | Medium | None |
| E | Interface Capability Detection | Medium | None |
| F | Bridge / IPS Mode | Large | A |
| G | AF_XDP Backend | Large | A |

## Dependency Graph

```
Phase A (code quality) ──→ Phase F (bridge)
                       └──→ Phase G (AF_XDP)

Phases B, C, D, E are independent of each other and of A.
All can be done in parallel.
```

## Versioning

- Phases A–E → release as **v0.2.0**
- Phase F (bridge) → release as **v0.3.0**
- Phase G (AF_XDP) → release as **v0.4.0** (behind `af-xdp` feature flag)
