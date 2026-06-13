# netring docs

All netring documentation lives in this one tree (`netring/docs/`). The repo root
`docs/` is a symlink here, so `docs/X.md` links resolve from both the crate
(docs.rs / crates.io) and the repo root (GitHub).

## Guides
- [FEATURES.md](FEATURES.md) — the Cargo feature graph (axes, recipes, couplings).
- [CRATE_BOUNDARY.md](CRATE_BOUNDARY.md) — the netring ↔ flowscope contract.
- [ARCHITECTURE.md](ARCHITECTURE.md) — system design, lifetime model, ring layout.
- [API_OVERVIEW.md](API_OVERVIEW.md) — types, methods, configuration.
- [ASYNC_GUIDE.md](ASYNC_GUIDE.md) — tokio patterns, Send rules, Monitor on multi-thread.
- [WRITING_DETECTORS.md](WRITING_DETECTORS.md) — `detector!` / `pattern_detector!` tutorial.
- [discoverability.md](discoverability.md) — the Monitor toolkit by use case.
- [scaling.md](scaling.md) — fan-out capture, `FanoutMode` matrix, anti-patterns.
- [TUNING_GUIDE.md](TUNING_GUIDE.md) — performance profiles, system tuning.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — common errors and fixes.

## Quality / internals
- [MIRI.md](MIRI.md) — miri + fuzzing strategy and the Stacked-vs-Tree-Borrows note.
- [EBPF_BANDWIDTH.md](EBPF_BANDWIDTH.md) — design doc for the eBPF bandwidth backend.
- [AF_XDP_EVALUATION.md](AF_XDP_EVALUATION.md) — AF_XDP design notes.

## Migration guides
- [MIGRATING_0.22_TO_0.23.md](MIGRATING_0.22_TO_0.23.md) — `Send` run-loop future.
- [MIGRATING_0.21_TO_0.22.md](MIGRATING_0.21_TO_0.22.md) — typed roles, flat `FlowPacket`, ops toolkit.
- [MIGRATING_0.20_TO_0.21.md](MIGRATING_0.20_TO_0.21.md) — Send Monitor, sharding, subscribers.
- [migration-0.19-to-0.20.md](migration-0.19-to-0.20.md) — legacy → declarative Monitor.
