# netring docs

All netring documentation lives in this one tree (`netring/docs/`). The repo root
`docs/` is a symlink here, so `docs/X.md` links resolve from both the crate
(docs.rs / crates.io) and the repo root (GitHub).

## Guides
- [FEATURES.md](FEATURES.md) — the Cargo feature graph (axes, recipes, couplings).
- [CRATE_BOUNDARY.md](CRATE_BOUNDARY.md) — the netring ↔ flowscope contract.
- [ARCHITECTURE.md](ARCHITECTURE.md) — system design, lifetime model, ring layout.
- [BACKENDS.md](BACKENDS.md) — the `AnyBackend` capture-backend design (AF_PACKET / AF_XDP / pcap / io_uring seam).
- [API_OVERVIEW.md](API_OVERVIEW.md) — types, methods, configuration.
- [ASYNC_GUIDE.md](ASYNC_GUIDE.md) — tokio patterns, Send rules, Monitor on multi-thread.
- [WRITING_DETECTORS.md](WRITING_DETECTORS.md) — `detector!` / `pattern_detector!` tutorial.
- [FINGERPRINTS.md](FINGERPRINTS.md) — TLS fingerprinting (JA3 / JA4 / JA4S), `on_fingerprint`, licensing.
- [discoverability.md](discoverability.md) — the Monitor toolkit by use case.
- [scaling.md](scaling.md) — fan-out capture, `FanoutMode` matrix, anti-patterns.
- [TUNING_GUIDE.md](TUNING_GUIDE.md) — performance profiles, system tuning.
- [PERFORMANCE.md](PERFORMANCE.md) — capture-vs-dispatch split, the dispatch-throughput bench, tuning levers, real-NIC methodology (0.25).
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — common errors and fixes.

The **0.25 subscription engine** (`packet()`/`flow::<P>()`/`session::<P>()` +
`.expr()`) is shown in `examples/monitor/subscriptions.rs`; the heavy OTLP/Kafka
exporters live in the [`netring-exporters`](../../netring-exporters) crate.

## Quality / internals
- [METRICS.md](METRICS.md) — every `netring_*` metric (capture gauges/counters, anomalies) + cardinality notes.
- [MIRI.md](MIRI.md) — miri + fuzzing strategy and the Stacked-vs-Tree-Borrows note.
- [AF_XDP.md](AF_XDP.md) — the AF_XDP backend: modes, rings, the program loader, multi-queue capture, steering.

## Migration guides
- [MIGRATING_0.26_TO_0.27.md](MIGRATING_0.26_TO_0.27.md) — the 1.0 API sweep (`#[non_exhaustive]` enums/output structs, sealed L7 markers), the `Capture::packets()` lending iterator, flowscope 0.19; plus the opt-in NSM stack (threat-intel, YARA, Sigma, OCSF, p0f, QUIC, asset inventory, ML export).
- [MIGRATING_0.24_TO_0.25.md](MIGRATING_0.24_TO_0.25.md) — subscriptions, async effects, TX symmetry, exporters crate; the one break (`FlowRecord.reason` → `Option`) + JA4S `ja4plus` gating.
- [MIGRATING_0.23_TO_0.24.md](MIGRATING_0.23_TO_0.24.md) — telemetry/health, exporters, JA4/JA4S, AF_XDP-in-Monitor (additive).
- [MIGRATING_0.22_TO_0.23.md](MIGRATING_0.22_TO_0.23.md) — `Send` run-loop future.
- [MIGRATING_0.21_TO_0.22.md](MIGRATING_0.21_TO_0.22.md) — typed roles, flat `FlowPacket`, ops toolkit.
- [MIGRATING_0.20_TO_0.21.md](MIGRATING_0.20_TO_0.21.md) — Send Monitor, sharding, subscribers.
- [migration-0.19-to-0.20.md](migration-0.19-to-0.20.md) — legacy → declarative Monitor.
