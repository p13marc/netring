# Migrating netring 0.24 → 0.25

0.25 ("Subscriptions, Async Effects, Performance & TX") is **additive** —
existing 0.24 monitors compile unchanged. There is **one breaking type
change** (`FlowRecord.reason`) that only affects code reading flow-export
records, and one **dependency bump** (flowscope 0.16). This guide covers the
break, the bump, and what's worth adopting.

## Dependency

netring 0.25 requires **flowscope ≥ 0.16.0** (was 0.15). Pulled transitively —
no code change on your side. The bump moves **JA4S behind the opt-in `ja4plus`
feature** (FoxIO License 1.1); see the licensing note below.

## Breaking: `FlowRecord.reason` is now `Option<EndReason>`

If you registered a `FlowExporter` (`MonitorBuilder::export_flows`) and read
`record.reason`, it changed from `EndReason` to `Option<EndReason>`:

```rust
// 0.24
match record.reason { EndReason::Fin => …, _ => … }

// 0.25 — None means an ongoing active-timeout snapshot (W1c), Some means ended.
match record.reason {
    Some(EndReason::Fin) => …,
    None => { /* interim record, flow still alive */ }
    _ => …,
}
// or:
if record.is_ongoing() { /* active-timeout snapshot */ }
```

This enables interim records for long-lived flows
([active timeout](#new-active-timeout-flow-export-w1c)).

## Breaking (licensing): JA4S now needs the `ja4plus` feature

JA4S is part of the JA4+ suite under the **FoxIO License 1.1** (non-commercial;
patent pending), not MIT/Apache. `TlsFingerprint.ja4s` now exists only under the
opt-in **`ja4plus`** feature (off by default, excluded from the `monitor` /
`all-parsers` umbrellas). JA3 + JA4-client stay royalty-free in the default TLS
surface. If you used `fp.ja4s`, add `features = ["ja4plus"]` and review the
FoxIO licensing terms in `docs/FINGERPRINTS.md`. (This already shipped in
flowscope 0.16.)

Separately, the `tls` feature now correctly enables `flowscope/tls-fingerprints`,
so JA3 + JA4-client actually populate (they were silently always-`None` before).

## New: the subscription engine (Phase A)

The new front door. Typed tiers — `packet()` (every frame), `flow::<P>()`
(at flow end), `session::<P>()` (on L7 parse) — with per-subscription filters
that split into a kernel conjunction + a userspace remainder. `on::<E>` still
works (it's the natural handler spelling). See `docs/` and the architecture
notes; nothing in your 0.24 code needs to change to keep working.

## New: async read + effect handlers (Phase B)

`MonitorBuilder::on_effect::<E>(|payload, &Ctx| async move { … Ok(Effects…) })`
— read the `Ctx` synchronously, do async I/O, and return deferred `Effects`.
Fixes the "async handlers couldn't read `Ctx`" gap. `on_async` (payload-only)
remains for the simple case.

## New: active-timeout flow export (W1c)

```rust
use std::time::Duration;
let monitor = Monitor::builder()
    .interface("eth0").protocol::<Tcp>()
    .export_flows(|rec| { /* … */ })
    .export_active_timeout(Duration::from_secs(60)) // interim records every 60s
    .build()?;
```

## New: in-Monitor AF_XDP loader (W1a)

```rust
// One-call AF_XDP capture — no external XDP loader (feature `xdp-loader`):
Monitor::builder().xdp_interface_loaded("eth0").protocol::<Tcp>()…
```

If you were using `xdp_interface` + an out-of-band redirect program, that still
works; `xdp_interface_loaded` just removes the manual step.

## New: resilience knobs (W1e)

```rust
.backend_error_policy(BackendErrorPolicy::Reopen)  // reopen a flapped source
.catch_handler_panics(true)                        // + HandlerErrorPolicy::Isolate
```

## New: performance & scaling (Phase C)

- `ShardedRunner::new(iface, FanoutMode::Cpu, group, n_cores, build).pin_cpus(true)`
  pins each shard to its core. See `docs/PERFORMANCE.md` for the tuning levers
  and the dispatch-throughput benchmark.

## New: TX symmetry (Phase D)

```rust
use netring::{AsyncInjector, TxPacer};
let mut tx = AsyncInjector::open("eth0")?;
tx.send_stream(frames, Some(TxPacer::packets_per_second(10_000.0))).await?;

// Egress timestamps:
let inj = Injector::builder().interface("eth0").tx_timestamps(true).build()?;
// after send + flush: inj.read_tx_timestamp()
```

## New: AF_XDP UMEM tuning (W4)

```rust
XdpSocket::builder().interface("eth0").hugepages(true).numa_node(0)…
```

## New: heavy exporters in a companion crate (W5)

OTLP and Kafka anomaly export now live in **`netring-exporters`** (keeps the
core free of those dependency trees):

```toml
netring-exporters = { version = "0.1", features = ["otlp"] } # or "kafka"
```

```rust
use netring_exporters::OtlpAnomalySink;
Monitor::builder()…
    .sink(OtlpAnomalySink::new("http://localhost:4318/v1/logs", "netring"))
```

## Removed / renamed

Nothing removed. The compat surface from 0.24 (`interface()`, `on_async`,
`on::<E>`) is intact — 0.25 is additive apart from the two breaks above.
