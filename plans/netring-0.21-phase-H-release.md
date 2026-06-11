# netring 0.21 Phase H — Release prep

## 1. Summary

Bump flowscope to 0.13.0 (direct jump from 0.11.1), absorb its breaking changes, sweep the `current_thread` flavor + `LocalSet` recipe out of every example, deprecate the legacy `ProtocolMonitor` / `AnomalyMonitor` / `AnomalyRule` surface, write the migration doc, tag + publish.

User explicitly authorized backward-compat breaks for this cycle.

## 2. Status

Not started. Last phase on the `0.21-dev` branch; depends on all prior phases.

## 3. Prerequisites

- Phases A through G complete.

## 4. Out of scope

- Removing the deprecated legacy API. `#[deprecated]` only in 0.21; removal in 0.22 per the original 0.20.0 plan.
- Publishing `netring-compat` shim. The 0.20.0 plan deferred this; absent a consumer asking, defer further.

## 5. Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `Cargo.toml` | `flowscope = "0.13"` (was `0.11`); version bump `0.21.0`; feature renames |
| Modify | `src/protocol/monitor.rs` | `#[deprecated(since = "0.21.0", note = "use Monitor::builder() from netring::monitor")]` on `ProtocolMonitor` / `ProtocolMonitorBuilder` |
| Modify | `src/anomaly/monitor.rs` | Same on `AnomalyMonitor` |
| Modify | `src/anomaly/rule.rs` | Same on `AnomalyRule` trait |
| New | `docs/MIGRATING_0.20_TO_0.21.md` | Side-by-side migration recipes |
| Modify | `examples/anomaly/*.rs` (12 files) | Optional: rewrite under the new API where the flowscope 0.12/0.13 bonus features apply (already partially in Phase I) |
| Modify | All examples — drop `#[tokio::main(flavor = "current_thread")]` → `#[tokio::main]` |
| Delete | `examples/monitor/multi_thread_localset.rs` (planned) | Never written; remove from the example index |
| New | `examples/monitor/multi_thread_default.rs` | Show the clean shape: `tokio::main` + `monitor.run_for()` with no flavor restriction |
| Modify | `CHANGELOG.md` | Comprehensive 0.21.0 entry |
| Modify | `README.md` | Update Monitor API section if helpful |
| Modify | `netring/CLAUDE.md` | Update module map + Recent additions |

## 6. API

### H.1 — flowscope 0.13 dep bump

```toml
# Cargo.toml
[dependencies]
flowscope = { version = "0.13", default-features = false }
```

Feature changes that ripple:
- `ja3` + `ja4` → `tls-fingerprints`. Rename in netring's feature passthroughs.
- `tracing-messages` removed.
- New optional features available: `emit-eve` (Phase B.2), `file-hash` (Phase I.4), `chrono` (Phase B if EveSink's ISO 8601 timestamps need chrono interop; default is alloc-free).

`Error::Module::Pipeline` removed upstream — netring maps to `Error::Module::Driver` if any internal mapping referenced it.

### H.2 — `Monitor: Send` sweep

flowscope 0.13.0's `Driver<E>: Send + Sync` propagates. netring's `Monitor` becomes `Send` for free. Every example loses the `flavor = "current_thread"` restriction:

```rust
// Before:
#[tokio::main(flavor = "current_thread")]
async fn main() { … }

// After:
#[tokio::main]
async fn main() { … }
```

Files touched (16 examples): all four `examples/monitor/*.rs` + the 12 `examples/anomaly/*.rs`.

Add a `static_assertions::assert_impl_all!(Monitor: Send);` compile-time check in `tests/monitor_send.rs`.

### H.3 — Deprecations

```rust
// src/protocol/monitor.rs
#[deprecated(since = "0.21.0", note = "Use `netring::monitor::Monitor::builder()` instead. This type will be removed in netring 0.22.")]
pub struct ProtocolMonitor<K> { … }

#[deprecated(since = "0.21.0", note = "Use `MonitorBuilder` instead. This type will be removed in netring 0.22.")]
pub struct ProtocolMonitorBuilder { … }
```

Same on `AnomalyMonitor` + `AnomalyRule`. Each gets a `note:` pointing to the corresponding `Monitor::builder` recipe.

### H.4 — `monitor-quickstart` feature aggregate

```toml
# Cargo.toml
[features]
monitor-quickstart = [
    "tokio", "channel", "flow", "parse", "pcap", "metrics",
    "http", "dns", "tls", "icmp", "emit",
    "tls-fingerprints",   # renamed from ja3 + ja4
    "eve-sink",           # Phase B.2
    "metrics-sink",       # Phase B.3
]
```

Examples that previously specified individual features point to the aggregate.

### H.5 — `multi_thread_default.rs`

```rust
//! Demonstrates that netring 0.21's Monitor is `Send`, so a single Monitor
//! can run on the default multi-thread tokio runtime without `LocalSet`.

use netring::prelude::*;

#[tokio::main]  // multi-thread default
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let monitor = Monitor::builder()
        .interface("eth0")
        .protocol::<Tcp>()
        .on::<FlowStarted<Tcp>>(|evt| {
            println!("flow started: {:?}", evt.key);
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?;

    monitor.run_until_signal().await
}
```

### H.6 — `docs/MIGRATING_0.20_TO_0.21.md`

Sections:
1. **Headline change: `Monitor` is now `Send`.** Drop the flavor restriction.
2. **Handler registration**: `.on::<E, _, _>` → `.on::<E>` / `.on_ctx::<E>`. Old form `#[deprecated]`.
3. **Anomaly emission**: `ctx.sink_mut().begin(kind, sev, ts).…` → `ctx.emit(kind, sev).…`.
4. **Multi-borrow handlers**: link to `ctx.split_state_sink` etc.
5. **EVE JSON output**: `EveSink::new(stdout, EveOptions::default())`.
6. **Per-CPU sharding**: `MonitorBuilder::fanout_per_cpu(iface, FanoutMode::Cpu)` + `merge_state::<T>`.
7. **Pcap replay**: `MonitorBuilder::pcap_source(path)`.
8. **Streaming subscribers**: `Monitor::subscribe::<E>()` for session protocols.
9. **flowscope 0.12 + 0.13 breaking changes that propagate**: `ja3+ja4 → tls-fingerprints`, `tracing-messages` removal, infallible `Timestamp → chrono`, `KeyFields/AnomalyFields` split.
10. **Legacy API deprecation timeline**: `ProtocolMonitor` / `AnomalyMonitor` / `AnomalyRule` removed in 0.22.

## 7. Implementation steps

1. **H.1** — bump `flowscope = "0.13"`. Run `cargo build` and fix every breakage:
   - `ja3 + ja4` → `tls-fingerprints` feature rename in `Cargo.toml` + `--features` args in `[[example]]` blocks and CI.
   - Drop `tracing-messages` feature.
   - Drop any `.try_into().unwrap()` on `Timestamp → chrono`.
   - `AnomalyFields` → `KeyFields + AnomalyFields` split (re-export both from `crate::anomaly`).
   - `Error::Module::Pipeline` → `Error::Module::Driver`.
2. **H.2** — sweep `#[tokio::main(flavor = "current_thread")]` → `#[tokio::main]` across all 16 examples. Add `assert_impl_all!(Monitor: Send)` test.
3. **H.3** — apply `#[deprecated]` to the legacy types with migration recipes in the `note:`.
4. **H.4** — add `monitor-quickstart` aggregate to `Cargo.toml`.
5. **H.5** — write `multi_thread_default.rs`.
6. **H.6** — write the migration doc.
7. **H.7** — CHANGELOG entry covering every phase's user-facing changes.
8. **H.8** — update `netring/CLAUDE.md` Recent additions block + module map.
9. **H.9** — `cargo nextest run --features monitor-quickstart` full suite green.
10. **H.10** — version bump in `Cargo.toml` to `0.21.0`.
11. **H.11** — `git tag 0.21.0` (no `v` prefix per project convention).
12. **H.12** — **DO NOT `cargo publish`** without explicit user approval. Tag locally; user decides when to push and publish.

## 8. Tests

- `tests/monitor_send.rs` — `static_assertions::assert_impl_all!(Monitor: Send);`. Compile-time only.
- Full nextest suite + clippy + fmt + doc tests + zero-alloc bench all green.
- Migration doc cross-checked by porting one legacy example by hand using only the doc.

## 9. Acceptance criteria

- `cargo build --all-features --all-targets` clean.
- `cargo +stable clippy --workspace --all-targets --all-features -- -D warnings` clean.
- `cargo fmt --check` clean.
- Test count comparable to 0.20.0 plus the new Phase A/B/D/E/F/G/I tests.
- `cargo publish --dry-run` clean (do NOT publish).
- Tag `0.21.0` created locally.
- `docs/MIGRATING_0.20_TO_0.21.md` reads cleanly + tested by manual port of one example.

## 10. Risks

- **R1 — Hidden user `flavor` dependency.** Some downstream users may have customized their `tokio::main` invocation around netring's `!Send` constraint (e.g., used `LocalSet` deliberately). The migration doc spells out the change. Their workarounds keep working — `LocalSet` is additive, not exclusive.
- **R2 — flowscope feature rename ripples.** `ja3 + ja4 → tls-fingerprints` affects CI matrix entries. Grep `--features` across `.github/workflows/`, `Cargo.toml`, and `[[example]]` blocks.
- **R3 — `Error::Module::Pipeline` cascade.** Any external code matching on this variant breaks. The 0.20 audit suggests netring doesn't expose `Error::Module` in any return type — verify.
- **R4 — Version-bump-without-publish race.** No real risk; just don't push the tag or publish until user explicitly approves.

## 11. Effort

- LoC delta: -100 (deletions from `flavor` sweep + correlate cleanup) + 300 (migration doc) + 50 (deprecation annotations) + 100 (CHANGELOG) ≈ +350 net.
- Time estimate: **~3 days**.

## 12. Provenance

- §5 table (flowscope 0.13 dep bump + breaking-change sweep).
- §2.4 (`Monitor: !Send`) → H.2 (resolved upstream; sweep is the user-facing follow-through).
- Original 0.20 Phase G deferred items: H.6 (migration doc), H.3 (deprecations).
- §3.7 (`multi_thread_localset.rs`) — superseded by H.5 (`multi_thread_default.rs`).
- §2.16 (`monitor-quickstart` aggregate) → H.4.
