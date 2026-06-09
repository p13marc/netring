# netring 0.20 — Phase G: Migration recipes + docs + release

**Effort:** 4–5 days
**Predecessor:** [`Phase F`](./netring-0.20-phase-F-percpu-sharding.md) — per-CPU sharding
**Successor:** none — this is the release

## 1. Goal

Land netring 0.20.0 on crates.io. The Monitor + Handler + Layer + macro + sharding work from Phases A–F is complete; this phase makes it usable:

- All 13 existing anomaly examples are rewritten in the new API.
- `examples/k8s_node_monitor.rs` from the redesign spec ships as a runnable file.
- `docs/MONITORING.md` replaces `WRITING_DETECTORS.md`.
- `docs/performance.md` documents the §7 perf contract.
- `docs/migration-0.19-to-0.20.md` walks users through every breaking change.
- `netring-compat` (companion crate) ships an `AnomalyRule → Handler` shim for one release.
- `CHANGELOG.md` final entry.
- 0.20.0 tagged + published.

The old `ProtocolMonitor` / `ProtocolMonitorBuilder` / `AnomalyMonitor` / `AnomalyRule` get **deleted** in this phase — the migration shim in `netring-compat` provides backward compat for one release.

## 2. Scope

### In
- Rewrite every existing detector example to use `Monitor::builder()` + `detector!` + `.on::<E>(...)`.
- Add `examples/k8s_node_monitor.rs` from the redesign spec §7.
- Add `examples/scaling/percpu_monitor.rs` demonstrating Phase F sharding.
- Delete `src/protocol/monitor.rs` (old builder), `src/protocol/event.rs` (old `ProtocolEvent` enum), and `src/anomaly/{monitor,rule,builtin}.rs` (old `AnomalyMonitor` / `AnomalyRule` / `FlowAnomalyRule`).
- Replace `src/protocol/event.rs` re-exports with the new event_typed types.
- `netring-compat` workspace member shipping `AnomalyRule → Handler` adapter.
- `docs/MONITORING.md` — new tutorial.
- `docs/performance.md` — perf contract for users.
- `docs/migration-0.19-to-0.20.md` — recipes for every breaking change.
- `CHANGELOG.md` final 0.20.0 entry.
- Version bump 0.19.0 → 0.20.0; tag; publish.
- `tests/api_stability.rs` snapshot of `cargo public-api` output.

### Out
- Further protocol additions — defer to 0.21+.
- AF_XDP per-CPU mode — defer.
- Documentation translation / formatting beyond markdown — handled by `cargo doc`.

## 3. Dependencies

- Phases A–F merged.
- `cargo-public-api` available locally (and in CI) for the API stability snapshot. Install via `cargo +stable install cargo-public-api --locked`; requires nightly toolchain installed (not active) for rustdoc JSON. In CI: `cargo public-api diff <base>..HEAD` is the current invocation; the older `--diff-git-checkouts` flag still works as an alias.
- `netring-compat` crate space available in the workspace (created in this phase).
- All existing examples build successfully on the new API (verified incrementally during Phases B–F).

## 4. Module layout

```
netring/
├── src/
│   ├── lib.rs                    M  — remove old anomaly/protocol exports; add monitor/ctx/layer/prelude
│   ├── anomaly/                  M
│   │   ├── mod.rs                M  — only export sink+severity+shipped_sinks
│   │   ├── builtin.rs            D  — FlowAnomalyRule deleted (migrated to handler in compat)
│   │   ├── monitor.rs            D  — AnomalyMonitor deleted
│   │   ├── rule.rs               D  — AnomalyRule trait deleted (lives in netring-compat)
│   │   └── compat.rs             D  — migration shim moves to netring-compat
│   ├── protocol/
│   │   ├── event.rs              D  — old ProtocolEvent enum deleted
│   │   ├── monitor.rs            D  — old ProtocolMonitorBuilder deleted
│   │   └── mod.rs                M  — only re-export Protocol/Dispatch/ParserKind/etc.
│   └── correlate/                  — unchanged
│
├── examples/
│   ├── anomaly/                  M  — all 13 rewritten
│   ├── flow/                     M  — rewritten where needed (top_n_flows, ewma_rate, etc.)
│   ├── l7/                       M  — full_monitor / multi_protocol_monitor rewritten
│   ├── k8s_node_monitor.rs       A  — the canonical multi-L4 scenario
│   └── scaling/percpu_monitor.rs A  — Phase F sharding demo
│
├── docs/
│   ├── MONITORING.md             A  — new detector tutorial (replaces WRITING_DETECTORS.md)
│   ├── performance.md            A  — §7 contract documented
│   └── migration-0.19-to-0.20.md A  — recipes
│
├── CHANGELOG.md                  M  — 0.20.0 entry
├── Cargo.toml                    M  — version 0.19.0 → 0.20.0
│
netring-compat/                   A  — new workspace member
├── Cargo.toml                    A
├── src/
│   └── lib.rs                    A  — AnomalyRule shim → Handler adapter
└── README.md                     A
```

**LoC estimates:** ~2000 LoC of example/test rewrites + ~600 lines of documentation + ~200 LoC `netring-compat`.

## 5. Detailed deliverables

### 5.1 Example rewrites

Each of the 13 existing detector examples gets a 30-50 line port. Pattern: convert `struct + impl AnomalyRule` to a `detector!` macro or to a closure + `.on::<E>(...)`.

Example diff for `dns_tunnel_detect.rs`:

```rust
// 0.19 — what's there today
struct DnsTunnelRule { threshold_bits: f64 }
impl AnomalyRule<FiveTupleKey> for DnsTunnelRule {
    fn name(&self) -> &'static str { "DnsTunnel" }
    fn observe(&mut self, evt, emit) { /* match + push */ }
}
let monitor = AnomalyMonitor::new().with_rule(DnsTunnelRule { threshold_bits: 4.0 });
```

```rust
// 0.20 — after rewrite
use netring::prelude::*;

let dns_tunnel = detector! {
    name: "DnsTunnel",
    severity: Warning,
    event: Dns,
    matches: |msg| matches!(msg, DnsMessage::Query(_)),
    emit: |msg, sink: Sink<()>, ts: Now| {
        let DnsMessage::Query(q) = msg else { return };
        for question in &q.questions {
            for label in question.name.split('.') {
                if label.len() < 16 { continue }
                let h = flowscope::detect::shannon_entropy(label.as_bytes());
                if h > 4.0 && flowscope::detect::is_base64ish(label) {
                    sink.begin("DnsTunnel", Severity::Warning, ts)
                        .with("label", label.to_string())
                        .with_metric("entropy_bits", h)
                        .emit();
                    return;
                }
            }
        }
    },
};

Monitor::builder()
    .interface("eth0")
    .protocol::<Dns>()
    .detect(dns_tunnel)
    .sink(StdoutJsonSink::default())
    .run_until_signal()
    .await?;
```

Effort per example: ~30 min if the port is mechanical, ~2 hours if the detector has nuanced state (e.g. `tls_to_unresolved_ip` with `DnsResolutionCache`). Total: 1.5–2 days for all 13.

### 5.2 `examples/k8s_node_monitor.rs`

This is the redesign spec's §7 example, verbatim. Copy from the redesign doc, verify it compiles, add to `Cargo.toml` `[[example]]` registration. ~90 LoC.

### 5.3 `examples/scaling/percpu_monitor.rs`

```rust
//! Per-CPU sharded monitor. Demonstrates Phase F's fanout API.
//!
//! Runs N AF_PACKET rings via PACKET_FANOUT_CPU; merges per-shard
//! HTTP request counters into a global accumulator every 10s.

use std::time::Duration;
use netring::prelude::*;

#[derive(Default, Clone)]
struct HttpStats { requests: u64, responses: u64 }

impl std::ops::AddAssign for HttpStats {
    fn add_assign(&mut self, o: Self) {
        self.requests += o.requests;
        self.responses += o.responses;
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "eth0".into());

    Monitor::builder()
        .fanout_per_cpu(iface, FanoutMode::Cpu)
        .protocol::<Http>()
        .state::<HttpStats>()
        .state_auto_merge::<HttpStats>()  // AddAssign-based merge
        .merge_interval(Duration::from_secs(10))
        .on::<Http>(|msg, stats: State<HttpStats>| {
            match msg {
                flowscope::http::HttpMessage::Request(_) => stats.requests += 1,
                flowscope::http::HttpMessage::Response(_) => stats.responses += 1,
            }
            Ok(())
        })
        .tick(Duration::from_secs(10), |_tick, stats: State<HttpStats>| {
            println!("requests={} responses={}", stats.requests, stats.responses);
            Ok(())
        })
        .run_until_signal()
        .await?;
    Ok(())
}
```

### 5.4 `netring-compat` workspace member

```
netring-compat/
├── Cargo.toml
└── src/lib.rs
```

`netring-compat/Cargo.toml`:

```toml
[package]
name = "netring-compat"
version = "0.20.0"
edition = "2024"
rust-version = "1.95"
description = "Backward-compatibility shim for netring 0.19 → 0.20"

[dependencies]
netring = { path = "../netring", version = "0.20" }
```

`netring-compat/src/lib.rs`:

```rust
//! `netring 0.19 → 0.20` compat shim. Deprecated; remove in
//! `netring 0.21`. Lets users with `AnomalyRule` impls plug into
//! the new `Monitor` builder without rewriting.

use std::sync::Arc;
use std::sync::Mutex;

use netring::ctx::{Ctx, Sink};
use netring::protocol::event_typed::Event;

#[deprecated(note = "AnomalyRule is replaced by Handler — see migration-0.19-to-0.20.md")]
pub trait AnomalyRule<K>: Send {
    fn name(&self) -> &'static str;
    fn observe(
        &mut self,
        evt: &netring::protocol::ProtocolEvent<K>,
        emit: &mut Vec<netring::anomaly::Anomaly<K>>,
    );
    fn on_tick(
        &mut self,
        _now: flowscope::Timestamp,
        _emit: &mut Vec<netring::anomaly::Anomaly<K>>,
    ) {}
}

/// Adapter — wraps an `AnomalyRule` so it can be registered via
/// `MonitorBuilder::on::<AnyEvent>(...)`.
///
/// `AnyEvent` is a catch-all event that fires for every event
/// the monitor sees. Costs one extra match per event compared
/// to native handlers. Use sparingly; migrate to native
/// `Handler<E, M>` for hot paths.
pub fn rule_as_handler<R: AnomalyRule<netring::protocol::FlowKey> + 'static>(
    rule: R,
) -> impl Fn(&AnyEvent, &mut Ctx<'_>) -> netring::error::Result<()> + Send + Sync {
    let rule = Arc::new(Mutex::new(rule));
    move |_evt: &AnyEvent, _ctx: &mut Ctx<'_>| {
        let _ = rule.lock();
        // The adapter delegates to the rule and forwards anomalies
        // to the sink. ~50 LoC.
        Ok(())
    }
}

/// Catch-all event — fires for every event netring delivers.
pub struct AnyEvent;
impl Event for AnyEvent {
    type Payload = AnyEvent;
}
```

The shim is ~150 LoC. Deprecation warnings point users at the migration guide.

### 5.5 Documentation

#### `docs/MONITORING.md` (~400 lines)

Replaces `WRITING_DETECTORS.md`. New table of contents:

1. The anatomy of a netring monitor
2. Protocol markers + the `Protocol` trait
3. Event types + typed handlers
4. The `Ctx` + extractors
5. The `detector!` macro for stateless rules
6. Cross-protocol detectors (the K8s scenario)
7. Composing with middleware (`DedupeAnomalies`, `MinSeverity`, …)
8. Output sinks
9. Testing detectors (synthetic event streams)
10. Production deployment (sharding, sinks, tuning)
11. Common false-positive patterns
12. MITRE ATT&CK mapping

Each section has code snippets that compile (doctest-friendly).

#### `docs/performance.md` (~150 lines)

Lifts §7 of the redesign spec into a standalone user-facing doc:
- The hot path is allocation-free
- Sync handlers are the default; async opt-in
- `Bytes`-based payload sharing
- The `Counter<K>` + `State<T>` extractors are zero-alloc
- The dhat-gated CI bench is the contract; users can reproduce locally
- When to use per-CPU sharding (>2 Mpps workloads)

#### `docs/migration-0.19-to-0.20.md` (~600 lines)

The big one. Section structure:

```
1. ProtocolMonitorBuilder → Monitor::builder
2. ProtocolEvent → typed event types (FlowStarted<P>, FlowEnded<P>, ...)
3. ProtocolMessage variant matches → .on::<P>(...) closures
4. AnomalyRule trait → Handler closure or detector! macro
5. AnomalyMonitor → Monitor (single struct)
6. Anomaly::new(...).with(...).emit() → sink.begin(...).with(...).emit()
7. FlowAnomalyRule → netring-compat adapter (deprecated)
8. ProtocolMonitor::next() Stream → Monitor::run_*()
9. Per-detector mechanical recipes (one per existing detector)
10. Scaling beyond single CPU — fanout_per_cpu
```

Each section has before/after code blocks. Estimated 30–40 hours of writing to get right.

### 5.6 CHANGELOG entry

```markdown
## 0.20.0 — Monitor redesign: protocol-agnostic Handler trait + dispatcher

The big one. Replaces `ProtocolMonitor` / `AnomalyMonitor` /
`AnomalyRule` with `Monitor::builder()` + `Handler<E, M>` +
`AnomalySink` + tower-style layers. Protocol-agnostic via the
`Protocol` trait; zero-allocation hot path verified by a dhat
benchmark in CI; ~22–30 working days of work behind it.

### Breaking — full surface

- `ProtocolMonitorBuilder` / `ProtocolMonitor` deleted; replaced
  by `Monitor::builder()`. Migration guide:
  docs/migration-0.19-to-0.20.md
- `ProtocolEvent<K>` enum deleted; replaced by typed events
  `FlowStarted<P>`, `FlowEnded<P>`, `FlowEstablished<P>`,
  `AnyFlowAnomaly`, `Tick` (plus the protocol marker itself as
  an event type for L7 messages).
- `ProtocolMessage` enum deleted; protocol messages now arrive
  as typed `&P::Message` to `.on::<P>(|msg| ...)` handlers.
- `AnomalyRule<K>` trait + `AnomalyMonitor` struct deleted; use
  `netring-compat` for the shim (deprecated; remove in 0.21).
- `Anomaly<K>` struct deleted; sinks receive rendered fields
  directly via `AnomalySink::write`. Handlers emit via
  `sink.begin(...).with(...).emit()`.

### Added

- `Monitor::builder()` with `bon`-derived typestate.
- `Protocol` trait + 7 builtin markers (`Tcp`, `Udp`, `Icmp`,
  `Http`, `Dns`, `Tls`, `TlsHandshake`) + extensible by
  downstream crates.
- `Handler<E, M>` + `AsyncHandler<E, M>` traits with axum-style
  blanket impls for 0..8 extractors.
- `Ctx<'a>` + `FromCtx` trait + `State<T>`, `Sink<A>`, `Now`,
  `Counter<K>` extractors.
- `Ctx::split_state_sink` etc. for disjoint-borrow handlers.
- `AnomalySink` + `AnomalyWriter` (ArrayVec inline storage,
  `Cow<'static, str>` observations).
- 4 shipped sinks: `StdoutSink`, `StdoutJsonSink`, `TracingSink`,
  `ChannelSink`.
- 5 shipped layers: `DedupeAnomalies`, `RateLimitAnomalies`,
  `MinSeverity`, `Sample`, `Tee`.
- `detector!` declarative macro.
- `netring::prelude` module.
- `Monitor::builder().interfaces([...])` multi-interface.
- `Monitor::builder().fanout_per_cpu(...)` per-CPU sharding.
- `Monitor::builder().merge_state::<T>(...)` cross-shard state merging.
- `Monitor::builder().shutdown()` graceful termination using
  flowscope 0.11.1's `force_close_into`.
- `benches/zero_alloc.rs` dhat-gated regression test; CI gate
  enforces ≤512 B / 100k events.
- `monitor` Cargo feature umbrella.

### Removed (without compat shim)

- `BpfFilter`-based per-protocol filtering on ProtocolMonitorBuilder
  — was 0.18 → 0.19 cleanup; the new Monitor doesn't need it.
- Other internal helpers tied to the old Driver<E, M> shape.

### Documentation

- `docs/MONITORING.md` (new — replaces WRITING_DETECTORS.md).
- `docs/performance.md` (new).
- `docs/migration-0.19-to-0.20.md` (new — per-detector recipes).
- All 13 anomaly examples rewritten.
- New `examples/k8s_node_monitor.rs` + `examples/scaling/percpu_monitor.rs`.

### Tests

- 380+ unit + integration tests passing.
- `tests/api_stability.rs` snapshot via `cargo public-api`.
- miri-tested `Ctx::split_*` safety.
- dhat-gated zero_alloc bench in CI.
```

### 5.7 `tests/api_stability.rs`

```rust
//! Snapshot of `cargo public-api` output. Failures here block
//! merges until the snapshot is intentionally updated.

#[test]
fn public_api_unchanged() {
    let api = cargo_public_api::Builder::from_root(env!("CARGO_MANIFEST_DIR"))
        .build()
        .unwrap();
    let snapshot = include_str!("api_stability_snapshot.txt");
    assert_eq!(api.to_string(), snapshot);
}
```

The snapshot is checked in. Any intentional public API change requires updating it; clear signal in PRs.

### 5.8 Version bump + release process

In Phase G's final commit:

```bash
# Bump version
sed -i 's/^version = "0.19.0"/version = "0.20.0"/' netring/Cargo.toml

# Verify
cargo build --features monitor
cargo nextest run -p netring --features monitor
cargo +stable clippy --all-targets --features monitor -- -D warnings
cargo fmt --check
cargo test --doc --features monitor
cargo bench --features bench-zero-alloc,monitor --bench zero_alloc

# Tag
git commit -am "netring 0.20.0: monitor redesign release"
git tag -a 0.20.0 -m "netring 0.20.0 — monitor redesign"

# Publish (only after user approval)
cargo publish -p netring-compat  # publish shim FIRST
cargo publish -p netring         # then the main crate
git push origin master
git push origin 0.20.0
```

## 6. Tests

In addition to the new `api_stability.rs`:

- All 13 rewritten examples build (`cargo build --examples --features monitor`).
- `examples/k8s_node_monitor.rs` builds + a smoke test runs against a pcap source.
- `examples/scaling/percpu_monitor.rs` builds.
- `netring-compat` builds independently + its lone unit test passes.
- dhat bench still passes.
- Pre-existing 370+ tests from Phases A–F all pass.
- New test count: ~390+.

## 7. Acceptance criteria

- [ ] All Phase A–F deliverables are merged.
- [ ] All 13 detector examples rewritten in the new API.
- [ ] `examples/k8s_node_monitor.rs` + `examples/scaling/percpu_monitor.rs` ship.
- [ ] `cargo build --features monitor` clean.
- [ ] `cargo nextest run --features monitor` passes.
- [ ] `cargo +stable clippy --all-targets --features monitor -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
- [ ] `cargo test --doc --features monitor` passes.
- [ ] `cargo bench --features bench-zero-alloc,monitor --bench zero_alloc` passes.
- [ ] `tests/api_stability.rs` snapshot committed.
- [ ] `docs/MONITORING.md` complete; doctest snippets compile.
- [ ] `docs/performance.md` complete.
- [ ] `docs/migration-0.19-to-0.20.md` complete with per-detector recipes.
- [ ] `CHANGELOG.md` 0.20.0 entry complete.
- [ ] `netring-compat` builds + its `AnomalyRule → Handler` adapter compiles.
- [ ] Version bumped to 0.20.0 in `Cargo.toml`.
- [ ] Tag `0.20.0` created locally.
- [ ] **User-approved before publishing to crates.io.**

## 8. Risks + mitigations

1. **Massive example rewrite is tedious and error-prone.**
   Mitigation: process one example per commit, test independently, peer-review the migration. The compat shim provides a safety net — if a user's detector doesn't fit the new API cleanly, they can use the shim for one release.

2. **`docs/migration-0.19-to-0.20.md` will be huge.**
   ~600 lines. Mitigation: structure it as before/after code blocks per detector, not prose. Users skim for the recipe they need.

3. **`tests/api_stability.rs` requires `cargo-public-api`.**
   May need to install it: `cargo install cargo-public-api`. Document in CI setup.

4. **`netring-compat` increases workspace complexity.**
   It's small (~150 LoC) and one-release. Document the deletion timeline (remove in 0.21) prominently in its README and Cargo.toml description.

5. **Publishing two crates in lockstep.**
   `netring-compat` must publish first (since it depends on `netring`). The release script enforces ordering. If publishing fails mid-way, the partial publish is recoverable (just retry).

6. **A latent bug found post-release.**
   Hotfix as 0.20.1 within hours. Document the rollback procedure (yank from crates.io + emergency patch).

## 9. Estimated effort + commit shape

**Total: 4–5 working days.** Spread:
- 1.5 days: example rewrites (~13 examples × 30–60 min each).
- 0.5 day: `examples/k8s_node_monitor.rs` + `examples/scaling/percpu_monitor.rs`.
- 0.5 day: `netring-compat` shim.
- 1 day: documentation writing (MONITORING.md + performance.md + migration guide).
- 0.5 day: API stability snapshot + final review.
- 0.5 day: release process + tag + (after approval) publish.

**Commits (~8):**

- `netring 0.20 (G.1): rewrite anomaly examples (1–4)` — first 4 detectors.
- `netring 0.20 (G.2): rewrite anomaly examples (5–9)` — next 5.
- `netring 0.20 (G.3): rewrite anomaly examples (10–13) + flow + l7 examples`
- `netring 0.20 (G.4): examples/k8s_node_monitor.rs + scaling/percpu_monitor.rs`
- `netring 0.20 (G.5): docs/MONITORING.md + docs/performance.md`
- `netring 0.20 (G.6): docs/migration-0.19-to-0.20.md`
- `netring 0.20 (G.7): netring-compat workspace member + AnomalyRule shim`
- `netring 0.20 (G.8): version bump 0.19.0 → 0.20.0 + tag + CHANGELOG.md`

## 10. Cross-phase notes

- This is the end of the 0.20 work. After G.8, master is at 0.20.0; the 0.20-dev branch is folded in.
- Post-release: open `plans/netring-0.21-roadmap.md` for the next cycle. Candidates: `netring-compat` removal, AF_XDP per-CPU sharding, additional `Protocol` markers (QUIC, HTTP/2), plugin auto-discovery (start with `linkme` for static-link zero-overhead; document the no-`dlopen` constraint; escalate to `inventory` only if dynamically-loaded shared-object plugins become a requirement), columnar event batching.
- The dhat bench moves from "new" to "live invariant"; future PRs that regress it are blocked by CI.
- `tests/api_stability.rs` becomes the canary for the post-1.0 API; intentional changes get a CHANGELOG entry + snapshot update.

Ready to execute once Phase F is merged.
