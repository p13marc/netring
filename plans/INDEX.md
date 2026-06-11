# plans/ — netring 0.21 backlog

Forward-looking implementation plans only. Historical record lives in `CHANGELOG.md` + `git log`; reference material lives in `netring/docs/`. Convention: when a plan ships, **delete the plan file** in the same PR.

> **Scope split.** Flow & session tracking lives in the separate [`flowscope`](https://github.com/p13marc/flowscope) crate. flowscope's `plans/` covers flow extraction, tracking, reassembly, session/datagram parsing, observability of flows, and L7 parsers. This index covers only netring-side plans (capture, monitor builder, anomaly toolkit, sinks, sharding).

---

## netring 0.21 — phased plan

Each phase ships as 1–3 commits on a `0.21-dev` branch. The final phase tags + publishes.

| Phase | Plan | Scope | Days |
|---|---|---|---|
| **A** | [`netring-0.21-phase-A-ergonomics.md`](./netring-0.21-phase-A-ergonomics.md) | Ergonomics polish + R1–R6 regression fixes + `AnomalySink` key tightening (13 sub-items) | ~6.5 |
| **B** | [`netring-0.21-phase-B-sinks-exports.md`](./netring-0.21-phase-B-sinks-exports.md) | `EveSink` adapter, `MetricsSink`, re-export `OwnedAnomaly`/`KeyFields`/`AnomalyFields`/`DetectorScore` | ~1.5 |
| **C** | [`netring-0.21-phase-C-percpu-sharding.md`](./netring-0.21-phase-C-percpu-sharding.md) | Per-CPU sharding (`fanout_per_cpu`, `ShardedMonitor`, merge worker) | ~5 |
| **D** | [`netring-0.21-phase-D-robustness.md`](./netring-0.21-phase-D-robustness.md) | Build validation, graceful drain, layer-chain integration test, builder name | ~3 |
| **E** | [`netring-0.21-phase-E-pcap-source.md`](./netring-0.21-phase-E-pcap-source.md) | Pcap source via `DeferredDriverBuilder`, `with_speed_factor`, `run_until_idle` | ~1.5 |
| **F** | [`netring-0.21-phase-F-subscribe.md`](./netring-0.21-phase-F-subscribe.md) | `monitor.subscribe::<E>` wrapping `BroadcastSlotHandle` | ~1 |
| **G** | [`netring-0.21-phase-G-correlate-cleanup.md`](./netring-0.21-phase-G-correlate-cleanup.md) | Delete `netring::correlate`, re-export `flowscope::correlate` | ~1 |
| **H** | [`netring-0.21-phase-H-release.md`](./netring-0.21-phase-H-release.md) | flowscope 0.13 dep bump, `Monitor: Send` sweep, deprecations, version bump | ~3 |
| **I** | [`netring-0.21-phase-I-flowscope-bonus.md`](./netring-0.21-phase-I-flowscope-bonus.md) | Adopt `detect::patterns` (Port/Beacon/DGA), `detect::file`, ECH, `FlowStateMap`, `Event::tcp()` | ~2 |

**Total: ~24.5 working days.** Phases A, B, D, E, G, I are largely parallelizable. Phase C is the longest (sharding architecture) and depends on A.1 (the `Arc<dyn Fn>` handler-storage switch). Phase H is sequenced last.

### Cross-phase invariants

Enforced across every phase:

1. `cargo nextest run -p netring --features tokio,channel,flow,parse,pcap,metrics,http,dns,tls,icmp,emit` passes.
2. `cargo +stable clippy --workspace --all-targets --all-features -- -D warnings` clean.
3. `cargo fmt --check` clean.
4. `cargo test --doc` passes.
5. `benches/zero_alloc.rs` reads **Δ 0 bytes / Δ 0 blocks** per 100k synthetic events. Any future regression past 512 B / 100 blocks blocks the merge.
6. flowscope dependency floor: `>= 0.13.0`. Direct jump from 0.11.1 (skip 0.12).

### Dependency chain

- A.1 (`Arc<dyn Fn>` storage swap) → C (sharding needs cloneable handlers)
- A.10 (`OwnedAnomaly` re-export) → B (`EveSink` adapter uses upstream type)
- B (`EveSink`) → I (`pattern_detector!` macro emits through `EveSink`)
- E (pcap source) → I (`pcap_replay.rs` adoption example)
- G (correlate cleanup) → H (CHANGELOG entry)
- All phases → H (release prep)

### Backward compatibility

The user explicitly authorized backward-compat breaks for this cycle. Concrete breaks shipping:

| Break | Phase | Mitigation |
|---|---|---|
| `AnomalySink::write` key: `&dyn Debug` → `&dyn Key` (KeyFields + Debug) | A.13 | Custom sink impls update one method signature; existing `with_key(&fivetuple)` users unaffected (FiveTupleKey already implements both) |
| `AnomalyWriter::with_key<K>` bound: `K: Debug` → `K: Key` | A.13 | Same; blanket impl makes `Key` automatic for `KeyFields + Debug` types |
| `Monitor: Send` propagates (was `!Send` in 0.20) | H.2 | `#[tokio::main(flavor = "current_thread")]` becomes `#[tokio::main]`; user code unaffected |
| Legacy `ProtocolMonitor` / `AnomalyMonitor` / `AnomalyRule` gain `#[deprecated]` | H.3 | Removal in 0.22; one-cycle deprecation window |
| netring's `correlate.rs` deleted; re-export from flowscope | G | `pub use flowscope::correlate::*` — call sites unchanged |
| netring's `OwnedAnomaly` (in `shipped_sinks`) deleted; re-export from flowscope | A.10 | Path change only; struct fields/methods identical |
| `Cargo.toml` features: `ja3 + ja4 → tls-fingerprints`, `tracing-messages` removed | H.1 | Rename in downstream `Cargo.toml`s |
| `flowscope = "0.13"` from `0.11.1` (skip 0.12) | H.1 | Direct jump; flowscope 0.12 changes absorbed in one bump |

Migration recipes documented in `docs/MIGRATING_0.20_TO_0.21.md` (Phase H.6).

---

## Live reference

- [`upstream-tracking.md`](./upstream-tracking.md) — rustc / kernel / flowscope features being watched.

## Recently shipped (durable record in CHANGELOG)

| Crate | Status |
|---|---|
| netring **0.20** | shipped at `8555929`. Monitor builder + Handler trait + 5 layers + detector! macro + multi-interface + tick handlers. F.1+F.2 shipped; F.3 deferred to 0.21 Phase C. |
| netring **0.19** | flowscope 0.11.1 absorption (typed `Driver<E>` + `SlotHandle<M, K>`). |
| netring **0.18** | unified-driver refactor + heuristic routing + 4 flow demos. |
| netring **0.17** | flowscope 0.10 absorption (parser_kinds + DnsResolutionCache + serde feature). |

## Companion flowscope wishlists — both shipped

- Round 1 → flowscope 0.12.0 (`781595f → 1ed1228`): plans 122–127 + bonus 143, 144, 146.
- Round 2 → flowscope 0.13.0 (`2095f28 → 7735587`): plans 147–156. Headline: Plan 156 was a 1-line `+ Send` bound fix; `Driver<E>: Send + Sync` unconditional.

Wishlist files deleted per convention (shipped → not forward-looking). Recipes preserved in this INDEX + flowscope's CHANGELOG.

## Deferred (recorded so a future ask doesn't get re-litigated)

- **Bevy-style `MonitorParam`** — compile-time access validation. Deferred to 0.22; ctx.split_* covers most ergonomics.
- **VRL embedded DSL** — wrong altitude; netring users write Rust `detector!`.
- **`Send` Driver** — **RESOLVED upstream** in flowscope 0.13.0 (1-line fix).
- **JA4+ family / IPFIX / HTTP/2 / QUIC** — flowscope's strategic deferrals; netring inherits.
- **Per-flow `ctx.flow_state_mut::<T>()`** — **REACTIVATED** in Phase I.7 via flowscope's `FlowStateMap`.
- **Suricata-compatible rule DSL** — declined; Zeek/Suricata territory.
- **Encrypted-traffic ML detection** — out of scope; user-defined `Handler`s.

---

## Numbering

Phases are letters (A–I). Sub-items are numbered (A.1, A.2, …). New phases for 0.22+ start at the next free letter (J).
