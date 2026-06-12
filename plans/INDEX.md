# plans/ — netring backlog

Forward-looking implementation plans only. Historical record lives in `CHANGELOG.md` + `git log`; reference material lives in `netring/docs/`. Convention: when a plan ships, **delete the plan file** in the same PR.

> **Scope split.** Flow & session tracking lives in the separate [`flowscope`](https://github.com/p13marc/flowscope) crate. flowscope's `plans/` covers flow extraction, tracking, reassembly, session/datagram parsing, observability of flows, and L7 parsers. This index covers only netring-side plans (capture, monitor builder, anomaly toolkit, sinks, sharding).

---

## Current

| Plan | Scope | Status |
|---|---|---|
| [`netring-0.21-release-gates.md`](./netring-0.21-release-gates.md) | Version bump + `netring/CLAUDE.md` refresh + tag + publish. The four release-gate items the user explicitly held back. | Held pending user trigger |
| [`netring-0.22-roadmap.md`](./netring-0.22-roadmap.md) | Legacy 0.19 API deletion + Phase C deferrals (merge worker, `LayerSpec`) + Phase G follow-up (re-export `KeyIndexed` once flowscope ships `drain_expired`) | Pending 0.21.0 tag |
| [`upstream-tracking.md`](./upstream-tracking.md) | rustc / kernel / flowscope features being watched | Live |

## Recently shipped (durable record in CHANGELOG)

| Crate | Status |
|---|---|
| netring **0.21** | 28 commits on `0.21-dev`. Phases A–I complete; release gates held. Send Monitor, ShardedRunner, subscribe::<P>(), pcap replay, run_until_idle, drain phase, flow_state, pattern_detector!, EveSink + MetricsSink, build-time validation. CHANGELOG entry drafted; tag/publish pending. |
| netring **0.20** | shipped at `8555929`. Monitor builder + Handler trait + 5 layers + detector! macro + multi-interface + tick handlers. F.1+F.2 shipped; F.3 → 0.21 Phase C. |
| netring **0.19** | flowscope 0.11.1 absorption (typed `Driver<E>` + `SlotHandle<M, K>`). |
| netring **0.18** | unified-driver refactor + heuristic routing + 4 flow demos. |
| netring **0.17** | flowscope 0.10 absorption (parser_kinds + DnsResolutionCache + serde feature). |

## Companion flowscope wishlists — both shipped

- Round 1 → flowscope 0.12.0 (`781595f → 1ed1228`): plans 122–127 + bonus 143, 144, 146.
- Round 2 → flowscope 0.13.0 (`2095f28 → 7735587`): plans 147–156. Headline: Plan 156 was a 1-line `+ Send` bound fix; `Driver<E>: Send + Sync` unconditional.

Wishlist files deleted per convention (shipped → not forward-looking). Recipes preserved here + in flowscope's CHANGELOG.

---

## 0.21 cycle retrospective (informational)

The 0.21 cycle ran as 9 phase plans (A–I) plus an audit-fix
batch. Each plan was deleted on ship; the post-audit gap items
(`AnomalyFields` re-export, `Tee::factory`, `pcap_speed_factor`,
`futures_core::Stream for EventStream`) folded into one
follow-up commit `d51e763` and don't have their own plan file
because they re-target items the phase plans already specified.

Cross-phase invariants enforced through every commit:

1. `cargo nextest run -p netring --features monitor-quickstart` passes
2. `cargo +stable clippy -p netring --features monitor-quickstart --all-targets -- -D warnings` clean
3. `cargo fmt --check` clean
4. `cargo test --doc` passes
5. `benches/zero_alloc.rs` reads **Δ 0 bytes / Δ 0 blocks** per 100k synthetic events
6. flowscope dep floor: `>= 0.13.0`

These invariants carry forward to 0.22+ unless explicitly relaxed.

### Backward compatibility breaks shipped in 0.21

| Break | Mitigation |
|---|---|
| `AnomalySink::write` key: `&dyn Debug` → `&dyn Key` (KeyFields + Debug) | Custom sink impls update one method signature; existing `with_key(&fivetuple)` users unaffected (FiveTupleKey already implements both) |
| `AnomalyWriter::with_key<K>` bound: `K: Debug` → `K: Key` | Same; blanket impl makes `Key` automatic for `KeyFields + Debug` types |
| `Monitor: Send` propagates (was `!Send` in 0.20) | `#[tokio::main(flavor = "current_thread")]` becomes `#[tokio::main]`; user code unaffected |
| Legacy `ProtocolMonitor` / `AnomalyMonitor` / `AnomalyRule` gain `#[deprecated]` | Removal in 0.22; one-cycle deprecation window |
| netring's `correlate::TimeBucketedCounter` deleted; re-export from flowscope | `pub use flowscope::correlate::*` — call sites change `::new(window, bucket)` → `::new_unbounded(window, bucket)` |
| netring's `OwnedAnomaly` re-exported from flowscope | Path change only; struct fields/methods identical |
| `flowscope = "0.13"` from `0.11.1` (skipping 0.12) | Direct jump; flowscope 0.12 changes absorbed in one bump |
| `ProtocolSlot: Send` supertrait | Required to make Monitor Send; no impact on user code (no public ProtocolSlot impls) |

Full migration recipes: `docs/MIGRATING_0.20_TO_0.21.md`.

## Deferred to 0.22+ (recorded so a future ask doesn't get re-litigated)

- **Bevy-style `MonitorParam`** — compile-time access validation. `ctx.split_*` covers most ergonomics.
- **VRL embedded DSL** — wrong altitude; netring users write Rust `detector!` / `pattern_detector!`.
- **JA4+ family / IPFIX / HTTP/2 / QUIC** — flowscope's strategic deferrals; netring inherits.
- **Suricata-compatible rule DSL** — declined; Zeek/Suricata territory.
- **Encrypted-traffic ML detection** — out of scope; user-defined `Handler`s.

Active 0.22 items live in [`netring-0.22-roadmap.md`](./netring-0.22-roadmap.md).

---

## Numbering

0.21 phases used letters (A–I). 0.22+ uses descriptive slugs ("legacy-delete", "merge-worker", "layer-spec") because the cycle is more list-of-discrete-items than phased delivery.
