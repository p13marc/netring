# netring 0.20 — phased implementation plans (INDEX, post-ship)

**Date:** 2026-06-09
**Status:** Phases A–E + G shipped in netring 0.20.0. Phase F deferred to 0.21+.

## Shipped — netring 0.20.0

The six shipped phase plans were deleted on ship per the
"delete on ship" convention. Their landed shape lives in
`CHANGELOG.md` (the 0.20.0 entry) and the source tree.

| # | Phase | Outcome | Commit shape |
|---|---|---|---|
| A | `Protocol` trait + `Event` types + 7 builtin markers | shipped 0.20 | A.1, A.2, A.3, A.4 |
| B | `Handler` + `Ctx` + `Dispatcher` + `Monitor` skeleton | shipped 0.20 | B.1, B.2, B.3, B.4 |
| C | `AnomalySink` + `AnomalyWriter` + 4 sinks + `split_*` + dhat bench + dhat CI gate | shipped 0.20 | C.1, C.2, C.3 |
| D | `AsyncHandler` (payload-only) + `Layer` trait (netring-internal) + 5 layers | shipped 0.20 | D.1, D.2 |
| E | `detector!` macro + `netring::prelude` + `monitor` umbrella Cargo feature | shipped 0.20 | E |
| G | 0.20.0 release prep — CHANGELOG, migration guide, version bump | shipped 0.20 | G |

### Deviations from the original plans (all documented in shipped code)

- **A.4** — `Protocol::parser()` returning `Box<dyn SessionParser>`
  couldn't satisfy flowscope's `P: SessionParser + Clone + Send`
  bound. Replaced with `Protocol::register(builder)` so the impl
  drives flowscope's typed builder with the concrete parser
  type. Documented in `src/protocol/mod.rs:80–88` rustdoc and
  CHANGELOG.
- **B** — Multi-extractor (0..=8 arity) blanket impls don't
  compose in sync Rust (sequential `&mut Ctx` borrows alias).
  Shipped two arities — `PayloadOnly` and `PayloadCtx` — and
  recovered the ergonomics via methods on `Ctx`
  (`state_mut::<T>()`, `counter_mut::<K>()`, `sink_mut()`).
  Documented in `src/ctx/mod.rs:19–31` and
  `src/monitor/handler.rs:10–17`.
- **C** — Single `Severity` enum reused from
  `src/anomaly/rule.rs` instead of a fresh `severity.rs` file
  (no duplication). `begin(...)` lives on
  `impl dyn AnomalySink + '_` and the blanket `AnomalySinkExt`
  trait — works through trait objects (layered chains) AND
  typed sinks. Both per Phase C plan §5.2 §6.
- **D** — Payload-only `AsyncHandler<E>` instead of multi-extractor
  `AsyncHandler<E, M>` (same borrow-checker limitation as B).
  Netring-internal `Layer` trait instead of `tower::Layer`
  re-export (avoids the tower dep; sanctioned by Phase D plan
  §8 Risk #3). Both documented in CHANGELOG.
- **E** — `detector!` macro grammar adapted to the ctx-method API
  (`|payload, ctx| body` not the FromCtx extractor form). Macro
  returns a typed `Detector<E, F>` wrapper so `.detect(d)`
  infers `E` without turbofish. Documented in
  `src/detector_macro.rs` rustdoc.
- **G** — Example rewrites, k8s example, `MONITORING.md`,
  `performance.md`, `netring-compat` crate, and legacy API
  deletion were deferred to 0.21+. 0.20.0 ships **coexistence**:
  the legacy `ProtocolMonitor` + `AnomalyMonitor` keep working
  alongside the new `Monitor::builder()`. 0.21.x adds
  `#[deprecated]`; 0.22.0 removes. CHANGELOG documents this
  timeline explicitly.

## Active backlog

| # | Phase | Plan file | Status |
|---|---|---|---|
| F | Per-CPU sharding + state merging | [`netring-0.20-phase-F-percpu-sharding.md`](./netring-0.20-phase-F-percpu-sharding.md) | deferred to **0.21+**; multi-interface + tick-handler firing land alongside |

Phase F is the major performance feature for 0.21+. Until it
lands:
- `MonitorBuilder::interfaces([a, b])` rejects with
  `BuildError::MultiInterfaceNotYetSupported` at build time.
- `MonitorBuilder::tick(...)` records the handler but the run
  loop doesn't fire it.

## Reading the F plan

Same structure as the shipped plans (Goal / Scope / Dependencies
/ Module layout / Detailed deliverables / Tests / Acceptance /
Risks / Effort / Cross-phase notes). Self-contained.

## Cross-phase invariants the F plan must preserve

These were enforced across A–E and continue:

1. `cargo nextest run -p netring --features tokio,channel,flow,parse,pcap,metrics,http,dns,tls,icmp,emit` passes.
2. `cargo +stable clippy --workspace --all-targets --all-features -- -D warnings` clean.
3. `cargo fmt --check` clean.
4. `cargo test --doc` passes.
5. The flowscope 0.11.1 API stays the target unless a separate
   phase bumps it.
6. `benches/zero_alloc.rs` reads **Δ 0 bytes / Δ 0 blocks** per
   100k synthetic events. Any future regression past the 512 B
   / 100 block threshold blocks the merge — enforced by the
   `zero-alloc` CI job (`.github/workflows/ci.yml`).
