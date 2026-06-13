# plans/ — netring backlog

Forward-looking implementation plans only. Historical record lives in `CHANGELOG.md`
+ `git log`; reference material lives in `netring/docs/`. Convention: when a plan ships,
**delete it** in the same PR.

> **Scope split.** Flow & session tracking lives in the separate
> [`flowscope`](https://github.com/p13marc/flowscope) crate (computational, no-tokio:
> parsers, tracking, reassembly, fingerprints incl. JA3/JA4, correlate primitives). This
> index covers netring-side plans (capture backends, the Monitor/subscription engine,
> sinks/exporters, sharding, observability).

---

## The six documents

| Doc | Role |
|---|---|
| [`netring-architecture.md`](./netring-architecture.md) | **Design north-star — read first.** The coherent end-to-end design every release implements: the data path, the `AnyBackend` enum, typed multi-stage filtering, the handler/effect model, resilience, threading, and the SemVer strategy. Design values: **performance · strongly-typed · async-friendly (tokio) · idiomatic.** |
| [`netring-strategic-review-2026-06.md`](./netring-strategic-review-2026-06.md) | The *why* — competitive landscape, pain points, differentiators, the M1–M4 roadmap. |
| [`netring-0.24-plan.md`](./netring-0.24-plan.md) | **Next release** — Zero-Copy Core + Production Trust (Phases A–E; keystone = B). |
| [`netring-0.25-plan.md`](./netring-0.25-plan.md) | **Release after** — Subscriptions, Async Effects & Performance (Phases A–D). |
| [`upstream-tracking.md`](./upstream-tracking.md) | Live: rustc / kernel / flowscope features being watched. |
| *(this)* `INDEX.md` | Roadmap overview, decisions, invariants, history. |

The first drafts were a single mega-plan, then nine phase files; this is the settled middle:
**one architecture spine + two consolidated release plans.** The architecture doc holds the
design rationale so the release plans stay execution-focused (phased sections, not re-derived
design).

---

## The roadmap to 1.0

```
0.23  Send run-loop future                 ── DONE (on 0.23-dev; publish pending)
0.24  Zero-Copy Core + Production Trust     ── keystone: AnyBackend enum + borrowed
  │     zero-copy + Send loop · AF_XDP reaches the Monitor · resilience · telemetry/
  │     health · syslog/IPFIX (+ OTLP/Kafka companion) · JA4/JA4S · miri/fuzz/perf-gate
0.25  Subscriptions, Effects & Performance  ── typed 3-tier subscriptions · filter
  │     pushdown → cBPF / table-driven XDP map (differentiator) · async read+effect
  │     handlers · NUMA pinning + symmetric fanout · published pps/Gbps · TX
  ▼   community test window → feedback incorporated → shims removed
1.0   Stabilization (SemVer promise; plan written once feedback is in)
```

**One break, not three.** 0.24/0.25 are *additive-with-shims* — they add the new surface
(`backend()`, `subscribe()`, effect-`on_async`) and **deprecate** the old; existing code
**keeps compiling**. The single forced migration — removing the shims + the SemVer-stable
promise — happens once, at **1.0**, after the new surface is field-tested. (Arch §7.)

**The keystone is 0.24 Phase B** — one rewrite that simultaneously makes the Monitor
zero-copy, keeps it `Send`, brings AF_XDP to the high-level API, and creates the `AnyBackend`
seam everything else (incl. 0.25's subscriptions) builds on.

### Decisions locked
- **Split:** 0.24 = foundations + I/O keystone + production trust · 0.25 = subscriptions +
  async-effect redesign + perf numbers + TX.
- **0.23 (Send):** ships first as a small interim; 0.24 builds on it.
- **OTLP/Kafka:** `netring-exporters` companion crate; **syslog + IPFIX in-tree**.
- **Filters:** typed builders first; `.expr()` strings → `wirefilter` are the runtime escape hatch.
- **`Packets` miri:** if flagged, ship the safer borrowed `for_each`/closure surface (0.24-B).
- **Health endpoint:** netring exposes `MonitorHealth`; the embedder serves HTTP.
- **Compat shims** live through 0.24/0.25, **removed at 1.0**.

### Design corrections locked into the architecture (don't re-introduce)
1. `dyn CaptureBackend` + `async fn` → silently `!Send` ⇒ use the **`AnyBackend` enum**.
2. AF_XDP filter "codegen" is unrealistic ⇒ **vendored parameterized XDP program + BPF map**.
3. No resilience story ⇒ **backend/handler/panic policies + telemetry**.
4. Stringly-typed filters ⇒ **typed builders**; `.expr()` is the runtime escape hatch.
5. Async handlers couldn't read `Ctx` ⇒ **`Fn(&P,&Ctx)->'static Fut`**: sync read + effect write.

---

## Recently shipped (durable record in CHANGELOG)

| Release | Status |
|---|---|
| netring **0.23** | `Send` run-loop future (`run_for`/… `Send + 'static`, spawnable). Done on `0.23-dev`; publish pending. |
| netring **0.22** | **Published 2026-06-13** (tag `0.22.0`). Operations toolkit + typed protocol model (breaking). Depends on flowscope 0.14.1 (also published 2026-06-13). |
| netring **0.21** | Send Monitor, `ShardedRunner`, `subscribe::<P>()`, pcap replay, drain phase, `pattern_detector!`, EveSink + MetricsSink. |
| netring **0.20** | Declarative `Monitor` builder + Handler trait + 5 layers + `detector!` + multi-interface + ticks. |
| netring **0.17–0.19** | flowscope 0.10→0.13 absorption (`Driver<E>: Send` unconditional). |

**Companion flowscope:** 0.12.0 (plans 122–127), 0.13.0 (147–156), 0.14.1 (ICMP routing fix).
**Next:** flowscope **0.15** (companion to netring 0.24 Phase E) — JA4S + ServerHello
extension/sig-alg + QUIC marker (~410 LoC, 0 deps, additive); lockstep publish gates 0.24.

---

## Invariants enforced through every commit (carried from 0.21, extended)
1. clippy `--all-features -D warnings` · `fmt --check` · `RUSTDOCFLAGS="-D warnings" doc` — clean.
2. `benches/zero_alloc.rs` **Δ 0 / 0** **and (0.24+)** a live-capture test reads **0 heap
   allocs/packet** in the run loop.
3. Run-loop future stays **`Send + 'static`** (`tests/monitor_send.rs`).
4. **(0.24+)** miri green on the pure-logic suite; cargo-fuzz smoke green; **(0.25)** loom on
   the effect/subscription paths; perf regression gate vs the 0.24 baseline.
5. flowscope dep floor `>= 0.15.0`.

### Backward-compat breaks (history + planned)
0.21 `AnomalySink::write` key `→ &dyn Key` · 0.22 typed roles + flat `FlowPacket` + 0.19
removed · 0.23 `on_async` futures `Send` · **0.24** `backend()` axis + feature flatten
(shimmed) · **0.25** typed 3-tier subscriptions + `on_async` effects (shimmed). SemVer
stability only at **1.0**.
