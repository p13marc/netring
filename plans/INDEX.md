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

## The documents

| Doc | Role |
|---|---|
| [`netring-architecture.md`](./netring-architecture.md) | **Design north-star — read first.** The coherent end-to-end design every release implements: the data path, the `AnyBackend` enum, typed multi-stage filtering, the handler/effect model, resilience, threading, and the SemVer strategy. Design values: **performance · strongly-typed · async-friendly (tokio) · idiomatic.** |
| [`netring-strategic-review-2026-06.md`](./netring-strategic-review-2026-06.md) | The *why* — competitive landscape, pain points, differentiators, the M1–M4 roadmap. |
| ~~`netring-0.24-plan.md`~~ | **Shipped — 0.24.0 released 2026-06-14** (Zero-Copy Core + Production Trust; keystone `AnyBackend`). Plan deleted on ship; deferrals carried into the 0.25 plan's "Deferred from 0.24" section. |
| ~~`netring-0.25-plan.md`~~ | **Shipped — 0.25.0 released 2026-06-15** (tag `0.25.0` + `netring-exporters` 0.1.0). Subscriptions, Async Effects, Performance & TX — the complete capability release; nothing deferred. Plan + subscription-engine design deleted on ship. |
| ~~`netring-0.26-afxdp-capture-plan.md`~~ | **Shipped — 0.26.0 released 2026-06-16** (tag `0.26.0` + `netring-exporters` 0.1.1). AF_XDP Multi-Queue Capture & Hardening (issues #4/#6): promiscuous · `XdpCapture` (one socket per RX queue, `Queues::Auto`) · Monitor `xdp_queues` (removed the single-queue footgun) · `XdpShardedRunner` (line-rate worker-per-queue) · B1/F3/F1 hardening. Plan deleted on ship. |
| [`upstream-tracking.md`](./upstream-tracking.md) | Live: rustc / kernel / flowscope features being watched. |
| *(this)* `INDEX.md` | Roadmap overview, decisions, invariants, history. |

### Candidate feature plans (post-0.26)

**No fixed sequence — 1.0 is gated by community validation, not a schedule.** Pick
any when ready, ship behind a feature flag, delete-on-ship. Each is research-grounded
with design, API, the flowscope-side change (we own flowscope), milestones, HW-gated
testing, and risks. Strategic framing (netring = "Retina's subscription model as a
production library") lives in `netring-strategic-review-2026-06.md`.

| Plan | Theme |
|---|---|
| [`netring-arp-plan.md`](./netring-arp-plan.md) | **ARP** — flowscope parser + `ArpTable` + `on_arp_anomaly` (spoof/poison/conflict/gratuitous detection), EtherType kernel-filter atom, `arp_watch` example. *(maintainer ask)* |
| [`netring-afxdp-rx-metadata-plan.md`](./netring-afxdp-rx-metadata-plan.md) | **AF_XDP RX HW metadata + timestamps** — XDP-hints kfuncs (HW timestamp / rx_hash / VLAN / checksum) → `PacketView` fields; vendored `redirect_meta` program; graceful degrade. |
| [`netring-quic-visibility-plan.md`](./netring-quic-visibility-plan.md) | **QUIC + encrypted visibility** — flowscope on-path QUIC-Initial parser (DCID-derived key → SNI/ALPN/JA4; *not* a QUIC stack); `Quic` protocol + `session::<Quic>`; encrypted-flow fingerprints. |
| [`netring-nic-flow-steering-plan.md`](./netring-nic-flow-steering-plan.md) | **NIC flow steering** — `ethtool` ntuple/RSS (`ETHTOOL_SRXCLSRLINS`, `FLOW_RSS`); typed `FlowRule` + `SteerGuard`; `XdpCapture::steer`. Closes the AF_XDP-vs-DPDK gap. |
| [`netring-capture-facade-multinic-plan.md`](./netring-capture-facade-multinic-plan.md) | **Capture facade + multi-NIC/tap merge** — `AsyncXdpMultiCapture` (**issue #11**), source-agnostic tap merge, `Backend::Auto` probe, pcap fallback. |
| [`netring-subscription-specialization-plan.md`](./netring-subscription-specialization-plan.md) | **Compile-time subscription specialization** — `subscribe!` proc-macro monomorphizing the dispatch + const-folding the kernel filter (Retina's codegen trick). **Spike/measure-first.** |

The first drafts were a single mega-plan, then nine phase files; this is the settled middle:
**one architecture spine + two consolidated release plans.** The architecture doc holds the
design rationale so the release plans stay execution-focused (phased sections, not re-derived
design).

---

## Release history (and the community-gated path to 1.0)

> 1.0 is **not scheduled** — it ships only after community validation. The
> post-0.26 work is a *set of candidate feature plans* (table above), picked in no
> fixed order, not a march to a release date.

```
0.23  Send run-loop future                 ── folded into 0.24 (never published standalone)
0.24  Zero-Copy Core + Production Trust     ── ✅ PUBLISHED 2026-06-14 (tag 0.24.0): AnyBackend
  │     enum + borrowed zero-copy + Send loop · AF_XDP reaches the Monitor (xdp_interface;
  │     live-XDP→0.25) · resilience + error counters · telemetry/health · syslog/IPFIX ·
  │     JA4/JA4S (flowscope 0.15.0) · miri/fuzz/perf-gate.  Deferrals → 0.25 backlog.
0.25  Subscriptions, Effects & Performance  ── ✅ PUBLISHED 2026-06-15 (tag 0.25.0 +
  │     netring-exporters 0.1.0): typed 3-tier subscriptions · filter pushdown → cBPF /
  │     table-driven XDP map (differentiator) · async read+effect handlers · NUMA/CPU
  │     pinning · published pps/Gbps · symmetric TX · in-Monitor AF_XDP loader · UMEM
  │     hugepages/NUMA · Reopen/panic-catch · JA4S license-gating · OTLP/Kafka crate ·
  │     EVE-tls-record. The complete capability release — nothing deferred.
0.26  AF_XDP Multi-Queue Capture & Hardening   ── ✅ PUBLISHED 2026-06-16 (tag 0.26.0
  │     + netring-exporters 0.1.1): promiscuous (#4) · XdpCapture (one socket per RX
  │     queue · Queues::Auto via ETHTOOL_GCHANNELS) · Monitor xdp_queues / AnyBackend::XdpMq
  │     (removed the silent single-queue footgun) · XdpShardedRunner (line-rate
  │     worker-per-queue + busy-poll) · B1/F3/F1 hardening (#6).
  │   candidate feature plans (no fixed sequence) → the "Candidate feature plans"
  │   table above: ARP · AF_XDP HW metadata/timestamps · QUIC visibility · NIC flow
  │   steering · capture facade + multi-NIC/tap merge (#11) · subscription specialization
  ▼   community validation → feedback incorporated → shims removed
1.0   Stabilization — **gated by community validation, not scheduled.** SemVer promise +
      shim removal + the deliberate defaults-breaks (Monitor AF_XDP → Queues::Auto, etc.);
      plan written only once real-world feedback is in.
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
- **Filters:** typed builders first; `.expr()` strings are the runtime escape hatch — parsed
  by an **own dep-free recursive-descent parser** over the same `Predicate` AST (**not**
  `wirefilter`; that crate is dead on crates.io — see `upstream-tracking.md`).
- **`Packets` miri:** if flagged, ship the safer borrowed `for_each`/closure surface (0.24-B).
- **Health endpoint:** netring exposes `MonitorHealth`; the embedder serves HTTP.
- **Compat shims** live through 0.24/0.25, **removed at 1.0**.

### Design corrections locked into the architecture (don't re-introduce)
1. `dyn CaptureBackend` is **not object-safe** (async fn in traits + the generic
   `drain_batch(impl FnMut)`; still true on stable Rust 2026 — RTN expresses the Send bound,
   doesn't grant `dyn`) ⇒ use the **`AnyBackend` enum**.
2. AF_XDP filter "codegen" is unrealistic ⇒ **vendored parameterized XDP program + BPF map**.
3. No resilience story ⇒ **backend/handler/panic policies + telemetry**.
4. Stringly-typed filters ⇒ **typed builders**; `.expr()` is the runtime escape hatch.
5. Async handlers couldn't read `Ctx` ⇒ **`Fn(&P,&Ctx)->'static Fut`**: sync read + effect write.
6. **JA4S ≠ BSD** ⇒ JA3/JA4(client) are BSD-3 + royalty-free; **JA4S is FoxIO License 1.1 +
   patent-pending** (commercial vendors need a FoxIO OEM license). Keep the default fingerprint
   surface BSD-clean: **JA4S opt-in feature, off by default** (0.25 backlog). (arch §9.6.)

---

## Recently shipped (durable record in CHANGELOG)

| Release | Status |
|---|---|
| netring **0.26** | **Published 2026-06-16** (tag `0.26.0`) + **netring-exporters 0.1.1**. AF_XDP Multi-Queue Capture & Hardening (issues #4/#6): promiscuous mode · `XdpCapture` (one socket per RX queue, `Queues::Auto` via `ETHTOOL_GCHANNELS`) · Monitor `xdp_queues`/`AnyBackend::XdpMq` (single-reactor, removed the silent single-queue footgun) · `XdpShardedRunner` (line-rate worker-per-queue + busy-poll) · `default_program` honors `max_queues` · per-queue NUMA. Depends on flowscope 0.16.0. Additive over 0.25. |
| netring **0.25** | **Published 2026-06-15** (tag `0.25.0`) + **netring-exporters 0.1.0**. Subscriptions, Async Effects, Performance & TX: typed 3-tier subscriptions + kernel filter pushdown (cBPF / XDP map) · async read+effect handlers · CPU/NUMA pinning + dispatch-throughput numbers · symmetric TX stack · in-Monitor AF_XDP loader · UMEM hugepages/NUMA · Reopen/panic-catch · JA4S `ja4plus` license-gating · OTLP/Kafka companion crate · EVE-tls-record. Depends on flowscope 0.16.0. Additive over 0.24. |
| netring **0.24** | **Published 2026-06-14** (tag `0.24.0`). Zero-Copy Core + Production Trust: `AnyBackend` + borrowed zero-copy + `Send` loop · AF_XDP-in-Monitor · resilience + error counters · telemetry/health · syslog/IPFIX exporters · JA4/JA4S. Depends on flowscope 0.15.0. Additive over 0.23. |
| netring **0.23** | `Send` run-loop future (spawnable). **Folded into 0.24 — never published standalone.** |
| netring **0.22** | **Published 2026-06-13** (tag `0.22.0`). Operations toolkit + typed protocol model (breaking). Depends on flowscope 0.14.1 (also published 2026-06-13). |
| netring **0.21** | Send Monitor, `ShardedRunner`, `subscribe::<P>()`, pcap replay, drain phase, `pattern_detector!`, EveSink + MetricsSink. |
| netring **0.20** | Declarative `Monitor` builder + Handler trait + 5 layers + `detector!` + multi-interface + ticks. |
| netring **0.17–0.19** | flowscope 0.10→0.13 absorption (`Driver<E>: Send` unconditional). |

**Companion flowscope:** 0.12.0 (plans 122–127), 0.13.0 (147–156), 0.14.1 (ICMP routing fix),
0.15.0 (JA4S + ServerHello `extension_types` + FoxIO-correct JA4 ALPN; companion to netring
0.24 Phase E), **0.16.0 (PUBLISHED 2026-06-15** — JA4S split behind opt-in `ja4plus`, FoxIO
License 1.1 + `NOTICE`; companion to netring 0.25). **✅ Done (was a "watch"):** the JA4S
license-gating split landed in flowscope 0.16 + netring `ja4plus` passthrough (commit
`27c6963`) — see Design correction 6 + `upstream-tracking.md`.

---

## Invariants enforced through every commit (carried from 0.21, extended)
1. clippy `--all-features -D warnings` · `fmt --check` · `RUSTDOCFLAGS="-D warnings" doc` — clean.
2. `benches/zero_alloc.rs` **Δ 0 / 0** **and (0.24+)** a live-capture test reads **0 heap
   allocs/packet** in the run loop.
3. Run-loop future stays **`Send + 'static`** (`tests/monitor_send.rs`).
4. **(0.24+)** miri green on the pure-logic suite **(0.25: now also covers `monitor::`
   type-erased casts)**; cargo-fuzz smoke green **(0.25: now also the `.expr()` parser)**.
   *(loom: N/A — the effect/subscription dispatch is sequential, not concurrent; the earlier
   "loom on the effect/subscription paths" line was an overclaim. perf regression gate = Phase
   C, not yet landed.)*
5. flowscope dep floor `>= 0.16.0`.

### Backward-compat breaks (history + planned)
0.21 `AnomalySink::write` key `→ &dyn Key` · 0.22 typed roles + flat `FlowPacket` + 0.19
removed · 0.23 `on_async` futures `Send` · **0.24** `backend()` axis + feature flatten
(shimmed) · **0.25** typed 3-tier subscriptions + `on_async` effects (shimmed) · **0.26**
AF_XDP multi-queue is *additive* (`XdpCapture`/`xdp_queues`; default stays single-queue) —
see `netring-0.26-afxdp-capture-plan.md` §7. **Planned 1.0 break:** Monitor AF_XDP defaults
to `Queues::Auto` (capture the whole NIC by default — the deliberate footgun-removal break,
after field-testing). SemVer stability only at **1.0**.
