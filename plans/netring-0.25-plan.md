# netring 0.25 — Subscriptions, Async Effects & Performance

> Second pre-1.0 release ([`netring-architecture.md`](./netring-architecture.md) first).
> 0.24 landed the keystone — a zero-copy + `Send` + multi-backend (AF_PACKET/AF_XDP/pcap)
> I/O core + production trust. **0.25 builds the redesigned API on top:** the
> strongly-typed 3-tier **subscription engine** with **kernel filter pushdown** (the
> differentiator), async handlers that read `Ctx` + return `Effects` (the `&mut Ctx`
> wart, solved), and the perf tuning + published throughput numbers. After 0.24 + 0.25
> are **community-tested on real traffic**, we cut **1.0**.
>
> Depends on 0.24's `AnyBackend`/`set_filter` + borrowed loop. Additive-with-shims
> (arch §7): existing code compiles unchanged. Grounded inline.

## Scope & locked decisions
- **0.25 =** subscriptions + pushdown (A) · async effects + dispatcher (B) · perf numbers (C)
  · TX symmetry (D, **trim-able → 1.0+**).
- **Filters are typed builders** (reuse `BpfFilterBuilder` vocabulary); `.expr("…")` strings
  are the *runtime* escape hatch (arch §4), parsed by an **own dep-free recursive-descent
  parser** over the same `Predicate` AST — **not** `wirefilter` (dead on crates.io). ✅ shipped.
- **Compat shims** from 0.24 (`interface()`, payload-only `on_async`) remain through 0.25;
  `on::<E>` becomes sugar over subscriptions. **All shims removed at 1.0.**

## Cross-cutting invariants (carried from 0.24)
clippy/fmt/**doc -D warnings** clean · dhat **Δ0** + **0 allocs/packet** (gated-off hot
path) · run-loop **`Send`** (now incl. the effect path, `monitor_send`) · **miri** (now
covers the `monitor::` type-erased casts) + **fuzz** (now incl. the `.expr()` parser) green
· **perf regression gate** vs the 0.24 baseline (= Phase C, not yet) · flowscope floor
`>= 0.16`. *(loom: N/A for the sequential effect/subscription dispatch — see the
Verification-coverage note in the status section; was an overclaim.)*

## Status table
> **Phase A design**: the subscription engine was redesigned research-grounded
> (Retina/Iris + Suricata/Zeek) — see **`netring-0.25-subscription-engine-design.md`**.
> netring's primitives already match the validated architecture; the rest is the
> S1–S5 phasing below. Landed pieces marked ✅.

> **Audit 2026-06-15:** adversarial verification confirmed every ✅ item below is
> implemented AND correctly wired (no MISSING/MIS-WIRED; the S2 union is provably
> starvation-free). The differentiator (Phase A subscriptions + S1/S2 pushdown +
> Phase B effects) is **complete + CI-validated**. Remaining for 0.25: Phase C
> (perf numbers) + D (TX, trim-able) + the deferral backlog + Phase R release.

| Phase | Item | Breaking | Status |
|---|---|---|---|
| **A** | 3 strongly-typed tiers: `packet()` / `flow::<P>()` / `session::<P>()` + per-sub typed filters | shim (`on::<E>`) | ✅ all three tiers e2e (A1a/b/c + S3a/b) |
| A | filter compiler **splits** AST → kernel conjunction + userspace remainder | additive | ✅ `kernel_approx` (A2) + cBPF compiler (A3a) |
| A | STAGE-0 pushdown: cBPF (AF_PACKET) + **table-driven XDP map** (AF_XDP) | additive | ✅ cBPF + **safe auto-apply** (S2, live-validated `monitor_lo_kernel_pushdown`); ◑ XDP map = #38 (AF_XDP path now CI-validated, `xdp_lo_smoke`) |
| A | `.expr()` runtime strings → own dep-free recursive-descent parser (**not** dead `wirefilter` crate) | no | ✅ A4 (`subscription/expr.rs`, fuzzed) |
| **B** | async `on_effect(|p, &Ctx| -> Future<Effects>)` — read sync + write deferred | shim | ✅ `on_effect` e2e (B1) |
| B | dispatcher: lift `MAX_EVENT_TYPES` (ArrayVec→spill) + debug type-tag | minor | ✅ (B2) |
| **C** | CPU/NUMA pinning in `ShardedRunner` + `FanoutMode::SymmetricHash` | no | ☐ not started |
| C | prefetch + batched AF_XDP refill + `#[cold]` (bench-gated) | no | ☐ not started |
| C | published pps/Gbps/latency + CI perf gate + `docs/PERFORMANCE.md` | no | ☐ not started |
| **D** | TX symmetry: stream injection · pacing · TX timestamps (**trim-able**) | no | ☐ not started |
| R | version bump · CHANGELOG · `MIGRATING_0.24_TO_0.25.md` · publish | — | ☐ (version still 0.24.0) |

### Subscription-engine phasing (supersedes the A rows above; see design doc)
- **S1** ✅ — `TrafficInterest` model: `Event::traffic_class()` + registry/protocol
  interest recording, mapped via `kernel_filter::{class_interest,dispatch_interest}`.
- **S2** ✅ — **safe union pushdown**: `compile_union` fail-open (any `Always` /
  over-budget → None), `kernel_prefilter()` folds all consumers + `Always` for broad
  ones, applied via `set_filter` (AF_PACKET). Live-validated (`monitor_lo_kernel_pushdown`
  CI job: shed 64k noise frames at the kernel). Closes #31, starvation-free.
- **S3** ✅ — flow (`FlowEnded`+stats) + session (on-parse) `.to()` dispatch (S3a/S3b).
  Closes #30. *(Orientation caveat: bidirectional key ⇒ flow/session `src_*`/`dst_*`
  are best-effort; use either-endpoint `port`/`host`. Documented.)*
- **S4** ✅ — already shipped in 0.24-C: bounded `ChannelSink` + `dropped` counter.
- **S5 (0.26+)** — staged early-shed (bounded L7 depth, per-flow bypass → AF_XDP map).

**Done:** S1→S2→S3→S4 + A4 (+ AF_XDP-path CI validation + 2 xdp-loader bug fixes).
**Remaining:** Phase C (perf) → D (TX) → R (release). A4 ✅.

### Verification coverage (audit 2026-06-15 — now enforced in CI)
- **miri** (Tree Borrows) now covers the type-erased `*const ()` casts in
  `monitor::dispatcher`/`registry`/`subscription` (was `config::`/`packet::` only).
- **fuzz** has an `expr_parse` target over the `.expr()` parser + AST consumers.
- **Send**: `monitor_send`'s spawnable assertion now registers an `on_effect`
  handler (covers the `&mut Ctx`-across-`.await` effect path; Send rests on `Ctx: Send`).
- **CI runs the cap-free 0.25 integration tests** (`monitor_replay` = B1 e2e + all
  tiers, `monitor_kernel_prefilter` = S2 union, `monitor_send`, …) — previously dormant.
- **loom: N/A for the effect/subscription dispatch** — it's sequential in the single
  run loop (no shared-state concurrency). The genuinely concurrent path is the
  `ShardedRunner` merge worker; a loom test there is a *separate* (optional) item, not
  the "effect/subscription apply" the cross-cutting line implied. *(Correcting the
  earlier overclaim — there is no loom test in-tree, and the effect path doesn't need one.)*
- **dhat Δ0** bench covers the **unchanged hot path** (no subs/effects → gated off);
  the gating preserves Δ0 for the common case. Per-tier allocation profiling is a Phase-C item.

## Deferred from 0.24 (backlog — fold into the phases above or do standalone)
Items the 0.24 plan scoped but shipped without (0.24.0 released 2026-06-14, additive):
- **B4 resilience tail:** `BackendErrorPolicy::Reopen{backoff}` (re-open a flapping
  source) + opt-in `catch_handler_panics` (`catch_unwind` around dispatch; needs an
  unwind-safety pass). Both want a *failing-backend rig* to exercise. `MonitorHealth::
  {handler,backend}_errors` counters + gauges already shipped in 0.24.
- **B5 AF_XDP UMEM hugepages + NUMA + ZC/copy-mode detect** (`MAP_HUGETLB`/`mbind`,
  `tracing::warn!` on silent copy-mode fallback) — overlaps 0.25-C NUMA pinning; needs HW.
- **◑ AF_XDP live validation (PARTIAL, 2026-06-15):** the AF_XDP *path* is now
  CI-validated — `tests/xdp_lo_smoke.rs` loads the redirect-all program on `lo`
  (SKB mode, root) and captures redirected frames; CI job `AF_XDP lo live (root)`.
  This found + fixed **two real shipped `xdp-loader` bugs**: the vendored
  `redirect_all.bpf.o` had no BTF (broke aya ≥ 0.13 loading) and `force_replace`'s
  `XDP_FLAGS_REPLACE` is rejected by the link API (`bpf_link_create`). **Still TODO:**
  (a) the `force_replace`/link-API loader fix (a user-facing bug — task #37); (b)
  **full in-Monitor xdp-loader integration** — `MonitorBuilder::xdp_interface` still
  opens a *bare* `AsyncXdpSocket::open` (run.rs) with no program attach/XSKMAP, so a
  Monitor-on-AF_XDP captures nothing without an external redirect program. (c) the
  A3c table-driven `filter_redirect.bpf` map program (task #38), now unblocked.
- **pcap → `AnyBackend` unification:** fold `replay_loop` into the one generic loop
  (a Pcap arm); 0.24 kept `replay_loop` separate.
- **D1 active-timeout flow export:** 0.24 emits a `FlowRecord` on `FlowEnded` (incl. idle
  timeout); add NetFlow-style *active* timeout (periodic export of still-open flows via
  `FlowTick`).
- **E2 EVE-tls-record:** JA4/JA4S/SNI in a Suricata `tls` EVE record (needs a TLS-record
  EVE writer; 0.24 has only the anomaly `EveSink`).
- **✅ JA4S license gating (DONE 2026-06-14):** flowscope **0.16.0** published
  with an opt-in `ja4plus` feature (JA4S off by default; JA3+JA4-client stay BSD
  under `tls-fingerprints`) + `LICENSE-FoxIO-1.1` + `NOTICE`. netring depends on
  flowscope 0.16, adds a passthrough `ja4plus` feature gating
  `TlsFingerprint.ja4s`, and (fix) `tls` now enables `flowscope/tls-fingerprints`
  so JA3/JA4 actually populate. Original note below kept for context:
- **⚠ JA4S license gating (do this in 0.25):** JA4S is **FoxIO License 1.1 + patent-pending**,
  NOT BSD (only JA3/JA4-client are BSD). It shipped un-gated inside flowscope 0.15's
  `tls-fingerprints` (0.24). Split it behind its own opt-in feature — flowscope `ja4plus` (or
  `ja4s`) **off by default**, netring passthrough — so the default fingerprint surface stays
  royalty-free (JA3 + JA4-client) and commercial vendors must consciously opt in. Carry the
  license notice (`FINGERPRINTS.md` already warns). Strategic: our target audience includes
  commercial NDR vendors, who need a FoxIO OEM license for JA4S — don't make them pull it by
  default. (arch §9.6.)
- **C5 tracing-JSON example** (structured logging of anomalies/telemetry).
- **`netring-exporters` companion crate:** `OtlpAnomalySink` + `KafkaSink` (heavy async/C
  deps kept out of core).

## 0.25 release readiness (audit 2026-06-15) — decision needed
The **differentiator is done + CI-validated**: Phase A (3 tiers + filter split + cBPF
compiler), S1/S2 safe fail-open pushdown (live-validated), Phase B (effects + dispatcher),
A4 `.expr()`, JA4S gating, AF_XDP-path CI validation. The audit found **no MISSING/MIS-WIRED
features** in any of it. What's genuinely outstanding splits into:

**Hard release tasks (Phase R — do at publish time):**
1. Bump `netring/Cargo.toml` `version` 0.24.0 → **0.25.0** (still 0.24.0).
2. Write **`docs/MIGRATING_0.24_TO_0.25.md`** (subscriptions, `on_async`→`on_effect`, dispatcher).
3. Finalize the `## 0.25.0` CHANGELOG (drop "Unreleased"; reconcile with what actually ships).

**Scope decision (the plan headlines 0.25 as "+ perf numbers" but Phase C is unstarted):**
- **Recommended:** ship 0.25 as **"Subscriptions, Async Effects & Safe Kernel Pushdown"** —
  the differentiator — and **re-scope Phase C (perf numbers/gate/PERFORMANCE.md) + Phase D
  (TX) to 0.26**, since C needs a real-NIC bench rig (in-sandbox only has lo) and D is already
  marked trim-able. Update the title/CHANGELOG accordingly. *(Alternative: hold 0.25 until at
  least C3 `docs/PERFORMANCE.md` + a pps gate land — but that blocks the validated
  differentiator on hardware-gated perf work.)*
- **Deferral backlog NOT in 0.25 either way** (all verified absent): B4 Reopen/panic-catch,
  B5 hugepages/NUMA, in-Monitor xdp-loader, pcap→AnyBackend fold, D1 active-timeout export,
  E2 EVE-tls-record, C5 example, netring-exporters crate, A3c XDP map. List them as "0.26+"
  in the CHANGELOG's "not yet" section so their absence is intentional, not silent.

---

## Phase A — Subscription Engine & Multi-Stage Filtering — arch §4, §5
*The differentiator. Subscription API is the new front door (additive; `on::<E>` shim).*

**Background:** the dispatcher is already 2-tier (lifecycle events `run.rs:199-212` + parser
messages `run.rs:215-236`); the **packet tier is missing** (raw packets only feed the
tracker). The Monitor pushes **no** derived kernel filter today (all traffic reaches
userspace). In-tree cBPF compiler exists (`config/bpf_compile.rs`); 0.24-B gave
`AnyBackend::set_filter`. We **wrap the existing dispatcher**.

- **A1 typed tiers** — `packet()` → `PacketView`; `flow::<P>()` → `FlowStarted/Ended/Tick<P>`;
  `session::<P>()` → `P::Message` (`P` strongly typed; invalid combos don't compile, per the
  0.22 roles). Each returns a `SubscriptionBuilder` with typed predicates + `.to(handler)`:
  ```rust
  .subscribe(packet().tcp().dst_port(443).to(h))         // typed kernel-pushable
  .subscribe(flow::<Tcp>().bytes_over(1<<20).to(h))       // typed userspace
  .subscribe(session::<Tls>().sni_glob("*.bank").to(h))   // typed userspace
  .subscribe(packet().expr("tcp port 443").to(h))         // runtime string (own parser)
  ```
  **packet tier** = a new `dispatch_packet_tier(view, ctx, pending)` inside 0.24-B's
  `drain_batch` closure **before** `track_into`. flow/session tiers = sugar over existing
  events/slots, gated by the subscription predicate. `on::<E>(h)` ⇒ a tier sub with an
  always-true filter (shim). `detector!`/`pattern_detector!` retarget onto `subscribe`.
- **A2 filter compiler split** (arch §4) — each typed/string filter → one predicate AST →
  split into **kernel-pushable conjunction** (L2–L4: tcp/udp/icmp, ports, host/net, vlan) +
  **userspace remainder** (L7/stateful: `sni_glob`, `bytes_over`, regex). The userspace parts
  become STAGE-1/2/3 prefilters (gate alloc/parse/callback — Suricata/Retina early-shed).
- **A3 STAGE-0 pushdown** (arch §4) — **conservative union** (OR of kernel conjunctions; a
  frame passes if *any* sub might want it):
  - **AF_PACKET:** compile union → cBPF; `set_filter()` (atomic); recompile + re-attach on reload.
  - **AF_XDP (table-driven, not codegen):** a **vendored parameterized XDP program**
    (`afxdp/loader/programs/filter_redirect.bpf.{c,o}`) reads a `BPF_MAP_TYPE_HASH`
    `{proto,port}→action` (+ LPM for host/net): `hit ? redirect→XSKMAP : XDP_PASS`; userspace
    populates the maps; reload = map update.
- **A4 `.expr()` parser** ✅ — netring field schema (5-tuple, proto, `tls.sni`/`tls.ja4`,
  `http.host`, `dns.qname`, byte/pkt counts) → the same `Predicate` AST as A2, so `.expr()`
  strings split identically. **Decision made: own dep-free recursive-descent parser**
  (`subscription/expr.rs`, fuzzed `fuzz/expr_parse`) — **`wirefilter-engine` NOT taken** (dead
  on crates.io, 0.6.1/2019). The compile-time typed path was already dep-free + inlined.
- **Tests:** each tier dispatches; **split** correctness (`tcp port 443 and tls.sni~…` →
  kernel=443, userspace=SNI); **pushdown** verified via 0.24-C `CaptureTelemetry.packets`
  (only the matching subset reaches userspace); conservative-union (sub X not dropped by sub Y);
  AF_XDP map-driven program on a rig; `.expr()` string ≡ typed equivalent.

## Phase B — Async Effects & Dispatcher — arch §5
*Fixes the two most-felt pain points. `on_async` signature changes (additive; payload-only shim).*

- **B1 async read+effect** (arch §5) — `Fn(&Payload, &Ctx) -> impl Future<Output =
  Result<Effects>> + 'static`. The closure reads `&Ctx` synchronously (in-borrow) and `move`s
  owned data into the `'static` future (idiomatic — the move-owned future is `Send`/`'static`);
  the future does I/O and returns `Effects` (typed: `emit`/`set_state::<T>(FnOnce(&mut T))`/
  `counter`/`enqueue`, `effects![]` sugar). The run loop (0.24-B) applies them after the batch
  drop. **Read (sync) + write (deferred), never `&mut Ctx` across `.await` ⇒ `Send`.** Deprecated
  payload-only shim returns `Effects::none()`. **⚠ Validate the two-lifetime blanket impl
  `Fn(&P,&Ctx<'_>)->Fut where Fut:'static` with a compile probe FIRST** — if it doesn't unify
  in stable Rust, fall back to payload-only + a `Send` `CtxSnapshot` passed by value (same
  ergonomic outcome). ✅ the blanket impl unified — no fallback needed. *(No loom: the apply
  path is sequential, not concurrent — Send-safety is asserted at compile time by
  `monitor_send.rs`, which now registers an `on_effect` handler.)* (Three idiomatic async
  paths, arch §5.)
- **B2 dispatcher** — lift `MAX_EVENT_TYPES=16` (`dispatcher.rs:23`): inline `ArrayVec` ≤16,
  spill to `FxHashMap` beyond (no ceiling, no hot-path cost). `#[cfg(debug_assertions)]`
  type-tag asserting registered `TypeId` == payload `TypeId` (silent type-confusion → loud
  test panic; zero release cost).
- **Tests:** an async handler reads flow state + emits + mutates state without `Arc<Mutex>`;
  `monitor_send` green; dhat Δ0 on the no-async path; compile-probe (or snapshot fallback);
  >16 event types build/dispatch; debug type-tag catches mis-registration.

## Phase C — Performance & Scaling — arch §2, §4
*Turns 0.24's zero-copy win into published numbers + line-rate scaling.*

- **C1 pinning + symmetric fanout** — `ShardedRunner::pin_cpus(true)` (one core/shard via
  `core_affinity`/`sched_setaffinity`; NUMA-co-located under AF_XDP with 0.24-B5's UMEM);
  `FanoutMode::SymmetricHash` (eBPF fanout) so both flow directions hit the same shard →
  lock-free shard-local state. Optional `steering` feature (rtnetlink/ethtool: workers 1:1 to
  RX queues). Update `scaling.md` (asymmetric-RSS pitfall). (`shard.rs` doesn't pin today.)
- **C2 micro-opts (bench-gated)** — prefetch next header/descriptor (`packet.rs:481-536`,
  `afxdp/ring.rs:195-232`); batched AF_XDP fill refill (`afxdp/batch.rs:168-178`); `#[cold]`
  on slow/error arms. Each must show a net-positive pps delta in C3 or it doesn't land.
- **C3 perf gate** — extend 0.24's harness to pps/Gbps/latency for AF_PACKET vs AF_XDP, copy
  vs zero-copy, **with vs without pushdown** (quantify Phase A); CI regression gate vs the
  0.24 baseline; keep 0-allocs/packet; `docs/PERFORMANCE.md` (numbers + tuning recipe + honest
  DPDK-adjacent positioning).
- **Tests:** pinning asserted via `sched_getaffinity`; bidirectional flow → same shard under
  `SymmetricHash`; before/after pps per micro-opt; CI perf job fails on regression.

## Phase D — TX Symmetry *(additive; trim-able → 1.0+)*
TX is spartan (`afpacket/tx.rs`: V1 frames, no async/pacing/stream/timestamps).
- `AsyncInjector::send_stream(impl Stream<Item = impl AsRef<[u8]>>)`; a token-bucket `TxPacer`
  (pps/bps); TX hardware timestamping (`SO_TIMESTAMPING` egress, graceful skip where
  unsupported). A subscription forward/transform tier only if Phase A makes it natural; else
  defer to post-1.0. **Cut without guilt if 0.25 is already large.**

## Phase R — Release → community test
All gates green (incl. miri/fuzz/loom + perf regression). Version `0.24 → 0.25`; CHANGELOG
`## 0.25.0`; `docs/MIGRATING_0.24_TO_0.25.md` (subscriptions, `on_async` effects, dispatcher).
`cargo publish`; tag `0.25.0`; delete this plan. **Open the community-test window** — the exit
criteria for 1.0 are validation, not features.

## The road to 1.0 (no plan file yet — by design)
A **stabilization** release gated on: community validation of the new surface (subscriptions,
`AnyBackend`, effect model, AF_XDP) on real traffic; **removal of the 0.24/0.25 shims**
(`interface()`, payload-only `on_async`, `on::<E>`); a documented **SemVer-stable surface**; a
**frozen perf baseline** + real-NIC numbers; `MIGRATING_0.25_TO_1.0.md`. The 1.0 plan is
written once community feedback is in.

## Coverage (review §2/§5/§6 finished by 0.24+0.25)
§2.1 async-Ctx→0.25-B · §2.2 features/non-Linux→0.24-A · §2.3 `Packets`→0.24-A(miri)+B ·
§2.4 dispatcher→0.25-B · §2.5 TX→0.25-D · §2.6 drops→0.24-C · §2.7 testing→0.24-A+0.25-C ·
§2.8 docs→0.24-A · §2.9 eBPF→0.25-A(XDP pushdown) · §5.1 subs+pushdown→0.25-A ·
§5.2 backend→0.24-B · §5.3 features→0.24-A · §5.4 async-Ctx→0.25-B · §5.5 crate boundary→0.24-A
· §6 perf (zero-copy/AF_XDP/NUMA/hugepage/pushdown/steering/gate)→0.24-B+0.25-C ·
*new:* Monitor-not-zero-copy→0.24-B · AF_XDP-absent→0.24-B.
**Post-1.0 (named so not forgotten):** plugin/DSL, ETA features, Arrow/Parquet, OTel
self-tracing, io_uring impl, file extraction, ICS/OT, clustering, reference daemon.

## Grounding
`protocol/mod.rs:43-200` · `builtin/{tcp,tls}.rs` · `run.rs:197,199-236,211-212` ·
`config/bpf_compile.rs` · `afpacket/rx.rs:199-215` · `afxdp/loader/` ·
`dispatcher.rs:23,37,148-193` · `async_handler.rs:8-25` · `ctx/mod.rs:108-122` ·
`monitor/shard.rs` · `afpacket/fanout.rs` · `packet.rs:481-536` ·
`afxdp/{ring.rs:195-232,batch.rs:168-178}` · `afpacket/tx.rs` · `benches/{throughput,zero_alloc}.rs`.
External: XSKMAP (`docs.kernel.org/bpf/map_xskmap.html`), table-driven XDP precedent
(XDP-Firewall), Suricata prefilter/eBPF, AFIT/RPITIT Send (rust-lang blog), pf-rs/typed-builder.
