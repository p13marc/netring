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
  → `wirefilter` (optional feature) are the *runtime* escape hatch (arch §4).
- **Compat shims** from 0.24 (`interface()`, payload-only `on_async`) remain through 0.25;
  `on::<E>` becomes sugar over subscriptions. **All shims removed at 1.0.**

## Cross-cutting invariants (carried from 0.24)
clippy/fmt/doc clean · dhat **Δ0** + **0 allocs/packet** · run-loop **`Send`** · **miri** +
**fuzz** + **loom** (new effect/subscription paths) green · **perf regression gate** vs the
0.24 baseline · flowscope floor `>= 0.15`.

## Status table
| Phase | Item | Breaking | Status |
|---|---|---|---|
| **A** | 3 strongly-typed tiers: `packet()` / `flow::<P>()` / `session::<P>()` + per-sub typed filters | shim (`on::<E>`) | ☐ |
| A | filter compiler **splits** AST → kernel conjunction + userspace remainder | additive | ☐ |
| A | STAGE-0 pushdown: cBPF (AF_PACKET) + **table-driven XDP map** (AF_XDP) | additive | ☐ |
| A | `.expr()` runtime strings → `wirefilter` (optional feature) | no | ☐ |
| **B** | async `on_async(|p, &Ctx| -> Future<Effects>)` — read sync + write deferred | shim | ☐ |
| B | dispatcher: lift `MAX_EVENT_TYPES` (ArrayVec→spill) + debug type-tag | minor | ☐ |
| **C** | CPU/NUMA pinning in `ShardedRunner` + `FanoutMode::SymmetricHash` | no | ☐ |
| C | prefetch + batched AF_XDP refill + `#[cold]` (bench-gated) | no | ☐ |
| C | published pps/Gbps/latency + CI perf gate + `docs/PERFORMANCE.md` | no | ☐ |
| **D** | TX symmetry: stream injection · pacing · TX timestamps (**trim-able**) | no | ☐ |
| R | CHANGELOG · migration · publish 0.25 → open community-test window | — | ☐ |

**Order:** A + B parallel (both wrap the dispatcher; A needs 0.24-B's `set_filter`) →
C (measures A's pushdown, tunes B's AF_XDP path). D independent/deferrable.

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
  .subscribe(packet().expr("tcp port 443").to(h))         // runtime string (wirefilter)
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
- **A4 `wirefilter`** (optional feature) — netring field schema (5-tuple, proto, `tls.sni`/
  `tls.ja4`, `http.host`, `dns.qname`, byte/pkt counts) → the same AST as A2, so `.expr()`
  strings split identically. Compile-time typed path stays dep-free + inlined.
- **Tests:** each tier dispatches; **split** correctness (`tcp port 443 and tls.sni~…` →
  kernel=443, userspace=SNI); **pushdown** verified via 0.24-C `CaptureTelemetry.packets`
  (only the matching subset reaches userspace); conservative-union (sub X not dropped by sub Y);
  AF_XDP map-driven program on a rig; `wirefilter` string ≡ typed equivalent.

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
  ergonomic outcome). loom-test the apply path. (See the three idiomatic async paths, arch §5.)
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
