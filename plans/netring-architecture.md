# netring — Target Architecture (0.24 → 0.25 → 1.0)

> The design north-star the release plans implement. *Good design before
> implementation.* This is the coherent end-to-end picture; the two release plans
> (`netring-0.24-plan.md`, `netring-0.25-plan.md`) phase it in. **Read this first.**
>
> Design values (in priority order where they conflict): **performance** (zero-copy
> hot path, kernel filter pushdown), **strongly typed** (typed builders over strings;
> enums over `dyn`; the type system enforces invalid states away), **async-friendly**
> (tokio-idiomatic: `Send` spawnable run loop, streams, channels, owned `'static`
> futures), **Rust-idiomatic** (RAII, ownership, no surprise globals). Breaking changes
> are concentrated at **1.0**, not spread across 0.24/0.25 (§7).

---

## 1. The data path (one diagram)

```
                         ┌──────────────────────────── kernel ────────────────────────────┐
 NIC ─► RSS/queues ─►    │ AF_PACKET: cBPF capture filter   │  AF_XDP: XDP prog + BPF map    │ ◄─ STAGE-0
                         │   (SO_ATTACH_FILTER)             │  (redirect XSK vs XDP_PASS)    │   (kernel pushdown)
                         └──────────────────────────────────┴───────────────┬───────────────┘
                                                                             ▼
   AnyBackend (enum: AfPacket | Xdp | Pcap)  ──►  readable().await   (borrows nothing → Send)
                                                                             │
                                              drain_batch(|view| …)   ◄─ ZERO-COPY borrow of the mmap ring
                                                                             │   (no await inside; batch dropped after)
                  ┌──────────────────────────────────────────────────────────┼──────────────────────────────────┐
                  ▼ STAGE-1 packet prefilter         ▼ STAGE-2 flow predicates  ▼ STAGE-3 session predicates
            packet-tier subs (PacketView)      flow tracker (flowscope)      L7 parser slots (Http/Dns/Tls/…)
                  │                                   │                              │
                  └───────────────────► dispatch ◄────┴──────────────┬───────────────┘
                                            │                        │
                       sync handlers (─&mut Ctx─, in-borrow)   async handlers (&Ctx read → 'static Send future → Effects)
                                            │                        │  (futures built in-borrow, awaited AFTER drop)
                                            ▼                        ▼
                                  Ctx state/counters/flow_state ◄─ apply Effects (sync, post-batch)
                                            │
                                            ▼  outputs
            anomaly sinks (event) · report sinks (periodic) · flow exporters (per-flow: IPFIX/syslog) · telemetry/health
```

Three filter stages (Suricata/Retina model): **STAGE-0** sheds traffic in the kernel
(cheapest); **STAGE-1/2/3** are userspace prefilters gating work before the expensive step
(flow-state alloc, L7 parse, the callback). Each subscription declares one **typed** filter;
the compiler splits it across the stages (§4).

---

## 2. Threading model — two shapes, one run loop

- **Single `Monitor`** (convenience): the run-loop future is **`Send + 'static`** (the 0.23
  property) → `tokio::spawn(monitor.run_for(..))` works on a multi-thread runtime. One core
  of throughput.
- **`ShardedRunner`** (performance): N shards, **one OS thread per shard, pinned to a
  core/NUMA node** (0.25-C), each a `current_thread` runtime. The kernel fans flows out
  (symmetric hash) → each shard owns disjoint flows → **lock-free shard-local state**;
  cross-shard aggregation is the existing merge worker.

Both run the *same* generic loop. `Send` is required only for the spawned single-Monitor
case; keeping the loop `Send` costs nothing (§3), so we don't fork the code path.

---

## 3. I/O core — `AnyBackend` enum + borrowed-batch loop *(perf + strongly typed)*

**Why an enum, not `dyn CaptureBackend`.** `async fn` in a trait does **not** yield a `Send`
future (the AFIT/RPITIT Send-bound problem) — a `dyn` backend with `async fn readable` would
silently make the run loop `!Send`, breaking the 0.23 premise. And `drain_batch(&mut self, f:
impl FnMut(PacketView))` is generic → **not object-safe**. A concrete enum kills both and
keeps the hot path monomorphized/inlinable — and it's the strongly-typed choice:

```rust
pub enum AnyBackend {                       // arms cfg-gated by backend features
    AfPacket(AsyncCapture<Capture>),
    #[cfg(feature = "af-xdp")] Xdp(AsyncXdpSocket),
    #[cfg(feature = "pcap")]   Pcap(PcapSource),
}
impl AnyBackend {
    pub async fn readable(&mut self) -> Result<()>;                       // concrete ⇒ Send
    pub fn drain_batch(&mut self, f: impl FnMut(PacketView<'_>)) -> Result<DrainOutcome>;
    pub fn stats(&self) -> Result<CaptureStats>;
    pub fn set_filter(&self, f: &KernelFilter) -> Result<()>;            // §4
    pub fn kind(&self) -> BackendKind;
}
```
A `CaptureBackend` *trait* survives only as the documented extensibility seam (a future
io_uring ZC-RX arm). The run loop holds `Vec<AnyBackend>`.

**Why borrowed-batch is zero-copy AND Send.** The run loop *owns* its backends. Per ready
backend: `readable().await` (borrows nothing) → `drain_batch(|view| …)` borrows the mmap ring
**synchronously**; inside, all **sync** dispatch runs in place (zero-copy) and async handlers'
**`'static` futures are built and queued** (not awaited — the closure is `Fn(&P,&Ctx)->Fut`,
`Fut:'static`, owns its data, never borrows `view`/`Ctx`) → the batch is **dropped** (RAII
releases the block) → **now** the queued futures are awaited and their `Effects` applied. No
`!Sync` borrow crosses `.await` ⇒ `Send` preserved. No packet copied — only the already-
present owned `events: Vec<FsEvent>` buffer and (with async handlers) a `SmallVec` of futures.

**Semantics (documented):** within a batch, sync handlers see per-packet state immediately;
async `Effects` apply at batch end. Async is for occasional I/O ⇒ batch-deferred is the right
default (a per-packet-async mode, which costs a copy, can come later).

---

## 4. Filtering — typed-first, multi-stage *(strongly typed + perf)*

**Filters are typed builders, not strings** (idiomatic Rust; reuse the existing typed
`BpfFilterBuilder` vocabulary — pf-rs / typed-builder precedent). A `.expr("…")` string
escape hatch exists for *runtime/operator-supplied* filters only (Cloudflare `wirefilter`,
optional feature). Both lower to the **same predicate AST**, so they split identically:

```rust
.subscribe(packet().tcp().dst_port(443).to(h))             // typed, kernel-pushable
.subscribe(flow::<Tcp>().bytes_over(1 << 20).to(h))         // typed, userspace
.subscribe(session::<Tls>().sni_glob("*.bank").to(h))       // typed, userspace
.subscribe(packet().expr("tcp port 443 and not host 10.0.0.1").to(h)) // runtime string (wirefilter)
```

The compiler **splits** each predicate AST:
- **Kernel-pushable conjunction** — L2–L4 (`tcp/udp/icmp`, `dst_port/src_port`, `host/net`,
  `vlan`) the in-tree cBPF compiler expresses. The **conservative union** (OR) across all
  subscriptions becomes **STAGE-0** (a frame passes if *any* sub might want it):
  - **AF_PACKET:** compile to cBPF, `SO_ATTACH_FILTER` (atomic swap on reload).
  - **AF_XDP:** **not** runtime codegen. A **vendored parameterized XDP program** reads a
    `BPF_MAP_TYPE_HASH` of `{proto,port}→action` (+ LPM map for host/net); userspace
    populates it from the subscription set; the program does `lookup ? redirect→XSKMAP :
    XDP_PASS` (PASS, not DROP — kernel stack coexists). Reload = update the map (no recompile).
- **Userspace remainder** — typed L7/stateful predicates (`sni_glob`, `bytes_over`, regex)
  run as **STAGE-1/2/3 prefilters**: evaluated *before* the expensive step they gate. Only
  what a subscription needs gets allocated/parsed.

Compile-time typed filters inline to zero overhead; `.expr()` parses to the same AST.

---

## 5. Handlers — strongly typed tiers; sync mutate, async read+effect

**Three strongly-typed subscription tiers** (`P` is the protocol marker; invalid
combinations don't compile, per the 0.22 `FlowProtocol`/`MessageProtocol` roles):
`packet()` → `PacketView` · `flow::<P>()` → `FlowStarted/Ended/Tick<P>` · `session::<P>()`
→ `P::Message`.

- **Sync handler:** `Fn(&Payload, &mut Ctx)` — runs in-borrow, mutates `Ctx`
  (state/counters/sink/flow_state) directly. Zero-alloc.
- **Async handler:** `Fn(&Payload, &Ctx) -> impl Future<Output = Result<Effects>> + 'static`.
  The closure body runs **synchronously** in-borrow — it **reads** `Ctx` and `move`s owned
  data into the returned `'static` future (idiomatic: the `move`-owned future satisfies
  `'static`/`Send` — tokio's spawn rule). The future does I/O and returns **`Effects`** (a
  typed list of `emit` / `set_state::<T>(FnOnce(&mut T))` / `counter` / `enqueue`) the loop
  applies synchronously after the batch. Read access (sync, via `&Ctx`) **and** write access
  (deferred, via `Effects`), never `&mut Ctx` across `.await` ⇒ `Send` preserved.

### Three idiomatic async paths (pick by use case)
1. **Inline `on_async` + `Effects`** (above) — react to an event, do I/O, affect monitor
   state. The strongly-typed, zero-extra-task path. Best for short per-event I/O.
2. **Typed event streams** — `monitor.subscribe::<P>()` → `EventStream<P::Message>`
   (`futures_core::Stream`), consumed in the user's own `tokio::spawn`'d task. Full async
   freedom (joins, timeouts, backpressure) for complex/long-running consumers. Already shipped.
3. **`ChannelSink`** — fire-and-forget anomalies to a downstream task/exporter. For shipping
   results out (the channel/isolation pattern tokio favors for shared mutable state).

---

## 6. Resilience *(production-grade; was missing)*

One bad packet/flow/handler must not kill the monitor.
- **Backend errors:** per-source `BackendErrorPolicy { FailFast (default) | SkipSource |
  Reopen { backoff } }`. (Today: first error returns `Err` and kills the loop.)
- **Handler errors:** `HandlerErrorPolicy { Propagate (default) | Isolate }` — `Isolate`
  logs + counts + continues to the next handler/event.
- **Handler panics:** opt-in `catch_handler_panics` wraps callbacks in `catch_unwind`
  (off the hot path by default; documented cost).
- All surface as telemetry (`netring_backend_errors_total{source}`,
  `netring_handler_errors_total{kind}`, `netring_handler_panics_total`). A monitor silently
  dropping a source or swallowing errors is one you can't trust — make it visible.

---

## 7. Compatibility & SemVer — one break, at 1.0

The 0.2x line is **additive-with-shims**; the single removal wave is **1.0**:
- **0.24** adds `backend()`; `interface()`/`fanout()`/`pcap_source()` keep working via
  `#[deprecated]` shims → existing 0.23 monitors **compile unchanged**.
- **0.25** adds `subscribe(...)` and effect-returning `on_async`; `on::<E>` and payload-only
  `on_async` keep working via shims → existing code **compiles unchanged**.
- **1.0** removes the shims, settles names, makes the SemVer-stable promise — the one forced
  migration, *after* the community has field-tested the new surface across 0.24 + 0.25.

So "breaking" on 0.24/0.25 means "new surface added, old deprecated," not "your code stops
compiling."

---

## 8. Map: architecture → release plan

| Slice | Plan / phase |
|---|---|
| §3 `AnyBackend` + borrowed loop (zero-copy/Send), backends, UMEM | 0.24-plan · Phase B (keystone) |
| §6 resilience | 0.24-plan · Phase B (+ telemetry in C) |
| §1 telemetry/health · §6 counters | 0.24-plan · Phase C |
| §1 sinks/flow-exporters | 0.24-plan · Phase D |
| §1 fingerprints (JA4) | 0.24-plan · Phase E |
| §4 typed filters + multi-stage · §5 tiers | 0.25-plan · Phase A |
| §5 handler/effect + ctx-read | 0.25-plan · Phase B |
| §2 sharded perf · §4 STAGE-0 measurement | 0.25-plan · Phase C |
| §7 shim removal + stabilization | 1.0 (plan written post-community-test) |

---

## 9. Corrections this design locked in (don't re-introduce)

1. **`dyn CaptureBackend` + `async fn` → silently `!Send`.** Use the `AnyBackend` enum.
2. **AF_XDP filter "codegen" is unrealistic.** Vendored parameterized XDP program + BPF map.
3. **No resilience story.** Per-source backend + per-handler error/panic policies + telemetry.
4. **Stringly-typed filters.** Typed builders first; `.expr()` string is the runtime escape hatch.
5. **Async handlers couldn't read `Ctx`.** `Fn(&P,&Ctx)->'static Fut` gives sync read + effect write.
