# netring 0.25 — Subscription Engine: design (research-grounded)

> **Status:** design proposal, 2026-06-14. Resolves the two open A1/A3 questions
> (flow/session delivery semantics; safe kernel pushdown) after researching the
> state of the art. The user authorized breaking changes ("we can redesign…
> break backward compatibility") to land the *best* design, not the most
> compatible one. Supersedes the open questions in `netring-0.25-plan.md` §A.

## TL;DR

Adopt the **Retina/Iris** subscription model, tempered by the **Suricata/Zeek**
"fail-open kernel filter + staged userspace early-shed" discipline:

1. **Every traffic consumer is a subscription**: a *tier* (when delivered) + a
   *filter* (`Predicate`) + a *delivery* (sync callback returning deferred
   effects). `on::<E>` / `protocol::<P>` / `export_flows` become sugar that
   register subscriptions — so the framework knows the **complete** set of
   traffic interests.
2. **The kernel prefilter is the OR-union of every subscription's
   `kernel_approx`, fail-open**: if any consumer wants everything, or the union
   can't be expressed in cBPF within budget, push **no** filter (capture all).
   A subscription can only ever *widen* the kernel filter → **no consumer is
   ever starved** (the property Zeek enforces with `max_filter_compile_time`).
   This makes auto-pushdown *safe by construction* and closes task #31.
3. **Delivery at the tier's natural completion point** (Retina): packet =
   per-frame streaming; flow = at `FlowEnded` with accumulated stats; session =
   when the L7 message parses. This resolves the flow/session `.to()` question
   (task #30).
4. **The real anti-starvation lever is staged userspace early-shed, not the
   kernel filter** (Suricata/Zeek/nDPI): every consumer sees the flow head; the
   tail of a decided flow is shed (bounded L7 depth, per-flow bypass). The
   kernel union is an *optimization*; the userspace staged pipeline is
   authoritative.

The happy result: netring's already-landed pieces (`Predicate` AST,
`kernel_approx` conservative superset, typed tier gating, fail-open cBPF
compiler, packet-tier streaming, deferred-`Effects` handlers) **are the
Retina/Iris architecture**. This is an *extension*, not a rewrite.

---

## What the research established

Three independent threads (Retina/Iris source + paper; Suricata/Zeek/nDPI docs;
Rust API-ergonomics survey) converged:

### Retina/Iris (Stanford) — the canonical prior art (≈ netring's exact shape)
- Subscription = **(filter, callback, subscribable level)**; levels are
  **packet / connection / session** — netring's **packet / flow / session**.
- One **shared predicate trie**: every subscription's pattern is inserted;
  shared prefixes collapse; each node tags (a) the **stage it terminates** and
  (b) the **set of subscribers** that fire there → one traversal, fan-out to N.
- Each predicate self-classifies to **the lowest stage that can decide it**
  (L3/L4 headers → packet; "which L7 proto" → connection; "L7 field value" →
  session). Exactly netring's `Atom::is_kernel_pushable` split.
- **Over-approximation is the safety invariant**: a stage emits a
  `MatchNonTerminal` "promote" verdict — it can only *over-admit*, never falsely
  reject. The NIC filter pops predicates until hardware-expressible
  (`while !is_fully_qualified { pop }`) — **byte-for-byte netring's
  `kernel_approx`** (`Not`/userspace atoms relax to `Always`).
- Delivery: connection subscription accumulates per-packet state in
  `pre_match`/`post_match`, **materializes & delivers in `on_terminate`**;
  session delivers when the parser returns `Done`.
- **Multi-subscription union** (Iris): all subscriptions feed one tree; the
  early/NIC filter is **the logical OR of every subscription's packet-level
  interest** → no subscription starved by construction.
- Avoid: hard **DPDK dependency** (netring's AF_PACKET/AF_XDP is the right
  call); **compile-time-only** filters (no runtime reconfig); **sync
  immutable-borrow callbacks** with no async path (netring's deferred-`Effects`
  fills this gap); **no logical `NOT`** in the DSL.

### Suricata / Zeek / nDPI — the operational discipline
- **The kernel filter is coarse, union-driven, and fail-open.** Zeek is the one
  that derives a BPF from loaded scripts: `capture_filters` OR'd (want),
  `restrict_filters` AND-NOT'd (don't-want), with a **cost ceiling**
  (`max_filter_compile_time` = 100 ms) that **shrinks the filter toward *open***
  when the union gets too expensive. A new consumer can only *widen* capture.
- Suricata does **not** push rule requirements into the capture BPF at all —
  capture broadly (minus operator exclusions), then **prefilter (MPM/fast_pattern)
  in userspace**. The kernel filter ≠ the per-consumer filter.
- **Staged early-shed is the real lever**: cheap header → flow-state →
  bounded-depth L7 parse → detector. Shed the *tail* of decided flows
  (Suricata `stream.reassembly.depth` + flow bypass → eBPF/XDP map; nDPI
  "give up after N packets"; Zeek dynamic analyzer attach/detach with a
  `dpd_buffer_size` early-bytes buffer).
- Per-worker flow-hash steering (RSS / AF_PACKET fanout) is **complementary**,
  not a content filter — netring already has it (`ShardedRunner`).

### Rust API ergonomics
- **One internal `Predicate` AST, two frontends**: a typed builder (in-Rust,
  compile-time-checked) and an optional runtime string parser (config / CLI /
  control-plane). netring already has the AST + typed builder.
- **`wirefilter-engine` is dead on crates.io** (0.6.1, 2019); the
  `cloudflare/wirefilter` repo lives but publishes via git. → For A4, build a
  small `pest`/`nom` parser over netring's own `Predicate` (don't take the dead
  dep); borrow wirefilter's *architecture* (typed `Scheme` → parse → indexed
  context), not the crate.
- **Sealed marker traits + sparse impls** are the right tool for the
  tier×protocol×filter validity matrix (SNI-only-on-TLS) — exactly netring's
  `HasSni`/`HasHttpHost`/`HasQname`. Optionally wrap with `bon` for builder
  ergonomics (compile-time parity with `typed-builder` since 2.1).
- **Hot-path callbacks stay synchronous and return deferred effects**; async
  enrichment runs behind a **bounded** channel with an **explicit, observable
  drop policy**. netring's B1 `Effects` + report sinks already match this; the
  one gap is making the async-effect channel bounded + drop-counted (tie to
  `CaptureTelemetry`).

---

## The design

### 1. Subscription as the single consumer model

```text
Subscription = Tier × Filter(Predicate) × Delivery
  Tier:     Packet | Flow<P> | Session<P>
  Filter:   Predicate  (Always = unfiltered)
  Delivery: Callback(Fn -> Effects) | Stream | Export | Report
```

Every existing consumer lowers to a subscription:

| Today                              | Becomes (sugar over)                                  |
|------------------------------------|-------------------------------------------------------|
| `subscribe(packet()…​.to(h))`        | Packet subscription (already this)                    |
| `on::<FlowStarted<Tcp>>(h)`         | Flow subscription, filter `proto==tcp`, deliver-on-start |
| `on::<HttpMessage>(h)`              | Session subscription `Http`, filter `Always`          |
| `protocol::<Tls>()`                 | declares a **session traffic-interest** (`tcp`, DPD)  |
| `export_flows(e)`                   | Flow subscription, filter `Always`, deliver-on-end    |
| `report_to(s)` / broadcast         | Flow/session subscription with a stream/report delivery |

**Migration stance.** Keep `on::<E>` / `protocol::<P>` / `export_flows` as the
*public ergonomic surface* — they are good. Internally, each one **registers a
traffic-interest record** into a single `SubscriptionSet`. The dispatcher and
run loop keep working as-is; the only new thing the `SubscriptionSet` powers is
the **union kernel prefilter** (§3). Full literal unification (on::<E> *is* a
subscription object) is a 1.0 cleanup — not needed for the value.

### 2. Tier delivery semantics (resolves task #30)

- **Packet** — streaming, per frame, borrowed `PacketView`, sync `Fn(&PacketView,
  &mut Ctx) -> Result<()>` (done). Filter evaluated on 5-tuple/vlan
  (`PacketFields`).
- **Flow<P>** — delivered at **`FlowEnded`** (Retina `on_terminate`) with the
  accumulated `FlowStats` (and a `Tick` variant for long flows, opt-in). The
  filter evaluates against the flow's stats + 5-tuple, so `bytes_over` /
  `packets_over` are meaningful (the flow has accumulated). Payload: a `Flow`
  record `{ key, stats, reason }`. `.to(handler)` = `Fn(&Flow<P>, &mut Ctx)`.
- **Session<P>** — delivered when an L7 message/session **parses**; payload
  `P::Message`; filter evaluates L7 fields (`sni`/`host`/`qname`) + 5-tuple.
  `.to(handler)` = `Fn(&P::Message, &mut Ctx)`.

All three deliver to the **deferred-`Effects`** shape for async work (B1), with
a bounded channel + drop counter for the async path.

`FieldSource` already abstracts this: packet tier fills 5-tuple; flow tier adds
`total_bytes`/`total_packets`; session tier adds the L7 globs. (Built in A1a.)

### 3. Safe automatic kernel pushdown (resolves task #31)

```text
kernel_prefilter(SubscriptionSet) =
    fold over ALL subscriptions:  acc = acc OR sub.filter.kernel_approx()
    if acc == Always            -> None        (capture everything; fail-open)
    if !expressible_in_budget    -> widen → None (Zeek cost-cap: degrade toward open)
    else                         -> Some(compile_to_cBPF(acc))
```

- The union is over **every** subscription's interest (not just packet subs) —
  this is what makes it safe: it is, by definition, a superset of everything any
  consumer wants. **A consumer can only widen capture, never narrow it.**
- **Fail-open** at two points: any `Always` interest → no filter; a union too
  large/complex for the cBPF instruction budget (or containing un-lowerable
  shapes like `Not`) → widen to no filter. Never push a filter that *might*
  drop a wanted frame. (`predicate_to_bpf` already returns `None` on
  un-lowerable shapes; add an instruction/branch budget that widens to `None`.)
- `on::<E>` / `protocol::<P>` contribute an **implied interest** Predicate:
  e.g. `FlowStarted<Tcp>` → `proto==tcp`; `FlowPacket` / un-typed → `Always`
  (→ capture all). Most realistic monitors have at least one broad consumer →
  `Always` → capture-all, which is correct and safe. Narrow monitors (a
  pure packet tap, or "only TLS on 443") get a real filter.
- Then the run loop calls `set_filter(&union)` on each AF_PACKET backend at
  start (and on reload). AF_XDP uses the **table-driven map** program (A3c,
  hardware-gated): the union's `{proto,port}`/LPM atoms populate a
  `BPF_MAP_TYPE_HASH`/LPM; reload = map update (no recompile).

### 4. Staged early-shed (the durable performance lever — future)

Kernel union is stage 0. Userspace stages (mostly flowscope-side, netring wires):
- **Bounded L7 parse depth** per flow (nDPI give-up / Suricata stream depth) —
  stop parsing a flow once classified or past a byte budget.
- **Per-flow bypass after classification** — once a flow matches no remaining
  subscription, stop tracking it; escalate the bypass into the **AF_XDP map**
  the way Suricata pushes bypass into eBPF.
- **Late/dynamic session attachment** with a small early-bytes buffer (Zeek
  `dpd_buffer_size`) — attach a parser when a signature fires even if the first
  bytes already flowed.

These are 0.26+; the tier model + safe union is the 0.25 deliverable.

### 5. Optional runtime string frontend (A4)

A small `pest`/`nom` parser over the **same `Predicate`** so `packet().expr("tcp
port 443 and tls.sni ~ *.bank")` and config/CLI/control-plane filters lower
identically to the typed path. Field schema mirrors the `FieldSource` accessors.
Do **not** depend on `wirefilter-engine` (dead); borrow its architecture.

---

## Why this is the best solution (not just *a* solution)

- It is the **validated** architecture of the only directly-comparable system
  (Retina/Iris), and netring's existing primitives already are it.
- It makes auto-pushdown **safe by construction** (union = superset) and
  **fail-open** (the discipline every mature NDR enforces), instead of the
  fragile "filter derived from a subset of consumers" trap that A3b exposed.
- It gives the flow/session tiers **principled, documented delivery semantics**
  (deliver-at-completion) rather than an ad-hoc guess.
- It keeps the **ergonomic surface** (`on::<E>`, `protocol::<P>`) intact while
  unifying the *interest model* underneath — minimal user churn for a large
  architectural gain.
- It positions the **real** performance work (staged early-shed, XDP bypass)
  as the natural next layer, matching how production systems actually scale.

## Phased execution (additive; one breaking touch-point)

- **S1 — `TrafficInterest` model.** A trait/enum mapping each consumer
  (`on::<E>` event type, `protocol::<P>`, exporters, tier subs) → a `Predicate`
  interest. A `SubscriptionSet` on the builder collects them. *(No behavior
  change; pure bookkeeping.)*
- **S2 — Safe union pushdown.** `kernel_prefilter()` folds the whole
  `SubscriptionSet` with the fail-open + cost-cap rules; the run loop applies it
  via `set_filter` (AF_PACKET) at start. Test: a narrow-only monitor gets a
  filter; adding a broad `on::<FlowPacket>` widens it to none (no starvation).
  *(This is the task #31 close — now safe.)*
- **S3 — Flow/session tier `.to()` dispatch.** Deliver-at-completion semantics;
  predicate-gated over the existing FlowEnded / P::Message dispatch. *(task #30.)*
- **S4 — Bounded async-effect channel + drop counter** wired to
  `CaptureTelemetry`. *(Closes the one ergonomics gap the research flagged.)*
- **S5 (0.26+) — staged early-shed**: bounded L7 depth, per-flow bypass into the
  AF_XDP map (A3c), late session attachment. *(The durable perf layer.)*
- **A4 (any time) — runtime `expr()` string frontend** over the same AST.

The only *breaking* change in S1–S4 is if/when `on_async` is folded into the
deferred-`Effects` delivery (S4) — small, and we have the migration shim
precedent. Everything else is additive.

## Open sub-decisions (low-stakes, decide while building)

- Flow `Tick` delivery: opt-in (`flow::<P>().every(dur)`)? Default off.
- Implied-interest precision for `protocol::<P>`: `tcp`/`udp` by L4, or the
  protocol's well-known ports? Ports risk missing non-standard-port traffic →
  default to the **L4 proto** (broader, safe), let users narrow with a filter.
- cBPF budget for the cost-cap widen-to-open threshold (start ~ a few hundred
  instructions; measure).

## Sources
Retina (SIGCOMM'22) + `stanford-esrg/{retina,iris}`; Suricata/Zeek/nDPI docs
(prefilter, packet-filter framework `capture_filters`/`restrict_filters`/
`max_filter_compile_time`, DPD analyzer tree, nDPI FPC); `cloudflare/wirefilter`,
`bon`, `typed-builder`, `pcap` lending-iter. Full URL list in the research
threads attached to this session.
