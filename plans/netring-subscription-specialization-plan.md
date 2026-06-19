# netring — Compile-time subscription specialization (plan)

> **Status:** plan, 2026-06-16. **Research/spike-first** — the most speculative
> theme; build only after measuring the runtime-dispatch cost. No fixed release
> slot. No flowscope touch. Additive (a new macro alongside the runtime builder).

## 1. Why

[Retina](https://perso.uclouvain.be/tom.barbette/retina/)'s real efficiency win
isn't just runtime filtering — it **compiles a binary tailored to the
subscription**, so unneeded work is *eliminated* at build time, not merely skipped
at runtime. netring already does runtime kernel-pushdown + staged userspace
shedding (0.25); a monomorphized dispatch would close the last efficiency gap to
Retina and is a differentiator **no other Rust capture library has**.

This is the crown-jewel API move — but also the riskiest, so it is gated on
**measurement**, not ambition (see §6).

## 2. Design

### Principle
Given a subscription set known at compile time, generate a specialized pipeline:
- Tiers never subscribed are **compiled out** (no `session` reassembly/parser link
  if only `packet`/`flow` are used; no flow tracker if only `packet`).
- The kernel filter (cBPF + XDP map) is **const-folded** from the same static
  subscription, so the in-kernel shed is derived at build time too.
- Handler dispatch is monomorphized (no `TypeId` slot lookup, no boxed dyn) for the
  fixed event set.

### Surface — a `subscribe!` macro, beside (not replacing) the runtime builder
```rust
// Compile-time-specialized monitor: only the packet tier + a tcp/443 filter exist
// in the generated code; flow/session machinery and their deps are gone.
let monitor = netring::subscribe! {
    interface: "eth0",
    packet(tcp && dst port 443) => |view, ctx| { /* … */ },
    flow::<Tcp>(bytes > 1<<20)   => |ended, ctx| { /* … */ },
};
monitor.run_until_signal().await?;
```
- A procedural macro (`netring-macros`) parses the static subscription DSL (reusing
  the `.expr()` grammar + the typed-tier shapes), emits:
  - the const kernel-filter (call the existing `Predicate`→cBPF/XDP-map compiler at
    `const`/build time where possible, else a `OnceLock` computed once);
  - a generated `Dispatch` struct with concrete per-tier methods (no slot table);
  - feature-gates / cfg so absent tiers don't link their parsers.
- **The runtime builder stays** the dynamic path (`.expr()` strings, plugin
  detectors, runtime-built subscriptions). The macro is the opt-in "I know my
  subscription at build time — give me Retina-class codegen."

### Reuse
- The `Predicate` AST, the cBPF/XDP-map compiler, the typed tier combinators, and
  the kernel-pushdown union all already exist — the macro is mostly a *front-end*
  that feeds them at compile time + a codegen back-end that drops unused tiers. It
  is **not** a rewrite of the engine.

## 3. flowscope side
None directly. (The parsers it conditionally links are flowscope's; the macro just
controls whether they're pulled in.)

## 4. Milestones
- **M0 — spike + measure.** Use the existing `dispatch_throughput` bench + dhat to
  quantify where runtime dispatch actually costs (slot lookup? dyn dispatch? tier
  machinery for unused tiers?). **Only the proven-costly parts justify codegen.**
- **M1** `subscribe!` front-end: parse the static DSL → existing `Predicate` +
  typed tiers; generate a monomorphized packet-only fast path (the simplest, likely
  highest-win case).
- **M2** flow/session specialization + drop-unused-tier cfg/linking.
- **M3** const-fold / `OnceLock` the kernel filter from the static subscription.
- **M4** docs (when to reach for the macro vs the builder; the codegen model).

## 5. Testing
- Equivalence: the macro path and the runtime-builder path must produce **identical
  dispatch behavior** for the same subscription — a parameterized test runs both
  over the same pcap and asserts equal events (the macro is an optimization, not a
  semantic change).
- The dispatch-throughput bench + dhat Δ0 are the gates (no per-packet alloc;
  measurable improvement over the runtime path on the specialized case, else the
  complexity isn't worth it — **be willing to not ship M2/M3 if M0 shows the
  runtime path is already cheap enough**).
- `trybuild` compile-fail tests for malformed `subscribe!` input (good diagnostics).

## 6. Risks & open decisions
- **Measurement-gated, hard stop.** Benchmarks were intentionally dropped from the
  roadmap, but this theme *specifically* needs the existing `dispatch_throughput`
  micro-bench + dhat to justify itself. If runtime dispatch is already near the
  ceiling, **ship M1 (ergonomic macro) only, or shelve entirely** — do not build
  codegen against a guessed cost.
- **Proc-macro complexity + diagnostics.** A DSL macro is a maintenance + error-
  message burden; keep the grammar a strict subset of the existing `.expr()` +
  typed tiers, and lean on `trybuild` for good errors.
- **Duplication risk.** Two dispatch paths (runtime + generated) must not drift —
  the equivalence test is the guardrail; share the `Predicate`/compiler core so
  only the *front-end* and *linking* differ.
- **Open:** macro (`subscribe!`) vs const-generic builder. Recommend the macro —
  const generics can't easily drop tier *linking* or fold the kernel filter; a
  proc-macro can. Revisit if const-eval grows the capability.
