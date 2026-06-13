# netring — Deep Strategic Review & Roadmap (2026-06)

> Status: **discussion draft for review.** Analysis written 2026-06-13 against
> `netring` 0.23-dev + `flowscope` 0.14.1. Inputs: a full read-only codebase
> audit, a competitive-landscape survey (Rust crates, Retina, Suricata/Zeek/nDPI,
> kernel I/O techniques), and a production-NSM feature-expectation survey. The
> brief explicitly allowed breaking changes and ground-up redesign, so this
> document is deliberately ambitious — treat the "Redesign" sections as options,
> not commitments. Sources at the end.

---

## 0. TL;DR

netring is a **mature, unusually clean** zero-copy capture library (AF_PACKET
TPACKET_v3 + AF_XDP) with a genuinely differentiated high-level layer: a typed,
declarative `Monitor` API, anomaly sinks, a report stream, per-CPU sharding, and
pcap replay. Almost no tech debt (0 TODOs, ~120 well-documented `unsafe` blocks,
dhat-verified zero-alloc hot path). The hard part — a correct, fast, ergonomic
capture+dispatch core — is **done**.

The gap is **not** quality; it's **reach and positioning**. The market has a
clear shape in 2026, and netring sits in a defensible but under-exploited niche:

> **Strategic thesis.** Position netring as *"the Rust, line-rate **feature-emitter
> and declarative monitoring substrate** for NSM/NDR"* — not a competing IDS. It
> should capture at line rate (AF_XDP/AF_PACKET), track flows/sessions (flowscope),
> let users express detection declaratively (`Monitor`), and **emit everything
> downstream tools already understand** (EVE JSON, IPFIX/NetFlow, OTLP, Kafka,
> Arrow). ML, response, and clustering stay downstream — which is exactly where the
> 2025–26 NDR market says the value-add lives, and it keeps the library fast and
> dependency-light.

Its **one structural advantage over the closest peer** (Stanford's Retina, a
Rust 100 Gbps analysis framework on DPDK): netring is on **AF_XDP + XDP/eBPF**,
so it can **push filters into the kernel** and shed traffic *before* userspace —
something a DPDK design cannot do as cheaply. That, plus Rust safety and
*library* ergonomics (embeddable, testable with pcaps), is the wedge.

The three highest-leverage moves:
1. **Close the production-output gap** — JA4, IPFIX/NetFlow export, OTLP, Kafka,
   and **drop/backpressure as first-class telemetry**. These are table-stakes and
   mostly "we already have the state, this is serialization/transport."
2. **Adopt Retina's explicit 3-tier subscription model + filter pushdown** as the
   `Monitor`'s organizing principle, with filters compiled to BPF/XDP at the kernel.
3. **Tidy the foundations that will otherwise bite at scale** — feature-flag
   sprawl, the async-handler `Ctx` wart, miri/fuzz coverage for the `unsafe`,
   docs consolidation.

---

## 1. What netring is today (the honest strengths)

These are real and worth protecting through any redesign:

- **Zero-copy core with a sound lifetime model.** mmap ring with RAII block
  release, strict-provenance pointer math, `unsafe impl Send for MmapRing` done
  correctly. dhat proves **Δ0 bytes / 0 blocks** over 100k dispatches.
- **A type-safe protocol/dispatch system.** `Protocol`/`FlowProtocol`/`MessageProtocol`
  roles make `on::<Tcp>` and `FlowStarted<Http>` *compile errors*. TypeId-keyed
  dispatch with no hashing on the hot path.
- **A declarative `Monitor`** that already does what most people reach for Suricata
  scripts to do: typed lifecycle events, per-app bandwidth, ICMP-error correlation,
  TCP-reset detection, periodic reports, broadcast subscribers, layered sinks.
- **In-tree cBPF compiler** (no libpcap/clang/tcpdump dependency) + software interp.
- **Operational primitives already present:** PACKET_FANOUT modes, per-CPU
  `ShardedRunner` + cross-shard merge, busy-poll trio, pcap replay, drain timeouts,
  AF_XDP self-loader via aya.
- **Library-grade DX seeds:** pcap replay = deterministic detector testing;
  `AnomalySink`/`ReportSink`/`PacketSource` traits = clean extension points;
  EVE-JSON + Prometheus sinks already shipped.
- **Discipline:** zero TODOs, clean clippy `--all-features -D warnings`, rustdoc
  `-D warnings`, MSRV-pinned CI, cargo-deny + cargo-machete.

**Whitespace netring occupies that few others do:** almost no Rust crate combines
*zero-copy capture + stateful flow/session tracking + a declarative API*. `pcap`
and `pnet` are stateless/sync; `xsk-rs`/`afxdp` are low-level AF_XDP plumbing;
`etherparse`/`pdu` are stateless parsers; Retina is DPDK + research-grade. netring
+ flowscope is the only one assembling the whole stack in safe Rust.

---

## 2. Pain points (what to fix regardless of strategy)

Ordered by leverage. Citations are `file:line` into `netring/`.

### 2.1 Async handlers can't touch `&mut Ctx` (ergonomic wart)
`AsyncHandler<E>` receives only `&E::Payload`, never `&mut Ctx` (`src/monitor/
async_handler.rs:7-32`). The HRTB lifetime gymnastics over `Ctx<'a>` don't
compose in stable Rust, so any "inspect state, then do async I/O" path forces a
two-stage pattern (sync handler updates state → `ChannelSink`/`Arc<Mutex>` →
async worker). This is the single most-felt API limitation. **It deserves a
real design pass** (see §5.4), not just a doc workaround.

### 2.2 Feature-flag sprawl + non-Linux foot-guns
~20 features with non-obvious couplings (`flow` forces `parse`; the `monitor`
vs `monitor-quickstart` split; `xdp-loader` is all-or-nothing and pulls `aya`).
CI only exercises a couple of combinations. A macOS user who pulls
`monitor-quickstart` fails deep in the aya tree with no friendly message. The
core low-level I/O is orthogonal to the monitor stack, but the gating *implies*
they're coupled. **Flatten and document the feature graph; add a top-level
`compile_error!` for non-Linux with a clear message; expand CI's combination
matrix** (`Cargo.toml:76-148`, `.github/workflows/ci.yml`).

### 2.3 The `Packets` lifetime-erasure pattern is sound-but-unverifiable
`src/afpacket/rx.rs:~410-454` `transmute`s `Packet<'cap>`/`BatchIter`/`PacketBatch`
to `'static` to thread a lending iterator through `Iterator::next()`. Documented
("for-loop is sound; `.collect()` is not"), but the compiler gives **no help** —
a user `.collect()` silently extends borrows past the batch. **No miri in CI.**
This is the highest-risk `unsafe` in the crate. Mitigations: a miri job (even
loopback-free unit coverage of the iterator), and/or a safer surface that makes
the unsound `.collect()` impossible (a `for_each`-style consumer, or returning
owned `OwnedPacket` from the ergonomic path and reserving borrowing for an
explicit `unsafe`/scoped API).

### 2.4 Dispatcher caps + type-erasure fragility
`MAX_EVENT_TYPES = 16` (`src/monitor/dispatcher.rs:23`) is an `ArrayVec` cap that
fails the build with `TooManyEventTypes` — fine for realistic detectors, but the
error doesn't explain the cap, and a large multi-protocol monitor could hit it.
The `Arc<dyn Fn(*const (), …)>` type-erasure (`dispatcher.rs:37`) is sound by
registry invariant but has no in-band type tag; a registry bug is silent type
confusion. **Acceptable today; revisit if the dispatch core is redesigned (§5).**

### 2.5 TX path is spartan
`src/afpacket/tx.rs` is frame-based V1 with batch alloc + per-frame send. No
TX-side BPF, no pacing/rate-limit/priority, no async `on_tx_packet` symmetry with
RX, no TX hardware timestamping/offload, no "inject from a `Stream`." Fine for
basic forwarding/packet-gen; a gap if netring wants to be a full dataplane tool.

### 2.6 Drop / backpressure visibility is not first-class
This is both a pain point *and* a table-stakes feature gap (see §4.3). Suricata
users live in `stats.log` chasing capture/kernel/ring drops; a capture library
that doesn't surface per-worker drop + slow-subscriber backpressure honestly is
not trusted in production. Stats exist at the socket level but aren't elevated
into the `Monitor`'s telemetry/report stream as named, per-worker signals.

### 2.7 Testing breadth
~330 tests (unit + root-gated integration) + a dhat regression bench is good, but:
no **fuzzing** (the in-tree BPF compiler + bytecode gen is custom and a perfect
fuzz target), only one **proptest** file, no **miri** (see §2.3), no **loom** for
the multi-shard/merge concurrency, no **throughput assertions** (`throughput.rs`
times but doesn't gate), and integration is **loopback-only** (no real-NIC or
AF_XDP-on-NIC CI, understandably). 

### 2.8 Docs split across two trees
`docs/` (root) vs `netring/docs/` causes real discovery friction (e.g.
`WRITING_DETECTORS.md` lives in the nested tree; README links resolve differently
from root vs crate). Consolidate to one tree with a clear index.

### 2.9 eBPF bandwidth backend is design-only
`docs/EBPF_BANDWIDTH.md` exists; the implementation is a soft `RollingRate` over
`FlowPacket`. Reasonable, but the "eBPF" story is aspirational — either ship a
real opt-in XDP/eBPF aggregation path (§3, §5.2) or stop implying it's imminent.

---

## 3. Where netring should *lead* — the strategic differentiators

These are the moves that make netring distinctive rather than just complete.

### 3.1 Retina's subscription model + **filter pushdown into the kernel**
Retina's proven abstraction: users *subscribe* to **packets**, reassembled
**connections (flows)**, or parsed **sessions**, each with a **filter + callback**;
filters are **compiled (Wireshark-like syntax) into a memory-safe Rust function,
inlined** into the path; **multi-stage filtering** sheds work as early as possible;
v1.1 added **multiple concurrent subscriptions** with distinct datatypes. This is
*exactly* the mental model netring's `Monitor` is groping toward — adopt it
explicitly (§5.1).

netring's edge: Retina is on **DPDK**, so its earliest filter stage is still in
userspace. netring is on **AF_XDP/XDP** and ships an aya loader — it can compile
the cheapest filter predicates **down to BPF (socket filter) and XDP (in-kernel)**
and drop unwanted traffic *before it ever reaches userspace*. That is a genuine,
defensible performance story Retina structurally cannot match. **"Retina's API,
but the first filter stage runs in the kernel."**

### 3.2 Modern fingerprinting & encrypted-traffic features (mostly in flowscope)
TLS is >95% of web traffic; payload DPI is dead for most flows. The frontier is
behavioral/encrypted analysis:
- **JA4** (TLS client fingerprint) — the single highest-value detection feature;
  resists the TLS-extension randomization that broke JA3 (Chrome 110+/Firefox 114+);
  now in Suricata 8, Zeek, Wireshark, Arkime. **BSD-3, no patent claims** → safe to
  implement in MIT/Apache Rust. **Belongs in flowscope** (computational), surfaced
  through netring's TLS events.
- **JA4+ suite** (JA4S/JA4H/JA4X/JA4L/JA4SSH…) — license-gated (**FoxIO License
  1.1**: free for OSS/internal, OEM license to *sell*). Feature-flag it and document
  the obligation (Arkime's toggle is the model).
- **ETA feature emission** — packet-size distributions, inter-arrival timing, flow
  directionality, burst patterns. netring's per-flow + report model is ideal for
  *emitting these vectors*; the ML lives downstream. This is a strong, defensible
  niche and respects "no heavy deps in lib crates."
- **Beaconing/C2** via inter-arrival periodicity; **DNS analytics** (entropy, long
  subdomains, query-rate baselines) — both map onto existing report/correlate
  machinery.

### 3.3 Be the best **export** layer in Rust
A modern NSM component is judged on producing output other tools already ingest.
netring already builds flow state — so the marginal cost is serialization/transport:
- **IPFIX / NetFlow v9/v10** export — IETF-standard flow telemetry; consider reusing
  **`netgauze-flow-pkt`** (Rust, IANA-IE codegen) rather than hand-rolling.
- **OTLP (OpenTelemetry)** — the format with the most momentum; the OTel Collector
  already ships a `netflowreceiver` and there's an eBPF network workgroup. Native
  OTLP makes netring a first-class OTel citizen.
- **Kafka/Redpanda** sink — required at SOC scale; maps onto the existing
  broadcast-subscriber model.
- **Arrow/Parquet (+ Arrow Flight)** — columnar analytics output; few capture tools
  offer it and arrow-rs/parquet-rs are first-class. A Rust-native differentiator.
- Keep tracking the **EVE JSON schema** (already shipped) and add **syslog**.

### 3.4 A real filter/expression language story
Two complementary layers:
- **Compile-time**: macro/codegen that turns declarative filters into inlined,
  type-checked Rust predicates (Retina-style) — zero overhead, compile-verified.
- **Runtime**: for operator-supplied/dynamic filters, **reuse Cloudflare's
  `wirefilter`** (Wireshark-style syntax over a typed schema, optimizing compiler)
  rather than building a parser. wirefilter for dynamic, macros for static.

### 3.5 Plugin system + sandboxed detection DSL (the "library" feature)
What most makes netring a *library* rather than a daemon:
- A clean **third-party analyzer trait** ("bring-your-own-protocol-parser"),
  the Rust analog of Zeek's Spicy.
- A **compiled, sandboxed detection-expression layer** (Rhai or a small VRL-like
  DSL) for hot-path logic — *not* embedded Lua/WASM. (Vector deliberately steers
  users from Lua to its compiled VRL and removed its WASM transform; same lesson.)

### 3.6 Self-observability as a differentiator
Round out **self-metrics** (packets/bytes/**drops**/ring-full/active-flows/mem,
*per worker*), add **health/readiness** structs/endpoints for K8s, ship a
`tracing` JSON facade, and — uniquely — **OpenTelemetry self-tracing** of the
capture→parse→detect→sink pipeline. Few NSM tools instrument *themselves* with OTel.

### 3.7 Watch io_uring **ZC RX** as a future backend
io_uring zero-copy receive (kernel 6.x) keeps kernel TCP processing while DMA-ing
payloads to userspace — the *opposite* tradeoff from AF_XDP's raw frames, and ideal
for **session-level** subscriptions (kernel does reassembly; netring consumes
payloads zero-copy). This argues for a **pluggable capture-backend abstraction**
(§5.2) now, so a ZC-RX backend can drop in later.

---

## 4. Feature roadmap — prioritized

Mapped to which crate owns the work. **flowscope** = computational/parsing/no-tokio;
**netring** = async/capture/sinks/transport/orchestration.

### 4.1 Table-stakes (do these to be credibly "production-grade")
| Feature | Crate | Notes |
|---|---|---|
| **JA4** fingerprinting | flowscope | #1 detection feature; BSD-3, safe. Surface via netring TLS events. |
| **Drop/backpressure telemetry** | netring | Per-worker capture/kernel/ring-full drops + honest slow-subscriber semantics, in report stream + Prometheus. Also a pain point (§2.6). |
| **IPFIX / NetFlow export** | netring (model in flowscope) | Reuse `netgauze-flow-pkt`. You already have the flow state. |
| **OTLP output** | netring | Native OpenTelemetry; high momentum. |
| **Kafka sink** | netring | SOC-scale requirement; fits broadcast-subscriber model. |
| **Hot config/detector reload** | netring | Swap detectors/filters without tearing down capture. |
| **QUIC + HTTP/2 (→HTTP/3) visibility** | flowscope | The gap legacy tools handle worst; QUIC Initial + JA4-over-QUIC. |
| **NUMA pinning + flow-symmetric steering** | netring | Document the asymmetric-RSS-hash pitfall (two flow directions → different queues). Helpers via rtnetlink/ethtool. |
| **Health/readiness + `tracing` JSON logs** | netring | K8s expectation. |
| **syslog sink** | netring | Cheap; large install base. |

### 4.2 Differentiators (where netring leads)
| Feature | Crate | Notes |
|---|---|---|
| **3-tier subscription model + kernel filter pushdown** | netring | §3.1/§5.1 — the headline. |
| **ETA / beaconing feature emission** | flowscope (emit) | Feature vectors out, ML downstream. |
| **JA4+ suite** (license-gated) | flowscope | FoxIO 1.1 — feature-flag + document. |
| **Arrow/Parquet (+ Flight) output** | netring | Rust-native analytics export. |
| **OTel self-tracing** of the pipeline | netring | Pairs with OTLP output. |
| **Analyzer plugin trait + sandboxed detection DSL** | both | Spicy-analog + Rhai/VRL-style, not Lua/WASM. |
| **Runtime filter language (wirefilter)** | netring | Complements compile-time macros. |
| **Real eBPF/XDP pre-filter & aggregation** | netring | Make the design doc real, opt-in. |

### 4.3 Nice-to-have / vertical / probably-out-of-scope
sFlow export · file extraction+hashing (heavy, platform-tier) · ICS/OT parsers
(Modbus/DNP3/… — vertical; cheaper once the plugin DSL lands) · Zeek-log-compatible
output · Suricata-rule ingestion + "datasets" IOC-matching (the datasets primitive
is the high-value subset) · clustering/HA · a thin reference daemon + container image
(adoption nicety) · Windows/macOS (high effort, low demand — AF_PACKET/AF_XDP are
Linux-only).

**Explicitly leave downstream:** ML/anomaly *models*, automated response, SIEM
correlation. Gartner 2025: by 2027 <40% of detected anomalies get automated
response — the value is good, explainable *features*, not models in the capture lib.

---

## 5. Redesign opportunities (breaking changes on the table)

The brief allowed "redesign everything." These are the structural bets worth
considering for a 1.0 line.

### 5.1 Make the `Monitor` an explicit 3-tier subscription engine
Today the `Monitor` is a flat handler table over typed events. Reframe it around
Retina's proven tiers, each with its own filter and one-or-more output datatypes,
with **many concurrent subscriptions sharing one capture+flow substrate**:

```
Monitor::builder()
  .subscribe(packet().filter("tcp port 443").to(sink_a))     // packet tier  → BPF/XDP
  .subscribe(flow().filter("tcp and bytes > 1MB").to(sink_b)) // connection tier
  .subscribe(session::<Tls>().filter("tls.sni ~ \"*.bank\"").to(sink_c)) // session tier
```

Filters compile to a **multi-stage pipeline**: cheapest predicates → **BPF socket
filter / XDP program (kernel)**; flow-level predicates → before flow-state alloc;
session predicates → after L7 parse. Work is shed at the earliest possible stage —
the Retina performance unlock, made stronger by netring's kernel access. The
existing `on::<E>` API can remain as sugar over the packet/session tiers.

### 5.2 A pluggable **capture-backend** abstraction
Introduce a `CaptureBackend` trait so the `Monitor` is backend-agnostic:
`AfPacket` (TPACKET_v3, universal fallback), `AfXdp` (zero-copy w/ copy-mode +
cloud/virtio detection & graceful fallback), `Pcap` (offline), and later
`IoUringZcRx` (session-tier, kernel reassembly). One `Monitor`, swappable I/O.
This also forces a clean answer to the AF_XDP "zero-copy unavailable in cloud VMs"
caveat (virtio lacks steering → must fall back to copy mode and *say so*).

### 5.3 Decouple core I/O from the monitor in the feature graph
The low-level capture/inject/XDP API and the high-level monitor stack are
conceptually independent; the feature gating shouldn't conflate them. Flatten to a
small set of orthogonal axes (backend × parse-depth × sinks), provide 2–3 honest
umbrellas, and gate non-Linux with a clear `compile_error!`. Publish a **feature
matrix** ("bare capture: `[]`; monitoring: `tokio,flow,parse`; everything:
`full`").

### 5.4 Solve async-handler `Ctx` access properly
Options to evaluate (pick one, breaking is fine):
- **Command/effect return** — async handlers return a `Vec<Effect>` (emit, set-state,
  enqueue) applied synchronously by the run loop; no `&mut Ctx` across `.await`,
  fully `Send`, and composable.
- **Owned `Ctx` snapshot** — hand async handlers a `Send` snapshot + a command
  channel back to the loop.
- **Actor-per-shard** — the run loop owns state; handlers send messages.
The command-return model is the most idiomatic and dovetails with the new
`Send` run loop (0.23) and the subscription redesign.

### 5.5 Split responsibilities crisply across the two crates
Make the boundary a documented contract: **flowscope** owns everything
computational and `no-tokio` (parsers, reassembly, JA4/JA4+, ETA feature
extraction, IPFIX *field model*, correlate primitives); **netring** owns async,
capture backends, the subscription engine, sinks/exporters (IPFIX/OTLP/Kafka/Arrow
*transport*), steering/NUMA helpers, hot reload, self-observability. This keeps the
hot computational paths dependency-light and reusable, per the existing constraint.

---

## 6. Performance roadmap

netring's realistic ceiling on commodity NICs is **single-digit-to-low-tens of
Mpps/core** with AF_XDP zero-copy — below DPDK's ~18 Mpps/core, but **without
DPDK's exclusive-NIC, high-idle-CPU operational cost**, and coexisting with the
kernel stack/tooling. The pitch: *"DPDK-adjacent capture throughput with
kernel-native operability."* To get and prove it:

- **Batched ring draining** (already block-based on AF_PACKET; ensure AF_XDP RX
  drains in ring batches, not per-descriptor).
- **Prefetch** next descriptor/header while parsing current (DPDK idiom).
- **NUMA pinning** of NIC queue + UMEM + worker + flow shard on one node.
- **Hugepage-backed UMEM** (2M/1G) to cut TLB misses (reported ~28% gains).
- **Early filter pushdown** to XDP/BPF (§5.1) — the biggest single win; drop
  before reassembly/alloc.
- **Per-flow CPU steering** (PACKET_FANOUT `cluster_flow` / per-queue XSKs) so each
  core owns disjoint flows → lock-free shard-local state (already aligned with the
  cross-shard merge design); add **symmetric-hash** handling so both directions of
  a flow land on the same worker.
- **Make perf a gate, not a vibe:** add a throughput bench with assertions and a
  pps/latency regression check alongside the dhat job.

---

## 7. Quality & operability hardening

- **miri** job covering the `Packets` lifetime-erasure and pointer math (§2.3).
- **cargo-fuzz** targets for the BPF compiler/bytecode-gen and any custom parsing.
- **proptest** for flow tracking, split helpers, layer chains, BPF interp↔compile
  equivalence.
- **loom** for the multi-shard merge worker and any cross-thread channel handoff.
- **Expanded feature-combination CI** (the untested combos in §2.2).
- **Drop/backpressure telemetry** wired into the report stream (§2.6/§4.1).
- **Docs consolidation** to one tree + a single index; promote pcap-replay testing
  to a documented, first-class "test your detectors" workflow (a real selling point).
- **Reference daemon + container image** (thin) to lower adoption friction without
  bloating the library.

---

## 8. Suggested sequencing (themes, not dates)

A possible ordering that front-loads credibility and de-risks the big redesign:

- **M1 — "Production output & trust"** (mostly additive, high ROI):
  JA4 (flowscope) · drop/backpressure telemetry · IPFIX export · OTLP + Kafka sinks ·
  health/readiness + `tracing` JSON · syslog. Plus the cheap hardening: miri + fuzz
  jobs, feature-matrix docs + non-Linux `compile_error!`, docs consolidation.
- **M2 — "Modern visibility"**: QUIC/HTTP2 (flowscope) · ETA/beaconing feature
  emission · NUMA + symmetric steering helpers · hot reload · Arrow/Parquet output ·
  OTel self-tracing.
- **M3 — "The redesign" (1.0 line, breaking)**: 3-tier subscription engine +
  kernel filter pushdown · pluggable capture-backend trait · async-handler `Ctx`
  via command-return · feature-graph flattening · crate-boundary contract · runtime
  filter language (wirefilter) + analyzer plugin trait + sandboxed detection DSL.
- **M4 — "Frontier/optional"**: real eBPF/XDP aggregation backend · io_uring ZC RX
  backend · JA4+ (license-gated) · file extraction · ICS/OT parsers · reference daemon.

This keeps every milestone shippable on its own, defers the breaking redesign until
the additive wins have built credibility, and ensures the foundational hardening
(miri/fuzz/feature-graph) lands *before* the big surface-area changes.

---

## 9. Risks & open questions for you

1. **Product identity.** Is netring a *library* (embed/compose/test) first, or do
   you also want a *daemon/product*? The recommendation is library-first with a thin
   reference daemon — but it changes prioritization (e.g., clustering, rule DSL).
2. **flowscope coupling.** Much of the high-value detection work (JA4, ETA, QUIC)
   lands in flowscope. Are you comfortable driving both crates in lockstep, and is
   the `no-tokio`/computational boundary one you want to keep hard?
3. **Breaking appetite & 1.0.** Is the 3-tier subscription redesign worth a 1.0
   reset, or should the current `Monitor` evolve incrementally? (It can evolve — the
   subscription API can wrap the existing dispatch.)
4. **License posture.** JA4 (BSD-3) is clean; **JA4+ (FoxIO 1.1)** restricts
   *selling*. Acceptable to feature-gate + document, or avoid entirely?
5. **Scope discipline.** The temptation is to chase Suricata's feature list. The
   thesis says *don't* — be the substrate, not the IDS. Agree?
6. **Hardware testing.** Real-NIC/AF_XDP perf claims need a test rig. Is there
   hardware to stand up a throughput/latency CI lane, or do we rely on loopback +
   manual validation?

---

## Appendix A — codebase audit highlights (file:line)

- Public API surface: `src/lib.rs`, `src/monitor/mod.rs:83-152`, `src/protocol/mod.rs:65-100`,
  `src/ctx/mod.rs:70-155`, `src/anomaly/mod.rs:34-76`, `src/config/mod.rs`, `src/traits.rs:37-118`.
- `unsafe`: ~120 blocks; densest in `afpacket/ring.rs` (mmap math, sound),
  `afpacket/rx.rs:~410-454` (lifetime erasure — highest risk), `ctx/split.rs:54-100`
  (disjoint-field projection, sound), `afxdp/ring.rs` (some under-documented).
- Tech-debt signals: **0** TODO/FIXME/HACK in `src/`; ~12 documented `#[allow]`;
  no deprecated items (0.19 API fully removed in 0.22); panics in non-test code are
  graceful fallbacks or invariant asserts.
- Dispatch: `MAX_EVENT_TYPES=16` (`dispatcher.rs:23`); `Arc<dyn Fn(*const(),…)>`
  type-erasure (`dispatcher.rs:37`).
- Tests: ~330 (unit + root-gated integration) + dhat Δ0 bench; gaps: no
  miri/fuzz/loom, one proptest file, loopback-only integration, no perf gate.
- Features: ~20 flags; `monitor`/`monitor-quickstart` umbrellas; `flow`→`parse`
  coupling; `xdp-loader` all-or-nothing.

---

## Appendix B — Sources

**Rust crates & frameworks**
- pcap: https://docs.rs/pcap · https://deepwiki.com/rust-pcap/pcap/2.4-packet-processing
- libpnet: https://github.com/libpnet/libpnet
- xsk-rs / afxdp-rs: https://github.com/aterlo/afxdp-rs · https://lib.rs/crates/afxdp
- aya (eBPF/XDP, Rust): https://github.com/aya-rs/aya · https://aya-rs.dev/book/programs/xdp
- etherparse: https://docs.rs/etherparse · pdu: https://lib.rs/crates/pdu · smoltcp: https://crates.io/crates/smoltcp
- Retina: https://github.com/stanford-esrg/retina · https://zakird.com/papers/retina.pdf · https://dl.acm.org/doi/abs/10.1145/3544216.3544227 · https://inl.info.ucl.ac.be/ensg/2022/09/01/retina.html
- NetGauze (IPFIX/NetFlow in Rust): https://github.com/NetGauze/NetGauze · https://lib.rs/crates/netgauze-flow-pkt
- wirefilter (Cloudflare): https://github.com/cloudflare/wirefilter · https://blog.cloudflare.com/building-even-faster-interpreters-in-rust/

**Incumbents & production NSM**
- Suricata EVE JSON: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html · AF_PACKET: https://docs.suricata.io/en/latest/performance/packet-capture.html · rule reload: https://docs.suricata.io/en/latest/rule-management/rule-reload.html · datasets: https://docs.suricata.io/en/latest/rules/datasets.html · QUIC: https://docs.suricata.io/en/suricata-7.0.4/rules/quic-keywords.html · 8.0 release: https://suricata.io/2025/07/08/suricata-8-0-0-released/
- Zeek JA4: https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/ · Spicy: https://docs.zeek.org/projects/spicy/en/latest/zeek.html
- nDPI/ntop: https://www.ntop.org/introducing-ndpi-v3-encrypted-malware-traffic-analysis-with-ease/ · https://www.ntop.org/beyond-ja3-ja4-introducing-ndpi-traffic-fingerprint/ · https://www.ntop.org/enabling-zeek-and-suricata-on-demand-at-40-100-gbit-using-pf_ring/
- JA4 spec/license: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md · https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md · JA3 fade: https://www.stamus-networks.com/blog/ja3-fingerprints-fade-browsers-embrace-tls-extension-randomization
- NDR market: https://corelight.com/blog/gartner-ndr-leader-2025 · https://www.stamus-networks.com/suricata-vs-zeek

**Kernel / I/O techniques**
- AF_XDP: https://docs.kernel.org/networking/af_xdp.html · https://docs.ebpf.io/linux/concepts/af_xdp/ · ZC unavailable in cloud VMs: https://lwn.net/Articles/756549/
- io_uring ZC RX: https://docs.kernel.org/networking/iou-zcrx.html · https://lwn.net/Articles/994603/
- Timestamping/PTP: https://docs.kernel.org/networking/timestamping.html
- Steering (RSS/RPS/RFS/aRFS): https://medium.com/@tom_84912/the-alphabet-soup-of-receive-packet-steering-rss-rps-rfs-and-arfs-c84347156d68
- eBPF observability (Cilium/Tetragon): https://tetragon.io/ · https://oneuptime.com/blog/post/2026-01-07-ebpf-network-traffic-monitoring/view
- DPDK/VPP perf: https://medium.com/google-cloud/forwarding-over-100-mpps-with-fd-io-vpp-on-x86-62b9447da554

**Output formats & DX**
- OTel netflowreceiver: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/netflowreceiver/README.md · OTel-network: https://github.com/open-telemetry/opentelemetry-network
- Arrow/Parquet/Flight: https://www.influxdata.com/blog/apache-arrow-parquet-flight-and-their-ecosystem-are-a-game-changer-for-olap/
- Vector VRL (vs Lua/WASM): https://vector.dev/docs/reference/vrl/
- flow protocols (IPFIX/NetFlow/sFlow): https://library.nagios.com/monitoring/netflow-sflow-ipfix-which-flow-protocol-should-you-use/
