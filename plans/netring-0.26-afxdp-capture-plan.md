# netring 0.26 — AF_XDP Multi-Queue Capture & Hardening

> **Status:** in progress, updated 2026-06-16. The last *feature* release before
> 1.0 stabilization. Closes the AF_XDP-capture gaps surfaced reviewing issue #4
> (promiscuous, PR #5) and tracked in **issue #6**. Breaking changes are
> permitted (the maintainer authorized redesign); inventoried in §7, aligned to
> the **one break at 1.0** SemVer model
> ([`netring-architecture.md`](./netring-architecture.md) §7).
>
> **Progress:** M0 (promiscuous) shipped in **PR #5** (merged). M1 (queue
> discovery: `queue_count`/`Queues`) + M2 (`XdpCapture` sync handle) shipped in
> **PR #7** (merged). Remaining: the **threading-model redesign** below (§4.5) →
> M3/M4/M5.
>
> **Redesign note (2026-06-16).** Implementing M2 + researching how Suricata/DPDK
> actually run multi-queue AF_XDP changed the Monitor-integration design. The
> performant production model is **worker-per-queue** (one socket per core +
> busy-poll — Suricata `threads: auto`), *not* a single async reactor draining N
> queues. That maps onto netring's existing **`ShardedRunner`**. So the plan is
> now **tiered** (§4.5): a simple single-reactor path *and* a sharded
> worker-per-queue path, mirroring how the rest of netring scales (plain Monitor
> vs `ShardedRunner`). This supersedes the earlier "one `AnyBackend::Xdp` per
> queue in the single run loop" sketch.

---

## 1. Why — the validated model and our gap

AF_XDP is, by kernel ABI, **one socket : one netdev RX queue**. A modern NIC
spreads inbound traffic across queues via RSS, so a single socket *under-captures*
even in promiscuous mode (promisc lifts the MAC filter; it does not collapse RSS).
This is universal, not a netring quirk — and **every capture framework exposes a
higher-level multi-queue abstraction over the raw ABI**:

| Project | High-level multi-queue surface |
|---|---|
| DPDK AF_XDP PMD | `start_queue` + `queue_count` → opens N sockets across a queue range |
| Suricata | `threads: auto` → auto-detects RSS queue count, one socket/thread per queue |
| xdpdump / xdp-tools | per-queue capture, tags each packet with its receiving queue |

Sources: [kernel AF_XDP docs](https://docs.kernel.org/networking/af_xdp.html),
[DPDK AF_XDP PMD](https://doc.dpdk.org/guides/nics/af_xdp.html),
[Suricata AF_XDP](https://docs.suricata.io/en/latest/capture-hardware/af-xdp.html),
[RedHat: capturing in XDP](https://www.redhat.com/en/blog/capturing-network-traffic-express-data-path-xdp-environment).

Two further research facts that shape the design:

- **Queue-count auto-detection** is done via the `ETHTOOL_GCHANNELS` ioctl
  (`combined_count`) — this is how Suricata's `auto` works
  ([ethtool-netlink](https://docs.kernel.org/networking/ethtool-netlink.html)).
- **Shared UMEM across per-CPU sockets has a live FILL-queue race** (kernel docs;
  [LKML 2025](https://lkml.iu.edu/hypermail/linux/kernel/2504.2/00597.html)). So
  **one UMEM per socket is the correct *default*** for multi-queue capture; shared
  UMEM is a memory optimization with a sharp edge, not the baseline.

**Our gap.** The Rust AF_XDP crates (xsk-rs, xdpilone, xdp, afxdp-rs) are *socket
libraries* — none provides a multi-queue capture/monitor abstraction. That higher
layer is exactly netring's differentiator, and it is the layer the issue author
wanted ("instead of my handcrafted setup: aya, xdpilone, manual steps"). Today we
make users hand-roll it (the ~60-line `examples/xdp/xdp_multiqueue.rs` dance), and
the Monitor silently binds queue 0 only. **That is below netring's altitude.**

---

## 2. Inventory — gaps, footguns, bugs

Severity: 🔴 correctness/silent-data-loss · 🟠 ergonomics/pain · 🟡 polish.

| # | Item | Sev | Kind | Status |
|---|---|---|---|---|
| G1 | **No high-level multi-queue capture API.** Full-NIC AF_XDP = manual N-socket + program + XSKMAP dance. | 🟠 | gap | ✅ **DONE** — `XdpCapture` (PR #7, M2) |
| G2 | **Monitor binds queue 0 only** → silent under-capture on every multi-queue NIC. | 🔴 | footgun | ⏳ **M4** (the headline remaining work) |
| G3 | **No queue-count discovery.** Users must `ethtool -l` by hand; no `Queues::Auto`. | 🟠 | gap | ✅ **DONE** — `queue_count`/`Queues::Auto` (PR #7, M1) |
| B1 | **`default_program(_max_queues)` ignores its argument** — XSKMAP baked at `max_entries=256`. | 🟡 | bug/wart | ◑ **partial** — PR #7 errors loudly on queue id ≥ 256 (the silent-failure risk). Honoring the param via BTF resize, or deprecating it, deferred to M5/1.0. |
| F1 | **`shared_umem` is a footgun:** manual frame-space partitioning + the per-CPU FILL race. | 🟠 | footgun | ⏳ **M5** — `XdpCapture` defaults to per-socket UMEM (PR #7); a partitioning helper + caveats are M5. |
| F2 | **Copy-mode perf cliff** surfaced only as a log line. | 🟡 | footgun | ✅ **DONE** — `is_zerocopy()` on `XdpSocket` + `XdpCapture` (PR #7). |
| F3 | **No per-queue NUMA affinity.** `numa_node` is one value; per-queue sockets should bind each UMEM to that queue's node. | 🟡 | gap | ⏳ **M5** |
| D1 | **Promiscuous (issue #4).** Per-socket guard + monitor-wide flag. | ✅ | — | **DONE** — PR #5. |

**Where we are.** G1/G3/F2 closed and B1's sharp edge defanged in PR #7 (M1+M2).
The remaining headline is **G2** — the silent single-queue Monitor footgun — whose
fix is the threading-model work in §4.5 (M3/M4). F1/F3 are the M5 hardening.

### 2.1 Learnings from M1/M2 (don't relitigate)
- **The unified round-robin needs a *fresh* readiness probe.** First cut gated each
  socket on the cached producer index (`rx_is_empty`), which only refreshes inside
  `consumer_peek` — so it gated away its own refresh and captured nothing. Fixed
  with `rx_poll_ready` / `XdpRing::refresh_count` (one `Acquire` load). **The
  root-gated `lo` live test caught this** — keep every new drain path live-tested.
- **`XdpCapture` owns one program + N own-UMEM sockets + one promisc guard;**
  `into_parts()` hands out `(Vec<XdpSocket>, XdpCaptureGuard)` so worker threads
  can't drop the program by accident. This is the seam M4/M5 build on.
- **Feature-combo gotcha:** a helper used only by an `xdp-loader`-gated caller must
  itself be `xdp-loader`-gated or the `af-xdp`-only clippy combo fails (`-D
  warnings`). `--all-features` locally masks it — run the matrix.

---

## 3. Design — the `XdpCapture` high-level handle

A single owned handle that automates the whole multi-queue dance and is the
recommended entry point for real-NIC AF_XDP. Low-level `XdpSocketBuilder` stays as
the escape hatch (one socket, full control).

```rust
use netring::xdp::{XdpCapture, Queues, XdpFlags};

let mut cap = XdpCapture::builder()
    .interface("eth0")
    .queues(Queues::Auto)          // ETHTOOL_GCHANNELS; or ::range(0..4) / ::single(0)
    .promiscuous(true)             // ONE interface-global guard (issue #4)
    .mode(XdpMode::Rx)
    .attach_flags(XdpFlags::DRV_MODE)  // SKB default; DRV opt-in for real NICs
    .build()?;
```

**What `build()` does, in order:**
1. Resolve the queue set (`Queues::Auto` → `queue_count(iface)` via ethtool, §3.3).
2. Load the redirect program **once** (`default_program`, fixed once B1 is fixed).
3. For each queue `q`: open an `XdpSocket` with its **own UMEM** (safe default,
   per §1), `queue_id(q)`, optional per-queue NUMA pin (F3).
4. Register each socket at index `q` in the program's XSKMAP.
5. Attach the program **once** to the interface; the attachment is owned by the
   `XdpCapture` (RAII detach on drop, *after* the sockets).
6. Install **one** promiscuous guard for the interface (not per socket).

### 3.1 Draining — two shapes (both, like Suricata + DPDK) — ✅ M2

As implemented in PR #7:

```rust
// (a) Single-thread, unified round-robin — simplest:
while let Some((queue_id, batch)) = cap.next_batch_blocking(timeout)? {
    for pkt in &batch { /* … */ }
}

// (b) Worker-per-queue — scales to line rate (Suricata model):
let (sockets, guard) = cap.into_parts();     // guard owns program + promisc
let guard = std::sync::Arc::new(guard);
for sock in sockets {
    let g = guard.clone();
    std::thread::spawn(move || { let _g = g; /* drain sock on its own core */ });
}
```

`into_parts()` returns `(Vec<XdpSocket>, XdpCaptureGuard)`; the guard keeps the single
attachment + promisc alive so the worker model can't detach the program by dropping
the handle. Async mirror `AsyncXdpCapture` = **M3**. The Monitor wires (a) as Tier 1
and (b) as Tier 2 — see §4.5.

### 3.2 `Queues`

```rust
pub enum Queues {
    Single(u32),        // one queue (today's behavior; default)
    Range(Range<u32>),  // explicit span
    Auto,               // all RSS/combined queues, detected via ethtool
}
```

`Auto` resolves at build to `0..queue_count(iface)`. If detection fails (virtual
iface, `lo`, permission) it falls back to `Single(0)` with a `warn!` — never an
error, so `Auto` is always safe to default to.

### 3.3 Queue-count discovery (G3)

```rust
pub fn queue_count(iface: &str) -> Result<u32, Error>;   // netring::xdp
```

Implementation: `socket(AF_INET, SOCK_DGRAM, 0)` + `ioctl(SIOCETHTOOL,
ETHTOOL_GCHANNELS)` reading `struct ethtool_channels`. RSS queue count =
`combined_count` if non-zero, else `rx_count` (per the kernel channel model). New
ffi: `SIOCETHTOOL`, `ETHTOOL_GCHANNELS`, `struct ethtool_channels` (vendored in
`afxdp/ffi.rs` since `libc` doesn't export the ethtool structs). Standalone-useful
and unit-testable on any host (`lo` returns the fallback path).

---

## 4. Monitor integration (G2) — the silent-footgun fix

The footgun fix is the **threading-model redesign** in §4.5. The Monitor API surface
that drives it (consistent with the monitor-wide `promiscuous` decision in PR #5):

```rust
// Tier 1 — single-reactor, captures every queue on one core (the default fix):
Monitor::builder()
    .xdp_interface_loaded("eth0")
    .xdp_queues(Queues::Auto)      // monitor-wide, mirrors .promiscuous(bool)
    .promiscuous(true)
    .protocol::<Tcp>()
    .build()?;

// Tier 2 — sharded, one worker (core) per queue, for line rate:
XdpShardedRunner::new("eth0", Queues::Auto, |q, builder| builder.protocol::<Tcp>())
    .promiscuous(true)
    .busy_poll(50)                 // µs; pairs with SO_PREFER_BUSY_POLL
    .pin_cpus(true)
    .run_for(d)?;
```

`xdp_queues(Queues)` is **monitor-wide** (every AF_XDP interface) — same shape as
`promiscuous(bool)`, avoiding the positional "last-added" wart rejected in PR #5.
Default stays `Queues::Single(0)` (no behavior change until opt-in; the 1.0 break is
to default it to `Auto`, §7).

---

## 4.5 Threading model — the tiered redesign *(the important part)*

**What changed and why.** The earlier sketch — "expand one xdp interface into N
`AnyBackend::Xdp` in the single run loop" — is wrong on two counts:

1. **Program lifetime.** All N per-queue sockets share **one** attached program +
   XSKMAP. Expanding into N independent `BackendSpec`s breaks the 1-spec↔1-backend
   invariant the `Reopen` policy relies on, and there's no natural owner for the
   shared program/promisc guard.
2. **Performance.** Research (Suricata `threads: auto`, DPDK, VPP) is unanimous: the
   line-rate model is **one worker per RSS queue** (a socket per core, ideally
   busy-polled), *not* one reactor draining N queues. A single async round-robin
   caps at one core — fine for moderate rates, wrong for line rate.

So mirror how netring *already* scales — **plain Monitor vs `ShardedRunner`** — with
**two tiers** over the same `XdpCapture` core:

### Tier 1 — single-reactor (`AnyBackend::XdpMq`, M3+M4)
One `AsyncXdpCapture` (N sockets, owns the program) wrapped as a **single**
`AnyBackend::XdpMq` arm. `readable().await` awaits readiness across the N fds;
`drain_batch(f)` round-robins all ready queues synchronously (zero-copy, `Send`
preserved — same borrowed-batch discipline as Arch §3, one socket at a time). This:
- **preserves 1-spec↔1-backend** → `Reopen` rebuilds the whole `XdpCapture`, the
  program/promisc guard lives *inside* the backend (no side-vec);
- **removes G2** for the common case — `.xdp_queues(Auto)` now captures every queue;
- is single-core (the honest limitation; Tier 2 is the answer for line rate).

`AsyncXdpCapture` (M3) = `XdpCapture` + one `tokio::AsyncFd` per socket; `readable`
is a `poll_fn`/`select` over them (any-ready wins). This is the only genuinely new
async machinery, and it's small.

### Tier 2 — sharded worker-per-queue (`XdpShardedRunner`, M5)
The performant path, parallel to `ShardedRunner` (AF_PACKET fanout). The coupling
that makes AF_XDP different from `PACKET_FANOUT`: the **program is shared setup**, not
per-worker. So:
- Build **one** `XdpCapture` (program + N sockets + promisc) up front; `into_parts()`
  → `(Vec<XdpSocket>, XdpCaptureGuard)`.
- Spawn one OS thread per queue (reuse `ShardedRunner`'s thread/`current_thread`-rt/
  CPU-pin/merge-worker machinery); shard `i` runs a single-shard `Monitor` whose
  backend **is the provided `sockets[i]`**.
- The `XdpCaptureGuard` is held by the runner (in an `Arc`) for the run's duration so
  the program outlives every shard.
- **New seam required:** the Monitor must accept a *pre-built* AF_XDP backend (today
  it only builds its own from a spec). Add `BackendSpec::XdpProvided(AsyncXdpSocket)`
  (or `MonitorBuilder::xdp_socket(socket)`), drained through the existing
  `AnyBackend::Xdp` arm. This is the one architectural addition; it also future-proofs
  "bring your own socket" use cases.
- **Perf knobs** (Suricata-validated): per-socket busy-poll
  (`SO_BUSY_POLL`/`SO_PREFER_BUSY_POLL`/`SO_BUSY_POLL_BUDGET` — already on
  `XdpSocketBuilder`, thread through `XdpCapture`), CPU pinning (have it), and
  *document* the system NAPI knobs (`napi-defer-hard-irqs`, `gro-flush-timeout`) that
  make busy-poll effective — netring sets the socket opts, the operator sets the
  netdev knobs.

**Why both, not just Tier 2.** Tier 2 needs N cores and is overkill for a flow
monitor at 1–5 Gbps; Tier 1 is one builder flag. Offering both matches plain-Monitor
↔ `ShardedRunner` and lets the footgun fix (Tier 1) ship before the heavier Tier 2.

**Decisions locked:** monitor-wide `xdp_queues` (symmetry, §9 Q3); Tier 1 via a new
`AnyBackend::XdpMq` arm (not spec-expansion); Tier 2 via `XdpShardedRunner` +
`BackendSpec::XdpProvided`.

---

## 5. Footgun & bug fixes

- **B1 — `default_program` max_queues** — ◑ *partial (PR #7), rest M5.* PR #7 errors
  loudly on queue id ≥ 256 (the XSKMAP cap), killing the silent-failure risk. M5:
  either (a) **honor** `max_queues` via aya BTF map-resize before load, or (b)
  `#[deprecated]` the param and document the fixed 256 cap. A lying parameter is worse
  than an honest constant.
- **F1 — `shared_umem`** — ⏳ *M5.* Default is already **per-socket UMEM** (PR #7), so
  the safe path is the easy path. M5: re-document the raw `XdpSocketBuilder::shared_umem`
  with the per-CPU FILL-race caveat, and add a guarded `XdpCapture::shared_umem(true)`
  opt-in that does the frame-space partitioning *for* the user (Q6).
- **F2 — copy-mode** — ✅ *done (PR #7).* `XdpSocket::is_zerocopy()` /
  `XdpCapture::is_zerocopy()` surface the bind mode; the `lo` live test asserts
  `is_zerocopy() == false` under SKB.
- **F3 — per-queue NUMA** — ⏳ *M5.* `XdpCapture` optionally pins each queue's UMEM to
  that queue's NUMA node (best-effort, mirrors 0.25 W4 `numa_node`).
- **G2/Monitor docs** — ⏳ *M4.* Once `xdp_queues` lands, the "single queue (queue 0)"
  caveat on `xdp_interface_loaded` becomes "defaults to queue 0; `.xdp_queues(Auto)`
  for the whole NIC" — the footgun *removed*, not just documented.

---

## 6. Phasing

| Phase | Scope | Status |
|---|---|---|
| **M0** | Promiscuous (issue #4) + manual `xdp_multiqueue` example. | ✅ **PR #5** |
| **M1** | `queue_count()` (ETHTOOL_GCHANNELS) + `Queues` enum. | ✅ **PR #7** |
| **M2** | `XdpCapture`: per-socket-UMEM open + 1-program register + unified `next_batch`/`into_parts`. B1 overflow-guard. F2 `is_zerocopy()`. Example rewritten on it. | ✅ **PR #7** |
| **M3** | `AsyncXdpCapture` (tokio): `XdpCapture` + one `AsyncFd`/socket; `readable().await` over N fds (poll_fn/select); unified async `next_batch`. | ⏳ next |
| **M4** | **Tier 1 footgun fix (G2):** `AnyBackend::XdpMq(AsyncXdpCapture)` arm + monitor-wide `MonitorBuilder::xdp_queues(Queues)`. 1-spec↔1-backend preserved; `Reopen` rebuilds the capture. | ⏳ next (headline) |
| **M5** | **Tier 2:** `XdpShardedRunner` (worker-per-queue over `ShardedRunner`) + the `BackendSpec::XdpProvided` seam + busy-poll passthrough on `XdpCapture`. **F1** shared-UMEM opt-in + partitioning helper. **F3** per-queue NUMA. **B1** honor/deprecate `max_queues`. | ⏳ |
| **M6** | Docs (API_OVERVIEW/scaling/TROUBLESHOOTING/FEATURES), `MIGRATING_0.25_TO_0.26`, CHANGELOG `## 0.26.0`, version bump, release. | ⏳ |

**PR slicing:** M3+M4 = one PR (the footgun fix — Tier 1 is useless without the async
wrapper). M5 = one or two PRs (Tier 2 sharding; then F1/F3/B1 hardening). M6 folds in
per PR + a release PR. Keep each green before the next.

**Testing reality.** CI exercises only `lo` (single queue), so **N>1 is
example-validated, not CI-validated** — stated plainly in the plan + CHANGELOG, no
silent coverage claims. Structural coverage: N=1 root-gated `lo` live tests for every
new drain path (Tier 1 `XdpMq` backend, Tier 2 shard) — **M2 proved these catch real
bugs** (the `rx_poll_ready` cache bug, §2.1) — plus unit tests for queue math, guard
lifetimes, and round-robin fairness with a mock ring. Real-NIC validation: the
`xdp_multiqueue` example + @georgmu's offer on #6.

---

## 7. Breaking-change inventory (allowed; aligned to "one break at 1.0")

Shipped in PR #5/#7 — **all additive** (`XdpCapture`, `queue_count`, `Queues`,
`is_zerocopy`, monitor-wide `promiscuous`). Planned:

1. **`xdp_queues` / `AnyBackend::XdpMq` / `XdpShardedRunner` (M4/M5):** additive. The
   Monitor default stays `Queues::Single(0)`.
2. **`BackendSpec::XdpProvided` seam (M5):** internal (`pub(crate)`); the public face
   is `XdpShardedRunner` / a `MonitorBuilder::xdp_socket` — additive.
3. **B1 `default_program(max_queues)` (M5):** prefer a `#[deprecated]` shim that
   ignores the arg (0.26 stays additive); the signature removal is a **1.0** break.
4. **`shared_umem` (M5):** if the safe partitioning helper changes the shape, gate
   behind `XdpCapture::shared_umem` and `#[deprecated]` the raw `XdpSocketBuilder`
   method; removal at 1.0.
5. **Planned 1.0 break:** Monitor AF_XDP defaults to `Queues::Auto` (capture the whole
   NIC by default — the deliberate footgun-removal break, after field-testing).

Net: **0.26 stays additive-with-shims** (Arch §7); the one deliberate defaults-break
is a **1.0** item, recorded here + in INDEX so it isn't forgotten.

---

## 8. Out of scope (tracked, not built here)

- io_uring ZC-RX backend (Arch §3 future `CaptureBackend` seam).
- NIC flow-steering config (`ethtool -N` / `tc`) to pin specific flows to a queue —
  netring reads queue count, it doesn't reprogram RSS.
- A pcap-style "just give me everything on this NIC regardless of backend" facade
  unifying AF_PACKET-fanout and AF_XDP-multi-queue under one call — attractive 1.0
  polish, but a separate design.

---

## 9. Open decisions to lock before M2

- ~~**Q1 — unified `next_batch` borrow shape.**~~ ✅ Resolved in M2: zero-copy/`Send`
  holds (one socket borrowed at a time); needed a *fresh* readiness probe (§2.1).
- ~~**Q2 — `into_parts` guard.**~~ ✅ Resolved in M2: returns `(Vec<XdpSocket>,
  XdpCaptureGuard)` — the guard owns the program + promisc so workers can't detach by
  accident.
- ~~**Q3 — `xdp_queues` scope.**~~ ✅ Locked: monitor-wide (symmetric with
  `promiscuous`).
- **Q4 — Tier-2 backend seam (M5).** `BackendSpec::XdpProvided(AsyncXdpSocket)` vs a
  public `MonitorBuilder::xdp_socket(...)`. Recommend the internal spec + the
  `XdpShardedRunner` public face; expose `xdp_socket` only if a "bring-your-own-socket"
  demand appears.
- **Q5 — B1 (M5).** Honor `max_queues` via aya BTF map-resize (a) vs `#[deprecated]`
  shim ignoring it (b). Spike (a) on stable aya; fall back to (b). (PR #7 already
  removed the silent-failure risk via the ≥256 error.)
- **Q6 — shared-UMEM partitioning helper (M5/F1).** Confirm a safe per-queue frame
  partition that sidesteps the FILL race, or keep per-socket UMEM the only blessed
  path and document `shared_umem` as expert-only.
- **Q7 — `AsyncXdpCapture` readiness (M3).** N× `AsyncFd` + `poll_fn`/`select` (simple)
  vs one epoll fd registering all N (one wakeup, more machinery). Start with N×
  `AsyncFd`; revisit only if reactor pressure shows up at high queue counts.

---

## 10. Definition of done

- **Done (PR #5/#7):** `XdpCapture` + `Queues` + `queue_count()` + `is_zerocopy()`;
  B1 silent-failure removed; `xdp_multiqueue` example on `XdpCapture`.
- **M3/M4:** `AsyncXdpCapture` + `AnyBackend::XdpMq` + monitor-wide `xdp_queues(Queues)`
  → the **G2 footgun is gone** (Tier 1 captures every queue; default documented,
  `Auto` one call).
- **M5:** `XdpShardedRunner` (Tier 2 worker-per-queue + busy-poll) ; F1/F3/B1 hardening.
- **M6:** docs + `MIGRATING_0.25_TO_0.26` + CHANGELOG `## 0.26.0` + version bump.
- Gates throughout: fmt + clippy `--all-features -D warnings` + the **feature-combo
  matrix** (§2.1 lesson) + rustdoc `-D warnings` + dhat Δ 0/0 + root-gated `lo` live
  tests for each new drain path.
- This plan **deleted on ship**, its locked decisions (the tiered threading model
  §4.5) folded into `netring-architecture.md`.
