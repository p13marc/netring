# netring 0.26 — AF_XDP Multi-Queue Capture & Hardening

> **Status:** plan, 2026-06-15. The last *feature* release before 1.0 stabilization.
> Closes the AF_XDP-capture gaps surfaced reviewing issue #4 (promiscuous mode,
> PR #5). Breaking changes are permitted (the maintainer authorized redesign);
> they are inventoried in §7 and aligned to the **one break at 1.0** SemVer model
> ([`netring-architecture.md`](./netring-architecture.md) §7).
>
> **North-star alignment.** This plan adds *no* new run-loop machinery: the
> Monitor already holds `Vec<AnyBackend>` and round-robin-polls multiple sources
> (Arch §3, Phase F.1 multi-interface). "One AF_XDP socket per NIC queue" drops
> straight into that model. The work is a high-level *handle* over the kernel's
> immutable 1-socket-per-queue ABI, plus footgun removal.

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

| # | Item | Sev | Kind | Where |
|---|---|---|---|---|
| G1 | **No high-level multi-queue capture API.** Full-NIC AF_XDP = manual N-socket + program + XSKMAP dance. | 🟠 | gap | `afxdp/` |
| G2 | **Monitor binds queue 0 only** → silent under-capture on every multi-queue NIC. Documented, not solved. | 🔴 | footgun | `monitor/run.rs::open_xdp_backend` |
| G3 | **No queue-count discovery.** Users must `ethtool -l` by hand; no `Queues::Auto`. | 🟠 | gap | `afxdp/` |
| B1 | **`default_program(_max_queues)` ignores its argument** — XSKMAP is baked at `max_entries=256`. The parameter lies (works ≤256 queues, silent contract violation above). | 🟡 | bug/wart | `afxdp/loader/default_program.rs` |
| F1 | **`shared_umem` is a footgun:** manual frame-space partitioning + the per-CPU FILL race. Exposed with only a prose caveat. | 🟠 | footgun | `afxdp/mod.rs::shared_umem` |
| F2 | **Copy-mode perf cliff.** We `warn!` on COPY bind, but the high-level handle should *surface* it as data, and steer DRV/SKB choice. | 🟡 | footgun | `afxdp/mod.rs::build` |
| F3 | **No per-queue NUMA affinity.** `numa_node` is a single value; per-queue sockets should bind each UMEM to that queue's node. | 🟡 | gap | `afxdp/umem.rs` |
| D1 | **Promiscuous (issue #4) — DONE in PR #5.** Per-socket guard + monitor-wide flag. Design settled; listed for completeness. | ✅ | — | merged |

The headline is **G1 + G2** (the missing high-level API and the silent Monitor
footgun). G3/B1/F1–F3 are the hardening that makes the high-level API *correct and
complete* rather than a thin wrapper.

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

### 3.1 Draining — two shapes (both, like Suricata + DPDK)

```rust
// (a) Single-thread, unified round-robin — simplest:
while let Some(batch) = cap.recv()? {        // batch carries .queue_id()
    for pkt in &batch { /* … */ }
}

// (b) Worker-per-queue — scales to line rate (Suricata model):
for sock in cap.into_sockets() {             // Vec<XdpSocket>, program kept alive by a guard
    std::thread::spawn(move || { /* drain sock on its own core */ });
}
```

`into_sockets()` returns the N sockets **plus** a `ProgramGuard` (keeps the single
attachment + promisc guard alive) so the worker model can't accidentally detach the
program by dropping the handle. Async mirror: `AsyncXdpCapture` (tokio), unified
`recv().await` + `into_async_sockets()`.

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

Make the Monitor capture the whole NIC, riding the **existing** multi-source loop.

**API (consistent with the monitor-wide `promiscuous` decision in PR #5):**
```rust
Monitor::builder()
    .xdp_interface_loaded("eth0")
    .xdp_queues(Queues::Auto)      // monitor-wide, mirrors .promiscuous(bool)
    .promiscuous(true)
    .protocol::<Tcp>()
    .build()?;
```

`xdp_queues(Queues)` is **monitor-wide** (applies to every AF_XDP interface) — same
shape as `promiscuous(bool)`, so the two read symmetrically and avoid the positional
"last-added" wart rejected in the PR-#5 review. Default stays `Queues::Single(0)`
(no behavior change for existing code until they opt in).

**Run-loop mechanics.** `open_xdp_backend` becomes "open the *interface*": it builds
an `XdpCapture` for that iface (1 program + N sockets), pushes each socket as an
`AnyBackend::Xdp` into the run loop's `Vec<AnyBackend>` (which already round-robins),
and stashes the `XdpCapture`'s program/promisc guard in a side `Vec<ProgramGuard>`
kept alive for the run's duration. No new polling code — the N sockets are just more
sources. The `Reopen` resilience policy (0.25 W1e) extends naturally per socket.

**Decision to lock (§9 Q3):** monitor-wide `xdp_queues` vs per-interface. Recommend
monitor-wide for symmetry; per-interface only if a real mixed-NIC need appears.

---

## 5. Footgun & bug fixes

- **B1 — `default_program` max_queues.** Either (a) **honor it** by rewriting the
  XSKMAP `max_entries` via aya's BTF map-resize before load, or (b) **drop the
  parameter** and document the fixed 256 cap. Recommend (a) if aya's
  `map_mut().set_max_entries()` works pre-load on stable; else (b) — a lying
  parameter is worse than an honest constant. `XdpCapture` sizes the map to the
  queue count either way.
- **F1 — `shared_umem`.** Keep it (memory optimization) but (1) re-document with the
  per-CPU FILL-race caveat and a link, (2) make `XdpCapture`'s default **per-socket
  UMEM** (no sharing) so the safe path is the easy path, (3) optionally add a
  `XdpCapture::shared_umem(true)` opt-in that does the partitioning *for* the user
  (the "SharedUmem helper… planned" promised in the `shared_umem` rustdoc).
- **F2 — copy-mode.** Promote the COPY-bind `warn!` to a queryable
  `XdpCapture::zerocopy() -> bool` (and per-socket `XdpSocket::is_zerocopy()`), so
  callers/tests can assert the binding mode instead of grepping logs.
- **F3 — per-queue NUMA.** `XdpCapture` optionally pins each queue's UMEM to that
  queue's NUMA node (read once, best-effort, mirrors 0.25 W4 `numa_node`).
- **G2/Monitor docs.** Once §4 lands, the "single queue (queue 0)" caveat on
  `xdp_interface_loaded` becomes "defaults to queue 0; `.xdp_queues(Auto)` for the
  whole NIC" — the footgun is *removed*, not just documented.

---

## 6. Phasing

| Phase | Scope | Testable in CI (`lo`, root) |
|---|---|---|
| **M0** | Merge PR #5 (promiscuous). Land `examples/xdp/xdp_multiqueue.rs` (done). | ✅ already green |
| **M1** | `queue_count()` via ETHTOOL_GCHANNELS + ffi + `Queues` enum. | ✅ unit + `lo` fallback |
| **M2** | `XdpCapture` builder + per-socket-UMEM open + 1-program register + unified `recv()` + `into_sockets()`. B1 fix. F2 `zerocopy()`. | ✅ N=1 on `lo` (root); N>1 HW-gated |
| **M3** | `AsyncXdpCapture` (tokio) — unified `recv().await` + async sockets. | ✅ N=1 on `lo` |
| **M4** | Monitor `xdp_queues(Queues)` → one backend per queue through the existing loop; `ProgramGuard` side-vec; `Reopen` per socket. | ✅ N=1 on `lo`; G2 removed |
| **M5** | F1 `shared_umem` opt-in + partitioning helper; F3 per-queue NUMA. | partial (HW) |
| **M6** | Docs (API_OVERVIEW, scaling.md, TROUBLESHOOTING, FEATURES), migration note, CHANGELOG, rewrite `xdp_multiqueue.rs` on top of `XdpCapture` (it shrinks to ~10 lines — the proof the API earns its keep). | ✅ |

**Testing reality.** CI exercises only `lo` (single queue), so the N>1 path is
**structurally** validated (N=1 degenerate + unit tests for queue math, map
registration, guard lifetimes) but **functionally** HW-gated. Mitigations: (1) a
`miri`/unit harness over the queue-set resolution and round-robin drain logic with a
mock backend; (2) keep the root-gated `lo` live test asserting N=1 capture +
zerocopy()==false (SKB on lo); (3) ship the example as the real-NIC validation path
and explicitly ask @georgmu (issue #4) to run it on his multi-queue NIC. **No silent
coverage claims** — the plan and CHANGELOG state the N>1 path is example-validated,
not CI-validated.

---

## 7. Breaking-change inventory (allowed; aligned to "one break at 1.0")

Most of this is **additive** (`XdpCapture`, `queue_count`, `Queues`, `xdp_queues`,
`is_zerocopy`). The candidate breaks — to bundle into the 1.0 stabilization wave, not
sprung piecemeal:

1. **B1(b) path:** if we drop `default_program`'s `max_queues` parameter, that's a
   signature break → 1.0 (or a `#[deprecated]` shim in 0.26 ignoring the arg, removed
   at 1.0). Prefer the shim so 0.26 stays additive.
2. **`xdp_interface_loaded` default queue set:** stays `Single(0)` in 0.26 (additive).
   *At 1.0*, consider defaulting Monitor AF_XDP to `Queues::Auto` so the safe,
   complete behavior is the default — the one deliberate break, after field-testing.
3. **`shared_umem` signature:** if the partitioning helper changes its shape, gate
   behind the new `XdpCapture::shared_umem` and `#[deprecate]` the raw builder method.

Net: **0.26 is additive-with-shims** (matches Arch §7); the deliberate defaults-break
(Auto-by-default) is a **1.0** decision listed here so it isn't forgotten.

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

- **Q1 — Unified `recv()` ownership.** Round-robin over N sockets in one call
  returning a queue-tagged batch: confirm the borrow shape stays zero-copy/`Send`
  (it should — same borrowed-batch discipline as Arch §3, one socket at a time).
- **Q2 — `into_sockets()` guard.** Return `(Vec<XdpSocket>, ProgramGuard)` vs a
  `XdpSockets` collection type that owns the guard. Recommend the collection type so
  the guard can't be dropped by accident.
- **Q3 — Monitor `xdp_queues` scope.** Monitor-wide (recommended, symmetric with
  `promiscuous`) vs per-interface.
- **Q4 — B1.** Honor `max_queues` via BTF resize (a) vs deprecate the param (b).
  Spike aya's pre-load map resize on stable; fall back to (b).
- **Q5 — `Queues::Auto` as the eventual default.** 0.26 keeps `Single(0)`; lock the
  1.0 default-to-Auto break here so it's on the 1.0 checklist.

---

## 10. Definition of done

- `XdpCapture` + `AsyncXdpCapture` + `Queues` + `queue_count()` shipped; B1 honest;
  `is_zerocopy()` queryable.
- Monitor `xdp_queues(Queues)` captures every queue through the existing loop; the
  G2 silent-under-capture footgun is **gone** (default documented, `Auto` one call).
- `examples/xdp/xdp_multiqueue.rs` rewritten on `XdpCapture` (~10 lines).
- Gates: fmt + clippy `--all-features -D warnings` + rustdoc `-D warnings` + dhat
  Δ 0/0 + the root-gated `lo` N=1 live test, all green.
- Docs updated; CHANGELOG `## 0.26.0`; this plan **deleted on ship** (delete-on-ship
  convention), its locked decisions folded into `netring-architecture.md`.
