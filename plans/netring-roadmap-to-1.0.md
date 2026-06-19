# netring — Roadmap to best-in-class (post-0.26 → 1.0)

> **Status:** strategic plan, 2026-06-16. Written after 0.26.0 shipped (the AF_XDP
> multi-queue stack). Research-grounded competitive assessment + detailed
> per-theme plans. Breaking changes permitted (maintainer-authorized); the one
> forced migration is still bundled at **1.0** (Arch §7). **flowscope is
> maintainer-owned** — its co-evolution is in scope and called out per theme.

---

## 0. Thesis — the position to own

The Rust ecosystem above the socket layer is **fragmented and shallow**:
socket-only crates (`xsk-rs`, `xdpilone`, `xdp-socket` — which explicitly punt on
BPF/netlink), `pcap`/`pnet` (weaker than PcapPlusPlus), and DPDK-bound NFV
(`capsule`). **No production-grade, embeddable Rust capture + analysis
framework exists.** netring already is one.

The academic gold standard for *what netring is* — subscribe to
packets/flows/sessions, shed in-kernel, defer expensive work — is **Retina**
(SIGCOMM'22, 160 Gbps on one server). netring's subscription engine *is* the
Retina model, but Retina is research-grade (DPDK, recompile-per-experiment) while
netring is a real, async, resilient, observable library on AF_PACKET + AF_XDP.

> **Positioning: "Retina's subscription model as a production Rust library —
> DPDK-class throughput without DPDK's deployment tax, embeddable, async,
> batteries-included."** Every theme below either *proves* that claim, *pushes*
> the frontier so it stays true, or *polishes* the API so it feels inevitable.

**The gating insight: "best" is unprovable without published benchmarks.** P0
(below) comes first; it unlocks the credibility every other theme trades on.

---

## 1. Cross-cutting decisions

- **flowscope co-evolution.** We own flowscope, so protocol/L7/L2 work (QUIC, ARP,
  encrypted-visibility fingerprints, RX-metadata fields on `PacketView`) lands
  there first and netring surfaces it. Each theme lists its flowscope-side change.
  Floor bumps are cheap; coordinate the version in lock-step (publish flowscope,
  then netring `cargo update --precise`).
- **Breaking-change strategy.** 0.2x stays additive-with-shims; the removal wave +
  SemVer promise is **1.0** (Arch §7). New themes add surface; deprecations
  accumulate; 1.0 collects them. Two deliberate 1.0 defaults-breaks are already
  logged (Monitor AF_XDP → `Queues::Auto`; see §10).
- **HW-gated honesty.** CI is `lo`-only. Anything needing a real NIC (line-rate
  benchmarks, HW timestamps, DRV-mode zero-copy, io_uring ZC-RX, flow steering) is
  **structurally** tested on `lo` + **explicitly labelled example/HW-validated,
  not CI-validated.** No silent coverage claims (the rule that's served us since
  the multi-queue work).
- **dhat Δ0 + Send run loop** remain invariants through every theme.

---

## 2. P0 — Prove it: the benchmark harness  *(do first; gates the "best" claim)*

**Why.** Retina cites 160 Gbps; netring cites a dispatch micro-bench. To claim the
category we need reproducible, public **pps/Gbps + drop** numbers across backends
and subscription configs, with the kernel-shedding effect *measured*.

**Design.**
- **Generator:** a netring AF_XDP TX injector (we already have `send_stream` +
  `TxPacer`) blasting a configurable mix at a target rate, *or* documented
  `pktgen`/`trafgen` recipes. Loopback `veth`/`lo` for smoke; a second box +
  real NIC for the real numbers.
- **Subject matrix:** AF_PACKET plain · AF_PACKET fanout (N) · AF_XDP single ·
  AF_XDP `xdp_queues` (XdpMq) · `XdpShardedRunner` (N) — each × subscription tier
  {raw packet, flow, session} × {kernel-pushdown on/off} to quantify the
  Retina-style "strategically discard" win.
- **Metrics:** offered vs captured pps/Gbps, drop sources (`rx_dropped`,
  `rx_ring_full`, `rx_fill_ring_empty`), per-core CPU, p50/p99 dispatch latency.
- **`docs/BENCHMARKS.md`:** methodology (NIC/kernel/CPU/IRQ-affinity/BIOS),
  a results table template, and a one-command repro script. **A results table the
  maintainer fills on real hardware** — the landing-page hook.
- Keep the cap-free dhat/dispatch micro-bench as the CI perf gate; the line-rate
  harness is `#[cfg(feature = "bench-line-rate")]`, HW-run.

**Milestones:** M1 generator + harness skeleton (lo smoke) · M2 subject matrix +
metrics collection · M3 `BENCHMARKS.md` + repro script + a first real-NIC run.

**flowscope:** none. **Breaking:** none (additive bench feature).

---

## 3. F1 — Precise capture: AF_XDP RX hardware metadata + timestamps

**Why.** Kernel 6.3+ exposes [XDP-hints kfuncs]: **HW timestamp, RX hash (+ type),
VLAN, checksum status** to AF_XDP. There's literally a `// not yet wired` TODO in
our AF_XDP recv path. **No Rust library surfaces these**, and hardware timestamps
are gold for latency/forensics/precise capture — a clean differentiator.

**Design.**
- A small XDP metadata program (or extend `redirect_all`/`filter_redirect`) that
  calls `bpf_xdp_metadata_rx_timestamp` / `_rx_hash` / `_rx_vlan_tag` and writes
  them into the 32-byte UMEM metadata area ahead of each frame (`XDP_PKT_CONTENTS`
  headroom). Userspace reads the struct from the frame's metadata region.
- Driver-gated: kfuncs return `-EOPNOTSUPP`/`-ENODATA`; **gracefully degrade** to
  the software timestamp we use today. Surface availability via a
  `XdpCapture::rx_metadata() -> RxMetaSupport` probe.
- **flowscope:** extend `PacketView`/`Timestamp` to carry an optional
  `hw_timestamp`, `rx_hash`, `rx_hash_type`, `vlan`, `checksum_ok`. (We own it —
  add the fields; netring populates from AF_XDP, leaves `None` on AF_PACKET unless
  `SO_TIMESTAMPING` is wired there too.) This is the one place a small flowscope
  break (PacketView gains fields) is worth it.
- `PacketView::hw_timestamp()` flows into the Monitor's per-packet `ts` so flow
  records get NIC-accurate timing.

**Milestones:** M1 flowscope `PacketView` metadata fields (publish) · M2 the XDP
metadata program + UMEM-headroom read + `RxMetaSupport` probe · M3 wire into
`AnyBackend`/Monitor ts + a root-gated `lo` test (lo gives `-ENODATA` → exercises
the degrade path) · M4 docs + example.

**Breaking:** flowscope `PacketView` gains fields (minor; netring shim-friendly).
**HW-gated:** real timestamps need a supporting NIC (ice/mlx5); lo validates degrade.

---

## 4. F2 — io_uring ZC-RX backend  *(stay at the frontier)*

**Why.** Linux 6.15 lands [io_uring zero-copy RX]: **~200 Gbps off one core,
31–43% faster than epoll**. The `AnyBackend` enum already documents an io_uring
seam (Arch §3). Adding it keeps netring ahead as kernels roll forward and gives a
single-flow, header/data-split zero-copy path AF_XDP can't match for steered flows.

**Design.**
- New `AnyBackend::IoUring(IoUringCapture)` arm — same `readable().await` +
  `drain_batch(impl FnMut(PacketView))` contract, so the Monitor + subscription
  engine work unchanged.
- Needs HW header/data-split + flow steering + RSS (the kernel doesn't configure
  the NIC — pairs with **F3** below). Gate on `feature = "io-uring"` + a runtime
  capability probe; `Backend::Auto` (theme A1) only picks it when supported.
- Likely a thin dep on `io-uring`/`tokio-uring` or a vendored ZC-RX ioctl path
  (decide at spike time — avoid a heavy runtime).

**Milestones:** M1 spike ZC-RX setup (page-pool, refill ring) behind the feature ·
M2 `AnyBackend::IoUring` + drain · M3 capability probe + docs. **HW-gated** (needs a
ZC-RX-capable NIC + 6.15); ship as a documented frontier backend, not a default.

**flowscope:** none. **Breaking:** additive (`AnyBackend` is `pub(crate)`).

---

## 5. F3 — NIC flow steering  *(close the last AF_XDP-vs-DPDK gap)*

**Why.** Research's one knock on AF_XDP vs DPDK: *"you can't program flow-matching
rules in the NIC."* We already read queue count; programming steering (flow X →
queue Y) lets the multi-queue/sharded capture **pin chosen flows to chosen
cores**, and is a prerequisite for io_uring ZC-RX (steer the ZC flow to its queue).

**Design.**
- `netring::xdp::steer` — wrappers over `ethtool` `ETHTOOL_SRXCLSRLINS` (ntuple
  rules) + `ETHTOOL_SRSSH` (RSS indirection), or the rtnetlink/`ethtool-netlink`
  equivalents. A typed builder: `FlowRule::tcp().dst_port(443).to_queue(3)`.
- `XdpCaptureBuilder::steer(rule)` / `XdpShardedRunner::steer(...)` convenience.
- Needs `CAP_NET_ADMIN`; degrade with a clear error on unsupported NICs.

**Milestones:** M1 `queue_count` already done → add `set_rss` / `insert_ntuple` ffi
+ typed `FlowRule` · M2 builder integration + an example (steer SYN/443 to a
dedicated capture queue) · M3 docs. **HW-gated.**

**flowscope:** none. **Breaking:** additive.

---

## 6. P1 — Protocol frontier: QUIC + encrypted visibility  *(relevance)*

**Why.** Research is blunt: *"QUIC… Wireshark, Zeek, Suricata, Snort lose
visibility."* Analysis value is migrating to (a) QUIC Initial/SNI parsing and (b)
**encrypted-traffic metadata** without decryption — exactly where JA4 already
plays. This is the protocol gap that most affects netring's 2026+ relevance.

**Design (mostly flowscope — we own it).**
- **flowscope `quic` feature:** parse the QUIC long-header Initial (version, DCID/
  SCID, and the well-known-key-decrypted CRYPTO frame → TLS ClientHello → SNI/ALPN/
  JA4). QUIC Initial packets are encrypted with a *derived-from-DCID* key (RFC 9001
  §5.2) — decryptable on-path without secrets. Emit `QuicMessage { version, scid,
  dcid, sni, alpn, ja4 }`. Datagram-style (UDP/443), like the DNS parser.
- **Encrypted-visibility fingerprints:** lean into JA4's family — JA4 over QUIC,
  and packet-size/inter-arrival "flow fingerprints" for encrypted sessions
  (a `flowscope::fingerprint` module; netring surfaces via `on_fingerprint`).
- **netring surface:** a `Quic` `MessageProtocol` marker → `on::<Quic>`,
  `session::<Quic>().sni_glob(...)` (the subscription tier already supports
  L7-field gating — QUIC SNI slots into `L7Fields` like TLS/HTTP/DNS).
- Licensing: JA4 (client) stays BSD; keep JA4S/JA4+ behind the existing `ja4plus`
  gate (Arch §9.6). QUIC parsing itself is unencumbered.

**Milestones:** M1 flowscope QUIC Initial + SNI/JA4 (publish) · M2 netring `Quic`
protocol + subscription `L7Fields` impl + EVE/flow surfacing · M3 example
(QUIC SNI monitor) + docs · M4 (stretch) encrypted-flow fingerprints.

**Breaking:** flowscope additive feature; netring additive protocol.

---

## 7. P2 — ARP: parsing, table, and spoof detection  *(maintainer ask)*

**Why.** ARP is high-value and underserved: L2 asset discovery (IP↔MAC inventory),
duplicate-IP detection, and **ARP-spoofing/poisoning (MITM) detection** — a
classic, still-relevant LAN attack. It's connectionless request/reply, so it fits
the same correlation shape as DNS/ICMP that flowscope + netring already model.

**Design.**
- **flowscope `arp` feature:** parse EtherType `0x0806` → `ArpMessage { oper
  (Request/Reply/RARP), sender_mac, sender_ip, target_mac, target_ip }`. L2,
  no IP flow key; request→reply correlation by `(sender_ip, target_ip)` (like DNS
  query/response). Gratuitous-ARP detection (sender_ip == target_ip).
- **`ArpTable` (flowscope::correlate or netring):** IP → (MAC, first_seen,
  last_seen, change_count). The stateful core, mirroring `KeyIndexed`/`label_table`.
- **netring ops surface (0.22-style toolkit):**
  - `Arp` `MessageProtocol` marker → `on::<Arp>` / `session::<Arp>()`.
  - `MonitorBuilder::arp_table()` + `Ctx::arp_table()` accessor (like
    `label_table`/`bandwidth`).
  - `MonitorBuilder::on_arp_anomaly(|a: &ArpAnomaly, ctx|)` — typed events:
    `SpoofSuspected { ip, old_mac, new_mac }` (a known IP's MAC changed),
    `Conflict { ip, macs }` (two MACs claim one IP), `Gratuitous`,
    `Unsolicited` (reply with no request). The headline security detector.
- **Capture note:** ARP is broadcast L2 — AF_PACKET sees it natively; AF_XDP's
  `redirect_all` passes it, but a `filter_redirect`/subscription pushdown must
  include an ARP allow-rule (extend the kernel filter to match EtherType, not just
  IP `{proto,port}`). Promiscuous helps see *others'* ARP for full-segment
  monitoring. Document this.
- An `examples/monitor/arp_watch.rs` (live IP↔MAC table + spoof alerts) — a
  compelling, runnable security demo.

**Milestones:** M1 flowscope ARP parser + `ArpMessage` (publish) · M2 `ArpTable` +
netring `Arp` protocol + `arp_table()`/`Ctx` accessor · M3 `on_arp_anomaly` +
detector logic + EVE surfacing · M4 kernel-filter EtherType support (so ARP
survives subscription pushdown) · M5 example + docs.

**Breaking:** flowscope additive; netring additive (new protocol + ops methods).
Kernel-filter EtherType matching is an internal extension to the predicate AST.

---

## 8. A1 — API capstone: declarative capture facade + multi-NIC merge

**Why.** Users now choose AF_PACKET vs `xdp_interface_loaded` vs `XdpShardedRunner`
by hand. The capstone of the multi-queue work is a **policy-driven facade** that
makes the right choice — and a real hole (issue #11) is multi-NIC AF_XDP merge.

**Design.**
- **`Backend::Auto` / a `Capture` facade:** *"capture eth0 at the
  highest-available performance"* → probes (AF_XDP DRV? queue count? io_uring
  ZC-RX? else AF_PACKET) and picks backend + queue strategy + single-reactor-vs-
  sharded, overridable. `Monitor::builder().capture("eth0", Backend::Auto)`.
- **Multi-NIC merge (issue #11):** `AsyncXdpMultiCapture` — open N AF_XDP
  interfaces (each multi-queue via `XdpCapture`), unified `TaggedEvent` stream,
  reusing the existing `multi_streams` round-robin select. Composes N NICs × M
  queues.
- **Tap mode:** a TAP splits TX/RX across two NICs → the two legs are the two
  directions of the *same* flows. Today multi-interface keys flows per-`source_idx`
  (two half-flows). Add a **source-agnostic merge** mode: feed one tracker keyed by
  the bidirectional 5-tuple, ignoring source — so a tap reconstructs whole flows.
  (`AsyncMultiCapture` gets the same option; flowscope tracker already supports
  bidirectional keys — the change is "don't include source in the key.")

**Milestones:** M1 `AsyncXdpMultiCapture` + `TaggedEvent` (reuse multi_streams) ·
M2 tap/merge mode (source-agnostic bidirectional tracking) · M3 `Backend::Auto`
probe + facade · M4 docs + a tap example.

**Breaking:** additive surface; `Backend::Auto` may become the *recommended* path
at 1.0 (doc shift, not a break).

---

## 9. A2 — Compile-time subscription specialization  *(the Retina efficiency trick)*

**Why.** Retina's real win is generating a binary *tailored* to the subscription so
unneeded work is **eliminated**, not just skipped. netring does runtime pushdown +
staged shedding; a monomorphized path would close the last efficiency gap to
Retina and is a genuine differentiator no other Rust lib has.

**Design (research-then-build — the riskiest theme).**
- A `subscribe!{ ... }` proc-macro (or const-generic pipeline) that, given a fixed
  subscription set, generates a specialized dispatch with dead tiers compiled out
  (no `session` machinery if you only subscribe `packet`; no L7 parser link if no
  `session::<P>`). Pairs with the existing kernel-pushdown so the in-kernel filter
  is also derived at compile time.
- Keep the runtime builder as the dynamic path (`.expr()`, plugins). The macro is
  the "I know my subscription at build time, give me Retina speed" opt-in.
- **Gated on P0** — only worth building once benchmarks show where the runtime
  dispatch actually costs.

**Milestones:** M0 spike + benchmark the runtime-dispatch overhead (needs P0) · M1
proc-macro for the packet-only fast path · M2 flow/session specialization · M3
const-fold the kernel filter. Could be its own pre-1.0 release.

**Breaking:** additive (new macro alongside the builder).

---

## 10. 1.0 — Stabilization

After the themes field-test across 0.27+: remove the `#[deprecated]` shims, settle
names, make the SemVer-stable promise. **Deliberate defaults-breaks bundled here:**
1. Monitor AF_XDP defaults to `Queues::Auto` (capture the whole NIC by default).
2. `Backend::Auto` becomes the recommended/default capture path (if A1 lands).
3. Any `PacketView`/protocol-trait breaks from F1 (HW metadata fields) /
   protocol additions, collected into one wave.
Plan written once the community-test feedback is in (Arch §7).

---

## 11. Sequencing (proposed)

```
0.27  Prove it & precise capture   ── P0 benchmarks (gates everything) + F1 AF_XDP HW
  │     metadata/timestamps. Smallest, highest-credibility. flowscope: PacketView fields.
0.28  Protocol frontier            ── P1 QUIC + encrypted visibility, P2 ARP (both
  │     flowscope-led). The relevance + maintainer-ask release.
0.29  API capstone & steering      ── A1 declarative facade + multi-NIC/tap merge (#11),
  │     F3 NIC flow steering. Makes the multi-queue work feel inevitable.
0.30  Frontier backend             ── F2 io_uring ZC-RX (when 6.15+ is common) + A2 spike.
  ▼     A2 compile-time specialization may slip to its own release.
1.0   Stabilization                ── shim removal + SemVer + the defaults-breaks (§10).
```

Order is **value × credibility-first**: benchmarks before everything (they prove
the claim), then the cheap unique differentiator (HW timestamps), then relevance
(QUIC/ARP), then the API capstone, then the speculative frontier backend.

---

## 12. Risks & open decisions

- **P0 is non-negotiable and partly non-code** (real-NIC runs, methodology). It's
  the project's biggest credibility lever and the easiest to under-invest in.
- **F1/F2/F3 are HW-gated** — design for graceful degrade + a `lo` structural test;
  recruit real-NIC validation (the @georgmu pattern).
- **A2 is the riskiest** (proc-macro pipeline) and **must follow P0** so it
  optimizes a measured cost, not a guessed one.
- **flowscope version cadence:** several themes need a flowscope publish first
  (PacketView fields, QUIC, ARP). Batch them to minimize lock-step churn.
- **Scope discipline:** this is ~4 releases. Each theme should still ship behind a
  feature flag and as its own release plan (delete-on-ship), not a big-bang.
- **Open: cross-platform `pcap` fallback backend** — listed as table-stakes in the
  assessment, not yet themed. Decide whether a dev/macOS `AnyBackend::Pcap` (we
  already have a `pcap` source for replay) is worth a public live-capture arm, or
  stays Linux-only. Lean: add it at A1 (`Backend::Auto` falls back to pcap on
  non-Linux) for adoption, without touching the fast path.

[XDP-hints kfuncs]: https://docs.kernel.org/networking/xdp-rx-metadata.html
[io_uring zero-copy RX]: https://docs.kernel.org/networking/iou-zcrx.html
