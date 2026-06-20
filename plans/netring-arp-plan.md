# netring — ARP visibility & spoof detection (plan)

> **Status: IMPLEMENTED (PR #18, 2026-06-20)** — flowscope 0.17 ships the `arp`
> module + `NeighborTable`; netring adds the `arp` feature. Delete-on-ship once
> #18 merges + releases. Two pieces were **deferred to follow-up issues** (see
> §7).
>
> **Design divergence from this plan (deliberate):** the plan envisioned ARP as a
> `MessageProtocol` (`on::<Arp>` + `session::<Arp>()`). flowscope 0.17 ships ARP
> as a **free-function parser** (`arp::parse_frame`), not a `SessionParser` — and
> ARP has no 5-tuple, so it doesn't fit the session/datagram driver. So netring
> surfaces it as the **ops-toolkit hook style** (like `on_icmp_error`):
> `MonitorBuilder::on_arp` (raw `ArpMessage` feed) + `on_arp_anomaly`, parsed
> per-frame in the zero-copy drain (`dispatch_arp` in `run.rs`) + the replay loop.
> flowscope's generic `NeighborTable<L3, L4>` (= `ArpTable`) replaced the plan's
> bespoke `ArpTable`/`ArpBinding`; the detector derives `ArpAnomaly` from its
> `NeighborEvent` + `ArpMessage::is_likely_spoof`.
>
> ---
> Original plan below (2026-06-16). Candidate feature; no fixed release slot (1.0 is
> gated by community validation, not a roadmap). **flowscope-led** (we own it):
> the parser + table land there, netring surfaces them. Additive; any
> protocol-trait churn defers to the eventual 1.0 stabilization (Arch §7).

## 1. Why

ARP is high-value and underserved by Rust tooling: **L2 asset discovery**
(IP↔MAC inventory), **duplicate-IP detection**, and **ARP-spoofing/poisoning
(MITM) detection** — a classic, still-common LAN attack (the basis of
`arpwatch`/`arpalert`). It's connectionless request/reply, so it fits the same
correlation shape flowscope + netring already model for DNS and ICMP — this is a
natural extension, not new machinery.

## 2. Design

### flowscope side — `arp` feature (+ a strong-typing upgrade we own)
- **Introduce a `MacAddr([u8; 6])` newtype** in flowscope (Display `aa:bb:…`,
  `From<[u8;6]>`, `is_broadcast`/`is_multicast`/`is_zero` helpers). Today flowscope
  uses **raw `[u8; 6]`** (e.g. `MacPairKey.a/b`) — a deliberate compat break to
  adopt `MacAddr` everywhere (MacPair too) so ARP, the L2 keys, and (later) the
  VLAN metadata all share one strongly-typed MAC. This is exactly the
  "strongly-typed over raw bytes" value; cheap, `#[repr(transparent)]`, zero-cost.
- Parse EtherType `0x0806` (28-byte payload) → a **typed** message:
  `ArpMessage { oper: ArpOp, sender: MacAddr, sender_ip: Ipv4Addr, target:
  MacAddr, target_ip: Ipv4Addr }`, `enum ArpOp { Request, Reply, RarpRequest,
  RarpReply }`. **`Ipv4Addr`, not `IpAddr`** — ARP is IPv4 (the htype/ptype/hlen/
  plen header fields are validated, not surfaced; non-IPv4-over-Ethernet ARP is
  rejected, not coerced).
- L2, **no IP 5-tuple** — ARP rides below the flow tracker. Expose it as a
  *datagram-style* parser (like DNS-over-UDP): request→reply correlation keyed by
  `(sender_ip, target_ip)`, plus gratuitous detection (`sender_ip == target_ip`)
  and unsolicited replies.
- `ArpTable` in `flowscope::correlate` (mirrors `KeyIndexed`/`label_table`):
  `Ipv4Addr → ArpBinding { mac: MacAddr, first_seen, last_seen, seen_count,
  change_count, prior_mac: Option<MacAddr> }`. Source-of-truth for the detector.
  Bounded + TTL'd. Strongly typed throughout.

### netring side — ops toolkit (0.22-style, like `on_icmp_error`/`label_table`)
- `Arp` **`MessageProtocol`** marker → `on::<Arp>(|m: &ArpMessage, …|)` and the
  subscription tier `session::<Arp>()` (gated like the other L7 sessions).
  Because ARP has no 5-tuple, `session::<Arp>()` filters on ARP fields
  (`.sender_ip(..)`, `.oper(..)`), not the shared 5-tuple combinators — a small
  `L7Fields`-style impl for ARP.
- `MonitorBuilder::arp_table()` enrolls the `ArpTable`; `Ctx::arp_table()`
  accessor (parallel to `Ctx::label_table()`/`bandwidth()`).
- **`MonitorBuilder::on_arp_anomaly(|a: &ArpAnomaly, ctx|)`** — the headline
  security surface. Typed events derived in the run loop against the table:
  - `SpoofSuspected { ip, old_mac, new_mac }` — a known IP's MAC changed (the
    poisoning signal). Tunable: ignore the first N seconds (DHCP churn), or a
    per-IP allowlist of legitimate MAC changes.
  - `Conflict { ip, macs: [MAC; 2] }` — two MACs actively claim one IP.
  - `Gratuitous { ip, mac }` — announce/defend (info; spoofing often uses these).
  - `Unsolicited { ip, mac }` — a reply with no matching outstanding request.
  - `BindingNew { ip, mac }` — first sighting (asset-discovery feed).
  Severities: Spoof/Conflict = Warning/Critical; Gratuitous/Unsolicited/New = Info.
- EVE surfacing: an `event_type:"anomaly"` (or a dedicated `arp` record) so the
  existing EVE/syslog/IPFIX/OTLP sinks carry ARP findings with no new sink.

### Capture-path subtlety (must document + handle)
- ARP is **broadcast L2**. AF_PACKET sees it natively. AF_XDP's `redirect_all`
  passes it, but the **subscription kernel-pushdown filter** keys on IP
  `{proto,port}` and would **shed ARP** — so a monitor with both `session::<Arp>()`
  and IP subscriptions must widen the kernel filter to *also* match EtherType
  `0x0806`. **Good news:** the cBPF compiler (`config/bpf_compile.rs`) **already
  emits EtherType loads/compares** (for the VLAN `0x8100`/`0x88a8` path), so this
  is a small **`Atom::EtherType(u16)`** added to the predicate AST + a `Predicate`
  combinator (`packet().ethertype(0x0806)` / the `.expr()` keyword `arp`), reusing
  the existing compiler machinery — not new codegen. (The XDP `{proto,port}` map is
  a separate path; ARP rides the cBPF/fail-open side, which is correct.) Fail-open
  already covers the conservative case; this makes ARP a first-class pushdown term.
- Promiscuous mode (issue #4, shipped) lets a monitor see *other hosts'* ARP for
  full-segment / span-port coverage — note it in the docs.

## 3. Milestones
- **M1 ✅** flowscope `arp` parser + `ArpMessage` + `is_likely_spoof` (shipped
  flowscope 0.17; flowscope#1 closed).
- **M2 ✅ (partial)** `NeighborTable`/`ArpTable` (flowscope::correlate) +
  netring `on_arp` (raw feed). **`Ctx::arp_table()` deferred** → §7.
- **M3 ✅** `on_arp_anomaly` + detector (`ArpWatch` over `NeighborEvent` +
  `is_likely_spoof`) + tunables (`arp_warmup` warm-up, `arp_allow` allowlist,
  `arp_report_{gratuitous,new_binding}`). EVE surfacing rides the existing
  anomaly sink (`ctx.emit(kind.as_str(), kind.severity())`).
- **M4 ⏸ DEFERRED** EtherType atom + subscription-pushdown / `session::<Arp>()`
  field gating → §7. Today arming any ARP hook forces **fail-open capture-all**
  (`arp_wants_all()`), which is correct (no shedding) but unoptimized.
- **M5 ✅** `examples/monitor/arp_watch.rs` + docs (CHANGELOG/FEATURES/CLAUDE/
  examples README). Cap-free `arp_replay` pcap test + 5 unit tests. (The
  root-gated lo-inject test was dropped — PF_PACKET TX on `lo` doesn't loop a
  raw injected L2 frame back to PF_PACKET RX taps; pcap replay drives the same
  `dispatch_arp` path deterministically.)

## 7. Deferred → follow-up issues
- **`Ctx::arp_table()`** (cross-protocol IP→MAC lookup, e.g. a TLS handler
  resolving a peer IP to its MAC). Needs an `#[cfg(feature="arp")]
  arp_table: Option<&ArpTable>` field threaded through ~13 `Ctx` construction
  sites; deferred to keep PR #18 focused. The table already exists inside
  `ArpWatch` — only the read accessor is missing.
- **ARP as a first-class subscription/predicate term** — `Atom::EtherType(0x0806)`
  in the predicate AST + `packet().ethertype(..)` combinator + `.expr()` keyword
  `arp`, so a monitor with BOTH ARP hooks and narrow IP subscriptions can push
  "ethertype arp OR (ip narrow)" into the kernel instead of falling back to
  capture-all. The cBPF compiler already emits EtherType loads (VLAN path), so
  this reuses existing codegen. Optionally also `session::<Arp>()` field gating
  (`.sender_ip(..)`/`.oper(..)`).
- **NDP (IPv6 neighbor) sibling** — flowscope's `NeighborTable<L3, L4>` is
  already generic, so an `ndp` feature (ICMPv6 NS/NA) could reuse it with an
  `Ipv6Addr` L3. Open naming decision (`on_l2_anomaly` unifying ARP+NDP?).

## 4. Testing
- Cap-free: parser unit tests (golden ARP request/reply bytes, gratuitous,
  RARP); `ArpTable` diff logic + each `ArpAnomaly` variant via synthetic feeds;
  predicate EtherType atom via the cBPF interpreter (`BpfFilter::matches`).
- Root-gated `lo` live test: inject ARP frames on `lo` (raw AF_PACKET send),
  assert `on::<Arp>` fires and a forged MAC change raises `SpoofSuspected`.
- Real-segment spoof detection (two hosts, an attacker doing `arpspoof`) is the
  HW/topology-gated validation — example-documented, not CI.

## 5. Breaking changes
flowscope additive (`arp` feature). netring additive (new protocol marker + ops
methods + an `ArpAnomaly` event type). The EtherType predicate atom is an internal
AST extension. No user break; protocol-trait additions ride the existing
additive-with-shims convention.

## 6. Risks & open decisions
- **False positives** are the make-or-break for the spoof detector: DHCP lease
  changes, failover/VRRP MAC moves, and load-balancers legitimately move IP↔MAC.
  Ship conservative defaults (warm-up window + change-rate threshold + allowlist),
  and emit `Info`-tier `BindingNew`/`Gratuitous` separately from `Warning`-tier
  `Spoof`. Document tuning.
- **IPv6 / NDP.** ARP is IPv4-only; the IPv6 equivalent is NDP (ICMPv6
  Neighbor Solicitation/Advertisement). Out of scope here, but design `ArpTable`/
  `on_arp_anomaly` names/shape so an `ndp` sibling can join later without a rename
  (consider `NeighborTable`/`on_l2_anomaly` if we want one surface for both —
  **open decision**).
- **Where `ArpTable` lives** — flowscope (reusable, source-agnostic) vs netring
  (Monitor-coupled). Recommend flowscope (matches `KeyIndexed`/`label_table`).
