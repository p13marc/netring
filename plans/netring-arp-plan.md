# netring — ARP visibility & spoof detection (plan)

> **Status:** plan, 2026-06-16. Candidate feature; no fixed release slot (1.0 is
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

### flowscope side — `arp` feature
- Parse EtherType `0x0806` (28-byte payload):
  `ArpMessage { hw_type, proto_type, oper, sender_mac: [u8;6], sender_ip: IpAddr,
  target_mac: [u8;6], target_ip: IpAddr }` with `oper ∈ {Request, Reply,
  RarpRequest, RarpReply}`. IPv4 ARP first; carry the generic shape for RARP.
- L2, **no IP 5-tuple** — ARP rides below the flow tracker. Expose it as a
  *datagram-style* parser (like the DNS-over-UDP one): request→reply correlation
  keyed by `(sender_ip, target_ip)`, plus gratuitous-ARP detection
  (`sender_ip == target_ip`, announce/defend) and unsolicited replies.
- `ArpTable` in `flowscope::correlate` (mirrors `KeyIndexed`/`label_table`):
  `IpAddr → ArpBinding { mac, first_seen, last_seen, seen_count, change_count,
  prior_mac: Option<MAC> }`. Source-of-truth for the detector. Bounded + TTL'd.

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
  passes it, but the **subscription kernel-pushdown filter** (cBPF + the XDP
  `{proto,port}` map) keys on IP `{proto,port}` and would **shed ARP** — so a
  monitor with both `session::<Arp>()` and IP subscriptions must widen the kernel
  filter to *also* match EtherType `0x0806`. → extend the predicate AST + the
  cBPF/XDP-map compiler with an **EtherType atom** (small, additive). Fail-open
  already covers the conservative case; this makes ARP a first-class pushdown term.
- Promiscuous mode (issue #4, shipped) lets a monitor see *other hosts'* ARP for
  full-segment / span-port coverage — note it in the docs.

## 3. Milestones
- **M1** flowscope `arp` parser + `ArpMessage` + datagram correlation (publish).
- **M2** `ArpTable` (flowscope::correlate) + netring `Arp` protocol marker +
  `arp_table()`/`Ctx::arp_table()`.
- **M3** `on_arp_anomaly` + the detector logic (table diff) + tunables
  (warm-up window, allowlist) + EVE surfacing.
- **M4** EtherType atom in the predicate AST + cBPF/XDP-map compiler (ARP
  survives subscription pushdown); `session::<Arp>()` field gating.
- **M5** `examples/monitor/arp_watch.rs` (live IP↔MAC table + spoof alerts) +
  docs (capture-path note, promiscuous tie-in, detector tuning).

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
