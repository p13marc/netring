# Changelog

## Unreleased

> Depends on flowscope **0.18**. Additive over 0.26 (existing code compiles
> unchanged).

### Fixed

- **`Capture::packets()` use-after-free soundness hole** (**breaking**;
  [#35](https://github.com/p13marc/netring/issues/35)) — `Packets` was an
  `Iterator<Item = Packet<'cap>>`, decoupling each packet's lifetime from the
  `&mut self` borrow that produced it. That let safe code `.collect()` (or
  otherwise retain) packets that borrow into mmap ring blocks the kernel recycles
  on the next pull — a real dangling read. `Packets` is now a **lending
  iterator**: the `Iterator` impl is removed in favor of
  `Packets::next_packet(&mut self) -> Option<Packet<'_>>` (plus
  `Packets::for_each(|pkt| ..)` for the common loop). Binding each packet to the
  per-call `&mut self` borrow makes holding two packets, or collecting them,
  a compile error — closing the hole with zero runtime cost. **Migration:**
  replace `for pkt in cap.packets() { .. }` with
  `let mut pkts = cap.packets(); while let Some(pkt) = pkts.next_packet() { .. }`
  (or `cap.packets().for_each(|pkt| ..)`); to retain packets, `pkt.to_owned()`
  into a `Vec` inside the loop. `packets_for` / `packets_until` change the same
  way. The zero-copy batch path (`Capture::next_batch`) is unaffected.
- **BPF nested-OR error UX** ([#38](https://github.com/p13marc/netring/issues/38))
  — the typed cBPF compiler rejected a nested `or()`/`negate()` inside an `or()`
  branch with a misleading `ConflictingProtocols` error that gave no hint. It
  now returns a dedicated `BuildError::NestedOr` with an actionable message
  ("flatten to a single OR of AND-chains, e.g. `a.or(b).or(c)` not
  `a.or(|x| x.or(...))`").

### Added

- **Passive asset inventory** (issue
  [#28](https://github.com/p13marc/netring/issues/28), part 2b) — a MAC-keyed
  device inventory built from the L2/L3 discovery protocols, via two new
  builder methods (feature `asset`):
  - **`MonitorBuilder::asset_inventory(capacity)`** — enables a bounded LRU
    `flowscope::Inventory`, fed automatically from each frame's ARP / NDP /
    LLDP / CDP (whichever source features are compiled in), folded into an
    `Asset` (MAC, IPs, hostname, platform, capabilities, `seen_via`).
  - **`MonitorBuilder::on_asset(|asset, ctx| …)`** — an **inventory-event**
    stream: fires when an observation creates a *new* asset or *changes* an
    existing one (a freshly-learned IP / hostname / platform), staying quiet on
    repeat-identical frames.

  The inventory is fed independently of the `on_arp`/`on_ndp`/`on_lldp`/`on_cdp`
  hooks — enabling `asset` + at least one source feature is enough. Prelude
  exports `Asset` / `Inventory` / `AssetCapabilities` / `AssetFingerprints` /
  `AssetSourceSet`. Example `monitor_asset_inventory`; cap-free `asset_inventory`
  pcap test (asserts new-or-changed dedup). DHCP (richest single source) and the
  UDP datagram protocols (SSDP / NetBIOS-NS / mDNS) don't feed the inventory yet
  — they're drained on the L7 path and need IP→MAC resolution (a follow-up).
- **LLDP + CDP L2 link-layer discovery** (issue
  [#28](https://github.com/p13marc/netring/issues/28), part 2a) — two new opt-in
  per-frame hooks mirroring `on_arp` / `on_ndp`, for the network-infrastructure
  half of an asset inventory:
  - **`MonitorBuilder::on_lldp`** (feature `lldp`) — every parsed IEEE 802.1AB
    `flowscope::LldpMessage` (chassis id, port id, system name, capabilities,
    management addresses). LLDP is EtherType `0x88cc`, so arming it contributes a
    precise `EtherType(0x88cc)` kernel-prefilter term (same pushdown as ARP).
  - **`MonitorBuilder::on_cdp`** (feature `cdp`) — every parsed Cisco
    `flowscope::CdpMessage` (device id, platform, software version,
    capabilities, addresses). CDP rides 802.3 LLC/SNAP, which has no EtherType
    term the cBPF model can match — **arming a CDP hook forces capture-all**
    (fail-open).

  Both are L2 (no 5-tuple), parsed per-frame in the zero-copy drain and the
  pcap replay loop. Folded into the `monitor` / `monitor-quickstart` umbrellas;
  prelude exports `LldpMessage`/`ChassisId`/`PortId` and
  `CdpMessage`/`CdpAddress`/`CdpCapabilities`. Example `monitor_l2_discovery`;
  cap-free `lldp_replay` / `cdp_replay` pcap tests. **Live-capture note:**
  LLDP/CDP are link-local multicast — the interface must actually receive them
  (promiscuous / multicast membership). The `asset::Inventory` aggregator that
  ties these to a MAC-keyed device record is the next slice of #28.
- **SSH protocol visibility + HASSH** (issue
  [#30](https://github.com/p13marc/netring/issues/30), first Tier-2 protocol) —
  new opt-in `Ssh` `Protocol` marker (feature `ssh`, TCP/22) surfacing
  flowscope 0.18's passive SSH parser via `.protocol::<Ssh>()` + `.on::<Ssh>()`.
  Each `flowscope::ssh::SshMessage` carries the version `Banner` and the decoded
  `KexInit` algorithm name-lists with the **HASSH** handshake fingerprint
  (`SshKexInit::hassh`, client or HASSHServer per `from_client`) — the SSH
  analogue of JA3/JA4. Parsing stops at `SSH_MSG_NEWKEYS` (the rest is
  encrypted). `Ssh` is a `MessageProtocol` (flow lifecycle is the underlying
  TCP flow); folded into `all-parsers` + the `monitor` / `monitor-quickstart`
  umbrellas; prelude exports `Ssh`. Example `monitor_ssh_hassh`. (The remaining
  Tier-2 protocols — FTP/SMTP/SNMP/NTP/… — land as flowscope ships parsers.)
- **JA4X + JA4H fingerprint surfacing** (issue
  [#31](https://github.com/p13marc/netring/issues/31)) — completes the FoxIO
  JA4+ family alongside the existing JA4 / JA4S:
  - `TlsFingerprint` gains a `ja4x` field (the leaf-certificate fingerprint:
    issuer / subject / extension OID hashes), populated from
    `flowscope::tls::TlsHandshake::ja4x`. Existing `on_fingerprint` handlers
    get it for free. `None` for TLS 1.3 (encrypted cert).
  - New `HttpFingerprint` bundle (JA4H + method / host / user-agent + flow key)
    and a `MonitorBuilder::on_http_fingerprint(|fp, ctx| …)` hook — the HTTP
    analogue of `on_fingerprint`: it auto-registers the `Http` protocol and
    computes JA4H over each request via `flowscope::http::ja4h_fingerprint`.

  Both JA4X and JA4H are **FoxIO License 1.1** (non-commercial; patent
  pending), so they live behind the opt-in `ja4plus` feature (with JA4S) —
  the default JA3 + JA4 client surface stays BSD/royalty-free. Prelude exports
  `HttpFingerprint`. The `monitor_ja4_fingerprint` example now matches JA4 /
  JA4S / JA4X / JA4H against a blocklist. (p0f passive-TCP and HASSH/SSH
  fingerprints are a follow-up — p0f needs packet-tier plumbing and HASSH a
  new SSH parser overlapping #30.)
- **Asset-discovery protocol visibility** (issue
  [#28](https://github.com/p13marc/netring/issues/28), part 1) — three new
  opt-in L7 datagram `Protocol` markers surfacing flowscope 0.18's passive
  broadcast/discovery parsers, usable via `.protocol::<P>()` + `.on::<P>()`:
  - **`Dhcp`** (feature `dhcp`, UDP/67–68) → `flowscope::dhcp::DhcpMessage`:
    `client_mac` → `hostname` (opt 12), `vendor_class` (opt 60), and the
    Fingerbank-style `fingerprint()` (opt 55 + opt 60) — the richest single
    asset-discovery signal on a LAN.
  - **`Ssdp`** (feature `ssdp`, UDP/1900) → `flowscope::ssdp::SsdpMessage`:
    UPnP `server` banner, `location` URL, `usn` / `st` service type.
  - **`Nbns`** (feature `netbios-ns`, UDP/137) → `flowscope::netbios_ns::NbnsMessage`:
    `queried_name` / `name_suffix` and `answer_addresses` (legacy Windows
    hostnames; also the NBT-NS poisoning channel).

  All three are `MessageProtocol`s (the flow lifecycle is the underlying UDP
  flow). New umbrella feature `asset-protocols = [dhcp, ssdp, netbios-ns]`,
  folded into `all-parsers` and the `monitor` / `monitor-quickstart`
  umbrellas. Prelude exports `Dhcp`/`Ssdp`/`Nbns`. Example
  `monitor_asset_discovery`. Parsers are passive and metadata-only.
  (mDNS, the L2 LLDP/CDP parsers, and the `asset::Inventory` aggregator that
  ties all sources to a MAC-keyed device record are a follow-up — mDNS yields
  the same `DnsMessage` as `Dns`, so it belongs in the absorb-based inventory
  path, not a type-dispatched `on::<P>` marker.)
- **Lateral-movement / Active Directory protocol visibility**
  ([#29](https://github.com/p13marc/netring/issues/29)) — four new opt-in L7
  `Protocol` markers surfacing flowscope 0.18's passive AD parsers, each usable
  via `.protocol::<P>()` + `.on::<P>(|msg, ctx| …)`:
  - **`Smb`** (feature `smb`, TCP/445) → `flowscope::smb::SmbMessage`: admin-share
    access (`tree_connect_is_admin_share`), abused named pipes
    (`create_is_admin_named_pipe`), DCE-RPC binds incl. `drsuapi` (DCSync), and
    `ntlm_auth` identity.
  - **`Kerberos`** (feature `kerberos`, TCP/88) → `flowscope::kerberos::KerberosMessage`:
    `kerberoast_suspect` (RC4-HMAC TGS-REQ, T1558.003), offered `etypes`, and
    `error_code` brute-force/enumeration signals.
  - **`Ldap`** (feature `ldap`, TCP/389) → `flowscope::ldap::LdapMessage`:
    `search_attributes_spn_query` (GetUserSPNs / BloodHound), `bind_auth_kind`
    (cleartext Simple vs SASL), and `result_code`.
  - **`Rdp`** (feature `rdp`, TCP/3389) → `flowscope::rdp::RdpMessage`: the
    `mstshash=` `cookie_username` (T1021.001) and NLA/CredSSP downgrades via the
    negotiated `RdpProtocols`.

  All four are `MessageProtocol`s (their flow lifecycle is the underlying TCP
  flow). New umbrella feature `ad-protocols = [smb, kerberos, ldap, rdp]`, folded
  into `all-parsers` and the `monitor` / `monitor-quickstart` umbrellas. Prelude
  exports `Smb`/`Kerberos`/`Ldap`/`Rdp`. Example `monitor_lateral_movement`
  emits an anomaly per high-signal indicator. Parsers are passive and
  metadata-only (no payload decryption, no active probing). Kerberos surfaces the
  TCP/88 path; UDP/88 is a follow-up.
- **Reassembler-hardening config on `MonitorBuilder`**
  ([#34](https://github.com/p13marc/netring/issues/34)) — surfaces flowscope
  0.18's reassembler hardening: `tcp_overlap_policy(..)` (the Ptacek–Newsham
  overlap-resolution policy; default BSD `First`), `reassembly_memcap(bytes,
  policy)` (state-holding-DoS bound), and `active_idle_threshold(..)`
  (CICFlowMeter active/idle accounting). `tracker_config()` inspects the
  resolved config. Prelude re-exports `TcpOverlapPolicy` / `MemcapPolicy`.
- **NDP (IPv6 Neighbor Discovery) visibility + spoof detection** — new opt-in
  `ndp` feature ([#24](https://github.com/p13marc/netring/issues/24)), the IPv6
  sibling of `arp`. The Monitor walks each frame to its ICMPv6 NS/NA message
  (via flowscope 0.18's `ndp` module) in the zero-copy drain, learns
  `IPv6 → MAC` bindings into a `NeighborTable`, and surfaces
  `MonitorBuilder::on_ndp` (raw `NdpMessage` feed) + `on_ndp_anomaly`
  (`SpoofSuspected` = unsolicited override NA carrying a MAC, the SLAAC-poisoning
  vector; `BindingChanged`; opt-in `Unsolicited` / `NewBinding`), with
  `ndp_allow` / `ndp_warmup` / `ndp_report_*` tuning. Arming an NDP hook narrows
  the kernel prefilter to ICMPv6 (proto 58). In the `monitor` umbrellas; prelude
  exports `NdpAnomaly`/`NdpAnomalyKind` + `NdpMessage`/`NdpKind`.
- **ARP visibility + spoof/binding-change detection** — new opt-in `arp`
  feature ([#12](https://github.com/p13marc/netring/issues/12)). ARP is L2
  (no 5-tuple), so the Monitor parses each frame for ARP inside the zero-copy
  drain (and the pcap-replay loop), mirroring the packet-tier hook, and drives
  a detector built on flowscope's `NeighborTable` + `ArpMessage::is_likely_spoof`.
  - `MonitorBuilder::on_arp(|m: &ArpMessage, ctx|)` — every parsed ARP message.
  - `MonitorBuilder::on_arp_anomaly(|a: &ArpAnomaly, ctx|)` — derived security
    signal: `SpoofSuspected` (gratuitous reply, target MAC ≠ sender — fires even
    during warm-up) and `BindingChanged` (a known IP now claims a different MAC),
    plus opt-in informational `Gratuitous` / `NewBinding`.
  - `arp_allow(ip, mac)` allowlist (gateways/VRRP), `arp_warmup(d)` (default 5 s),
    `arp_report_gratuitous` / `arp_report_new_binding`.
  - Arming any ARP hook forces capture-all at the kernel prefilter (ARP can't be
    expressed in the 5-tuple cBPF union) — fail-open, no starvation.
  - `arp` is in the `monitor` / `monitor-quickstart` umbrellas. Prelude exports
    `ArpAnomaly`/`ArpAnomalyKind` + re-exports `ArpMessage`/`ArpOp`/`MacAddr`.
  - Example `monitor_arp_watch`; cap-free `arp_replay` pcap test (drives the
    real `replay → dispatch_arp → parse_frame → detector` path).
- **ARP as a first-class kernel-pushdown term**
  ([#20](https://github.com/p13marc/netring/issues/20)). New `Atom::EtherType`
  predicate atom + `packet().ethertype(..)` / `.arp()` combinators + `.expr()`
  keywords `arp` / `ethertype 0x0806`. Arming an ARP hook now contributes a
  precise `EtherType(0x0806)` interest instead of forcing fail-open
  capture-all: a pure-ARP monitor sheds non-ARP traffic in-kernel, and an
  ARP+IP monitor captures `arp OR (the IP interests)`. The cBPF compiler
  already emitted EtherType matches (the VLAN path), so this is AST + wiring,
  not new codegen.
- **`Ctx::arp_table()`** ([#19](https://github.com/p13marc/netring/issues/19),
  [#23](https://github.com/p13marc/netring/issues/23)) — read-only access to
  the learned `IP → MAC` binding table. An **ARP** detector can look beyond the
  triggering message (cross-check the sender's gateway, ARP-scan counting,
  binding change history); and (#23) **flow / session / lifecycle handlers**
  can resolve a peer IP to the MAC that last claimed it — e.g. an
  `on::<FlowStarted<Tcp>>` / `on::<Tls>` handler annotating a flow with the
  peer's MAC. Threaded into the post-borrow dispatchers (`Δ0` alloc preserved);
  `None` only on the packet tier (pre-flow) and the shutdown drain.
  `MonitorBuilder::arp_table()` arms learning without an ARP handler (so a
  pure flow/TLS monitor can enrich with MACs). The run loop now parses ARP
  whenever any ARP hook *or* `arp_table()` is armed (was gated on having an ARP
  handler, which left a table-only monitor empty).

### Changed

- **flowscope 0.16 → 0.18.** 0.17 brought `MacAddr`, the `arp` module, the
  `NeighborTable`, `RxMetadata` on a now-`#[non_exhaustive]` `PacketView`, and
  `detect::fingerprint`. **0.18** is a huge additive release — ~25 new protocol
  parsers (QUIC, SMB2/3, Kerberos, LDAP, SSH, DHCP, LLDP/CDP, NTP, SSDP, mDNS,
  NetBIOS-NS, FTP, SMTP, WireGuard, Modbus, DNP3, STUN, RDP, SNMP, RADIUS, TFTP),
  the `asset` inventory layer, `ml_features` (CICFlowMeter parity) + `nprint`,
  binary IPFIX export (`ipfix::wire`), p0f/HASSH/JA4H/JA4X fingerprints, and TCP
  overlap-policy + memcap reassembler hardening. netring consumes only the stable
  core (arp/tls/http/dns/icmp/driver), so the bump is additive — the one fix is a
  fallback arm for the now-`#[non_exhaustive]` `L4Proto` in the cBPF lowering
  (fail-open). Surfacing the new 0.18 capabilities is tracked in follow-up issues.

## 0.26.0 — 2026-06-16 — AF_XDP multi-queue capture & promiscuous mode

> Completes the AF_XDP capture story (issues #4 + #6): promiscuous mode, the
> high-level `XdpCapture` (one socket per RX queue, `Queues::Auto` via ethtool),
> the Monitor `xdp_queues` single-reactor tier that removes the silent
> single-queue under-capture footgun, and the `XdpShardedRunner` line-rate tier
> (one Monitor per queue, busy-poll). Additive over 0.25 (existing code compiles
> unchanged). Depends on flowscope 0.16. Companion `netring-exporters` 0.1.1.

### Added

- **AF_XDP hardening** ([#6](https://github.com/p13marc/netring/issues/6), M5 finish).
  - **B1:** `netring::xdp::default_program(max_queues)` now **honors** its argument —
    the XSKMAP is sized via aya's `EbpfLoader::set_max_entries` (was ignored; map
    fixed at 256). `XdpCapture` sizes the map to exactly its queue set.
  - **F3:** `XdpCaptureBuilder::numa_auto()` / `XdpShardedRunner::numa_auto(true)`
    bind every queue's UMEM to the NIC's NUMA node, read from
    `/sys/class/net/<iface>/device/numa_node` (new `netring::xdp::interface_numa_node`).
  - **F1:** `XdpSocketBuilder::shared_umem` documented as **expert-only** with the
    per-CPU FILL-queue race caveat; per-socket UMEM (the `XdpCapture` default)
    stays the blessed multi-queue path. (No shared-UMEM opt-in added to
    `XdpCapture` — it would be a footgun.)

- **Per-queue sharded AF_XDP capture: `XdpShardedRunner`** ([#6](https://github.com/p13marc/netring/issues/6), M5 Tier 2).
  The line-rate multi-queue model — one `Monitor` (worker thread) per RX queue,
  the AF_XDP analogue of `ShardedRunner` (which shards AF_PACKET via
  `PACKET_FANOUT`). It builds one shared `XdpCapture` (one attached program, one
  socket per queue, one promiscuous guard) and hands each shard its socket via a
  new injection seam, so every queue gets full flow tracking on its own core
  (Suricata's `threads: auto`). Per-queue **busy-poll** (`SO_BUSY_POLL` /
  `SO_PREFER_BUSY_POLL` / `SO_BUSY_POLL_BUDGET`, also new on `XdpCapture`) + CPU
  pinning are the performance levers. Use `MonitorBuilder::xdp_queues` for the
  single-reactor (one-core) tier; `XdpShardedRunner` when one core can't keep up.
  Example: `examples/xdp/xdp_sharded.rs`.

- **Monitor multi-queue AF_XDP + async capture** ([#6](https://github.com/p13marc/netring/issues/6), M3/M4).
  `MonitorBuilder::xdp_queues(Queues)` (monitor-wide, mirroring `promiscuous`)
  makes a self-loading AF_XDP interface capture **every RX queue**, not just
  queue 0 — removing the silent single-queue under-capture footgun on multi-queue
  NICs. `Queues::Auto` opens one socket per queue behind a single program and
  drains them through a unified round-robin (`AnyBackend::XdpMq`); the default
  stays `Queues::Single(0)` (no behavior change). New `netring::AsyncXdpCapture`
  is the tokio front for `XdpCapture` (per-queue `AsyncFd`s, unified
  `readable().await` + owned `recv()`, `into_parts()` for the worker-per-queue
  model). This is the single-reactor tier; the sharded worker-per-queue tier
  (line rate) is still to come.

- **High-level multi-queue AF_XDP capture** ([#6](https://github.com/p13marc/netring/issues/6)).
  `netring::xdp::XdpCapture` opens **one socket per RX queue** (the only way to
  capture a whole multi-queue NIC — RSS spreads traffic across queues, which a
  single socket can't see even in promiscuous mode), loading one redirect
  program, registering each socket in its XSKMAP, attaching once, and draining
  them through a unified round-robin `next_batch()` / `next_batch_blocking()`.
  Each socket gets its **own UMEM** (the safe default — sharing a UMEM across
  per-CPU sockets races on the FILL ring). Queue selection via
  `Queues::{Single, Range, Auto}`; `Auto` auto-detects the RSS queue count with
  `netring::xdp::queue_count()` (`ETHTOOL_GCHANNELS`) and falls back to queue 0.
  `into_parts()` hands out the per-queue sockets + a guard for the
  worker-per-queue model. `XdpSocket::is_zerocopy()` / `XdpCapture::is_zerocopy()`
  surface the bind mode (was log-only). This is phases M1–M2 of the 0.26 plan;
  the Monitor `xdp_queues(...)` integration that removes the single-queue
  under-capture footgun and an async wrapper follow.
- **Promiscuous mode for AF_XDP** ([#4](https://github.com/p13marc/netring/issues/4)).
  `XdpSocketBuilder::promiscuous(bool)` (per-socket) and a backend-agnostic
  `MonitorBuilder::promiscuous(bool)` (monitor-wide; applies to both AF_PACKET
  *and* AF_XDP capture interfaces) put the interface into promiscuous mode for
  the capture's lifetime, so AF_XDP can see traffic not addressed to the local
  MAC (SPAN/mirror ports, passive sniffing). Promiscuity is a `netdev` property —
  AF_XDP has no socket knob for it — so netring holds it through an auxiliary
  AF_PACKET socket joined to `PACKET_MR_PROMISC` (the same mechanism the
  AF_PACKET path uses). The kernel reference-counts `dev->promiscuity` and
  releases it automatically when the socket is dropped, including on crash; no
  manual restore, no leak. Default off. Two documented caveats:
  `PACKET_MR_PROMISC` does not raise the user-visible `IFF_PROMISC` flag, and on
  a multi-queue NIC a single XSK still only sees its bound queue's RSS share —
  full capture wants one socket per queue (`examples/xdp/xdp_multiqueue.rs`) or a
  single queue (`ethtool -L <iface> combined 1`).

## 0.25.0 — 2026-06-15 — subscriptions, async effects, performance & TX

> The complete capability release on the 0.24 keystone: typed 3-tier
> subscriptions + kernel filter pushdown, async read+effect handlers, perf &
> scaling (CPU pinning, dispatch-throughput numbers), the symmetric TX stack,
> the in-Monitor AF_XDP loader, UMEM hugepages/NUMA, and the `netring-exporters`
> companion crate. Additive over 0.24 (existing code compiles unchanged).
> Depends on **flowscope 0.16**.

### JA4S licensing fix + JA3/JA4 now actually populate

- **JA4S moved behind the opt-in `ja4plus` feature** (off by default; excluded
  from the `monitor` / `all-parsers` umbrellas). JA4S is part of the JA4+ suite
  and is **FoxIO License 1.1** (non-commercial; patent pending), not MIT/Apache.
  `TlsFingerprint.ja4s` only exists under `ja4plus`, which pulls flowscope's
  `ja4plus` (≥ 0.16). The default TLS fingerprint surface (JA3 + JA4 client)
  stays royalty-free / BSD. Commercial use of `ja4plus` requires a FoxIO OEM
  license — see `docs/FINGERPRINTS.md`. Depends on **flowscope 0.16**, which
  did the same gating upstream (`LICENSE-FoxIO-1.1` + `NOTICE`).
- **Fix:** the `tls` feature now enables `flowscope/tls-fingerprints`, so JA3 +
  JA4 client fingerprints actually compute (they were silently always-`None`
  before — the passthrough was missing). The `monitor_ja4_fingerprint` example
  now requires `ja4plus` (it demonstrates JA4S).

### Runtime filter strings — `.expr()` (Phase A4)

- `packet()/flow::<P>()/session::<P>().expr("tcp and dst port 443")` — a small,
  **dependency-free** recursive-descent parser from a Wireshark-ish filter
  string to the **same** `Predicate` AST the typed combinators produce. One AST,
  two frontends: `packet().expr("tcp and dst port 443")` and
  `packet().tcp().dst_port(443)` are identical (a test pins this), so a runtime
  string lowers to the same userspace eval *and* kernel pushdown. This is the
  path for filters from config / CLI / a control plane.
- Grammar: `and`/`or`/`not` (+ `&&`/`||`/`!`), parens, `tcp`/`udp`/`icmp`,
  `[src|dst] port|host|net`, `vlan`, `bytes > N` / `packets > N`, and
  `tls.sni`/`http.host`/`dns.qname ~ GLOB`. We deliberately do **not** depend on
  the dead `wirefilter-engine` crate (0.6.1/2019). `parse()` returns a
  `ParseError` (no panics) on malformed input.

### Subscription engine — typed tiers + filter predicates (Phase A1)

The new front door (additive; `on::<E>` unaffected). A **subscription** pairs
a strongly-typed tier with a filter [`Predicate`] and a handler:

- Three tier constructors in `netring::monitor::subscription`: `packet()`
  (every frame), `flow::<P: FlowProtocol>()`, `session::<P: MessageProtocol>()`.
  Invalid combinations are compile errors — `flow::<Http>()` and
  `session::<Tcp>()` don't compile; L7 glob filters are gated per protocol
  (`session::<Tls>().sni_glob`, `session::<Dns>().qname_glob`).
- Typed filter combinators AND into one `Predicate` AST (proto / ports /
  host / net / vlan — kernel-pushable — plus byte/packet counts and L7
  sni/host/qname globs). The AST is shared by userspace evaluation
  (`Predicate::eval` over a `FieldSource`) and, in A2/A3, kernel pushdown;
  `Atom::is_kernel_pushable()` is the split classifier.
- **Packet tier wired end-to-end**: `MonitorBuilder::subscribe(packet()…​.to(h))`
  runs the handler on every matching frame as a borrowed `PacketView`,
  synchronously **inside the zero-copy drain before flow tracking** — so the
  handler sees raw frames pre-tracking with no copy. Works on live capture and
  pcap replay. Monitors with no packet subs keep the `track_into`-only hot
  loop (dhat stays `Δ 0`); the run-loop future stays `Send`.
- `IpNet::contains(&IpAddr)` (v4 + v6); dependency-free case-insensitive `Glob`.

### Kernel filter split + cBPF compiler (Phase A2 / A3a)

- `Predicate::kernel_approx()` — the conservative **split**: a predicate over
  only kernel-pushable atoms that is a superset of the original (every frame
  the filter wants still passes). Userspace atoms relax to `Always`; `Not` is
  pushed only when fully kernel-pushable. The full predicate stays the
  userspace filter; the kernel side is a pure prefilter.
- A classic-BPF compiler lowers a kernel-approx predicate to a `BpfFilter`
  (DNF → conjunctions of L2–L4 atoms, OR-unioned across packet subs), with a
  safe fallback to "no filter" for shapes it can't express (negations, etc.).
  Verified in-sandbox via the `BpfFilter::matches` software interpreter.
### Safe automatic kernel pushdown (Phase S1 / S2)

The kernel prefilter is now computed from **every** consumer's traffic interest
and auto-applied to the AF_PACKET capture — safely.

- Each consumer declares its traffic interest: handlers via a new
  `Event::traffic_class()` (→ the protocol's `Dispatch`, default `Any`),
  protocol parsers via their `Dispatch`, packet subs via their filter. The
  Monitor folds them into the OR-union `kernel_prefilter()`.
- Because the union is a **superset** of every consumer's interest, the pushed
  filter can never drop a frame any consumer wants — **starvation-free by
  construction**. It is **fail-open**: any "wants everything" consumer (a broad
  handler, exporter, tick/report, broadcast, bandwidth), or a union exceeding
  the cBPF clause budget, collapses it to "capture all" (no filter).
- The run loop applies the union via `set_filter` on each AF_PACKET socket at
  start. A narrow monitor (`protocol::<Tls>()`) pushes `tcp port 443/8443`;
  adding `on::<FlowStarted<Udp>>` widens it to also pass UDP; adding
  `on::<FlowPacket>` collapses it to capture-all. Verified end-to-end via the
  `BpfFilter::matches` interpreter (`tests/monitor_kernel_prefilter.rs`).
  `kernel_prefilter()` stays public for inspection. dhat `Δ 0` on the hot path.

### Flow & session tier dispatch (Phase S3)

The flow and session tiers now deliver, at each tier's **natural completion
point** (Retina `on_terminate` semantics):

- `flow::<P>().bytes_over(N).to(handler)` — fires once per flow, at `FlowEnded`,
  with the accumulated stats (so byte/packet-count filters are meaningful).
- `session::<P>().sni_glob("*.bank").to(handler)` — fires with each parsed
  `P::Message` whose L7 fields (SNI / HTTP host / DNS qname, via a new
  `L7Fields` trait per message type) and flow 5-tuple match the filter.

Both are sugar over the existing typed dispatch: `.to()` installs a
predicate-gated `on::<…>` handler. A new `Subscribable` trait lets the one
`MonitorBuilder::subscribe` accept any tier (packet / flow / session). The
tier's traffic interest is recorded automatically (a superset of the filter),
so it composes with the S1/S2 kernel-prefilter union safely. Verified end-to-end
via pcap replay (`replay_flow_tier_delivers_once_at_flow_end_gated_by_stats`,
`replay_session_tier_dns_qname_glob_gates_delivery`). dhat `Δ 0`.

The table-driven AF_XDP map program (A3c, hardware-gated) and the runtime
`.expr()` string frontend (A4) follow. (Design:
`plans/netring-0.25-subscription-engine-design.md`.)

### Async read + effect handlers (Phase B1)

- New `MonitorBuilder::on_effect::<E>(handler)` — an **async** handler that
  reads the `Ctx` **synchronously** (`Fn(&E::Payload, &Ctx<'_>)`) and returns
  a `'static` future resolving to an `Effects` value: a deferred, owned
  description of the writes to apply (today: `Effects::emit(anomaly)` /
  `and_emit`; `set_state`/`counter`/`enqueue` are additive follow-ups). The
  run loop awaits the future, then applies the effects to the sink under a
  short `&mut Ctx` write phase. Because the handler never holds `&mut Ctx`
  across `.await`, the run-loop future stays **`Send`** — unlike a
  hypothetical `Fn(&mut Ctx) -> Future` shape. This closes the gap between
  `on_async` (payload-only, can `.await` but can't read `Ctx`) and sync `on`
  (reads `Ctx` but can't `.await`).
- Effect handlers fire **after** the sync and async passes for the same
  lifecycle event, in registration order. Monitors that register no effect
  handlers pay nothing: the run loop gates the effect pass on
  `effect_handler_count() > 0`, so the per-event `Ctx`-rebuilding translation
  is skipped entirely. dhat steady state stays `Δ 0 / 0`.

### Dispatcher (Phase B2)

- The per-monitor distinct-event-type cap is lifted (was a hard 16): the
  lookup table is inline (no hashing) for the first 16 types and spills to
  a hash map beyond, so there's no practical ceiling. dhat stays `Δ 0`.
- Debug-only dispatcher type-tag asserts the `TypeId → slot` mapping stays
  consistent (turns a silent type-erasure desync into a loud test panic;
  zero release cost).

### In-Monitor AF_XDP loader + table-driven filter map (W1a)

- `MonitorBuilder::xdp_interface_loaded(iface)` (feature `xdp-loader`): the
  Monitor attaches the built-in redirect-all XDP program and registers its
  socket on the XSKMAP itself — one-call AF_XDP capture, no external loader.
  (`xdp_interface(iface)` remains the bring-your-own-program form.)
- Table-driven `filter_redirect.bpf` program + `loader::filter_program()` +
  `XdpProgram::set_filter(proto, port, on)`: a `BPF_MAP_TYPE_HASH`-driven
  XDP program that redirects only `{proto, port}`-matching frames (the
  kernel-side early-shed), populated from the subscription union.
- **Fix:** the loader now embeds bytecode with `aya::include_bytes_aligned!`
  instead of `include_bytes!`. The zero-copy ELF parse requires alignment;
  the plain macro loaded only when the static happened to land aligned and
  failed (`"error parsing ELF data"`) in any build that also pulls `tokio`
  (i.e. every Monitor build) — so redirect-all was already broken for
  Monitor-on-AF_XDP. Guarded by a cap-free `vendored_programs_parse_under_aya`
  test.
- **Fix:** `XdpSocketBuilder::force_replace(true)` no longer crashes with
  `EINVAL` — `XDP_FLAGS_REPLACE` is netlink-only and rejected by the link API
  on kernel ≥ 5.9, so it's no longer OR'd into the link-create flags; a failed
  attach returns an actionable error instead.

### Active-timeout flow export (W1c)

- `MonitorBuilder::export_active_timeout(period)`: emits interim `FlowRecord`s
  for long-lived flows every `period` (NetFlow/IPFIX active-timeout semantics),
  not just one at `FlowEnded`. **Breaking (additive type change):**
  `FlowRecord.reason` is now `Option<EndReason>` — `None` marks an ongoing
  active-timeout snapshot (`FlowRecord::is_ongoing()`); IPFIX maps it to
  flowEndReason `0x02` (active timeout).

### EVE `event_type:"tls"` records (W1d)

- `netring::anomaly::{EveTlsSink, eve_tls_record}` (features `eve-sink` + `tls`):
  Suricata-compatible `event_type:"tls"` EVE records (sni, ja3.hash, ja4,
  ja4s under `ja4plus`, alpn, 5-tuple, ISO-8601 timestamp) — the protocol-record
  companion to `EveSink`'s `event_type:"anomaly"`. Wire it via `on_fingerprint`.

### Resilience: backend Reopen + handler panic catching (W1e)

- `BackendErrorPolicy::Reopen`: rebuilds a failed capture source in place (same
  kind + filter) so a transient fault (interface flap, driver reset) self-heals.
- `MonitorBuilder::catch_handler_panics(true)`: wraps sync handlers in
  `catch_unwind`, converting a panic into `Error::HandlerPanic` routed through
  the configured `HandlerErrorPolicy` (pair with `Isolate` to log + count +
  continue). Off by default; async handlers/effects are not covered.

### Performance & scaling (Phase C)

- `ShardedRunner::pin_cpus(true)`: pins each shard's OS thread to its core via
  `sched_setaffinity` (keeps flow state + RX ring + worker core-local).
- `benches/dispatch_throughput.rs`: a cap-free userspace pps proxy
  (~4.7 Melem/s/core flow tracking on the dev box), run in CI. `docs/PERFORMANCE.md`
  documents the capture-vs-dispatch split, the dhat-Δ0 enforced gate, tuning
  levers (pushdown, sharding+pinning, fanout + symmetric-RSS pitfall, AF_XDP,
  busy-poll, hugepages), and an honest real-NIC-pending methodology.
- `monitor/tracing_json` example: structured JSON logging of anomalies +
  telemetry via `tracing-subscriber`.

### TX symmetry (Phase D)

- `AsyncInjector::send_stream(stream, Option<TxPacer>)`: transmits every frame
  from a `Stream<Item = impl AsRef<[u8]>>`, optionally paced. `TxPacer` is a
  token-bucket pacer (`packets_per_second` / `bits_per_second`).
- TX egress timestamping: `InjectorBuilder::tx_timestamps(true)` enables
  `SO_TIMESTAMPING`; `Injector::read_tx_timestamp()` /
  `AsyncInjector::read_tx_timestamp()` read the `SCM_TIMESTAMPING` egress
  timestamp off the error queue (hardware-preferred-else-software).

### AF_XDP UMEM hugepages + NUMA (W4)

- `XdpSocketBuilder::hugepages(bool)` (`MAP_HUGETLB`, graceful fallback) +
  `numa_node(u32)` (`mbind`/`MPOL_BIND`, best-effort). After bind, a
  `getsockopt(XDP_OPTIONS)` check warns when the kernel fell back to COPY mode.

### `netring-exporters` companion crate (W5)

- New workspace crate keeping heavy OTLP/Kafka deps out of core.
  `OtlpAnomalySink` (feature `otlp`, OTLP/HTTP-JSON logs via blocking `ureq`)
  and `KafkaSink` (feature `kafka`, `rdkafka`/librdkafka) both implement
  `AnomalySink`, so they drop into `MonitorBuilder::sink(...)`.

## 0.24.0 — zero-copy core + production trust

> **Released 2026-06-14.** Makes the `Monitor` pipeline zero-copy +
> resilient + self-observable, and brings AF_XDP to the high-level
> Monitor. The previous published version was **0.22.0**; 0.24.0 folds in
> the **0.23 `Send` run-loop** work (never released standalone) — see the
> 0.23.0 section below + `docs/MIGRATING_0.22_TO_0.23.md` if upgrading
> from 0.22. From 0.23 it is **additive** (`docs/MIGRATING_0.23_TO_0.24.md`);
> the one planned break is reserved for 1.0. Depends on flowscope `0.15`.

### Zero-copy + `Send` borrowed run loop (Phase B keystone)

The run loop drains **borrowed** zero-copy batches in place and feeds
each packet's view straight to the flowscope driver — the per-packet
`Packet::to_owned` copy is gone. The future stays `Send` (the only
borrow held across an `.await` is inside `readable()`, and all dispatch
runs *after* the batch is dropped). dhat steady state stays `Δ 0 / 0`.

### Backend abstraction — `AnyBackend` (Phase B)

- The Monitor run loop is now **backend-agnostic**: every capture source is
  an `AnyBackend` drained through one `drain_batch(impl FnMut(PacketView))`
  path (a concrete enum, not a `dyn`/AFIT trait — keeps the run-loop future
  `Send`). The borrowed zero-copy + Send + dhat-Δ0 contract is preserved.
- `MonitorBuilder::xdp_interface(iface)` (feature `af-xdp`) — adds an AF_XDP
  capture source alongside `.interface(...)`; the run loop opens an
  `AnyBackend::Xdp` and drains it identically. This is the seam that lets
  AF_XDP reach the high-level Monitor (an attached XDP redirect program is
  still required to receive traffic; full in-Monitor loader integration is a
  follow-up). Live AF_XDP capture needs hardware to exercise end to end.

### Resilience (Phase B)

- `HandlerErrorPolicy { Propagate (default), Isolate }` +
  `MonitorBuilder::handler_error_policy` — `Isolate` logs + counts a
  handler error and continues, so one bad detector/flow can't tear down
  the pipeline.
- `BackendErrorPolicy { FailFast (default), SkipSource }` +
  `MonitorBuilder::backend_error_policy` — `SkipSource` keeps servicing
  the other capture sources, with a consecutive-error circuit breaker.
- Errors swallowed by `Isolate` / `SkipSource` are silent by design, so
  they're now counted and exposed: `MonitorHealth::handler_errors()` /
  `backend_errors()` (+ in the snapshot), and `MonitorHealth::record_metrics()`
  emits `netring_monitor_{handler_errors,backend_errors,active_flows}`
  gauges (feature `metrics`). Alert on a rising count.

### Capture telemetry (Phase C1/C2)

- `CaptureTelemetry { source, packets, drops, freezes, drop_rate }` +
  `MonitorBuilder::on_capture_stats(period, |telemetry, ctx|)` — the run
  loop samples each source's cumulative kernel counters every `period`
  and fires the handler once per source, with a **windowed** `drop_rate`
  (so a current loss spike is visible even when lifetime totals dwarf
  it) plus `lifetime_drop_rate()` / `is_degraded(threshold)` helpers.
  Gated: a monitor without the hook never arms the sampler (zero cost).
- `CaptureHealth` (a built-in `Report`) + `MonitorBuilder::capture_health(period, sink)`
  — the no-code form: ships one per-source health record per period to any
  `ReportSink<CaptureHealth>` (`StdoutReportSink` / `JsonReportSink` / custom).
- `CaptureTelemetry::record_metrics()` + `MonitorBuilder::capture_metrics(period)`
  (feature `metrics`) — Prometheus gauges `netring_capture_{packets,drops,freezes,drop_rate}`
  tagged `source`. New `docs/METRICS.md` catalogs every `netring_*` metric
  with cardinality notes.

### TLS fingerprinting — JA4/JA4S (Phase E)

- Bumps flowscope to **0.15** (adds JA4S server fingerprinting).
- `TlsFingerprint` + `MonitorBuilder::on_fingerprint(|fp, ctx|)` (feature
  `tls`) — bundles SNI + ALPN + JA3/JA4/JA4S + flow key per completed
  handshake, auto-registering the `TlsHandshake` protocol. `.ja4s` is also
  available directly via `on::<TlsHandshake>` now that the dep carries it.
- `examples/monitor/ja4_fingerprint.rs` — JA4/JA4S blocklist IOC matcher;
  `docs/FINGERPRINTS.md` — the JA3/JA4/JA4S guide + JA4 (BSD) vs JA4+
  (FoxIO) licensing note.

### Monitor health (Phase C4)

- `Monitor::health()` → `MonitorHealth`, a cheap cloneable `Arc`-backed
  handle (lock-free atomics). Kubernetes-probe split:
  `is_ready()` (sockets open + loop servicing) for `/readyz`,
  `is_live(window)` (event within window, with startup grace) for
  `/healthz`, plus `uptime()` / `last_event_age()` / `active_flows()` /
  `packets()` / `drops()` / `snapshot()`. The run loop (live + replay)
  updates it as it captures.
- `examples/monitor/health_endpoint.rs` — serves readiness/liveness over
  a dependency-free tiny tokio HTTP/1.1 responder (no axum).

### Exporters (Phase D)

- `FlowRecord` + `FlowExporter` + `MonitorBuilder::export_flows(e)` — the
  fourth output shape: one record per *completed flow* (5-tuple +
  directional byte/packet counts + start/end + end-reason), built from
  each `FlowEnded` and fanned out to registered exporters (live + replay,
  including flows finalized at shutdown). A bare `FnMut(&FlowRecord)` is a
  `FlowExporter`; `JsonFlowExporter<W>` writes NDJSON (feature `serde`).
- `SyslogSink<W>` (feature `syslog`, no deps) — an `AnomalySink` that
  writes one RFC 5424 line per anomaly to any `Write`. `<PRI>1 TS HOST
  APP PROCID MSGID [SD] MSG`, with the 5-tuple key + observations/metrics
  in a `[netring@<PEN> …]` structured-data element (RFC 5424 §6.3.3
  escaping). Builder setters for app-name / hostname / procid / facility
  (`SyslogFacility`) / enterprise-id; `SyslogSink::stdout()`.
- `IpfixExporter<W>` (feature `ipfix`, no deps) — a `FlowExporter` that
  encodes each `FlowRecord` as an IPFIX / NetFlow v10 message (RFC 7011):
  IPv4/IPv6 template sets + per-flow data sets over ~11 core IANA IEs
  (proto, src/dst addr+port, packet/octet counts, flow start/end ms, end
  reason). `resend_templates_every(n)` for lossy UDP transport. Golden-
  byte tested.

### Backpressure honesty (Phase C3)

- `ChannelSink::bounded(capacity)` — drop-with-count via `try_send`, so
  the capture task never blocks on a slow anomaly consumer.

### CI

- Dedicated cap-free **Monitor lib tests** job runs the `flow`-gated
  Monitor/telemetry/layer suite (~300 tests) that no other job covered.
- miri (Tree Borrows) + cargo-fuzz (cBPF compiler/interpreter) jobs.

## 0.23.0 — spawnable run loop (breaking)

> **Folded into 0.24.0 — never released to crates.io standalone.** A
> small, focused **breaking** change: the `Monitor` run-loop future is now
> `Send + 'static`. Migration:
> [`netring/docs/MIGRATING_0.22_TO_0.23.md`](netring/docs/MIGRATING_0.22_TO_0.23.md).

### `Monitor::run_for(..)` and friends return a `Send` future

The future returned by `run_for` / `run_until` / `run_until_signal` /
`run_until_idle` is now **`Send + 'static`**, so the run loop can be
`tokio::spawn`'d onto its own worker task instead of being pinned to
the task that owns it (the 0.22 `!Send` caveat is resolved). Keeping it
on the main task with `tokio::select!` still works — spawning is now an
additional option.

Two `!Send` sources on the async-dispatch path were removed; the
capture mmap ring was already `Send`, so **no per-packet copy was
needed** and the dhat zero-alloc steady state is unchanged
(`Δ 0 bytes / 0 blocks`).

- `BoxFuture<T>` is now `Pin<Box<dyn Future<Output = T> + Send>>`.
- `Dispatcher::dispatch_async` constructs each handler future before
  any `.await`, inside a block that confines the type-erased payload
  pointer (zero-alloc fast paths for the 0- and 1-handler cases).

**Breaking.** `on_async` handlers must now return `Send` futures — the
same requirement `tokio::spawn` imposes. Handlers that capture `Arc<…>`
and perform network/disk I/O (the canonical case) already satisfy it; a
handler holding a non-`Send` guard across its own `.await` must move
that work behind a `ChannelSink` or `Arc<Mutex<…>>`.

- `examples/monitor/multi_thread_default.rs` now demonstrates
  `tokio::spawn(monitor.run_for(..))`.
- `tests/monitor_send.rs` gains a compile-time assertion that all four
  run-mode futures are `Send + 'static`.

## 0.22.0 — operations toolkit + typed protocol model (breaking)

> **Released 2026-06-13.** A large, deliberately
> infrequent **breaking** release: it reshapes the type model so the
> next cycles build on a cleaner foundation, absorbs flowscope 0.14,
> ships a high-level operations toolkit (bandwidth-by-app, ICMP-error
> correlation, custom labels, a report stream), completes sharding, and
> removes the legacy 0.19 surface. Migration:
> [`docs/MIGRATING_0.21_TO_0.22.md`](netring/docs/MIGRATING_0.21_TO_0.22.md).
>
> **flowscope floor: `>= 0.14.1`** (the ICMP datagram-routing fix that
> makes `on_icmp_error` work — see below).

### Headline — the `net_diagnostic` example: 306 → ~70 LoC

The real-life "what's on this NIC?" monitor (ICMP errors + TCP resets +
bandwidth-by-app) collapses from 306 lines of hand-rolled classifiers, a
bandwidth HashMap, and a multi-slot tick reporter to ~70 lines on the new
high-level API: `on_icmp_error` + `on_tcp_reset` + `on_bandwidth`.

### Breaking changes

- **Legacy 0.19 API removed** (~−5400 LoC): `ProtocolMonitor` /
  `ProtocolMonitorBuilder`, `AnomalyMonitor`, `AnomalyRule`,
  `FlowAnomalyRule`, the `ProtocolEvent` / `ProtocolMessage` sum-type,
  and the deprecated `on_with_marker`. The `Anomaly` / `AnomalyContext`
  / `Severity` value types stay. Use `Monitor::builder()` +
  `detect(detector!{…})` / `pattern_detector!{…}`.
- **Typed protocol roles** (`FlowProtocol` / `MessageProtocol`). The
  type system now rejects nonsensical combinations: `on::<Tcp>` and
  `FlowStarted<Http>` are **compile errors** (Tcp has no message; HTTP
  rides a TCP flow). `Tcp`/`Udp` are flow-only, `Http`/`Dns`/`Tls`
  message-only, `Icmp` both. `subscribe`/`with_broadcast` are bounded to
  `MessageProtocol`.
- **`FlowPacket` is flat** — `FlowPacket { proto, key, side, len, tcp,
  ts }` replaces `FlowPacket<P>`. One handler branches on `evt.proto`
  instead of two. (Lifecycle events `FlowStarted`/`Ended`/`Established`/
  `FlowTick<P>` stay parameterised.)
- `KeyIndexed` is now `flow`-gated (it already lived behind `flow`).

### Added — flowscope 0.14 absorption (the operations toolkit)

- **Bandwidth by app.** `MonitorBuilder::on_bandwidth(period, |bw| …)` —
  a one-liner that auto-registers a per-app rolling byte-rate and a
  periodic report; the closure gets a typed `BandwidthReport`
  (`top(n)` / `rate(app)` / `total()` / `app_count()` — no `Timestamp`/
  `Option`/`RollingRate` at the call site). Also `bandwidth_by_app()` /
  `bandwidth_windowed()` + `ctx.bandwidth()`. Per-packet path stays
  zero-alloc.
- **ICMP-error correlation.** `MonitorBuilder::on_icmp_error(|err, ctx| …)`
  + the `IcmpError` typed event — unified v4/v6, pre-classified
  (`IcmpErrorKind`: `DestUnreachable`/`TimeExceeded`/`ParameterProblem`/
  `MtuSignal`), with the originating flow joined (`correlated_flow` via
  `from_inner_canonical`, `stats` via `FlowTracker::stats_for_inner`).
- **TCP resets.** `on_tcp_reset(|rst, ctx| …)` + `TcpRst { key, stats,
  ts, zero_payload }`, synthesised from `FlowEnded<Tcp>` with `reason ==
  Rst`.
- **Custom port labels.** `MonitorBuilder::label_table(table)` +
  `ctx.label_table()` + `netring::well_known::LabelTable`.
- **`all_l4()` / `all_l7()`** protocol umbrellas.
- **Report stream** (a third output beside anomalies + broadcast):
  `Report` / `ReportSink` traits + `report(period, |snap| …)` /
  `report_to(period, build, sink)` + `ReportSnapshot`; `StdoutReportSink`
  / `JsonReportSink`; `BandwidthSnapshot` as the reference report.
- **`Ctx` accessors:** `state::<T>()` (immutable), `counter::<K>()`,
  `label_table()`, `lookup_icmp_flow()`. Prelude gains ~15 names; new
  `docs/discoverability.md` (primitives-by-use-case tour).
- `KeyIndexed::drain_expired_into(now, &mut buf)` (allocation-free
  variant; kept netring-side — flowscope's 0.14 `KeyIndexed` diverged
  into an LRU shape).

### Added — sharding completion

- **Cross-shard state merging.** `ShardedRunner::merge_state` /
  `state_auto_merge` / `on_merge` — a merge-worker thread folds each
  shard's `T` into a global total (no more `Tee + ChannelSink` collator
  workaround). No hot-path locking; per-shard state stays local.
- **`LayerSpec`** + `LayerFactory` — per-shard layer minting
  (`ShardedRunner::layer(spec)`); cloneable config layers pass directly,
  non-`Clone` layers (`Tee`) via `LayerFactory`.

### Added — polish

- `MinSeverity::{at_least,info,warning,error}` are now `const fn`;
  `info()` added.
- `MonitorBuilder::tick_ctx(period, |ctx| …)` — payload-eliding tick.
- `docs/MIGRATING_0.21_TO_0.22.md`, `plans/netring-0.22-send-future-decision.md`,
  `examples/monitor/multi_thread_default.rs`.

### Fixed (flowscope 0.14.1, shipped this cycle)

- **ICMP datagram routing.** `datagram_broadcast(IcmpParser)` never
  delivered ICMP messages — the datagram driver extracted only UDP
  payloads, so `on_icmp_error` (and the 0.21 ICMP examples) were silently
  broken. flowscope 0.14.1 also returns the ICMP message for
  `TransportSlice::Icmpv4`/`Icmpv6`.

### Deferred

- **eBPF-accelerated bandwidth** (R6) — designed in
  `netring/docs/EBPF_BANDWIDTH.md` (per-CPU BPF-map accounting, Cilium/aya
  shape); the XDP backend's payoff needs measurement on a real multi-Gbps
  NIC, so it's gated on that (0.23 or a hardware session).
- Kernel-side TCP-RST / ICMP correlation eBPF — 0.23.

## 0.21.0 — Send Monitor + sharding + streaming subscribers + pcap replay

The 0.21 cycle polishes the 0.20 Monitor API into a Send, multi-thread
runtime; adds per-CPU sharding, a streaming-subscriber API, offline
pcap replay, a graceful drain phase, and a wide pattern-detector
catalogue adopted from flowscope 0.13's `detect::patterns` /
`detect::file` modules. Legacy `ProtocolMonitor` / `AnomalyMonitor` /
`AnomalyRule` types are marked `#[deprecated(since = "0.21.0")]`;
removal scheduled for 0.22.0.

### Highlights

- **Monitor is now `Send`.** flowscope 0.13's `Driver<E>: Send + Sync`
  cleared the last `!Send` field; `Monitor`, `MonitorBuilder`,
  `ShardedRunner`, `EventStream<M>` all carry compile-time `Send`
  asserts (`tests/monitor_send.rs`). All monitor examples drop
  `#[tokio::main(flavor = "current_thread")]` for plain
  `#[tokio::main]`.
- **Per-CPU sharding** via `ShardedRunner::new(iface, mode, group_id,
  num_shards, build_shard)`. AF_PACKET fanout distributes packets
  by `FanoutMode::Cpu` / `Hash` / `EBPF`. Each shard runs on its
  own OS thread + tokio runtime.
- **Streaming subscribers** via `MonitorBuilder::with_broadcast::<P>()` +
  `Monitor::subscribe::<P>() -> EventStream<P::Message>`. `EventStream`
  implements `futures_core::Stream` for plug-in with
  `StreamExt::next()` / `tokio::select!`.
- **Offline pcap replay** via `MonitorBuilder::pcap_source(path) +
  Monitor::replay()`. Optional `pcap_speed_factor(f)` for paced
  replay. Skips the `NoInterface` check at build time.
- **`run_until_idle(window)`** stop condition — exits after `window`
  of inactivity (tick fires + packets reset the timer). Pairs
  cleanly with pcap replay.
- **Graceful drain** — `MonitorBuilder::drain_timeout(dur)` (default
  1s) flushes in-flight flow ends + protocol-slot drains + sink
  flush before returning. Bounded; skipped at `Duration::ZERO`.
- **Per-flow state** via `MonitorBuilder::flow_state::<T>(idle_timeout)`
  + `ctx.flow_state_mut::<T>() -> Option<&mut T>`. Backed by
  flowscope's `FlowStateMap`. Lazy-creates per flow, evicts on
  `FlowEnded`.

### Added — Monitor builder API

- **`MonitorBuilder::name(name)`** + `Ctx::monitor_name: Option<&str>`
  propagation. Multi-monitor processes can disambiguate per
  emission. `Box<str>` storage on `Monitor`, borrowed at dispatch
  time.
- **`MonitorBuilder::fanout(FanoutMode, group_id)`** AF_PACKET
  fanout setter for single-shard interop or sharded mode wiring.
- **Split `.on::<E>()` (PayloadOnly) and `.on_ctx::<E>()` (PayloadCtx)**
  handler registrations. `on::<E, _, _>()` deprecated.
- **`MonitorBuilder::state_init::<T, F>(factory)`** for non-`Default`
  state types; **`.state_with::<T>(value)`** for caller-supplied
  initial state.
- **`MonitorBuilder::flow_state::<T>(idle_timeout)`** + the
  matching `ctx.flow_state_mut::<T>()` accessor.
- **`MonitorBuilder::counter::<K>(window, bucket)`** unchanged but
  now uses `TimeBucketedCounter::new_unbounded` upstream.
- **`MonitorBuilder::with_broadcast::<P>()`** opts the protocol into
  broadcast delivery so `Monitor::subscribe::<P>()` works for it.
- **`MonitorBuilder::pcap_source(path)`** + **`pcap_speed_factor(f)`** +
  `Monitor::replay()` / `replay_with_config(cfg)`. Relaxes the
  `NoInterface` check when set.
- **`MonitorBuilder::drain_timeout(dur)`** — graceful drain budget;
  default 1s.

### Added — handler/event surface

- **`FlowPacket<P>`, `FlowTick<P>`, `ParserClosed<P>`** typed
  events — `dispatch_lifecycle` arms for both sync and async
  paths.
- **`Event::protocol_marker()` + `Event::protocol_name()`** trait
  methods feed the new build-time validation
  (`BuildError::HandlerForUnregisteredProtocol`).
- **`Ctx::emit(kind, severity)`** shortcut anchors an
  `AnomalyWriter` to `ctx.ts` in one expression.
- **`Ctx::split_state_sink<T>` + `_counter` + `_sink_counter` +
  `_state_sink_counter`** disjoint-borrow helpers via audited
  `unsafe`.
- **`AnomalyWriter::with_dynamic(label, value)`** runtime-label
  escape hatch (one `Box::leak` per call — documented).
- **`AnomalyWriter::emit_owned() -> OwnedAnomaly`** materializes
  without firing the sink — useful for log lines + downstream
  collectors.

### Added — sinks + layers

- **`EveSink`** (feature `eve-sink`) — Suricata EVE JSON adapter
  over `flowscope::emit::EveJsonWriter`. Downcast 5-tuples land
  in structured JSON fields; non-FiveTupleKey events stay
  loggable.
- **`MetricsSink`** (feature `metrics`) — metrics-rs facade
  emitting `netring_anomaly_total` counter + `netring_anomaly_metric`
  histogram. Cardinality contract: only `kind` + `severity`
  labels.
- **`Tee::factory(|| sink)`** closure-based secondary-sink ctor.
  Each `Layer::wrap` invocation mints a fresh secondary; pairs
  with `ShardedRunner` for per-shard JSON logs without `S: Clone`.
- **`crate::anomaly::sink::publish_owned(&mut dyn AnomalySink, &OwnedAnomaly)`**
  publishes an `OwnedAnomaly` through any layer chain; used by
  `pattern_detector!`.

### Added — detection patterns

- **`pattern_detector! { name, event, detector, feed, verdict }`**
  macro wrapping any detector implementing
  `flowscope::DetectorScore` in `Arc<Mutex<D>>`. Used by:
  - `examples/monitor/port_scan.rs` — TRW port-scan detection
  - `examples/monitor/beacon_detector.rs` — C2 beacon detection
  - `examples/monitor/dga_query.rs` — DGA domain scoring on DNS
    queries
- **`examples/monitor/file_hash_dfir.rs`** — Sha256Sink + FileType
  flagging PE/ELF/Mach-O over plain HTTP. Gated on new `file-hash`
  Cargo feature.
- **`examples/monitor/ech_adoption.rs`** — ECH outcome surveillance
  using flowscope's `TlsHandshake::ech_outcome`.

### Added — release/quickstart features

- **Cargo feature `monitor-quickstart`** — pulls every 0.21 sink +
  detector + flowscope-bonus feature: `tokio + channel + flow +
  parse + pcap + metrics + http + dns + tls + icmp + emit +
  eve-sink + file-hash + serde`. Lean embedded builds still
  cherry-pick the granular flags directly.
- **Cargo feature `file-hash`** — pass-through for
  `flowscope/file-hash`. Pulls `sha2` only when enabled.
- **Cargo feature `eve-sink`** — pass-through for
  `flowscope/emit-eve`.
- **`netring::prelude`** now re-exports `AnomalyFields`,
  `DetectorScore`, `Key`, `KeyFields` alongside the existing
  monitor surface.

### Added — build-time validation

- **`BuildError::HandlerForUnregisteredProtocol { protocol_name }`** —
  fires when a handler for an L7 message event is registered
  without `.protocol::<P>()`. Lifecycle events
  (`FlowStarted<Tcp>` etc.), `Tick`, `AnyFlowAnomaly` are exempt.
- **`BuildError::CounterNotRegistered { detector, type_name }`** —
  fires when `detector! { counters: [K] }` is declared without
  a matching `.counter::<K>(...)`.
- **`BuildError::ProtocolNotBroadcast { protocol_name }`** —
  fires when `Monitor::subscribe::<P>()` is called for a
  non-broadcast-opted protocol.
- **`BuildError::PcapSourceRequired`** — fires when
  `Monitor::replay()` is called without `pcap_source` set.

### Changed

- **Legacy types `#[deprecated(since = "0.21.0")]`:**
  `ProtocolMonitor`, `ProtocolMonitorBuilder`, `AnomalyMonitor`,
  `AnomalyRule`. Note message points at
  `docs/MIGRATING_0.20_TO_0.21.md`. Removal scheduled for 0.22.0.
- **`AnomalySink::write` key parameter** is `Option<&dyn Key>`
  (was `Option<&dyn Debug>` in 0.20). The new `Key` super-trait
  inherits `KeyFields + Debug + Send + Sync` so sinks can
  downcast for structured emission (e.g. EveSink → 5-tuple JSON
  fields).
- **`netring::correlate::TimeBucketedCounter`** dropped from
  netring; re-exported from `flowscope::correlate` (along with
  `BurstDetector`, `Ewma`, `FlowStateMap`, `KeylessSequencePattern`,
  `SequencePattern`, `TimeBucketedSet`, `TopK`). All in-tree call
  sites switched to `::new_unbounded(window, bucket)`.
  `KeyIndexed` stays netring-side because flowscope's version
  lacks the `drain_expired(now) -> impl Iterator<Item = (K, V)>`
  semantics netring's "expected B-after-A didn't happen"
  detectors need.
- **`flowscope` dep bumped 0.11.1 → 0.13.0.** Pickups:
  `BroadcastSlotHandle`, `DetectorScore`, `OwnedAnomaly`,
  `AnomalyFields`, `FlowStateMap`, `Sha256Sink + FileType`,
  ECH outcomes on `TlsHandshake`, `pattern_detector` upstream
  helpers.
- **`BoxedHandler`** storage swapped from `Box<dyn FnMut + Send>`
  to `Arc<dyn Fn + Send + Sync>` (private API but enables the
  `Dispatcher::clone_for_shard` cheap-refcount path used by
  Phase C sharding).
- **`Protocol::register_broadcast(builder)`** companion trait
  method — defaults to `Err`, overridden on `Http` (others gain
  the override case-by-case when their `Message` types are
  `Clone`).
- **`ProtocolSlot: Send`** supertrait. Required to make
  `Monitor: Send`.

### Internal

- ~25 commits on `0.21-dev` branch under the per-phase plans
  (`plans/netring-0.21-phase-{A..I}-*.md`). Each plan file is
  deleted in this release per the "delete on ship" convention.
- New `netring::monitor::shard` module containing
  `ShardedRunner` + per-shard thread spawn machinery.
- New `netring::monitor::subscribe` module with `EventStream<M>`
  + `Stream` impl.
- Updated dhat zero-alloc bench still measures Δ 0 bytes / Δ 0
  blocks over 100k synthetic dispatches with the new fields
  threaded through `Ctx::new`.

### Migration

A dedicated guide lives at `docs/MIGRATING_0.20_TO_0.21.md`. The
legacy API surface continues to compile; mechanical migration
recipes are mostly opt-in (the bump itself is API-additive). The
notable breaks:

- `AnomalySink::write` key type — `Option<&dyn Debug>` →
  `Option<&dyn Key>`. Custom sink impls need to update.
- `Protocol` trait grows `register_broadcast` — default impl
  returns `Err`, so existing `Protocol` impls compile unchanged
  unless they want broadcast.
- `Event` trait grows `protocol_marker()` + `protocol_name()` —
  defaults to `None` / `"unknown"`, so existing `Event` impls
  compile unchanged.
- `TimeBucketedCounter::new(window, bucket)` →
  `TimeBucketedCounter::new_unbounded(window, bucket)`. Or
  pull flowscope's 3-arg `new(window, bucket, capacity)`
  directly when you want the cap.

## 0.20.0 — declarative Monitor API (Protocol trait + Handler + Layer + macro)

The biggest API redesign since 0.13. Brings a single fluent
entrypoint for multi-protocol monitors built around a
[`Protocol`](netring::protocol::Protocol) plugin trait, a typed
event dispatcher with sync + async [`Handler`](netring::monitor::Handler)
slots, tower-style [`Layer`](netring::layer::Layer) middleware
over anomaly emission, and a `detector!` macro for stateless
detector definitions.

```rust
use netring::prelude::*;

Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()
    .protocol::<Http>()
    .on::<FlowStarted<Tcp>, _, _>(|evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
        ctx.state_mut::<HttpStats>().connections += 1;
        Ok(())
    })
    .on::<Http, _, _>(|msg: &flowscope::http::HttpMessage, ctx: &mut Ctx<'_>| {
        ctx.counter_mut::<IpAddr>().bump(client_ip, ctx.ts);
        Ok(())
    })
    .layer(MinSeverity::warning())
    .layer(DedupeAnomalies::within(Duration::from_secs(60)))
    .sink(StdoutJsonSink::default())
    .run_until_signal()
    .await?;
```

The legacy `ProtocolMonitor` / `ProtocolMonitorBuilder` /
`AnomalyMonitor` / `AnomalyRule` API surface continues to work
in 0.20.0 — both APIs coexist. The legacy types are *not* yet
deprecated; a future 0.21.x release will mark them `#[deprecated]`,
and 0.22.0 will remove them. The migration is mechanical: see
`docs/migration-0.19-to-0.20.md` for recipes.

### Added — `netring::protocol::Protocol` plugin layer

- **`Protocol` trait** — open-set plugin layer for protocols. Implementors
  are zero-sized markers (e.g. `pub struct Http;`); they expose
  `type Message`, `const NAME: &'static str`, `fn dispatch() -> Dispatch`
  and `fn register(&mut DriverBuilder<FiveTuple>) -> Result<SlotHandle…>`.
- **7 builtin markers in `netring::protocol::builtin`**: `Tcp`, `Udp`
  (lifecycle-only — central tracker emits events), `Icmp` (under
  `feature = "icmp"`), `Http`, `Dns`, `Tls`, `TlsHandshake` (under
  their respective L7 features).
- **`Dispatch` enum**: `Tcp(Vec<u16>)`, `Udp(Vec<u16>)`, `Icmp`,
  `AllTcp`, `AllUdp`, `Signature(fn(&[u8]) -> SignatureMatch)`.
  Routes packets to protocol slots; the `Signature` variant
  enables heuristic, port-agnostic dispatch.
- **`FlowKey` type alias** = `flowscope::extract::FiveTupleKey`.
- **`SignatureMatch` enum** mirroring flowscope's: `Match` /
  `NoMatch` / `NeedMoreData`. `From<flowscope::detect::signatures::SignatureMatch>`
  for lossless interop with flowscope's signature library.
- **`ProtocolInitError`** — thiserror struct surfaced from
  `Protocol::register`; lifecycle-only markers return `Err` to
  signal "no parser slot needed."

### Added — `netring::monitor::Monitor` + `MonitorBuilder`

- **`Monitor::builder()`** fluent API for assembling a fully-wired
  monitor — interface, protocols, handlers, state, counters, sink,
  layers, ticks — and running it.
- **`MonitorBuilder` methods**:
  - `.interface("eth0")` / `.interfaces([…])` — capture interface(s).
  - `.protocol::<P>()` — register a `Protocol` impl; calls
    `P::register(&mut driver_builder)` to install the parser slot.
  - `.on::<E, _, _>(handler)` — register a sync handler for event `E`.
  - `.on_async::<E, _>(handler)` — register an async handler.
  - `.state::<T>()` / `.state_with(value)` — pre-register monitor state.
  - `.counter::<K>(window, bucket)` — register a `TimeBucketedCounter<K>`.
  - `.sink(s)` — replace the default `NoopSink`.
  - `.layer(L)` — wrap the sink chain in a middleware layer
    (outermost-first; runtime order: emit → L1 → L2 → S).
  - `.tick(period, handler)` — register a periodic tick handler
    (recorded but not yet fired; lights up in Phase F).
  - `.detect(handler)` — sugar alias for `.on(...)`.
  - `.build() -> Result<Monitor>`.
- **Run modes**: `Monitor::run_until(deadline)` /
  `run_for(duration)` / `run_until_signal()` (SIGINT/SIGTERM via
  tokio::signal::unix).
- **`!Send` `Monitor`** — flowscope's `SlotHandle` holds `Rc<RefCell<…>>`.
  Use with `#[tokio::main(flavor = "current_thread")]` or
  `LocalSet`. Documented in the `Monitor` rustdoc.

### Added — `Handler` + `AsyncHandler` traits

- **`Handler<E, Marker>`** trait — sync handler shape. Blanket
  impls via the axum coherence-marker trick:
  - `Fn(&E::Payload) -> Result<()>` — `Handler<E, PayloadOnly>`
  - `Fn(&E::Payload, &mut Ctx<'_>) -> Result<()>` — `Handler<E, PayloadCtx>`
- **`AsyncHandler<E>`** trait — async handler shape:
  - `Fn(&E::Payload) -> Fut where Fut: Future<Output = Result<()>> + 'static`
  - Per-dispatch cost: one boxed future per async handler per
    event. Sync handlers cost zero allocations.
  - Async handlers receive payload-only — capture an `Arc<…>` for
    shared state, or pair with a `ChannelSink` for downstream I/O.

### Added — `Ctx<'a>` per-event context

- **`Ctx::flow: Option<FlowKey>`**, **`Ctx::ts: Timestamp`**,
  **`Ctx::source: SourceIdx`** — public fields populated by the
  dispatcher per event.
- **`Ctx::state_mut::<T>()`** — `&mut T` lazy-created on first
  access; `T: Default + Send + 'static`.
- **`Ctx::counter_mut::<K>()`** — `&mut TimeBucketedCounter<K>`
  registered via `MonitorBuilder::counter::<K>(...)`.
- **`Ctx::sink_mut()`** — `&mut dyn AnomalySink` for emission.
- **`Ctx::split_state_sink::<T>()`** and friends — disjoint-borrow
  helpers via audited `unsafe` for handlers that need
  simultaneous `&mut` to two or three Ctx fields.

### Added — typed event markers

- **`FlowStarted<P: Protocol>`**, **`FlowEnded<P>`**,
  **`FlowEstablished<P>`** — typed lifecycle events that the
  dispatcher routes by `TypeId`. A handler for `FlowStarted<Tcp>`
  never fires for UDP starts.
- **`AnyFlowAnomaly`** — cross-protocol anomaly event from the
  flowscope tracker.
- **`Tick`** — periodic tick payload (recorded; firing path lands
  in Phase F).
- **`Event` trait** — what handlers subscribe to. Blanket impl
  `impl<P: Protocol> Event for P { type Payload = P::Message }`
  lets users write `.on::<Http>(...)` for raw HTTP messages.

### Added — `netring::anomaly::sink` + `AnomalyWriter`

- **`AnomalySink` trait** — replaces ad-hoc `Anomaly<K>` push to
  a `Vec`. Object-safe; exposes a single `write(...)` method.
- **`AnomalyWriter<'sink>`** — stack-only builder for one anomaly.
  `ArrayVec<_, 8>` for observations and metrics; `&'static str`
  literals pass through `with(...)` as `Cow::Borrowed` (zero
  alloc). Overflow past 8 entries is silently dropped.
- **`AnomalySinkExt`** blanket extension — gives typed sinks a
  `.begin(...)` method without coercing through `&mut dyn`.

### Added — 4 shipped sinks

- **`StdoutSink`** — one greppable text line per anomaly to
  stdout. Reused scratch buffer (zero allocations in steady state).
- **`StdoutJsonSink`** — one JSON object per anomaly, feature
  `serde`. One allocation per emit (serde_json::Map).
- **`TracingSink`** — emits `tracing::event!` at the level
  matching the anomaly's `Severity`. Target = `netring::anomaly`.
- **`ChannelSink`** — forwards owned `OwnedAnomaly` payloads to a
  tokio mpsc receiver. The only shipped sink that allocates per
  anomaly (intentional — retains payload past dispatch frame).

### Added — `netring::layer` middleware

- **`Layer` trait** — netring-internal middleware shape (object-safe).
- **`MinSeverity`** — drops anomalies below a `Severity` floor.
- **`DedupeAnomalies`** — suppresses repeated `(kind, key)`
  anomalies within a sliding window.
- **`RateLimitAnomalies`** — per-kind token-bucket rate limiter.
- **`Sample`** — probabilistic per-anomaly sampling (inline
  xorshift64*; no rand dep).
- **`Tee`** — fan-out to two sinks.

### Added — `detector!` macro

Declarative DSL for stateless detectors. Expands to a closure
that satisfies `Handler<E, PayloadCtx>`:

```rust
let det = detector! {
    name:     "TruncatedTls",
    severity: Warning,
    event:    TlsHandshake,
    matches:  |hs| hs.outcome == HandshakeOutcome::Truncated,
    emit:     |hs, ctx| {
        let now = ctx.ts;
        ctx.sink_mut()
            .begin("TruncatedTls", Severity::Warning, now)
            .with("sni", hs.sni.as_deref().unwrap_or("<none>"))
            .emit();
    },
};
Monitor::builder().protocol::<TlsHandshake>().detect(det).build()?;
```

### Added — `netring::prelude`

Glob-importable surface: `use netring::prelude::*;` brings in
~30 names covering the canonical monitor + detector flow.

### Added — `monitor` umbrella Cargo feature

```toml
netring = { version = "0.20", features = ["monitor"] }
```

Pulls `tokio + channel + flow + parse + metrics + http + dns + tls
+ icmp + emit + serde` — the full Monitor experience. Embedded
users who need a lean build keep using the granular features.

### Added — `bench-zero-alloc` Cargo feature + dhat benchmark

`benches/zero_alloc.rs` runs 100k synthetic dispatches through a
fully-wired `Dispatcher` (3 handlers + state + counter + sink)
under `dhat` and asserts `Δ heap < 512 bytes / Δ blocks < 100`
in steady state. Local run measures **Δ 0 bytes / Δ 0 blocks** —
the dispatcher + sink path is allocation-free.

```sh
cargo bench --features bench-zero-alloc --bench zero_alloc
```

On regression `dhat-heap.json` drops in CWD with the per-callsite
profile.

### Added — `error::BuildError`

New error enum surfaced from `MonitorBuilder::build`. Variants:
`NoInterface`, `MultiInterfaceNotYetSupported`,
`TooManyEventTypes { limit: 16, actual }`,
`ProtocolDispatchMismatch(String)`.

### Coexistence with the 0.19 API

The legacy `ProtocolMonitor` / `ProtocolMonitorBuilder` /
`ProtocolEvent` / `AnomalyMonitor` / `AnomalyRule` /
`FlowAnomalyRule` continue to exist and work in 0.20.0 — no
existing example or detector required code changes. A future
0.21.x will add `#[deprecated]` attributes; 0.22.0 will remove
them.

### Phase F shipped (parts F.1 + F.2)

- **Multi-interface monitors** (`.interfaces([a, b, c])`) — Phase
  F.1. Run loop fans in N AF_PACKET captures with a fair
  round-robin select; each event tagged with its source
  interface's `SourceIdx` (0 for the first registered iface,
  etc.). Single-interface monitors continue to work unchanged.
  `BuildError::MultiInterfaceNotYetSupported` is now
  `#[deprecated]` and no longer returned by the builder.
- **Tick handler firing** — Phase F.2. The run loop now runs a
  per-handler `tokio::time::interval` alongside the packet
  stream. First tick fires at `now + period`; missed ticks are
  skipped, not queued. Both the `.tick(period, handler)`
  closure and any `.on::<Tick, _, _>(handler)` registrations
  fire on each tick.

### Phase F placeholder (deferred to 0.21+)

- **Per-CPU sharding** (PACKET_FANOUT-backed `fanout_per_cpu`
  builder + `merge_state` + `ShardedMonitor`) — Phase F.3. Needs
  resolution of the "handler factory" problem (per-shard
  dispatchers need either `Fn + Clone` user handlers or
  `Arc<dyn Fn>` factories — not addressed by the original Phase
  F plan). Targeted for 0.21.

### New deps

- `rustc-hash = "2"` — `FxHashMap` for `TypeId`-keyed maps.
- `arrayvec = "0.7"` — `ArrayVec` for the dispatcher slot table
  + the anomaly writer's inline observations/metrics.
- `dhat = "0.3"` (optional, `bench-zero-alloc` feature only) —
  steady-state allocation regression benchmark.

### Tests

463 tests at landing time (up from 314 at 0.19.0). Coverage adds
unit tests per layer, dispatcher + registry tests, async-handler
integration tests, the dhat zero-alloc bench, and end-to-end
Monitor smoke tests on `lo`.

### Files / module changes

- New: `src/ctx/`, `src/monitor/`, `src/layer/`, `src/prelude.rs`,
  `src/detector_macro.rs`, `src/anomaly/sink.rs`,
  `src/anomaly/shipped_sinks.rs`, `benches/zero_alloc.rs`.
- Modified: `src/lib.rs` (new module declarations + re-exports),
  `src/error.rs` (BuildError + Build variant), `src/protocol/mod.rs`
  (Protocol trait + Dispatch + SignatureMatch + ProtocolInitError),
  `src/protocol/builtin/*.rs` (each impls Protocol via
  `register`).

## 0.19.0 — flowscope 0.11.1 absorption

Mechanical lockstep bump to flowscope 0.11.1. flowscope's plan 121
shipped the typed `Driver<E>` + `SlotHandle<M, K>` shape (replacing
the closed `Driver<E, M>` from 0.10), plan 119 added scratch-buffer
parser APIs + `Driver::track_into`, and plan 120 migrated HTTP
payloads (method/path/reason/headers) to `Bytes` throughout.

netring 0.19.0 absorbs these changes while preserving the existing
public API surface — `ProtocolMonitorBuilder`, `ProtocolMonitor`,
`ProtocolEvent`, `ProtocolMessage`, every per-protocol method,
every example, every detector continues to work without code
changes *except* the single Send-bound note below.

The larger user-facing redesign — `Protocol` trait + `Handler<E,
M>` blanket impls + tower-style middleware — is documented in
[`plans/netring-0.19-redesign-2026-06-09.md`](plans/netring-0.19-redesign-2026-06-09.md)
and lands as a future release on top of this 0.19.0 baseline.

### Breaking

- **`ProtocolMonitor`'s `Stream` impl is no longer `+ Send`.**
  flowscope 0.11's `SlotHandle<M, K>` uses `Rc<RefCell>` for
  single-thread-by-design dispatch; this transitively makes
  `ProtocolMonitor` `!Send`. Users on
  `#[tokio::main(flavor = "current_thread")]` (the recommended
  pattern for packet capture) see zero impact. Users who were
  `tokio::spawn`-ing a `ProtocolMonitor` on the default multi-
  thread runtime need to either:
    1. switch to `flavor = "current_thread"` (recommended; better
       perf on capture workloads anyway), or
    2. wrap the monitor in a worker that forwards events over a
       `tokio::sync::mpsc::channel` (the channel's
       `Receiver` is `Send`).
- **`ProtocolEvent<K>` is now a netring-owned `enum`** instead
  of a `pub type` alias for flowscope's `Event<K, M>`. Variant
  names, field names, and pattern-match shapes are unchanged
  from 0.18 — existing `ProtocolEvent::FlowStarted { key, l4, ts,
  .. }` / `ProtocolEvent::Message { parser_kind, message, .. }`
  patterns continue to compile.

### Changed (internal)

- `flowscope = "0.10"` → `flowscope = "0.11"` in `Cargo.toml`.
- `src/protocol/monitor.rs` rewritten internally to use
  flowscope's typed `Driver<E>` + per-protocol `SlotHandle<M, K>`
  drain pattern. Eliminates the prior need for a closed `M`
  lift across all parsers.
- `src/protocol/event.rs` now defines `ProtocolEvent<K>` as a
  netring-owned enum that mirrors flowscope's lifecycle
  `Event<K>` variants 1:1 plus the netring-synthesized `Message`
  variant.
- `src/async_adapters/session_stream.rs` + `datagram_stream.rs`
  parser-feed paths updated to the new
  `feed_initiator(&mut self, bytes, ts, &mut Vec<M>)` /
  `parse(&mut self, bytes, side, ts, &mut Vec<M>)` /
  `on_tick(&mut self, now, &mut Vec<M>)` scratch-buffer
  signatures (flowscope plan 119).
- HTTP-handling examples (`http_session.rs`, `full_monitor.rs`)
  format `req.method` / `req.path` / `resp.reason` via
  `String::from_utf8_lossy(&bytes)` since flowscope 0.11
  exposes them as `Bytes` (plan 120).
- `TlsClientHello::compression` is now `Bytes` (was `Vec<u8>`);
  test fixture in `tests/anomaly_monitor_smoke.rs` uses
  `Default::default()`.
- Internal: zero-alloc gains from flowscope's `track_into` +
  scratch-buffer parsers compose through to netring's hot path.
  No netring-side change required to inherit them.

### Tests

- 299/299 unit + integration tests pass.
- All doctests pass (the three that referenced the old parser
  signatures were updated mechanically).
- Clippy clean under `--all-targets --features tokio,channel,flow,parse,pcap,metrics,http,dns,tls,icmp,emit -- -D warnings`.

## 0.18.0 — unified-driver refactor + new detectors

Centerpiece architectural refactor + flowscope-tooling adoption:
`ProtocolMonitor` collapses N captures + N kernel BPF filters
down to ONE capture + flowscope's unified `Driver<E, M>`. Memory
savings scale linearly with the protocol count (5-protocol
monitor: 5 × tpacket_v3 rings → 1, typically 80–160 MiB → 16–32
MiB). Plus 7 new reference examples (3 anomaly detectors, 4
flow-level demos) and a heuristic-routing builder for
port-agnostic protocol matching.

### Breaking

- **`ProtocolEvent<K>` variant rename.** Variants flatten to
  match flowscope's `Event<K, M>`:
  `Flow(FlowEvent::Started { … })` → `FlowStarted { … }`,
  `Flow(FlowEvent::Ended { … })` → `FlowEnded { … }`,
  `Flow(FlowEvent::FlowAnomaly { … })` → `FlowAnomaly { … }`,
  `Flow(FlowEvent::TrackerAnomaly { … })` → `TrackerAnomaly { … }`,
  etc. `ProtocolEvent<K>` itself is now a type alias for
  `flowscope::driver_unified::Event<K, ProtocolMessage>` (path
  A from the 0.18 plan).
- **`ProtocolEvent::Message` field rename.** `kind` →
  `parser_kind` to match flowscope.
- Both changes mechanical: most detectors only needed a
  variant-pattern rewrite. The migration table is documented in
  `protocol/event.rs` docs and `WRITING_DETECTORS.md` (new
  Migration notes section).

### Added

- **`ProtocolMonitorBuilder::http_heuristic()` /
  `tls_handshake_heuristic()`** — port-agnostic protocol
  dispatch via flowscope's signature-based heuristic slots
  (plan 116 / `flowscope::detect::signatures::*`). Routes any
  TCP flow whose first packet matches a curated payload
  signature to the corresponding parser, regardless of port.
  Combines with `.http_on_ports()` / `.tls_handshake_on_ports()`
  for "well-known ports plus catch-all" deployments. Useful for
  port-randomized C2 detection, proxy discovery, and HTTP/TLS
  on debug ports.
- **`netring/emit` Cargo feature.** Pass-through for flowscope's
  `emit` module — pulls `flowscope/emit` (no extra deps). Used
  by the new `zeek_export.rs` example.
- **Three new anomaly detectors** under `examples/anomaly/`,
  each with parallel integration tests in
  `tests/anomaly_new_detectors.rs` (9 unit tests total):
  - `dns_tunnel_detect.rs` — high-entropy + base64-shaped DNS
    subdomain labels (MITRE T1071.004 / T1041). Uses
    `flowscope::detect::shannon_entropy` + `is_base64ish`.
  - `port_scan.rs` — distinct dst-port cardinality per source
    over a sliding window (MITRE T1046). Uses
    `flowscope::correlate::TimeBucketedSet`.
  - `syn_flood_burst.rs` — burst flow-starts per source within
    a short window (MITRE T1498.001). Uses
    `flowscope::correlate::BurstDetector`. Severity Critical.
- **Four new flow-level examples** under `examples/flow/`:
  - `top_n_flows.rs` — streaming top-K by total bytes
    (`flowscope::correlate::TopK`).
  - `ewma_rate.rs` — per-flow exponential-moving-average
    smoothed packet size (`flowscope::correlate::Ewma`).
  - `active_flows_snapshot.rs` — periodic live-flow snapshot
    via `FlowStream::snapshot_flow_stats` (which calls
    `FlowTracker::iter_active`).
  - `zeek_export.rs` — Zeek-compatible `conn.log` writer via
    `flowscope::emit::ZeekConnLogWriter`.
- **`WRITING_DETECTORS.md`** gains a §5 subsection
  "Port-agnostic routing (heuristic dispatch)" + a top-of-doc
  "Migration notes (netring 0.18)" section with the variant
  rename table.

### Changed

- **`ProtocolMonitor` internals.** Pre-0.18 opened N
  `AsyncCapture`s, one per enabled protocol, each with a
  per-protocol kernel BPF filter. As of 0.18 the monitor opens
  ONE capture (no kernel filter) and dispatches user-side
  through flowscope's unified `Driver<E, M>` with one slot per
  enabled protocol. Trade-off: memory wins linearly with
  protocol count; per-packet user-side dispatch adds one match
  in exchange for one fewer kernel BPF eval. Public surface
  (`.flow()` / `.http()` / `.dns()` / `.tls()` / `.icmp()` /
  `.tls_handshake()`) unchanged.
- **`examples/l7/multi_protocol_monitor.rs`** — `describe()`
  collapsed from a 40-LoC `either_port` chain to one call to
  `flowscope::well_known::protocol_label`. Now covers ~70
  services (the previous chain hard-coded 6).
- **`examples/anomaly/icmp_explained_drop.rs`** —
  `reason.to_string()` → `reason.as_str()` (zero-alloc; uses
  `EndReason::as_str()` shipped in flowscope 0.10).
- **`examples/flow/summary.rs` + `examples/l7/full_monitor.rs`**
  — `stats.bytes_initiator + stats.bytes_responder` →
  `stats.total_bytes()`; same for `total_packets()`.

## 0.17.0 — flowscope 0.10 lockstep bump + wishlist absorption

Lockstep update to flowscope 0.10.1. flowscope shipped every
actionable item across three rounds of netring feedback (rounds
for 0.5/0.6, 0.7, 0.8) plus the absorbed 0.9 cycle (high-level
`Pipeline`, `flowscope::correlate`, `FlowMultiSessionDriver`,
JA4, OOO reassembler, unified `flowscope::Error`,
`flowscope::layers`) plus the 0.10 cycle (centerpiece unified
`Driver<E, M>` + `Event<K, M>`, exchange aggregators, parser
ergonomics, correlate extensions, `detect` / `aggregate` /
`emit` / `well_known` modules, signature recognizers, helper
sweep).

This release covers the **mechanical bump + immediate wishlist
absorption**. The major architectural items (collapse
`ProtocolMonitor` onto the unified driver; adopt the new
correlate / detect / aggregate tooling in new detectors) are
scheduled for netring 0.18 and 0.19 respectively.

### Breaking

- **None on the public netring API surface.** flowscope 0.10 is
  dramatically more backward-compatible than the 0.17 plan
  anticipated; the plan's unified-`Error` migration and
  `Established { l4 }` destructure work are both no-ops on
  master. Downstream consumers depending on flowscope-side
  error types directly should follow flowscope's own 0.9
  migration shape (see
  [flowscope CHANGELOG](https://github.com/p13marc/flowscope/blob/master/CHANGELOG.md#090)).
- **`netring::correlate::TimeBucketedCounter` and
  `KeyIndexed`** are now joined by re-exports of flowscope's
  `BurstDetector` / `BurstHit` / `Ewma` / `SequencePattern` /
  `KeylessSequencePattern` / `TimeBucketedSet` / `TopK`. The
  netring-owned types stay (their API surface — particularly
  `drain_expired` — has no flowscope equivalent). Documented
  inline.

### Added

- **`netring/serde` Cargo feature.** Derives `Serialize` on
  `Anomaly<K>` / `AnomalyContext` / `Severity` and adds
  `Anomaly::to_json_value() -> serde_json::Value`. Composes
  with `flowscope/serde` for users shipping full parsed
  `ProtocolMessage` payloads through line-oriented JSON sinks.
  `Deserialize` is intentionally not derived (`&'static str`
  fields can't roundtrip; consumers reverse via `Value`).
  Wire vocabulary locked by a unit test that checks the
  rendered field names.
- **`ProtocolMessage::TlsHandshake(TlsHandshake)`** variant
  under the `tls` feature gate — surfaces flowscope 0.9's
  `TlsHandshakeParser` aggregator output (one synthesised
  event per handshake; carries SNI, ALPN, optional JA3 / JA4,
  negotiated version, cipher suite, `resumption_attempted`,
  and `HandshakeOutcome`).
- **`ProtocolMonitorBuilder::tls_handshake()` /
  `tls_handshake_on_ports([...])`** — opt-in `.tls_handshake()`
  builder leg that runs `TlsHandshakeParser` alongside (or
  instead of) `.tls()`. Default ports 443, 8443.

### Adopted across detectors

- **`flowscope::parser_kinds::*` constants** at every match
  site (`kind: "dns-udp"` → `kind: flowscope::parser_kinds::DNS_UDP`).
  Compile-time typo protection across 16 sites in
  `examples/anomaly/`, `tests/`, and `benches/`.
- **`IcmpType::error_inner()`** in
  `examples/anomaly/icmp_explained_drop.rs` — collapses the
  prior 40-LoC pattern-match helper to a one-liner. Label is
  now `&'static str` (a stable metric-friendly slug).
- **`flowscope::dns::DnsResolutionCache`** in
  `examples/anomaly/tls_to_unresolved_ip.rs` — replaces the
  per-source `HashMap<IpAddr, KeyIndexed<IpAddr, ()>>` shape.
  Gains LRU-bounded growth (16,384 entry default cap) and
  hostname canonicalisation.
  `examples/anomaly/dns_resolved_no_connection.rs` is **not**
  migrated — its drain-on-expiry pattern depends on iterating
  the dropped resolutions to surface them as anomalies, which
  `DnsResolutionCache::sweep` (returns just a count) can't
  express.
- **`AnomalyKind::short_kind()`** in `FlowAnomalyRule` — the
  per-flow + tracker anomaly arms now record the stable slug
  for Prometheus-friendly metric labels instead of the
  Display rendering with parameters.
- **`TlsHandshakeParser`** in `examples/anomaly/slow_tls_handshake.rs`
  — rule rewritten from per-message ClientHello/ServerHello
  correlation to alert-on-`HandshakeOutcome::Truncated`. Loses
  the "slow but completed" arm (the aggregator doesn't expose
  a precomputed RTT field) but the simpler rule catches the
  strongest case. Plan-of-record Path A; Path B (per-message
  subscription for RTT) is a follow-up.
- **`FlowTracker::iter_active()`** under the hood — the
  `snapshot_flow_stats` accessors on `FlowStream`,
  `SessionStream`, `DatagramStream` switch from the
  flowscope-deprecated `all_flow_stats()` to
  `iter_active().map(|af| (af.key, af.stats))`. Preserves the
  historical `(key, stats)` return shape; doc comment points
  callers at `tracker().iter_active()` for the richer view.

### Tests

20 anomaly module tests (was 19; +`anomaly_to_json_value_wire_vocabulary`).
Workspace tests still 349 across all suites; clippy
`--all-targets --all-features -- -D warnings` clean.

## 0.16.0 — flowscope 0.7 bump, ICMP correlation, anomaly harness

Lockstep update to flowscope 0.7.0 plus the 0.16 anomaly-correlation
roadmap. Pre-1.0 breaking changes on flow-event destructuring; full
plan in
[`plans/netring-0.17-flowscope-0.7-bump-2026-06-03.md`](plans/netring-0.17-flowscope-0.7-bump-2026-06-03.md)
and prior
[`plans/netring-0.16-roadmap-2026-05-29.md`](plans/netring-0.16-roadmap-2026-05-29.md).

### Breaking

- **flowscope 0.7** — `FlowEvent::Ended` and `SessionEvent::Closed`
  gain `l4: Option<L4Proto>`. All destructure sites must bind or
  `..` the new field. Migration sites in netring's own tree are
  done; downstream consumers must mirror.
- **`netring::Severity` gains `Default = Info`** (additive default
  for `FlowAnomalyRule`'s `min_severity` field).

### New — `netring::protocol` unified L7 stream

- **`ProtocolEvent<K>` + `ProtocolMessage`** — sum-type over flow
  lifecycle + L7 messages (HTTP / DNS / TLS / ICMP). Each Message
  carries `parser_kind` for routing without downcasting.
  `#[non_exhaustive]`.
- **`ProtocolMonitorBuilder` + `ProtocolMonitor<K>`** — declarative
  entry: `.interface(name).flow().http().dns().tls().icmp().build(extractor)`
  opens one filtered `AsyncCapture` per enabled protocol and yields
  a unified async `Stream<Item = Result<ProtocolEvent<K>, Error>>`.
  Round-robin polls inner streams; one chatty protocol can't starve
  the others.
- `examples/l7/full_monitor.rs` rewritten on top of the builder —
  drops the hand-rolled `tokio::select!` orchestration.

### New — `netring::anomaly` correlation harness

- **`AnomalyMonitor<K>` + `AnomalyRule<K>` trait** — compose
  detectors as small typed rules over `ProtocolEvent<K>`. Each rule
  implements `name()` + `observe()` + optional `on_tick()` and
  pushes `Anomaly<K>` records into a shared scratch buffer.
- **`Anomaly<K>`** carries `kind` slug, `Severity` tier
  (`Info`/`Warning`/`Error`/`Critical`), optional key, timestamp,
  `AnomalyContext { observations, metrics }`.
- **`FlowAnomalyRule`** built-in — lifts every
  `FlowEvent::FlowAnomaly` / `TrackerAnomaly` into the same
  `Vec<Anomaly<K>>` pipeline. Severity tier comes from
  `AnomalyKind::severity()` via `From<flowscope::event::Severity>`.

### New — `netring::correlate` primitives

- **`TimeBucketedCounter<K>`** — per-key sliding-window rate
  counter for "this host issued >N events in the last T seconds"
  detectors.
- **`KeyIndexed<K, V>`** — TTL'd kv-cache with `drain_expired` for
  cross-protocol correlation ("the DNS response 200ms ago resolved
  to that IP — is the TCP flow going to the same IP?").

### New — `icmp` feature + `flowscope::icmp` re-exports

- New `icmp` Cargo feature → `flowscope/icmp`. `all-parsers`
  umbrella includes it.
- `ProtocolMessage::Icmp(IcmpMessage)` variant.
- `ProtocolMonitorBuilder::icmp()` / `.icmp_v4_only()` /
  `.icmp_v6_only()`. Combined v4 + v6 BPF filter
  (`ip proto 1 or ip6 ip_proto 58`).

### New — reference anomaly detectors (`examples/anomaly/`)

| Example | Demonstrates |
|---|---|
| `dns_query_burst` | `TimeBucketedCounter` — per-source-IP DNS rate |
| `dns_resolved_no_connection` | `KeyIndexed::drain_expired` cross-protocol |
| `anomaly_monitor_demo` | Two detectors composed on `AnomalyMonitor` |
| `slow_tls_handshake` | `ClientHello → ServerHello` timing via `KeyIndexed` |
| `lateral_movement` | Per-source host-pair fan-out via `KeyIndexed<IpAddr, ()>` |
| `icmp_explained_drop` | `IcmpInner` correlation — explained vs unexplained RSTs |

### Cleanup

- Examples reorganized into `examples/{basic,async_basics,filter,scaling,xdp,flow,l7,pcap,anomaly}/`
  subdirectories (example *names* unchanged).
- `full_monitor.rs` + `multi_protocol_monitor.rs` no longer carry
  the `HashMap<FiveTupleKey, L4Proto>` workaround — `l4` reads
  directly off `FlowEvent::Ended` (N4 from the 0.16 roadmap).
- `BpfFilter::builder().ports([...])` multi-port OR shortcut (N11).
- `full_monitor.rs` `l4_tag` helper now uses `L4Proto::Display`
  (flowscope 0.7 plan 77).

### Tests

318 tests across the workspace; 53 examples build; clippy
all-targets-all-features clean; doc warning-free.

## 0.15.0 — stream API completion (simple-nms wishlist round)

Three consolidated plans (24-26) closing simple-nms's
`10-upstream-wishlist-netring.md` items N1.1, N1.3-redirect, N1.4,
N1.5, N1.6, N1.7, and N2.1. No breaking changes on existing
surface; net new types and methods plus one `impl Clone for Dedup`.

### New — `StreamSetFilter` sub-trait

`stream.set_filter(&filter)` is now the canonical verb for atomic
in-kernel BPF filter swap on a built stream. Auto-implemented for
any [`StreamCapture`] whose source satisfies [`PacketSetFilter`]
(AF_PACKET only — `AsyncCapture<XdpSocket>`-backed streams don't
expose it). Replaces simple-nms's `flow_stream(...).with_bpf_filter(filter)`
ask, which had ambiguous timing semantics (apply at open vs apply
post-build).

```rust,ignore
use netring::{AsyncCapture, BpfFilter, StreamSetFilter};
let cap = AsyncCapture::open("eth0")?;
let stream = cap.flow_stream(FiveTuple::bidirectional());
let new = BpfFilter::builder().tcp().dst_port(443).build()?;
stream.set_filter(&new)?;
```

### New — `StreamCapture::dedup` / `dedup_mut` default methods

Default to `None`; overridden on `FlowStream` / `SessionStream` /
`DatagramStream` / `DedupStream` to return their dedup field. The
existing inherent `dedup()` methods stay (back-compat). Generic
code can now reach the dedup uniformly through the trait.

### New — `tracker_stats()` + `active_flows()` accessors

`FlowStream`, `SessionStream`, `DatagramStream`, `PcapFlowStream`,
`PcapSessionStream`, `PcapDatagramStream` all gain:

- `tracker_stats(&self) -> &flowscope::FlowTrackerStats` — one-call
  access to `flows_created` / `flows_ended` / `flows_evicted` /
  `packets_unmatched`.
- `active_flows(&self) -> usize` — count of live LRU entries
  (O(n)).

The three Multi*Streams add the fan-in versions
`per_source_tracker_stats()` and `total_active_flows()`, side-channeled
the same way `per_source_capture_stats` already is.

### New — pcap-tap snaplen

`with_pcap_tap_snaplen(n)` on all four async stream types caps the
recorded frame size to `n` bytes. PCAP record's `orig_len` keeps
the full wire length while `caplen` is bounded — same semantic as
`tcpdump -s <snaplen>`. `PcapTap` gains a `snaplen: Option<u32>`
field; `CaptureWriter::write_packet_truncated(pkt, caplen)` is the
new inherent helper.

### New — `Capture::busy_poll_config` + tracing

`BusyPollConfig { busy_poll_us, prefer_busy_poll, busy_poll_budget }`
plus `Capture::busy_poll_config(&self) -> &BusyPollConfig` lets a
built capture report which busy-poll knobs were applied at build
time. Reachable from a stream via
`stream.capture().get_ref().busy_poll_config()`. The builder also
emits a `tracing::info!(target: "netring::capture::busy_poll", …)`
when any knob is set, so operators can confirm engagement without
inspecting the TOML.

### New — `BpfFilter::to_human()` / `Display`

`BpfFilter` now carries an optional `BpfFilterBuilder` source
snapshot captured during `build()`. `to_human()` (and the new
`Display` impl) render it as canonical
[pcap-filter(7)](https://www.tcpdump.org/manpages/pcap-filter.7.html)
syntax — e.g. `"tcp and dst port 443 and (udp and dst port 53)"`.
Falls back to `"<raw bytecode, N instructions>"` for filters
constructed via `BpfFilter::new(raw_insns)`. Best-effort; no claim
of byte-identical match with libpcap's `tcpdump -dd` bytecode
output.

### New — `MultiStreamConfig` + `*_stream_with` constructors

`AsyncMultiCapture` gains three constructors that apply per-source
config at construction time:

- `flow_stream_with(extractor, MultiStreamConfig)`
- `session_stream_with(extractor, factory, MultiStreamConfig)`
- `datagram_stream_with(extractor, factory, MultiStreamConfig)`

`MultiStreamConfig<K>` is a builder over `tracker_config`,
`dedup` (cloned per source — see below), `idle_timeout_fn`
(Arc-shared), and `monotonic_ts`. Used because the existing
`with_*` builder pattern can't reach the boxed per-source streams
inside `SelectState` post-construction without leaking internal
types.

Existing `flow_stream` / `session_stream` / `datagram_stream`
constructors are preserved as `MultiStreamConfig::default()`
shortcuts — no BC break.

### Internal — `impl Clone for Dedup`

`Dedup` now implements `Clone` with **reset semantics**: clone
produces a fresh dedup with the same window/ring/direction-awareness
but zero counters and empty ring. Required by
`MultiStreamConfig::with_dedup(template)` so each source has
independent dedup state instead of contending on a shared one.
Documented loudly — the use case wants reset semantics, not a
counter snapshot.

### Tests

- 199 lib unit tests pass (+ 5 BusyPollConfig).
- 17 corpus cases in `tests/bpf_humanize.rs` cover the IR-to-string
  mapping (tcp/udp/icmp/ip/ip6/arp/vlan, src/dst host/net/port,
  OR composition, negation, fallback bytecode, Display ≡ to_human).
- New `tests/stream_api_completion.rs` covers set_filter via trait
  verb, dedup default propagation, tracker_stats at open,
  pcap_tap_snaplen chain, busy_poll_config round-trip.
- New `tests/multi_stream_config.rs` covers MultiStreamConfig
  propagation through all three `*_stream_with` constructors.

Clippy clean with `-D warnings` across lib + tests.

---

## 0.14.0 — flowscope 0.4 + per-parser `on_tick`

Bumps the `flowscope` dep from 0.3 to 0.4 and surfaces the headline
upstream addition — the periodic `on_tick` hook on `SessionParser`
and `DatagramParser` — through netring's async stream surfaces.

### Breaking — parser data methods take a `Timestamp`

flowscope 0.4 added a `ts: Timestamp` argument to every parser
data-feed method so stateful parsers can attach the observed
packet time directly to their messages. The shipped signatures
become:

```diff
 impl SessionParser for MyParser {
-    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Self::Message> { … }
-    fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Self::Message> { … }
+    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message> { … }
+    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message> { … }
 }

 impl DatagramParser for MyParser {
-    fn parse(&mut self, bytes: &[u8], side: FlowSide) -> Vec<Self::Message> { … }
+    fn parse(&mut self, bytes: &[u8], side: FlowSide, ts: Timestamp) -> Vec<Self::Message> { … }
 }
```

netring's session/datagram streams pass through the timestamp of
the carrying packet automatically; users who don't care about it
can name the parameter `_ts`.

### New — `on_tick` integration

`SessionParser::on_tick` and `DatagramParser::on_tick` (new in
flowscope 0.4; default no-op) are now driven by `SessionStream`
and `DatagramStream` on every sweep tick. The fire order mirrors
flowscope's own `FlowSessionDriver::sweep`:

1. Collect the tracker's swept flow events (Closed etc.).
2. For each still-live parser (including ones this sweep is
   about to close), call `parser.on_tick(now)` and emit returned
   messages as `SessionEvent::Application { side: Initiator, ts: now }`.
3. Translate the swept flow events (now driving any final `fin_*`
   per existing semantics).

This unlocks time-driven L7 patterns through the netring async
chain — DNS-style unanswered-request timeouts, periodic
heartbeats from a stateful parser, anything that needs a sweep-
cadence wakeup attributed to a specific flow. Parsers that
don't override `on_tick` are unaffected.

### Breaking — driver `S` type parameter removed (flowscope-side)

`FlowDriver<E, F, S>` → `FlowDriver<E, F>`,
`FlowSessionDriver<E, P, S>` → `FlowSessionDriver<E, P>`,
`FlowDatagramDriver<E, P, S>` → `FlowDatagramDriver<E, P>`. The
drivers always ran their tracker with `S = ()` anyway. netring
re-exports these unchanged; users who name the types directly
need to drop the trailing `, ()`.

netring's own async streams (`FlowStream<S, E, U, R>`,
`SessionStream`, `DatagramStream`) are unaffected; per-flow user
state lives on `FlowTracker<E, U>` as before.

### New — async one-line offline L7 pipelines

`AsyncPcapSource::sessions(extractor, parser)` and `.datagrams(extractor, parser)`
return new `PcapSessionStream<E, P>` / `PcapDatagramStream<E, P>`
types that wrap flowscope's `FlowSessionDriver` /
`FlowDatagramDriver` over the offline pcap reader. The
end-of-input flush (a final sweep at `Timestamp::MAX` that
closes every still-open flow) is folded in — no manual
`finish()` needed. `on_tick` integration comes for free since
flowscope's drivers drive it internally.

For users who built a flow stream first,
`PcapFlowStream::session_stream(parser)` /
`.datagram_stream(parser)` layer L7 on top, carrying tracker
config (idle timeouts, reassembler caps, overflow policy)
through the conversion.

```rust,ignore
let mut sessions = AsyncPcapSource::open("trace.pcap").await?
    .sessions(FiveTuple::bidirectional(), MyHttpParser::default());
while let Some(evt) = sessions.next().await {
    // SessionEvent::{Started, Application, Closed, Anomaly}
}
```

### Other inherited upstream changes

flowscope 0.4 also added:

- `Timestamp::MAX` (`u32::MAX`s + 999 999 999 ns) for forced
  end-of-input flushes.
- `FlowTracker::track(impl Into<PacketView>)` accepts an
  `&OwnedPacketView` directly (no `.as_view()`).
- DNS-over-UDP API unified on `DnsUdpParser`; the old
  `DnsUdpObserver` + `DnsHandler` trait are gone (consumer impact:
  see flowscope's CHANGELOG migration block).
- `FlowSessionDriver::new(extractor, parser)` /
  `FlowDatagramDriver::new(extractor, parser)` take the parser by
  value — bound relaxed from `Default + Clone` to `Clone`.
- Driver `finish()` method = `sweep(Timestamp::MAX)`.

These flow through netring transparently — no source change in
netring; consumers calling flowscope APIs directly migrate per
flowscope's CHANGELOG.

### Migration

For consumers who define their own `SessionParser` /
`DatagramParser` types:

1. Add `_ts: Timestamp` (or `ts` if you use it) to
   `feed_initiator` / `feed_responder` / `parse`.
2. Optionally override `on_tick(&mut self, now: Timestamp) -> Vec<Self::Message>`
   to emit time-driven messages (default impl returns `Vec::new()`).
3. Re-derive `Debug` on your `Message` type if it isn't already
   (the 0.3 bound; carried forward).

netring's session/datagram stream chains compose unchanged; no
new builder calls required to opt in to `on_tick`.

### New examples

- `examples/async_pcap_sessions.rs` — demos
  `AsyncPcapSource::sessions(...)` one-liner with a hand-rolled
  byte-counting `SessionParser`.
- `examples/async_on_tick.rs` — demos a custom
  `DatagramParser::on_tick` impl that emits heartbeat messages
  after a configurable idle window. Pairs with netring's
  `flow_stream(...).datagram_stream(parser)` chain.

### Tests

All existing test fixtures (`flow_stream_config`,
`with_dedup_propagation`, `flowscope_03_passthrough`,
`stream_observability`) updated to the new parser signatures.
198 lib + 10 proptest + 37 doctest tests pass.

---

## 0.13.1 — MSRV bump + clippy 1.95 cleanup

Patch release. No API changes, no new features — strictly
toolchain hygiene plus one async example added during the audit.

### MSRV: 1.85 → 1.95

The flow-tracker / pcap-tap / multi-streams hot paths shipped in
0.13.0 already used `if let X && let Y` let-chains (stabilized in
Rust 1.88) under stable, but the workspace `rust-version` still
declared 1.85 and the CI matrix tested against it. The Unit Tests
(1.85) job rightly rejected the code with E0658.

Rather than refactor the let-chains to nested `if let` blocks,
the MSRV is raised to 1.95 so the codebase can track current
stable idioms directly. This affects only the lower bound of the
supported toolchain — users on stable Rust (1.88+) are unaffected.

### Clippy 1.95 lint cleanup

The 1.95 toolchain promoted two lints under `-D warnings`:

- **`clippy::manual_is_multiple_of`** — fixed 8 sites
  (`afpacket/{mod,rx}.rs`, `config/mod.rs`, plus 5 examples)
  by replacing `n % m == 0` / `n % m != 0` idioms with
  `n.is_multiple_of(m)` / `!n.is_multiple_of(m)`.
- **`clippy::collapsible_if`** — 1.95 now folds through
  let-chain bindings, so 4 nested `if let X { if let Y { ... } }`
  blocks were collapsed to `if let X && let Y { ... }`. Sites:
  `afxdp/mod.rs` (AF_XDP prefill), `flow_broadcast.rs` (×2
  test-only timeout + .is_some() pairs), `examples/fanout.rs`
  (thread pinning).

### New example

- `async_stats_monitor.rs` — the async sibling of the existing
  sync `stats_monitor`. Demonstrates plan 20's
  `StreamCapture::capture_stats` /
  `capture_cumulative_stats` polling on a live `FlowStream`,
  printing per-second kernel-ring counters alongside flow
  start/end counts without disrupting the consumer.

### Test fixture fix

`tests/bpf_filter_lifecycle.rs` — the two `AsyncCapture::open_with_filter`
tests were `#[test]` and constructed the capture outside any
tokio runtime, so `AsyncFd::new` panicked with "no reactor
running". Switched to `#[tokio::test(flavor = "current_thread")]`
and removed the manual `Runtime::block_on`. No production-code
change.

### CI plumbing

- Matrix `rust: [stable, "1.85"]` → `[stable, "1.95"]`.
- `stream_capture.rs` doctest moved from a `flow`-feature example
  (`flow_stream`) to a feature-agnostic one (`dedup_stream`) so
  it compiles under CI's `tokio,channel` test command.
- Two `redundant explicit link target` rustdoc errors fixed
  (`stream_capture.rs:84` `Error::SockOpt`; `pcap_flow.rs:3`
  `AsyncPcapSource`).

### Upgrade guidance

`cargo update -p netring`. No source changes required for any
consumer already on Rust 1.95+.

---

## 0.13.0 — async-stream maturity: observability, BPF ergonomics, multi-source, offline replay

Four consolidated plans (20-23) closing the seven feedback items
from des-rs's 2026-05-14 round. The release is feature-additive
on the existing types; one minor convention break inside the async
adapter modules (private `from_tracker` signatures gained a `tap`
parameter — `pub(crate)`, no external impact).

### Plan 20 — `StreamCapture` trait + pcap tap

- **New** sealed `StreamCapture` trait gives `FlowStream`,
  `SessionStream`, `DatagramStream`, and `DedupStream` a uniform
  `capture()` accessor. Default-methoded `capture_stats()` /
  `capture_cumulative_stats()` make kernel ring counters reachable
  even after the capture has been moved into a stream — closes
  des-rs F#2 (silent packet loss invisibility).
- **New** `with_pcap_tap(writer)` / `with_pcap_tap_policy(writer,
  policy)` builders on all four stream types. Records each packet
  to a `CaptureWriter` **before** the flow tracker processes it;
  tap survives `session_stream` / `datagram_stream` /
  `with_async_reassembler` / `with_state` conversions — closes
  des-rs F#3 (single-invocation decode + record).
- **New** `TapErrorPolicy { Continue (default), DropTap, FailStream }`
  for disk-full handling. `Continue` logs via `tracing::warn!` and
  keeps recording; `DropTap` retires the tap; `FailStream` surfaces
  an `Err` from the next poll.

### Plan 21 — BPF filter ergonomics

- **New** `PacketSetFilter` trait scoping atomic in-kernel BPF
  filter replacement to AF_PACKET-backed sources only. `Capture`
  implements it; `XdpSocket` does not, so
  `AsyncCapture<XdpSocket>` does not even expose `set_filter` —
  trait-bound gating, no runtime `unimplemented!`.
- **New** `Capture::set_filter(&BpfFilter)` — kernel handles
  atomic replacement via `SO_ATTACH_FILTER`.
- **New** `AsyncCapture::open_with_filter(iface, BpfFilter)`
  one-call constructor.
- **New** `AsyncCapture::set_filter(&BpfFilter)` for AF_PACKET-backed
  captures.
- Composes with plan 20: `stream.capture().set_filter(&new_filter)`
  swaps the filter from inside a running stream.
- Closes des-rs F#1 (kernel-side filter on a 10-GbE DES sniffer
  drops CPU from ~30 % to ~1 %) and F#7 (dynamic filter swap).

### Plan 22 — Multi-source capture

- **New** `AsyncMultiCapture` type with five constructors:
  - `open(&[ifaces])` — multi-interface capture.
  - `open_with_filter(&[ifaces], BpfFilter)` — same + shared
    filter.
  - `open_workers(iface, n, group_id)` — `FanoutMode::Cpu`
    workers on one interface.
  - `open_workers_with_mode(iface, n, group_id, mode)` — explicit
    fanout mode.
  - `from_captures(vec, labels)` — heterogeneous setups.
- **New** `MultiFlowStream<E>`, `MultiSessionStream<E, F>`,
  `MultiDatagramStream<E, F>` fan in N per-source streams via a
  custom round-robin select (no `futures::stream::select_all`
  dep). Yield `TaggedEvent { source_idx, event }`.
- **New** per-source and aggregate capture stats accessors on each
  Multi* type: `per_source_capture_stats()` + `capture_stats()`.
- **New** `docs/scaling.md` covers the `FanoutMode` decision
  matrix, the canonical recipe with thread pinning, and seven
  anti-patterns (FANOUT_HASH on skewed traffic, PACKET_FANOUT on
  `lo`, wrong worker/queue ratios, …).
- Closes des-rs F#5 (multi-interface) + F#6 (scaling docs).

### Plan 23 — `AsyncPcapSource` + `PcapFlowStream`

- **New** `AsyncPcapSource` reads pcap and pcapng files
  asynchronously via tokio `mpsc` channel fed from a
  `spawn_blocking` task running the sync `pcap_file` reader.
  Auto-detects format at open.
- **New** `AsyncPcapConfig { replay_speed, queue_depth,
  loop_at_eof }`. Pacing replays at recorded wire rate (or a
  scaled multiple); EOF-loop for stress testing.
- **New** `PcapFormat::{LegacyPcap, Pcapng}` returned by
  `source.format()`.
- **New** `PcapFlowStream<E>` bridges the source's `OwnedPacket`
  output to a flowscope `FlowTracker`. Yields `FlowEvent`s through
  the same `Stream` trait as a live `FlowStream`. Mirrors the
  offline-meaningful subset of the builder methods.
- Live + offline pipelines unify via a generic consumer over
  `Stream<Item = Result<FlowEvent<K>, Error>>` — same
  downstream signature.
- Closes des-rs F#4 (offline replay through the same chain).

### Examples

Four new examples:

- `async_flow_with_tap` (plan 20).
- `async_filter` (plan 21).
- `async_fanout_workers` + `async_multi_interface` (plan 22).
- `async_pcap_replay` (plan 23).

### Internal

- New `pcap_tap`, `pcap_source`, `pcap_flow` modules — all behind
  `pcap + tokio` (or `+ flow` for `pcap_flow`).
- New `multi_capture`, `multi_streams` modules under
  `async_adapters/`.
- New `stream_capture` module (always available under `tokio`).
- `SessionStream::from_tracker` / `DatagramStream::from_tracker`
  signatures gained a `#[cfg(feature = "pcap")] tap` parameter
  — `pub(crate)`, no external break.
- `tempfile = "3"` added to dev-dependencies for offline-pcap
  fixtures.

---

## 0.12.0 — flowscope 0.3 + per-key idle timeouts + structured anomalies

Plan 19. Bumps `flowscope` from 0.2 to 0.3 and exposes the new
upstream knobs through netring's async stream surfaces.

### Breaking changes

- **`SessionEvent::Anomaly` is now forwarded** by `SessionStream`
  and `DatagramStream`. Previously these arms went to
  `tracing::warn!` and were dropped from the typed surface.
  Consumers matching `SessionEvent` exhaustively need a new arm:

  ```diff
   match evt {
       SessionEvent::Started { .. } => ...,
       SessionEvent::Application { .. } => ...,
       SessionEvent::Closed { .. } => ...,
  +    SessionEvent::Anomaly { .. } => ...,  // new in netring 0.12.0
  +    _ => ...,                              // forward-compatible
   }
  ```

- **`EndReason::ParseError`** is a new variant on the re-exported
  `flowscope::EndReason`. Exhaustive matches need an arm — treat
  like `Rst` (parser poisoned; reassembler is reset). netring's
  built-in handling already does this internally.
- **`SessionParser::Message` / `DatagramParser::Message` require
  `Debug`** (upstream change). Add `#[derive(Debug)]` to your
  message type. All flowscope-shipped parsers already do.
- **`SessionStream::new_with_config{,_and_dedup}` /
  `DatagramStream::new_with_config{,_and_dedup}`** removed
  (`pub(crate)` only — no external break). Replaced by
  `from_tracker` which moves the existing `FlowTracker` over from
  `FlowStream` so `idle_timeout_fn` and in-flight flow state
  survive the conversion. The public `FlowStream::session_stream`
  / `datagram_stream` entry points are unchanged.

### New — per-key idle timeouts

`FlowStream::with_idle_timeout_fn(F)` and the same on
`SessionStream` / `DatagramStream`. Predicate receives
`(&key, Option<L4Proto>)` and returns `Option<Duration>`; `None`
falls back to the per-protocol defaults from `FlowTrackerConfig`.

```rust
let stream = cap
    .flow_stream(FiveTuple::bidirectional())
    .with_idle_timeout_fn(|k, _l4| {
        if k.either_port(53) {
            Some(Duration::from_secs(5))
        } else {
            None
        }
    });
```

### New — monotonic timestamps

`FlowStream::with_monotonic_timestamps(true)` clamps NIC-supplied
timestamps to a running max. Each subsequent `view.timestamp`
becomes `max(view.timestamp, running_max)`; sweep `now` is
clamped the same way. Useful when downstream consumers want a
strictly non-decreasing timeline (log correlation, replay).
Default: off (raw NIC timestamps flow through unmodified).

Mirrored on `SessionStream::with_monotonic_timestamps` and
`DatagramStream::with_monotonic_timestamps`.

### New — `snapshot_flow_stats()` accessor

Borrow-iterator over `(&K, &FlowStats)` for live flows on all
three streams. Includes the new reassembler high-watermark fields.
Lazy — pays only for what you consume.

### Preserved state across stream conversions

`FlowStream::session_stream(parser)` and `.datagram_stream(parser)`
now move the underlying `FlowTracker` directly into the new stream
instead of rebuilding it from the extractor. This preserves:

- `idle_timeout_fn` (per-key timeout overrides)
- hot-cache state (plan 41's monoflow fast-path)
- in-flight flow records (in case the conversion happens after
  some traffic has been seen)

The `monotonic_ts` state also rides through.

### Other

- `FlowStats` now carries `reassembler_high_watermark_initiator`
  and `_responder` (set on `Ended` events by flowscope 0.3).
  Free passthrough through the existing `Ended { stats }` carrier.
- New `netring::flow::IdleTimeoutFn` re-export (type alias for the
  boxed predicate).
- New `examples/async_flow_idle_per_key.rs` demonstrating the
  per-key timeout + monotonic combo.
- New `tests/flowscope_03_passthrough.rs` covering the builder
  chain + conversion preservation.
- New unit tests for the `clamp_view` / `clamp_now` helpers.

---

## 0.11.0 — Typed BPF filter builder + custom XDP programs

Plan 18 (BPF builder) and plan 12 phase 2 (caller-loaded XDP
programs).

### New — `XdpSocketBuilder::with_program(prog)`

Plan 12 phase 2. The builder now accepts a caller-supplied
[`XdpProgram`] in addition to the built-in
`with_default_program()`. Use this when you've compiled your own
XDP program (via `aya-bpf` + `bpf-linker`, or
`clang -target bpf`) — netring takes care of registering the socket
on the program's XSKMAP, attaching the program to the interface,
and detaching on `XdpSocket` drop.

```rust,ignore
use aya::Ebpf;
use netring::xdp::{XdpFlags, XdpProgram};
use netring::XdpSocket;

let bpf = Ebpf::load(MY_BYTECODE)?;
let prog = XdpProgram::from_aya(bpf, "my_xdp", "xsks_map");

let xsk = XdpSocket::builder()
    .interface("eth0")
    .queue_id(0)
    .with_program(prog)
    .xdp_attach_flags(XdpFlags::DRV_MODE)
    .build()?;
```

Mutually exclusive with `with_default_program()` — `build()` errors
with `LoaderError::ExclusiveBuilderOptions` if both are set. For
multi-queue capture (one program serving many sockets) keep using
the manual `XdpProgram::register` + `XdpProgram::attach` pattern
where you own the attachment lifetime.

`XdpSocketBuilder` no longer derives `Clone` (the `XdpProgram` it
optionally holds is not cloneable). Builders are typically consumed
once anyway; let me know if this bites.

See `netring/examples/async_xdp_custom_program.rs` for the full
end-to-end recipe.

---

### Plan 18 — typed BPF filter builder

Replaces runtime `tcpdump -dd` shell-outs in downstream consumers
(e.g. nlink-lab) with an in-tree typed builder. Pure Rust, no native
deps, no `unsafe` in new code, no panics on bad input.

#### New — `BpfFilter::builder()`

A small typed vocabulary that compiles to classic BPF (`SO_ATTACH_FILTER`)
bytecode without external tools or libraries:

```rust
use netring::{BpfFilter, Capture};

let filter = BpfFilter::builder()
    .tcp()
    .dst_port(443)
    .or(|b| b.udp().dst_port(53))
    .build()?;

let cap = Capture::builder()
    .interface("eth0")
    .bpf_filter(filter)
    .build()?;
```

Supported fragments: `eth_type` / `ipv4` / `ipv6` / `arp`, `vlan` /
`vlan_id`, `ip_proto` / `tcp` / `udp` / `icmp`, `src_host` / `dst_host`
/ `host`, `src_net` / `dst_net` / `net`, `src_port` / `dst_port` /
`port`, plus `negate()` and `or(|b| ...)` composition. The empty
builder accepts every packet.

The compiler:

- auto-inserts an implicit IPv4 ethertype when only L4 fragments are
  named,
- rejects conflicting fragments at `build()` time
  (`tcp` + `udp` without `or`, `ipv4` + `ipv6`, multiple `vlan`),
- handles VLAN-tagged frames (`MatchFrag::Vlan` shifts subsequent
  offsets by +4),
- rejects IPv4 fragmented packets when an L4 port is asserted,
- emits `BPF_LDX_B_MSH` for variable IPv4 IHL,
- treats IPv6 as a fixed 40-byte header (no IHL trick),
- caps output at `BPF_MAXINSNS = 4096` and the cBPF 8-bit jump-offset
  limit (`BuildError::JumpTooFar` / `TooManyInstructions` otherwise).

#### New — `IpNet`

Zero-dep `pub struct IpNet { addr: IpAddr, prefix: u8 }` with
`FromStr` (`"10.0.0.0/24"`, bare addresses default to /32 or /128).
Used by `src_net` / `dst_net` / `net` builder methods. Living in
`netring::config::ipnet`, re-exported at the crate root.

#### Software interpreter — `BpfFilter::matches`

`BpfFilter::matches(&[u8]) -> bool` runs the bytecode against an
ethernet frame entirely in safe Rust (no kernel round-trip), used
internally by the proptests and useful for offline filter validation
(e.g. testing filter logic against pcap data without a live socket).
Implements the opcode subset the builder emits; fail-closed on
unknown opcodes / out-of-bounds loads.

#### Breaking — `BpfFilter::new` is now fallible

`BpfFilter::new(insns: Vec<BpfInsn>) -> Result<Self, BuildError>`.
Previously infallible. Bytecode is now validated against
`BPF_MAXINSNS` and rejected with `BuildError::TooManyInstructions`.
This is the escape hatch for callers who already have raw bytecode
from `tcpdump -dd` or another source — wrap it once and reuse.

#### Breaking — `CaptureBuilder::bpf_filter`

Now takes `BpfFilter` instead of `Vec<BpfInsn>`. Migration:

```rust
// before
.bpf_filter(insns)
// after — typed builder
.bpf_filter(BpfFilter::builder().tcp().dst_port(443).build()?)
// after — escape hatch (raw bytecode)
.bpf_filter(BpfFilter::new(insns)?)
```

#### Tests

- `netring/tests/bpf_builder_proptest.rs` — 10 proptest invariants
  for the compose algebra: builder doesn't panic, empty accepts all,
  `negate(F)` is the complement of `F`, double-negate is identity,
  OR is union, AND is intersection, adding a fragment is monotonic,
  the `BpfFilter::new` round-trip is clean, `src_net` matches the
  expected subset, `dst_port` match is exact. 256 cases per property
  by default; stress with `PROPTEST_CASES=10000 cargo test ...`.
- `netring/src/config/bpf_interp.rs` — 28 unit tests for the
  interpreter (every opcode + boundary cases).
- 183 lib tests pass; clippy clean across default and
  `tokio,af-xdp,flow,parse,pcap,metrics,xdp-loader`.

#### Example

`netring/examples/bpf_filter.rs` — end-to-end demo of the typed
builder attached to `Capture::builder()`.
`netring/examples/async_xdp_custom_program.rs` — illustrative
end-to-end use of `with_program()` for a caller-loaded XDP program.

---

## 0.10.0 — Session reassembly + chained dedup

Closes the two gaps surfaced by des-rs's second-round analysis at
`des-rs/des-discovery/reports/des-capture-rewrite-analysis-2026-05-09.md`
(items F6 and F7). Both gaps were on the live-capture path only —
flowscope's offline `FlowSessionDriver` already covered the same
ground for pcap replay.

### Behavioural change — `SessionStream` reassembles TCP

Plan 16. Before 0.10, `SessionStream::poll_next` fed raw TCP payloads
straight to `SessionParser::feed_*` in arrival order. That worked
fine for the shipped HTTP / TLS / DNS-TCP parsers (each does its own
per-side buffering), but **silently double-parsed retransmits and
loopback duplicates** for any length-prefixed binary protocol — DES
PSMSG, custom user wire formats, anything that treats "duplicate
bytes" as "two valid frames".

After 0.10, `SessionStream` holds a `BufferedReassembler` per
`(flow, side)` (mirroring flowscope's sync `FlowSessionDriver`):

- Each TCP segment goes through `BufferedReassembler::segment`.
  Out-of-order segments are dropped per [`OverflowPolicy`].
- On `FlowEvent::Packet`, the reassembler is drained and bytes flow
  to the parser.
- On `FlowEvent::Ended { reason: Fin | IdleTimeout }`, residual
  bytes are drained and fed before `parser.fin_*` is called.
- On `FlowEvent::Ended { reason: Rst | Evicted | BufferOverflow }`,
  the reassembler is dropped without drain (suspect data) and
  `parser.rst_*` is called.

Honours `FlowTrackerConfig::max_reassembler_buffer` +
`overflow_policy` automatically — set them via the existing
`with_config(cfg)` chain (`flow_stream(ext).with_config(cfg).session_stream(parser)`)
and per-side caps + `EndReason::BufferOverflow` flow termination
behave the same as on the offline `FlowSessionDriver`.

**For the four shipped parsers (HTTP / TLS / DNS-TCP / DNS-UDP)
this is a no-op semantically** — they re-buffer internally; the
extra `extend_from_slice` is the only cost. **For users with custom
binary `SessionParser` implementations** this is a correctness fix.
Users who relied on arrival-order semantics (e.g. counting
retransmits) need to handle that downstream of the parser now.

### `with_dedup(Dedup)` on the flow / session pipeline

Plan 17. Before 0.10, `cap.dedup_stream(d)` and `cap.flow_stream(e)`
were sibling methods — calling one consumed the capture and the
other was unreachable. After 0.10:

- `FlowStream::with_dedup(d)` — chainable builder.
- `SessionStream::with_dedup(d)` / `DatagramStream::with_dedup(d)` —
  same shape on the session-level streams.
- Dedup is carried forward through `with_state` /
  `with_async_reassembler` / `session_stream` / `datagram_stream`
  transitions on `FlowStream`.
- `dedup()` / `dedup_mut()` accessors return `Option<&Dedup>` /
  `Option<&mut Dedup>` for inspecting `seen()` / `dropped()`
  counters at runtime.

Typical loopback-aware DES capture wiring is now:

```rust
let mut s = AsyncCapture::open("lo")?
    .flow_stream(FiveTuple::bidirectional())
    .with_dedup(Dedup::loopback())
    .with_config(cfg)
    .session_stream(DesSessionParser::default());
```

`AsyncCapture::dedup_stream` and the standalone `DedupStream<S>` are
unchanged for users who only want dedup'd packets without flow
tracking.

### Tests

- `netring/tests/with_dedup_propagation.rs` — six integration tests
  (gated on `integration-tests`) confirming dedup carries through
  every transition + accessor surface.
- `netring/src/async_adapters/session_stream.rs` — eight new unit
  tests covering `process_session_event` for `Started`, `Packet`
  (drain path), `Packet` with no reassembler, `Ended` (Fin) with
  residual drain, `Ended` (BufferOverflow) without drain, `Ended`
  (Rst) without drain, `Anomaly` (no event), and the
  `build_reassembler_factory` cap/policy plumbing.
- All 124 lib unit tests pass; clippy clean across `tokio,flow` and
  `--all-features` with `-D warnings`.

### Migration notes

Internal API change: `SessionStream::new_with_config` and
`DatagramStream::new_with_config` are unchanged externally
(`pub(crate)`); they gained sibling
`new_with_config_and_dedup` constructors used by
`FlowStream::session_stream` / `datagram_stream`. No public-API
breakage.

The `SessionStream` behavioural change (reassembly between tracker
and parser) is the only user-visible delta. The shipped parsers are
unaffected.

---

## 0.9.0 — flowscope 0.2, config-aware session streams, dedup + pcap hardening

This release pulls in [flowscope 0.2](https://crates.io/crates/flowscope/0.2.0)'s
reassembly observability work and fixes a config-loss bug in the
session/datagram async builder chain. Closes feedback items F1, F2, F4
and F5 from des-rs's wishlist (`plans/feedback-from-des-rs-2026-05-09.md`).
F3 (netns capture) is intentionally not landed — see that plan for the
nlink-based composition recipe.

### Breaking — flowscope 0.2 surface

- **`FlowEvent::key()` now returns `Option<&K>`** (was `&K`). For non-
  `Anomaly` events the value is always `Some(_)`; pattern-matching is
  unaffected. Code that called `event.key()` directly on a re-exported
  `FlowEvent` needs `event.key().expect(...)` or pattern-match.
- **`EndReason::BufferOverflow`** is a new variant. Exhaustive matches
  over `EndReason` need a new arm. netring treats `BufferOverflow`
  like `Rst` for cleanup semantics.
- **`#[non_exhaustive]`** on `FlowStats`, `FlowTrackerConfig`,
  `AnomalyKind`, `OverflowPolicy`. Construct via `Default::default()`
  + field assignment instead of struct literals.
- **`FlowEvent::Anomaly { key, kind, ts }`** is a new variant.
  `FlowStream` passes it through verbatim; `SessionStream` and
  `DatagramStream` log it via `tracing::warn!` (target `netring::flow`)
  rather than surface it as a `SessionEvent`. Use `FlowStream` directly
  for structured access.

### `SessionStream::with_config` / `DatagramStream::with_config`

Both async session-level streams gain a builder-style `with_config`
method that mirrors `FlowStream::with_config`. Use this to set the
flowscope-0.2 reassembler buffer cap and overflow policy on the
session path.

### Bug fix — config propagation through session_stream / datagram_stream

Before this release, `cap.flow_stream(ext).with_config(cfg).session_stream(parser)`
silently lost `cfg` during the `FlowStream → SessionStream` transition
(the inner `FlowTracker` was discarded and rebuilt with defaults). The
config now propagates correctly. Same for `datagram_stream`.

This was invisible under flowscope 0.1 (no buffer-cap fields existed
to lose) but matters under 0.2.

### New re-exports

Under the `flow` feature gate: `AnomalyKind`, `FlowSessionDriver`,
`OverflowPolicy`. `FlowSessionDriver` is the sync mirror of
`SessionStream` for offline pcap replay.

### Hardening tests

- `tests/dedup_stress.rs` — 10k structured-payload TCP-shaped packets
  at 1 kHz and 2 kHz cadence assert `Dedup::loopback().dropped() == 0`.
  Closes the theoretical xxh3-64-collision concern for high-cadence
  TCP traffic.
- `pcap::tests::round_trip_preserves_nanosecond_timestamp` — explicit
  byte-for-byte timestamp round-trip via `CaptureWriter` →
  `pcap_file::pcap::PcapReader`. Confirms nanosecond precision is
  preserved across write → read.

### Internal

- `flowscope` dep bumped from `0.1` to `0.2` (default features still off).
- `flow_stream.rs:325-328` and `session_stream.rs:194` match arms
  extended for `EndReason::BufferOverflow`.
- `SessionStream::new` / `DatagramStream::new` removed in favor of
  `new_with_config(extractor, factory, config)` (private constructors;
  no public-API impact).

---

## 0.8.0 — XDP loader, busy-poll trio, broadcast, flowscope split

A feature-additive release. New AF_XDP self-contained loader (no more
`xdp-loader` CLI dance), kernel-5.11 busy-poll knobs that close most
of the AF_XDP↔DPDK latency gap, multi-subscriber flow-event broadcast,
and the workspace split of flow tracking out to a separate
[`flowscope`](https://github.com/p13marc/flowscope) crate. No
breaking changes; every existing user-facing API still works.

> **Publishing prerequisite:** the `flow` feature pulls
> `flowscope` from git pending the first flowscope crates.io
> release. Before publishing this version of netring, swap the
> git dep in `netring/Cargo.toml` to a version dep
> (`flowscope = "0.1"`).

### `XdpProgram::from_aya` — caller-loaded XDP programs (plan 12 phase 2)

Closes the gap for users who compile their own XDP program (via
`aya-bpf` / `bpf-linker`) and want netring to handle the kernel
attach + AF_XDP socket registration + RAII teardown. Previously,
`XdpProgram` could only be constructed via the built-in
`default_program()`; now users can wrap any pre-loaded `aya::Ebpf`:

```rust,ignore
let bpf = aya::Ebpf::load(MY_BYTECODE)?;
let mut prog = XdpProgram::from_aya(bpf, "my_xdp", "xsks_map");
prog.register(queue_id, &xsk)?;
let _attachment = prog.attach("eth0", XdpFlags::DRV_MODE)?;
```

Trivial — exposes the existing internal constructor as `from_aya`.
The user's program must define a `BPF_MAP_TYPE_XSKMAP` and call
`bpf_redirect_map(&xsks_map, ctx->rx_queue_index, ...)`.

Still deferred from plan 12: `with_xsk_map(&map)` for multi-queue
shared XSKMAP and a CAP_BPF integration test.

### `FlowBroadcast` — multi-subscriber flow events (plan 50.6)

`FlowStream::broadcast(buffer)` converts a single-consumer flow
stream into a `FlowBroadcast<K>` that fans events out to multiple
independent subscribers. Each `subscribe()` returns a fresh
`Stream` over `Arc<FlowEvent<K>>`. Slow subscribers see
`BroadcastRecvError::Lagged(n)` instead of blocking the others
(per `tokio::sync::broadcast` semantics).

Use case: a logger + a metrics exporter + a real-time UI all
consuming the same capture without contending on the underlying
fd.

- New types: `FlowBroadcast`, `FlowSubscriber`, `BroadcastRecvError`.
- New entry point: `FlowStream::<NoReassembler>::broadcast(buffer)`
  on the simple (non-reassembler) flow stream variant.
- `Arc<FlowEvent<K>>` so the (potentially large) event isn't
  cloned for every subscriber.
- Spawned task aborts on `FlowBroadcast::drop`, draining the
  underlying capture exactly as long as the broadcast handle lives.
- New optional dep: `tokio-stream 0.1` (with `sync` feature) for
  `BroadcastStream` adapter, behind the existing `tokio` feature.

Closes plan 50.6 from [flowscope's plan 50](https://github.com/p13marc/flowscope/blob/master/plans/50-deferred-catchup.md).

### Built-in XDP program loader for AF_XDP (plan 12)

`XdpSocketBuilder::with_default_program()` makes AF_XDP self-contained:
the builder loads a pre-compiled redirect-all XDP program, attaches
it to the interface, and registers the AF_XDP socket on its embedded
XSKMAP — all in one call. Previously every AF_XDP user had to load
and attach an XDP program externally (via aya, libxdp, bpftool); now
you don't.

- New optional Cargo feature `xdp-loader = ["af-xdp", "dep:aya"]`. Pulls
  `aya` (pure Rust) for the runtime program-load and netlink-attach
  machinery. With the feature off, netring builds without aya.
- New module `netring::xdp` (gated): `default_program(max_queues)`,
  `XdpProgram`, `XdpAttachment` (RAII detach guard), `XdpFlags`
  (`SKB_MODE` / `DRV_MODE` / `HW_MODE` / `REPLACE`).
- New `XdpSocketBuilder` methods (gated): `with_default_program()`,
  `xdp_attach_flags(...)`, `force_replace(true)`. Default attach mode
  is `SKB_MODE` (works on every interface including `lo`); switch to
  `DRV_MODE` for native-driver XDP on supported NICs.
- The 5-instruction redirect-all program (`bpf_redirect_map(&xsks_map,
  ctx->rx_queue_index, XDP_PASS)`) is hand-written in C and
  pre-compiled to `redirect_all.bpf.o` (~1 KB ELF). The compiled
  object is committed; only `clang` is needed to regenerate (and only
  the maintainer ever does that). Consumers don't need clang/libbpf.
- 3 unit tests verify ELF magic, BPF machine type, and presence of
  the program and map symbols in the vendored object.
- RAII teardown: dropping `XdpSocket` detaches the program from the
  interface and unloads the map.
- Example: `examples/async_xdp_self_loaded.rs`.

Out of scope for this release (deferred follow-ups):
- `XdpSocketBuilder::with_program(prog)` for caller-loaded custom aya
  programs.
- Multi-queue XSKMAP sharing (`with_xsk_map(&map)`).
- Hardware offload validation for SmartNICs.

References: <https://docs.kernel.org/networking/af_xdp.html>,
<https://aya-rs.dev/book/>.

### AF_XDP / AF_PACKET busy-poll trio (plan 11)

Expose Linux ≥ 5.11 socket options that close most of the latency
gap between AF_XDP and DPDK on payload-touching workloads:

- `SO_BUSY_POLL` (kernel ≥ 4.5) — already supported via `busy_poll_us`
  on `Capture::builder()`; now also on `XdpSocketBuilder`.
- `SO_PREFER_BUSY_POLL` (≥ 5.11) — new `prefer_busy_poll(bool)`
  builder method on both. Tells the kernel to prefer the busy-poll
  path over softirq scheduling.
- `SO_BUSY_POLL_BUDGET` (≥ 5.11) — new `busy_poll_budget(u16)` builder
  method on both. Caps per-poll packet count.

Pulled libc constants directly (`libc 0.2.183` exports both new
options); no native deps. The trio matches Suricata's
`af-xdp.busy-poll{,_budget,prefer}` config keys.

Example: `examples/async_xdp_busy_poll.rs`.

Reference: <https://docs.kernel.org/networking/af_xdp.html>,
arxiv 2402.10513 *Understanding Delays in AF_XDP-based Applications*.

### Build fix: flowscope dep is non-optional

The previous workspace-extraction commit (`0a04082`) made `flowscope`
an optional dep, which broke `cargo build` without the `parse`
feature because `Packet::view()` and `pub use flowscope::Timestamp`
in `lib.rs` are unconditional. This release makes `flowscope` a
non-optional dep with `default-features = false`. With no features,
flowscope pulls only `bitflags` + `thiserror` — both already in
netring's tree, so the no-feature dep tree is unchanged in
practice.

### Workspace split: flow tracking moves to `flowscope`

The flow & session tracking crate previously known as `netring-flow`
(plus its companions `netring-flow-{http,tls,dns,pcap}`) has been
extracted to a separate repository and consolidated into a single
crate, [`flowscope`](https://github.com/p13marc/flowscope). The
companion crates are now feature-gated modules of `flowscope`
(`http`, `tls` + `ja3`, `dns`, `pcap`).

netring's `flow` feature now pulls `flowscope` instead of
`netring-flow`. Until `flowscope` is published to crates.io, the
dep is sourced from git. Async stream adapters
(`AsyncCapture::flow_stream`, `.session_stream`, `.datagram_stream`)
remain in netring; only the underlying traits and parsers moved.

If you imported anything from `netring-flow` or its companions:
- `netring_flow::X` → `flowscope::X`
- `netring_flow_http::X` → `flowscope::http::X`
- `netring_flow_tls::X` → `flowscope::tls::X`
- `netring_flow_dns::X` → `flowscope::dns::X`
- `netring_flow_pcap::X` → `flowscope::pcap::X`

If you went through `netring::flow::*`, no change.

The CHANGELOG entries for plans 10, 12, 20, 22–24, 30, 31 (the flow
work shipped under netring 0.7.0) are preserved below as the original
release record. New flow-related changes will be tracked in
`flowscope`'s changelog.

## 0.7.0 — Flow & session tracking (workspace split)

A major release introducing pluggable flow & session tracking,
delivered across two crates in a Cargo workspace:

- **`netring` 0.7.0** — the existing AF_PACKET / AF_XDP capture +
  inject crate. Linux only.
- **`netring-flow` 0.1.0** (new) — pluggable flow & session tracking,
  cross-platform and **runtime-free** (no tokio, no async deps,
  no Linux-specific code). Pair with any source of `&[u8]` frames:
  pcap, tun-tap, replay, embedded.

The flow stack went through four implementation phases (alpha.0
through alpha.3 — see `plans/INDEX.md` and intermediate tags). What
shipped:

### Workspace + skeleton (was alpha.0)

- Repository is now a Cargo workspace. `netring` and `netring-flow`
  are members; `Cargo.lock` lives at the workspace root.
- `Timestamp` moved from `netring` to `netring-flow`.
  `netring::Timestamp` continues to work via re-export.
- `justfile` recipes and CI workflow updated for the workspace.
- End-user surface (`cargo add netring`, `cargo build`) unchanged.

### Flow extractor + built-ins (was alpha.1)

In `netring-flow`:

- **`PacketView<'a>`** — frame + timestamp; the abstract input to
  every extractor.
- **`FlowExtractor` trait** — implement to define what a flow is in
  your domain. `Send + Sync + 'static`, returns `Extracted<Key>`.
- **`Extracted<K>`** — flow descriptor: key, orientation
  (Forward/Reverse), `Option<L4Proto>`, `Option<TcpInfo>`.
- **`L4Proto`**, **`Orientation`**, **`TcpInfo`**, **`TcpFlags`**.
- **Built-in extractors**: `FiveTuple` (default `bidirectional()`),
  `IpPair`, `MacPair`.
- **Decap combinators**: `StripVlan`, `StripMpls`, `InnerVxlan`
  (default UDP/4789), `InnerGtpU` (default UDP/2152). Compose freely.
- New `extractors` feature (default-on), pulling `etherparse`.

In `netring`:

- **`Packet::view() -> netring_flow::PacketView<'_>`** — zero-cost
  bridge from the existing capture API to the flow types.
- **`netring::flow::*`** — all flow types re-exported under `parse`.
- **`parse`** feature now activates `netring-flow/extractors`.

### Flow tracker + AsyncCapture::flow_stream (was alpha.2)

In `netring-flow`:

- **`FlowTracker<E, S>`** — bidirectional flow tracker generic over
  an extractor and per-flow user state (defaults to `()`).
  Constructors: `new`, `with_config` (for `S: Default`), `with_state`,
  `with_config_and_state` (any `S`).
- **TCP state machine**: `Active → SynSent → SynReceived → Established
  → FinWait → ClosingTcp → Closed` (or `Reset` on RST).
- **Per-protocol idle timeouts** (Suricata defaults: TCP 5min, UDP
  60s, other 30s) with `FlowTracker::sweep(now)`.
- **LRU eviction** on `max_flows` overflow (default 100k) via the
  `lru` crate.
- **`FlowEvent<K>`**: `Started`, `Packet`, `Established`, `StateChange`,
  `Ended` (with reason, stats, history).
- **`FlowSide`** (Initiator/Responder), **`EndReason`**, **`FlowStats`**,
  **`HistoryString`** (Zeek-style `ShAdaFf`, capped at 16 chars).
- New `tracker` feature (default-on); pulls `ahash`, `smallvec`,
  `arrayvec`, `lru`.

In `netring`:

- **`FlowStream<S, E, U, R>`** — `futures_core::Stream<Item =
  Result<FlowEvent<K>, Error>>`. Driven from `AsyncCapture` via
  `AsyncFd::poll_read_ready_mut`.
- **`AsyncCapture::flow_stream(extractor)`** — the headline tokio
  API; consumes the capture and returns a `FlowStream`.
- **`FlowStream::with_state(init)`** — attach per-flow user state.
- **`FlowStream::with_config(config)`** — non-default tracker config.
- **`FlowStream::tracker()` / `tracker_mut()`** — stats / introspection
  / poking user state mid-stream.
- New `flow` feature on `netring`; pulls `parse` + `netring-flow/tracker`.

### Reassembler hooks (was alpha.3)

In `netring-flow` (sync, runtime-free):

- **`Reassembler` trait** — `segment(seq, payload)`, `fin()`, `rst()`.
- **`ReassemblerFactory<K>`** trait (gopacket-style).
- **`BufferedReassembler`** + **`BufferedReassemblerFactory`** —
  in-order accumulator with OOO drop counter.
- **`FlowTracker::track_with_payload<F>(view, F)`** — sync per-segment
  callback, fires before any events are returned.
- **`FlowTracker::extractor()`** accessor.
- **`FlowDriver<E, F, S>`** — sync wrapper bundling a tracker with a
  reassembler factory; manages per-(flow, side) reassemblers and
  cleans them up on `Ended`.
- **`FlowSide`** is now `Hash` (used as part of reassembler-instance keys).
- New `reassembler` feature (default-on, pure std).

In `netring` (gated by `flow + tokio`):

- **`AsyncReassembler` trait** — methods return
  `Pin<Box<dyn Future<Output = ()> + Send + 'static>>`.
- **`AsyncReassemblerFactory<K>`** trait.
- **`ChannelReassembler`** + **`channel_factory<K, F>(F)`** —
  spawn-task-per-flow pattern with `mpsc::Sender<Bytes>` and
  end-to-end backpressure.
- **`FlowStream::with_async_reassembler(factory)`** — type-shifts
  to `FlowStream<S, E, U, AsyncReassemblerSlot<K, F>>`.
- Async `Stream` impl awaits each reassembler future inline before
  yielding the next event — slow consumers backpressure all the way
  to the kernel ring.
- New deps under `flow + tokio`: `bytes`, `ahash`.

### `Conversation<K>` aggregate (plan 30)

A higher-level abstraction in `netring` (gated by `tokio + flow`)
that bundles a flow's two byte streams into a single async iterator.
Sugar over `with_async_reassembler(channel_factory(...))` for the
common "give me all the bytes from this flow" case.

- `Conversation<K>` — owns an mpsc receiver + shared end-reason
  cell. `next_chunk().await` returns `Initiator(Bytes)` /
  `Responder(Bytes)` / `Closed { reason }` / `None`.
- `ConversationStream<S, E>` — `Stream<Item = Result<Conversation<K>>>`,
  yields one conversation per flow.
- `FlowStream::into_conversations()` — entry point; consumes
  `FlowStream<S, E, (), NoReassembler>`.
- `FlowStream::into_conversations_with_capacity(N)` — explicit
  per-conversation channel capacity (default 64).
- `AsyncCapture::flow_conversations(extractor)` — shortcut.
- Implementation uses `Weak<ConvShared>` in the factory's lookup
  map so per-flow state is reclaimed automatically when both
  reassemblers drop — no leak.
- 5 unit tests + 1 example (`async_flow_conversations.rs`) + 1
  doctest.

### `SessionParser` + `DatagramParser` (plan 31, phase 1)

The pre-1.0 strategic abstraction: typed L7 message streams instead
of byte streams. New traits in `netring-flow` (runtime-free):

- **`SessionParser`** — one parser per flow, `feed_initiator` /
  `feed_responder` / `fin_*` / `rst_*` methods returning
  `Vec<Self::Message>`. For stream-based protocols (HTTP/1, TLS,
  DNS-over-TCP).
- **`DatagramParser`** — one parser per flow, `parse(payload, side)
  -> Vec<Self::Message>`. For packet-based protocols (DNS-over-UDP,
  syslog, NTP).
- **`SessionParserFactory<K>` / `DatagramParserFactory<K>`** with
  blanket impls for `Default + Clone` parsers — pass any such
  parser as its own factory; each new flow gets a clone.
- **`SessionEvent<K, M>`** — `Started { key, ts }`,
  `Application { key, side, message, ts }`,
  `Closed { key, reason, stats }`.
- New `session` feature on `netring-flow` (default-on, depends on
  `tracker`).

Async stream adapters in `netring` (gated on `flow + tokio`):

- **`AsyncCapture::flow_stream(...).session_stream(parser)`** —
  yields `SessionEvent<_, P::Message>` driven by a per-flow
  `SessionParser`. Bytes from each TCP segment dispatch to the
  parser; messages buffer in a per-stream `VecDeque` and drain via
  `Stream::poll_next`.
- **`AsyncCapture::flow_stream(...).datagram_stream(parser)`** —
  same shape for UDP. Walks Eth → optional VLAN×2 → IPv4/IPv6 →
  UDP and feeds the L4 payload to the parser. Skips IP fragments
  and IPv6 extension headers.

Trait bridges shipped with this phase:

- **`netring_flow_http::HttpParser`** — `SessionParser` impl
  producing `HttpMessage::{Request, Response}`. Wraps the existing
  `parser::step` / `eof` machinery; holds independent state per
  direction inside one parser. The callback-style `HttpFactory<H>`
  remains; users pick whichever shape fits.
- **`netring_flow_dns::DnsUdpParser`** — `DatagramParser` impl
  producing `DnsMessage::{Query, Response}`. Stateless across
  packets (correlation lives in the separate `Correlator` type).

Out of scope for this phase:
- `TlsParser` and `DnsTcpParser` bridges (the parser shape is
  proven; mechanical follow-up).
- Per-flow parser stats trait (`SessionParserStats`).
- Property tests across all parsers.
- Migration guide.

### `netring-flow-dns` companion crate (plan 24)

Passive DNS observer — UDP/53 only in v0.1. A new `DnsUdpObserver`
type wraps an inner `FlowExtractor` (the "extractor as tap" pattern)
and fires DNS events on every UDP/53 packet, while delegating flow
tracking to the inner extractor. Built on `simple-dns`.

- `parse_message` / `parse_message_at` — standalone DNS message
  parsers; return `DnsParseResult::{Query, Response}`.
- `DnsHandler` trait: `on_query`, `on_response`, `on_unanswered`.
- `Correlator<S>` — bounded `HashMap<(scope, tx_id), DnsQuery>` with
  oldest-first eviction, query/response matching with elapsed time,
  and `sweep(now)` for the configured `query_timeout` (default 30 s).
  Scoping by flow key prevents cross-flow tx-ID collisions.
- Decoded record types: A, AAAA, CNAME, NS, PTR, MX. Everything
  else surfaces as `DnsRdata::Other { rtype, data }`. TXT bodies
  empty for now (current `simple-dns` API limitation).
- Reads `transaction_id` and the flags word directly from the wire
  to avoid `simple-dns` opcode/rcode conversions; exposes accessors
  via `DnsFlags`.
- Internal `peek_udp` walks Ethernet → optional VLAN×2 → IPv4/IPv6
  → UDP without pulling `etherparse`. Fragments and IPv6 extension
  headers are skipped.
- 7 tests covering parse + correlator (match, orphan, sweep).
- Example: `examples/dns_log.rs` — pcap replay logging Q/R/timeouts
  with RTT.
- Out of scope for v0.1: TCP/53 reassembly (zone transfers, large
  responses), DoT/DoH/DoQ, EDNS(0) option decoding, DNSSEC validation.

### `netring-flow-tls` companion crate (plan 23)

A `ReassemblerFactory` that bridges `tls-parser` (rusticata) into
`netring-flow`'s reassembler. Passive observation only — no
decryption, no MITM. User implements `TlsHandler` to receive
`TlsClientHello` / `TlsServerHello` / `TlsAlert` events.

- Surfaced from ClientHello: legacy + record version, random,
  session ID, cipher suites (in order, GREASE-included), compression,
  SNI, ALPN list, `supported_versions` (for TLS 1.3), `supported_groups`,
  full extension-type list (ordered, suitable for fingerprinting).
- Surfaced from ServerHello: legacy + selected version, random,
  session ID, chosen cipher, ALPN selection.
- Alerts: level (Warning / Fatal / Other) + RFC 5246 description code.
- ChangeCipherSpec stops parsing on that direction (records past
  it are encrypted).
- Records spanning multiple TCP segments handled incrementally.
- Optional `ja3` feature: computes the JA3 canonical string +
  MD5 hex digest, fires `TlsHandler::on_ja3`. GREASE values (RFC
  8701) stripped per the upstream reference.
- 6 unit tests + 1 doctest + 1 JA3 test (when feature on) + 2
  fingerprint unit tests.
- Example: `examples/tls_observer.rs` — print SNI/ALPN per
  ClientHello from a pcap.
- README documents what's not surfaced (encrypted records,
  certificate parsing, session resumption details, JA4).

### `netring-flow-http` companion crate (plan 22)

A `ReassemblerFactory` that bridges `httparse`'s zero-copy HTTP/1.x
parser into `netring-flow`'s reassembler. User implements
`HttpHandler` to receive parsed `HttpRequest` / `HttpResponse`
events.

- HTTP/1.0 + HTTP/1.1 request/response lines + headers + body via
  Content-Length.
- Pipelined requests (multiple events per buffer pass).
- `Connection: close` body terminated by FIN (via
  `Reassembler::fin`).
- Messages split across multiple TCP segments handled
  incrementally.
- Configurable `max_buffer` (1 MiB default) and `max_headers`
  (64 default).
- 7 unit tests + 1 integration test against the Plan-12 HTTP fixture
  + 1 doctest.
- Example: `examples/http_log.rs` — log requests + responses from
  a pcap.
- README documents what's deferred (chunked encoding, HTTP/2,
  HEAD-correlation).

### `netring-flow-pcap` companion crate (plan 20)

A new workspace member that wraps `pcap-file` and exposes pcap
files as iterators of `PacketView`s or `FlowEvent`s. Removes ~10
lines of boilerplate from every offline-analysis program.

- `PcapFlowSource::open(path)` — open a pcap on disk.
- `PcapFlowSource::from_reader(R)` — wrap any `Read` (testing).
- `.views()` — `Iterator<Item = Result<OwnedPacketView, Error>>`
- `.with_extractor(extractor)` — `Iterator<Item = Result<FlowEvent<K>, Error>>`,
  drives an internal `FlowTracker` and runs a final far-future
  sweep on pcap exhaustion to flush unfinished flows as
  `Ended { IdleTimeout }`.
- 3 integration tests, 2 doctests, 1 example (`pcap_summary.rs`).
- README documents the relationship to other capture sources.

### Test infrastructure (plan 12)

- **3 pcap fixtures** under `netring-flow/tests/data/`:
  `http_session.pcap` (TCP HTTP/1.1 lifecycle), `dns_queries.pcap`
  (UDP/53 query/response pairs + NXDOMAIN + lone unanswered),
  `mixed_short.pcap` (TCP + UDP + ICMP). All synthetic; ~2 KB total.
- **Fixture generator**: `cargo run -p netring-flow --example
  generate_fixtures --features test-helpers` re-creates them
  deterministically.
- **3 fixture-driven integration tests** in `netring-flow/tests/pcap_fixtures.rs`.
- **10 property-based tests** (`proptest`) in
  `netring-flow/tests/proptest_invariants.rs` covering: 5-tuple
  canonicalization, TCP state machine never panics, tracker
  flow-count invariant, tracker stats balance, "every parser must
  not panic on arbitrary bytes" (5 separate properties: FiveTuple,
  StripVlan, StripMpls, InnerVxlan, InnerGtpU), and "Established
  always after Started." 256 cases per property by default.
- **6 `cargo fuzz` targets** under `netring-flow/fuzz/fuzz_targets/`
  for the 5 built-in extractors. Excluded from the workspace; run
  with `cargo +nightly fuzz run TARGET`. Justfile recipes:
  `just fuzz-build`, `just fuzz-smoke` (30s per target),
  `just fuzz TARGET`.
- **`test-helpers` feature** on `netring-flow` exposes
  `extract::parse::test_frames` (synthetic-frame builders) for
  downstream tests. Also opens `tcp_state` for proptest. Not for
  production use.

### Loopback dedup (plan 10)

- **`Dedup`** primitive in `netring`. Two factory modes:
  - `Dedup::loopback()` — 1ms window, 256-entry ring,
    direction-aware. Drops the kernel's `Outgoing/Host` re-injection
    pair on `lo`. Same-direction repeats (legitimate retransmits)
    are kept.
  - `Dedup::content(window, ring_size)` — generic content-hash
    dedup, direction-agnostic. Use for any capture where
    duplicates aren't loopback-shaped.
- **`AsyncCapture::dedup_stream(Dedup)`** — `Stream<Item = Result<OwnedPacket>>`
  with duplicates filtered. Sync users use the `Dedup::keep(&pkt)`
  loop directly.
- New dep: `xxhash-rust` (xxh3-64 for content hashing, ~zero deps).
- 10 unit tests; 2 integration tests on `lo`.
- Example: `examples/async_lo_dedup.rs`.

### Documentation (this release)

- **`netring-flow/docs/FLOW_GUIDE.md`** — comprehensive cookbook
  covering quick starts (sync + async), built-in extractors,
  encapsulation combinators, custom extractors (3 worked examples),
  per-flow user state, TCP events and history strings, sync + async
  reassembly, backpressure, idle timeouts, performance notes,
  source-agnosticism, `protolens` bridging.
- **`netring-flow/README.md`** — crates.io card.
- Workspace `README.md` — new "Flow & session tracking" section
  near the top.

### Examples added

In `netring-flow`:
- `pcap_flow_keys.rs` — extract 5-tuples from a pcap.
- `pcap_flow_summary.rs` — sync flow tracking over pcap.
- `pcap_buffered_reassembly.rs` — sync TCP reassembly over pcap
  via `FlowDriver`.

In `netring`:
- `async_lo_dedup.rs` — loopback dedup demo with periodic stats.
- `async_flow_keys.rs` — built-in + custom extractor on live capture.
- `async_flow_summary.rs` — Started/Established/Ended events.
- `async_flow_filter.rs` — protocol + port filter.
- `async_flow_history.rs` — Zeek-style `conn.log` output.
- `async_flow_channel.rs` — `channel_factory` + spawned per-flow tasks.

### Tests

- 202 unit + doctests passing across the workspace (was 97 in 0.6.0).
- New: 25 tracker tests, 13 reassembler / driver tests, 25 extractor
  tests, parser, history, TCP state machine.

### Migration from 0.6.0

- `netring::Timestamp` keeps working (re-export). Deep paths like
  `netring::packet::Timestamp` also still resolve.
- No public types or methods removed from `netring`.
- New optional `flow` feature opts into the flow API; existing
  `netring` users see no change unless they enable it.
- Workspace structure: if you depend on netring as a path dependency,
  update the path to `netring/netring/`.

## 0.6.0 — Async first

netring's primary API is now async/tokio. The sync types are still
first-class but the documentation, examples, and recommended patterns
all lead with the async wrappers.

### Added

- **`AsyncXdpSocket`** — async wrapper for AF_XDP, the previously-missing
  piece in the tokio story. Mirrors `AsyncCapture` for RX (three reception
  modes) and `AsyncInjector` for TX (`send().await` awaits `POLLOUT` under
  backpressure). One wrapper covers both directions since `XdpSocket`
  shares one fd. Behind `tokio + af-xdp` features.
  - `AsyncXdpSocket::open(iface)` / `::new(socket)`
  - `readable() → XdpReadableGuard` / `try_recv_batch()` / `recv()`
  - `into_stream() → XdpStream` (`futures_core::Stream`)
  - `send(data).await` / `flush().await` / `wait_drained(timeout).await`
  - `statistics()` (passthrough to `XdpStats`)

- **`AsyncCapture::open(iface)` / `AsyncInjector::open(iface)`** —
  one-liner shortcuts that replace
  `AsyncCapture::new(Capture::open(iface)?)?`. Specialized impls;
  the generic `new()` still works for builder-configured sources.

- **`Bridge::open_pair(a, b)`** — shortcut for
  `Bridge::builder().interface_a(a).interface_b(b).build()`.

- **`docs/ASYNC_GUIDE.md`** — full async guide covering all four
  async types, the three reception modes, `Send`/`!Send` rules,
  Stream + StreamExt usage, and patterns (mpsc fan-out, graceful
  shutdown, periodic stats + metrics integration).

- **Three new examples**:
  - `examples/async_streamext.rs` — `PacketStream` + `futures::StreamExt`
  - `examples/async_xdp.rs` — `AsyncXdpSocket` TX with backpressure
  - `examples/async_metrics.rs` — periodic `tokio::time::interval` +
    metrics integration

### Changed

- **README rewrite** — leads with async (Quick Start), demotes the
  sync API to its own section. Public API table now pairs sync types
  with their async wrappers.
- **Dev-dependency added**: `futures = "0.3"` (used by the
  `async_streamext` example only).

### Internal

- New module `src/async_adapters/tokio_xdp.rs`.

## 0.5.0 — Feature expansion + cleanup

### Breaking

- **Deprecated 0.3.x aliases removed**: `AfPacketRx`, `AfPacketRxBuilder`,
  `AfPacketTx`, `AfPacketTxBuilder` — use `Capture`, `CaptureBuilder`,
  `Injector`, `InjectorBuilder` (introduced in 0.4.0).
- **`XdpSocket::recv_batch` removed**: use `XdpSocket::next_batch` (renamed
  in 0.4.0).
- Both removals are mechanical migrations covered by 0.4.0's CHANGELOG.

### Added

- **`pcap` feature** — exports captured packets to PCAP files via the
  pure-Rust [`pcap-file`] crate. New `netring::pcap::CaptureWriter`
  type with `write_packet` (zero-copy) and `write_owned` (owned)
  entry points. Nanosecond-resolution kernel timestamps. Includes
  `examples/pcap_write.rs`.
- **`metrics` feature** — `netring::metrics::record_capture_delta`
  records three counters (`netring_capture_packets_total`,
  `netring_capture_drops_total`, `netring_capture_freezes_total`)
  via the [`metrics`] façade. Pair with any recorder
  (`metrics-exporter-prometheus`, OTel, statsd, ...).
- **AF_XDP `XDP_SHARED_UMEM` primitive** —
  `XdpSocketBuilder::shared_umem(primary: impl AsFd)` lets a secondary
  socket share an existing UMEM region. Documents the manual-partition
  contract (each socket allocates from its own free list; users are
  responsible for keeping address ranges disjoint). A higher-level
  `SharedUmem` helper that automates partitioning is planned for a
  future release.

### Documentation

- `docs/TUNING_GUIDE.md` updated for 0.4-era surface (rcvbuf,
  reuseport, fill_rxhash, snap_len, cumulative_stats, AF_XDP `XdpMode`,
  metrics integration).
- `docs/AF_XDP_EVALUATION.md` rewritten as a "what we shipped"
  retrospective covering the four-module layout, ring protocol,
  BPF-program requirement, and unfinished extensions.

### Tests + CI

- `tests/bridge.rs` — paired-veth integration tests for `Bridge`
  (idle smoke + into_inner decomposition). Skips gracefully without
  CAP_NET_ADMIN.
- `tests/xdp.rs` — Tx-only AF_XDP smoke test on `lo`. Skips
  gracefully where the kernel doesn't support XDP on the loopback.
- New `tests/helpers.rs::VethPair` RAII fixture.
- CI:
  - `actions/checkout@v4` → `@v5` (Node 20 deprecation).
  - New `cargo-deny` job (license + advisory + source allowlist).
  - New `cargo-machete` job (unused-dep detection).
  - Integration test feature set now includes `af-xdp`.

### Decision: PacketBackend trait deferred

A unified `PacketBackend` trait covering both AF_PACKET and AF_XDP
was scoped but deferred. The AF_PACKET `Packet` exposes metadata
(`direction`, `vlan_tci`, `rxhash`, `status`) that AF_XDP doesn't
surface, and forcing every AF_PACKET caller to unwrap `Option` for
fields they used directly is a worse trade-off than parallel concrete
APIs. Most users pick one backend (AF_PACKET ~500K–1M pps, AF_XDP
10–24M pps) and stay there. Will revisit when there's user code that
demands cross-backend generic handling.

[`pcap-file`]: https://crates.io/crates/pcap-file
[`metrics`]: https://crates.io/crates/metrics

## 0.4.0 — API redesign

The 0.3.0 surface had two parallel layers per direction: a high-level
wrapper (`Capture`/`Injector`) and a low-level type
(`AfPacketRx`/`AfPacketTx`). The wrappers added almost nothing — duplicated
builders, two `stats()`, two `attach_ebpf_filter()`, two ENOMEM-retry paths
to keep in sync. 0.4.0 collapses them.

### Breaking

- **`AfPacketRx` / `Capture` (wrapper) → merged into `Capture`**.
  - The `packets()` flat iterator, `poll_timeout` field, and ENOMEM retry
    move directly onto `Capture` / `CaptureBuilder`.
  - `Capture::into_inner()` is gone (no inner — Capture *is* the source).
  - `Capture::new(iface)` renamed to `Capture::open(iface)` to match
    `File::open` / `TcpStream::connect`.
- **`AfPacketTx` / `Injector` (wrapper) → merged into `Injector`** with
  the same shape; `Injector::open(iface)` is the new shortcut.
- **`AfPacketRxBuilder` / `CaptureBuilder` (wrapper)** → merged into
  `CaptureBuilder`. Same for `InjectorBuilder`.
- **`XdpSocket::recv_batch` → renamed to `XdpSocket::next_batch`** to
  match `Capture::next_batch` (kept as `#[deprecated]` alias for one
  release).
- **`XdpSocket::next_batch` no longer returns `Result`** — `Option`
  matches the AF_PACKET signature; nothing in `recv_batch` could ever
  return `Err` anyway.
- **`AsyncCapture::wait_readable` removed** — was deprecated in 0.3.0;
  use `readable().await?.next_batch()`.
- **`PacketStream::new(cap)` is still available** but `cap.into_stream()`
  is the new fluent shortcut.

### Migration

Old names ship as `#[deprecated]` type aliases so 0.3.0 code keeps
compiling for one release:

```rust
#[deprecated] pub type AfPacketRx        = Capture;
#[deprecated] pub type AfPacketRxBuilder = CaptureBuilder;
#[deprecated] pub type AfPacketTx        = Injector;
#[deprecated] pub type AfPacketTxBuilder = InjectorBuilder;
```

Source-level migration:

```diff
- let mut rx = AfPacketRxBuilder::default().interface("eth0").build()?;
+ let mut rx = Capture::builder().interface("eth0").build()?;

- let mut cap = Capture::new("eth0")?;
+ let mut cap = Capture::open("eth0")?;

- let batch = xdp.recv_batch()?;
+ let batch = xdp.next_batch();

- cap.wait_readable().await?;
- if let Some(b) = cap.get_mut().next_batch() { ... }
+ let mut g = cap.readable().await?;
+ if let Some(b) = g.next_batch() { ... }
```

### Added

- `Capture::open(iface)` / `Injector::open(iface)` / `XdpSocket::open(iface)` —
  one-liner shortcuts.
- `Capture` exposes `next_batch` and `next_batch_blocking` as inherent
  methods so users don't need `use PacketSource;` for the common case.
  `PacketSource` is still implemented and useful for generic code.
- `XdpSocket::next_batch_blocking(timeout)` — blocking RX with poll(2),
  EINTR-safe. Brings AF_XDP to feature parity with AF_PACKET on the
  blocking-receive surface.
- `AsyncCapture::into_stream()` fluent helper (same as `PacketStream::new`).

### Internal

- ~425 net lines removed by collapsing the wrapper layer (1041 deletions
  vs 616 insertions).
- ENOMEM retry logic moved from `CaptureBuilder` (wrapper) to the merged
  `CaptureBuilder` (now uses a private `build_inner` helper).

## 0.3.0

### Breaking

- **`Capture::attach_ebpf_filter` and `AfPacketRx::attach_ebpf_filter`** now take
  `impl AsFd` instead of `RawFd`. Migration:
  ```diff
  - cap.attach_ebpf_filter(prog.fd().as_raw_fd())?;
  + cap.attach_ebpf_filter(prog.fd())?;
  ```
- **`XdpSocket::statistics`** returns the new [`XdpStats`] type instead of
  `libc::xdp_statistics`. Field names are stable and documented; insulates
  downstream from libc churn.
- **`OwnedPacket`** now carries seven additional metadata fields (`status`,
  `direction`, `rxhash`, `vlan_tci`, `vlan_tpid`, `ll_protocol`,
  `source_ll_addr` / `source_ll_addr_len`). Code that constructed
  `OwnedPacket` struct-literally requires those fields. Field-name access
  continues to work.
- **`PacketBatch::iter()`** is no longer `ExactSizeIterator` — `tp_next_offset == 0`
  can terminate the walk early. Use `PacketBatch::len()` for the count.
- Internal: `XdpRing` switched to a token-based API (`PeekToken`,
  `ReserveToken`); affects only crate-internal callers.

### Added

- **AF_XDP zero-copy receive** — `XdpSocket::recv_batch()` returns
  `Option<XdpBatch<'_>>` borrowing directly from UMEM, mirroring the
  AF_PACKET `PacketBatch` lifecycle. New types: `XdpBatch`, `XdpPacket`,
  `XdpBatchIter`. RAII drop releases descriptors and refills the fill ring.
- **`XdpMode`** enum on `XdpSocketBuilder` — `Rx` / `Tx` / `RxTx` /
  `Custom { prefill }`. Fixes a bug where the default prefill drained
  the entire UMEM into the fill ring, leaving zero frames for `send()`.
  TX-only users **must** set `.mode(XdpMode::Tx)`.
- **`XdpSocket::flush`** now honors `XDP_USE_NEED_WAKEUP` — skips the
  `sendto` syscall when the kernel signals it is actively polling.
- **`Bridge::run_async` / `run_iterations_async`** behind `feature = "tokio"` —
  uses `AsyncFd` + `tokio::select!` instead of manual `poll(2)`. Cheaper
  for tokio users.
- **`Bridge` poll(2) wait** — sync `Bridge::run` now blocks on `poll(2)`
  before draining; previously a busy loop. New `BridgeBuilder::poll_timeout`
  setter (default 100 ms).
- **Per-direction `BridgeBuilder` overrides** — `a_block_size`, `a_block_count`,
  `a_frame_size`, `a_block_timeout_ms` and the `b_*` / `tx_*_*` mirrors.
  Asymmetric ring sizing for capture-on-A / forward-on-B with different MTUs.
- **`Bridge::into_inner()`** returns a new `BridgeHandles` struct
  `{ rx_a, tx_b, rx_b, tx_a }` for advanced patterns.
- **`Bridge::stats`** + `BridgeStats` now classifies dropped forwards into
  `*_dropped_too_large` and `*_dropped_ring_full` per direction.
- **`Capture::packets_for(Duration)` / `packets_until(Instant)`** — bounded
  variants of the unbounded `packets()` iterator. Useful for tests and
  time-limited captures.
- **`PacketIter::take_error()`** — inspect the I/O error that terminated
  iteration (previously discarded silently).
- **`AsyncCapture::readable()` / `ReadableGuard`** — single-step zero-copy
  receive without the `wait_readable + next_batch` race window. Also
  `try_recv_batch` for sugar.
- **`PacketStream`** — `futures_core::Stream<Item = Result<Vec<OwnedPacket>, Error>>`
  adapter over `AsyncCapture`. Composes with `StreamExt` combinators and
  is cancel-safe between polls. Pulls in a tiny `futures-core` dep
  gated by the `tokio` feature.
- **`AsyncInjector`** — async TX counterpart to `AsyncCapture`. `send`
  awaits `POLLOUT` when the ring is full instead of returning `None`;
  `wait_drained` blocks until every queued frame has been transmitted.
- **`AsyncPacketSource`** trait now has an impl for `AsyncCapture<S>`.
- **Cancel safety** documented on `readable`, `try_recv_batch`,
  `PacketStream::poll_next`, and all `AsyncInjector` methods.
- New `examples/async_stream.rs` demonstrating the Stream API.
- New `examples/async_inject.rs` — `AsyncInjector` with backpressure.
- New `examples/async_signal.rs` — Ctrl-C graceful shutdown via
  `tokio::signal::ctrl_c` + `tokio::select!`.
- New `examples/async_pipeline.rs` — capture → `tokio::sync::mpsc` →
  N worker tasks, the canonical fan-out pattern.
- New `examples/async_bridge.rs` — `Bridge::run_async` racing against
  Ctrl-C for graceful shutdown.
- **`PacketSource::cumulative_stats`** — monotonic running totals
  (default impl falls back to `stats()`; AF_PACKET overrides to accumulate
  deltas internally). Mirrored on `Capture` and `Bridge`.
- **`AfPacketTx::pending_count` / `wait_drained`** — observability for TX
  completions.
- **`AfPacketTx::available_slots` / `rejected_slots` / `frame_capacity`** —
  finer-grained slot inspection.
- **EINTR-safe syscall helpers** in `src/syscall.rs`. All blocking
  syscalls (`poll`, TX kick `sendto`) now retry on EINTR transparently.
- **`AfPacketRx::attach_fanout_ebpf` / `Capture::attach_fanout_ebpf`** —
  finally wires `FanoutMode::Ebpf` to a callable API.
- **`fill_rxhash` setter** on RX builders.
- **`SO_REUSEPORT`** setter on RX builders.
- **`SO_RCVBUF` / `SO_RCVBUFFORCE`** setters on RX builders.
- **`ChannelCapture::stop_and_drain()`** — graceful shutdown that returns
  buffered packets instead of discarding them.
- **`OwnedPacket::source_ll_addr()`** accessor for the valid prefix.

### Changed

- **`AfPacketTx::flush`** documentation clarified: the returned count is
  *queued*, not *transmitted* (frames may still be in flight or rejected).
  Use the new `pending_count`/`available_slots` accessors for transmission
  progress.
- **`AfPacketTx::Drop`** now logs a warn-level trace event when the
  best-effort flush fails, rather than discarding silently.
- **`MmapRing` MAP_LOCKED retry** logs a cause-specific hint
  (CAP_IPC_LOCK / RLIMIT_MEMLOCK / OOM) on the warn record.
- **`Bridge::stats`** docstring made explicit about the destructive read.
- **`Capture::packets`** rustdoc promoted the soundness warning ("do not
  collect across blocks") from a buried comment to a `# Soundness` section
  with example.
- **`source_ll_addr`** doc now explains the 8-byte cap (kernel
  `sockaddr_ll::sll_addr` size; LLEs longer than 8 are truncated by the
  kernel before reaching us).
- **`interface_info`** logs a debug-level trace when sysfs MTU is missing.

### Deprecated

- `AsyncCapture::wait_readable()` — use `readable().await?.next_batch()`
  instead. The two-step pattern called `clear_ready` eagerly, opening a
  race window between waiting and reading.

### Fixed

- **#1**: AF_XDP TX-only mode was broken. `xdp_send` example silently
  transmitted zero packets because `build()` prefilled the entire UMEM
  into the fill ring. Now `XdpMode::Tx` skips prefill; `RxTx` splits
  half-and-half.
- **#2**: `Bridge::run` busy-looped at 100 % CPU on idle interfaces.
  Now blocks on `poll(2)` over both RX fds.
- **#3**: `BatchIter` re-emitted the last packet repeatedly when given
  a corrupt `num_pkts > actual` count. Now terminates on the
  `tp_next_offset == 0` kernel marker.
- **#4**: `PacketIter` and `BatchIter` had different bounds checks;
  `Packet::direction()` from the high-level iterator could read past
  the bounds-check guarantee. `PacketIter` now delegates to `BatchIter`.
- **#9**: `AfPacketTx::flush` returned an inflated success count
  (queued, not sent). Documented; new accessors expose the truth.
- **#12**: `XdpSocket::recv` validated kernel-supplied `xdp_desc` bounds.
- **#15**: Bridge dropped jumbo packets with the wrong diagnostic;
  classification + counters added.
- **#17**: `PacketIter` swallowed I/O errors silently. `take_error()`
  now exposes the cause.
- **#18**: `Capture::stats(&self)` was destructive despite the immutable
  signature; `cumulative_stats()` provides the non-destructive surface.
- **#20**: `AfPacketTx::allocate` advanced the cursor on dropped slots
  and never reset `WRONG_FORMAT` slots. Now scans forward up to
  `frame_count` and resets rejections.
- **#21**: `XdpRing` callers could read past their peeked range;
  token-based API enforces bounds at runtime.
- **#22**: `XdpSocket` is now provably `Send` but `!Sync` via
  static const assertion + `compile_fail` doctest.
- **#24**: `ChannelCapture::Drop` discarded buffered packets;
  `stop_and_drain` provides the alternative.

### Removed

- Dead `MmapRing::block_size` accessor.
- `#[allow(dead_code)]` on `XdpRing::needs_wakeup` and
  `attach_fanout_ebpf` — both now part of the live API surface.

## 0.2.0

### Added

- **AF_XDP backend** (feature: `af-xdp`) — kernel-bypass packet I/O via XDP sockets
  - `XdpSocket` with `recv()`, `send()`, `flush()`, `poll()`, `statistics()`
  - `XdpSocketBuilder` with `interface()`, `queue_id()`, `frame_size()`, `frame_count()`, `need_wakeup()`
  - Pure Rust implementation using `libc` syscalls (no native C dependencies)
  - UMEM allocation with frame-based free list allocator
  - 4 ring types (Fill, RX, TX, Completion) with lock-free producer/consumer protocol
  - TX works without a BPF program; RX requires an external XDP program (e.g. via `aya`)
  - `xdp_send` example for TX-only usage
- **Bridge / IPS mode** — bidirectional packet forwarding between two interfaces
  - `Bridge`, `BridgeBuilder`, `BridgeAction`, `BridgeDirection`, `BridgeStats`
  - User-supplied filter callback for per-packet forward/drop decisions
- **Interface capability detection** via sysfs
  - `interface_info()` returns `InterfaceInfo` with MTU, speed, driver, queue count, carrier status
  - `RingProfile` presets: `Default`, `LowLatency`, `HighThroughput`, `MemoryConstrained`, `JumboFrames`
  - `InterfaceInfo::suggest_profile()` and `suggest_fanout_threads()`
- **Per-packet metadata** — `PacketDirection`, `PacketStatus` with VLAN, checksum, and flow hash fields
- **eBPF integration** — `BpfFilter`, `BpfInsn` for classic BPF socket filters; `FanoutMode`, `FanoutFlags`
- **Async adapters** — `AsyncCapture` (feature: `tokio`), `ChannelCapture` (feature: `channel`)
- **Packet parsing** — `etherparse` integration (feature: `parse`)
- `Debug` impl for `PacketBatch` and `BatchIter`
- `Send` impl for `XdpSocket`
- `#[must_use]` on `Bridge`
- Crate-root re-exports for `XdpSocket`, `XdpSocketBuilder`, `Bridge`, `BridgeAction`, `BridgeBuilder`, `BridgeDirection`, `BridgeStats`, `AsyncCapture`, `AsyncPacketSource`, `ChannelCapture`

### Changed

- **Breaking:** `XdpSocketBuilder` fields are now private (use setter methods)
- Extracted shared `raw_setsockopt()` helper into `src/sockopt.rs` (deduplicates AF_PACKET and AF_XDP backends)
- Updated `Cargo.toml` description and keywords to reflect AF_XDP support

### Fixed

- Broken rustdoc link to `AsyncPacketSource` in `traits.rs` module docs

## 0.1.0

Initial release.

- AF_PACKET TPACKET_V3 backend with zero-copy mmap ring buffers
- High-level API: `Capture`, `CaptureBuilder`, `Injector`, `InjectorBuilder`
- Low-level API: `AfPacketRx`, `AfPacketTx`, `PacketSource`, `PacketSink` traits
- `Packet` (zero-copy view), `PacketBatch` (RAII block), `OwnedPacket` (heap copy)
- `TxSlot` for frame-level TX with send-or-discard-on-drop semantics
- `CaptureStats` from kernel `PACKET_STATISTICS`
- `Timestamp` with nanosecond precision
