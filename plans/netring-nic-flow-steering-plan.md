# netring — NIC flow steering (plan)

> **Status:** plan, 2026-06-16. Candidate feature; no fixed release slot.
> No flowscope touch. Additive. **HW-gated** (needs a NIC with ntuple/RSS support
> + `CAP_NET_ADMIN`).

## 1. Why

Research's one substantive knock on AF_XDP vs DPDK: *"with AF_XDP you don't have
the option to program flow-matching rules in NICs and leverage RSS to spread
packets."* We already read the queue count (`queue_count`, 0.26); programming the
NIC's **steering rules** lets multi-queue/sharded capture **pin chosen flows to
chosen queues/cores** — closing the last AF_XDP↔DPDK gap and enabling targeted
capture (e.g. mirror only port-443 SYNs to a dedicated analysis core).

## 2. Design

### `netring::xdp::steer` — typed wrappers over the ethtool RX-NFC API
- **ntuple rules** via `SIOCETHTOOL` + `ETHTOOL_SRXCLSRLINS` (insert) /
  `ETHTOOL_SRXCLSRLDEL` (delete), populating `struct ethtool_rxnfc` with an
  `ethtool_rx_flow_spec` (flow type, match fields/masks, `ring_cookie` = target
  queue). `ETHTOOL_GRXCLSRLALL` to list. (Same `SIOCETHTOOL` ioctl plumbing we
  already vendored for `ETHTOOL_GCHANNELS` in 0.26 — extend `afxdp/ffi.rs`.)
- **RSS** via `ETHTOOL_SRXFH` (which header fields feed the hash) and, where
  supported, **extra RSS contexts** + the `FLOW_RSS` flag so a rule spreads
  matches across a context (the indirection-table value adds to `ring_cookie`).
- Typed, fallible builder so users don't hand-pack `ethtool_rxnfc`:
  ```rust
  use netring::xdp::steer::{FlowRule, RxSteer};
  let s = RxSteer::open("eth0")?;
  let id = s.insert(FlowRule::tcp().dst_port(443).flag_syn().to_queue(3))?;
  // … capture queue 3 with XdpCapture/XdpShardedRunner …
  s.remove(id)?;                          // RAII guard removes on drop too
  ```
- An RAII `SteerGuard` that removes inserted rules on drop (so a crashed capture
  doesn't leave stale NIC rules), mirroring the `PromiscGuard` pattern.

### Capture integration
- `XdpCaptureBuilder::steer(rule)` / `XdpShardedRunner::steer(rule)` convenience:
  insert the rule, bind the matching queue, keep the `SteerGuard` alongside the
  program/promisc guard. The common recipe — "capture exactly these flows on this
  queue" — becomes one chained call.

## 3. flowscope side
None.

## 4. Milestones
- **M1** `afxdp/ffi.rs`: `ETHTOOL_{S,G}RXCLSRL*`, `ETHTOOL_SRXFH`, `ethtool_rxnfc`,
  `ethtool_rx_flow_spec` vendored structs. `RxSteer::{open, insert, remove, list}`.
- **M2** typed `FlowRule` builder (tcp/udp, src/dst ip/port, masks, `to_queue`,
  `FLOW_RSS`/context) + `SteerGuard`.
- **M3** `XdpCaptureBuilder::steer` / `XdpShardedRunner::steer` integration +
  an example (steer SYN/443 to a dedicated capture queue).
- **M4** docs: capability/driver caveats, `CAP_NET_ADMIN`, the
  "AF_XDP-can-now-steer-like-DPDK" framing.

## 5. Testing
- Cap-free: `FlowRule` → `ethtool_rx_flow_spec` byte-packing golden tests (verify
  the union layout against the kernel struct, size asserts like the 0.26 ffi tests).
- Root-gated: `lo` has no RX-NFC support → `insert` returns `-EOPNOTSUPP`; the test
  asserts the **clean error path** (not a panic), exactly like `queue_count("lo")`.
- Real steering (rule actually redirects a flow to a queue) is HW-gated —
  example-validated on an ntuple-capable NIC (ixgbe/i40e/ice/mlx5).

## 6. Risks & open decisions
- **Driver fragmentation** is severe here — ntuple support, field coverage, RSS
  contexts, and `FLOW_RSS` all vary by driver. Surface capabilities + degrade with
  precise errors; never assume a rule took (verify via `GRXCLSRLALL` after insert).
- **ethtool ioctl vs netlink.** The classic `SIOCETHTOOL` ioctl path is simplest
  and matches our existing `queue_count` plumbing; the newer `ethtool-netlink` is
  richer but heavier. **Recommend ioctl** for v1; netlink only if a needed field
  is ioctl-unreachable.
- **Cleanup safety** — the `SteerGuard` must remove rules on drop, but a hard
  crash leaks them. Document a `RxSteer::clear_netring_rules(iface)` escape hatch
  (tag inserted rules with a recognizable location/cookie).
- **Scope:** read-side steering only (RX-NFC/RSS). Full P4-style programmable
  steering is out of scope.
