# netring Cargo features

Features are organized as **orthogonal axes**: pick what you need from each.
AF_PACKET capture/inject is always compiled (the base); everything else is opt-in.

## Quick recipes

| Goal | Features |
|---|---|
| Bare capture / inject (AF_PACKET) | *(none)* — `default = []` |
| AF_XDP capture | `af-xdp` (+ `xdp-loader` for the bundled redirect program) |
| Offline pcap replay | `pcap` (+ `tokio`/`flow` for the async/flow pipelines) |
| Flow tracking, no Monitor | `tokio, flow` |
| **Lean Monitor** (typed dispatch + run loop) | `monitor-lite` |
| Monitor + L7 parsers + sinks | `monitor` |
| Everything app-tier | `monitor-quickstart` |

## Axes

### Async runtime
- `tokio` — `AsyncCapture`, the async stream adapters, and the `Monitor` run loop.
- `channel` — `ChannelCapture` / `ChannelSink` (crossbeam).

### Capture backend
- *(base)* AF_PACKET (TPACKET_v3) — always available.
- `af-xdp` — `XdpSocket` / `AsyncXdpSocket` (zero-copy AF_XDP).
- `xdp-loader` — bundles an `aya`-loaded redirect program (**heavy** dep). Implies `af-xdp`.
- `pcap` — pcap read/write + offline source.

### Parse depth
- `parse` — etherparse L2–L4 extractors. **Implied by `flow`** (the tracker needs it).
- `flow` — flowscope flow/session tracking + reassembler. `flow + tokio` ⇒ `flow_stream` + the Monitor.
- `http` / `dns` / `tls` / `icmp` — L7 parser pass-throughs (each implies `flow`).
- `http2` — HTTP/2 + HPACK + gRPC (implies `flow`). **Dispatches by signature, not
  by port**: h2c has no standard cleartext port and h2-over-TLS is opaque to a
  passive tap, so it matches flowscope's 24-byte preface. That has two costs the
  port-routed parsers do not have — the kernel prefilter widens to `Always`
  (a signature cannot be evaluated in the kernel), and a heuristic probe runs on
  every TCP flow (one probe state per flow, up to 16 KiB of replay buffer). Also
  note it matches *prior-knowledge* h2c only; h2c negotiated over an HTTP/1
  `Upgrade` delivers its preface after the probe has given up. In `all-parsers`,
  and deliberately **not** in the `monitor` umbrellas.
- `all-parsers` — every L7 parser marker: the four above plus `http2`, the
  Active-Directory set (`smb`/`kerberos`/`ldap`/`rdp`), the device-facts set
  (`dhcp`/`ssdp`/`netbios-ns`), `ssh` and `quic`.
- `arp` — L2 ARP visibility + spoof/binding-change detection (implies `flow`).
  Adds `MonitorBuilder::on_arp` / `on_arp_anomaly`; parsed per-frame in the
  Monitor drain (ARP has no 5-tuple). In the `monitor` umbrellas.
- `file-hash` — flowscope `Sha256Sink` / `FileType`.

### Sinks / exporters / serialization
- `serde` — `Serialize` on `Anomaly`/`Severity` + JSON sinks.
- `metrics` — Prometheus-style `MetricsSink`.
- `emit` — flowscope Zeek/CSV writers. `eve-sink` — Suricata EVE JSON sink (implies `emit`).
- *(0.24 Phase D adds `syslog` + `ipfix`; OTLP/Kafka live in the `netring-exporters`
  companion crate, not as core features.)*

### Umbrellas
- `monitor-lite = tokio + channel + flow` — the minimum viable Monitor.
- `monitor` = `monitor-lite` + parsers + metrics + emit + serde.
- `monitor-quickstart` = `monitor` + pcap + eve-sink + ocsf-sink + file-hash.
  Note "quickstart" is the *curated* app tier, not everything: it deliberately
  leaves out the features that cost something you should opt into knowingly —
  `http2` (see above), `sigma`, `yara`, `ioc`, `nprint`/`ml-features`,
  `ja4plus` (FoxIO License), and the Tier-2 / OT protocol sets.

## Couplings & foot-guns
- `flow → parse` is a hard implication (the tracker needs etherparse extractors).
- `xdp-loader → aya` pulls the largest dependency; only enable it if you want the bundled
  XDP program (otherwise `af-xdp` + your own loader).
- **Linux only.** Any non-Linux target fails at a top-level `compile_error!` in `lib.rs`.

## Tested combinations (CI)
`--all-features`, `--no-default-features`, `flow`, `af-xdp`, `monitor-lite`,
`tokio,flow,dns,http`, and `tokio,channel` (unit) + `integration-tests,tokio,channel,af-xdp`
(root-gated). See `.github/workflows/ci.yml`.
