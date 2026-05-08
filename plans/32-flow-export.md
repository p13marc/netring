# Plan 32 — `netring-flow-export` (NetFlow / IPFIX export)

## Summary

Export `FlowEvent::Ended` records as NetFlow v9 / IPFIX template-based
flow records to a configurable collector (UDP or TCP). Bridges the
gap between netring-flow's tracker and the standard observability
pipeline that NetFlow collectors (nProbe, ntopng, Splunk Stream,
Kentik, etc.) consume.

## Status

Not started.

## Prerequisites

- Plans 00–04 published.
- `netring-flow` 0.1.x with `FlowTracker::stats()` exposing the
  fields we want to export.

## Out of scope

- IPFIX collector functionality (receiving). `netgauze-flow-service`
  already does that; we're the **exporter** side.
- sFlow export (different shape; would be a separate crate).
- Live re-exporters that take captured NetFlow and re-emit it.

---

## Why this crate

NetFlow / IPFIX are the de-facto standards for flow telemetry in
enterprise / ISP / cloud environments. Tools like ntopng, Kentik,
Plixer Scrutinizer, Splunk, ELK with the NetFlow plugin all expect
v9 / IPFIX records. Exposing our flow events as IPFIX makes
netring-flow plug-and-play with that ecosystem.

`netgauze-flow-pkt` already provides serialization for IPFIX
packet types. We integrate with their type system rather than
roll our own.

---

## Files

### NEW

```
netring-flow-export/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── template.rs        # IPFIX template definition for our records
│   ├── builder.rs         # Build IPFIX DataRecord from FlowStats
│   ├── exporter.rs        # IpfixExporter (sends UDP/TCP)
│   └── netflow_v9.rs      # Optional v9 mode (less rich than IPFIX)
└── examples/
    └── ipfix_collector.rs # Live capture → IPFIX → UDP/9995
```

---

## API

```rust
use netring_flow::{FlowEvent, FlowStats};

pub struct IpfixExporter {
    /// Target collector address.
    pub target: SocketAddr,
    /// UDP or TCP.
    pub transport: ExportTransport,
    /// Observation domain ID.
    pub domain_id: u32,
    /// How often to (re)transmit templates. Default: every 60s.
    pub template_refresh: Duration,
    /// Max records per data set. Default: 100.
    pub batch_size: usize,
    socket: ExportSocket,
    template_last_sent: Instant,
    sequence: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum ExportTransport { Udp, Tcp }

impl IpfixExporter {
    /// Construct, bind/connect to collector.
    pub async fn connect(target: SocketAddr, transport: ExportTransport)
        -> Result<Self, Error>;

    /// Export a single ended flow.
    pub async fn export(&mut self, key: &impl IntoFlowKey, stats: &FlowStats, history: &str)
        -> Result<(), Error>;

    /// Export a batch.
    pub async fn export_batch(&mut self, ...);

    /// Send template now (out-of-band).
    pub async fn send_template(&mut self) -> Result<(), Error>;
}

/// Convert any flow key to IPFIX-shaped tuple. Implement for your
/// custom key, or use the built-in for FiveTupleKey.
pub trait IntoFlowKey {
    fn source_address(&self) -> Option<IpAddr>;
    fn destination_address(&self) -> Option<IpAddr>;
    fn source_port(&self) -> Option<u16>;
    fn destination_port(&self) -> Option<u16>;
    fn protocol(&self) -> Option<u8>;
}

// Built-in for FiveTupleKey:
impl IntoFlowKey for netring_flow::extract::FiveTupleKey { ... }
```

---

## IPFIX template

Standard set of Information Elements (IEs) we export:

| IE ID | Name | Source from `FlowStats` |
|-------|------|--------------------------|
| 7 | sourceTransportPort | key.a.port() |
| 8 | sourceIPv4Address | key.a.ip() if v4 |
| 11 | destinationTransportPort | key.b.port() |
| 12 | destinationIPv4Address | key.b.ip() if v4 |
| 4 | protocolIdentifier | key.proto |
| 1 | octetDeltaCount (forward) | bytes_initiator |
| 2 | packetDeltaCount (forward) | packets_initiator |
| 23 | postOctetDeltaCount (reverse) | bytes_responder |
| 24 | postPacketDeltaCount (reverse) | packets_responder |
| 152 | flowStartMilliseconds | started |
| 153 | flowEndMilliseconds | last_seen |

Plus IPv6 variants (IE 27, 28). Define one template per IP family
per direction-mode; users can pick.

---

## Cargo.toml

```toml
[package]
name = "netring-flow-export"
version = "0.1.0"
description = "NetFlow v9 / IPFIX exporter for netring-flow"
keywords = ["netflow", "ipfix", "netring", "flow"]
categories = ["network-programming"]

[dependencies]
netring-flow = { version = "0.1", path = "../netring-flow", default-features = false, features = ["tracker"] }
netgauze-flow-pkt = "0.7"
tokio = { workspace = true, features = ["net", "rt"] }
bytes = { workspace = true }
thiserror = { workspace = true }
```

---

## Implementation steps

1. **Investigate `netgauze-flow-pkt`** — confirm it serializes
   IPFIX records (not just parses them). If only parses, we'll
   write our own minimal serializer or use `nom-derive` + `cookie-factory`.
2. **Define the template structure.**
3. **Build the encoder** that takes `FlowStats` + `IntoFlowKey` and
   produces an IPFIX DataRecord byte slice.
4. **Build the exporter** with batch + template-refresh logic.
5. **UDP transport** — straightforward `tokio::net::UdpSocket::send_to`.
6. **TCP transport** — connect, write IPFIX messages framed by their
   length header.
7. **Pluggable extractor** for non-FiveTuple keys via `IntoFlowKey`.
8. **Example** — wire to a `flow_stream` and export every Ended event.
9. **Test against a real collector** — point at `nfcapd` or `ntopng`,
   verify decoded.

---

## Cargo example wiring

```rust
let cap = AsyncCapture::open("eth0")?;
let mut exporter = IpfixExporter::connect(
    "127.0.0.1:9995".parse()?,
    ExportTransport::Udp,
).await?;

let mut stream = cap.flow_stream(FiveTuple::bidirectional());
while let Some(evt) = stream.next().await {
    match evt? {
        FlowEvent::Ended { key, stats, history, .. } => {
            exporter.export(&key, &stats, &history).await?;
        }
        _ => {}
    }
}
```

---

## Risks

1. **`netgauze-flow-pkt` API stability.** Pre-1.0; pin a minor
   version. If serialization is missing, we ship a minimal IPFIX
   serializer (~300 LOC).
2. **Template refresh.** UDP is unreliable; if a template packet
   drops, the collector can't decode subsequent data records until
   the next refresh. Default refresh of 60s mirrors industry norms.
3. **Time precision.** IPFIX `flowStartMilliseconds` is ms precision.
   Our `Timestamp` is ns. We round.
4. **Custom key types.** Users with non-5-tuple keys (cookies, MAC)
   need to implement `IntoFlowKey` themselves or skip those fields.
5. **Throughput.** UDP send per ended flow is fine for typical
   loads (1k flows/sec). At 100k flows/sec we'd want to batch
   multiple records into one IPFIX packet — already in the design
   (batch_size).
6. **TCP backpressure.** TCP send blocks if the collector is slow;
   our `export().await` propagates pressure. Document.

---

## Tests

- `template_record_round_trips` — encode + decode via netgauze.
- `udp_export_to_loopback` — send to `127.0.0.1:0`, verify bytes
  arrive.
- `tcp_export_framing` — send 3 records, verify wire format.

---

## Acceptance criteria

- [ ] Crate builds.
- [ ] Round-trip test against a synthetic FlowStats.
- [ ] Live capture → UDP IPFIX example works (verify with `tcpdump
      -X port 9995`).
- [ ] Decoded by `nfcapd` or `wireshark`'s NetFlow dissector.

## Effort

- LOC: ~700.
- Time: 2 days.

## What this unlocks

- Direct integration with the enterprise observability stack —
  netring-flow becomes a drop-in replacement for `nProbe` /
  `softflowd` in many deployments.
- Validates the `IntoFlowKey` abstraction for custom keys (used
  again later for sFlow export, log adapters, etc.).
