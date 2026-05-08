# netring-flow-pcap

Pcap source adapter for [`netring-flow`](https://crates.io/crates/netring-flow).

[![crates.io](https://img.shields.io/crates/v/netring-flow-pcap.svg)](https://crates.io/crates/netring-flow-pcap)
[![docs.rs](https://img.shields.io/docsrs/netring-flow-pcap)](https://docs.rs/netring-flow-pcap)
[![License](https://img.shields.io/crates/l/netring-flow-pcap.svg)](#license)

## What it is

A thin wrapper around [`pcap-file`](https://crates.io/crates/pcap-file)
that turns a pcap file into a stream of [`netring-flow`](https://crates.io/crates/netring-flow)
[`PacketView`]s — or, with one more line, a stream of `FlowEvent`s.

Removes ~10 lines of boilerplate from every program that does flow
tracking on a pcap file.

## Quick start

```rust,no_run
use netring_flow_pcap::PcapFlowSource;
use netring_flow::extract::FiveTuple;
use netring_flow::FlowEvent;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
for evt in PcapFlowSource::open("trace.pcap")?.with_extractor(FiveTuple::bidirectional()) {
    match evt? {
        FlowEvent::Started { key, .. } => println!("+ {} <-> {}", key.a, key.b),
        FlowEvent::Ended { key, history, .. } => println!("- {} <-> {}  hist={history}", key.a, key.b),
        _ => {}
    }
}
# Ok(()) }
```

## Lower-level usage

If you want explicit control of the tracker config / per-flow state:

```rust,no_run
use netring_flow_pcap::PcapFlowSource;
use netring_flow::{FlowTracker, FlowTrackerConfig};
use netring_flow::extract::FiveTuple;
use std::time::Duration;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut tracker = FlowTracker::<FiveTuple>::with_config(
    FiveTuple::bidirectional(),
    FlowTrackerConfig {
        idle_timeout_tcp: Duration::from_secs(60),
        ..Default::default()
    },
);

for view in PcapFlowSource::open("trace.pcap")?.views() {
    let view = view?;
    for _evt in tracker.track(view.as_view()) {
        // process
    }
}
# Ok(()) }
```

## When to use which crate

| You want… | Use |
|-----------|-----|
| Live AF_PACKET capture on Linux + flow events | [`netring`](https://crates.io/crates/netring) `flow_stream` |
| Pcap input + flow events, cross-platform | **`netring-flow-pcap`** (this crate) |
| Live capture via libpcap (any platform) | [`pcap`](https://crates.io/crates/pcap) + manual `netring-flow` adapter |
| Just the flow tracking primitives | [`netring-flow`](https://crates.io/crates/netring-flow) directly |

## Limitations

- One `Vec<u8>` allocation per packet (the underlying `pcap-file`
  reader reuses its internal buffer; we copy out). Fine for offline
  analysis; not appropriate for sustained 1+ Gbps live replay.
- pcapng support depends on what `pcap-file` 2.x exposes; standard
  pcap works out of the box.

## License

Dual MIT / Apache-2.0 (your choice).
