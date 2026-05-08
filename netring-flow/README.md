# netring-flow

Pluggable flow & session tracking for packet capture. **Cross-platform,
runtime-free** — no tokio, no async runtime, no Linux-specific deps.

[![crates.io](https://img.shields.io/crates/v/netring-flow.svg)](https://crates.io/crates/netring-flow)
[![docs.rs](https://img.shields.io/docsrs/netring-flow)](https://docs.rs/netring-flow)
[![License](https://img.shields.io/crates/l/netring-flow.svg)](#license)

## What it is

- **Pluggable flow keys** via the [`FlowExtractor`] trait. Built-ins:
  `FiveTuple`, `IpPair`, `MacPair`. Decap combinators: `StripVlan`,
  `StripMpls`, `InnerVxlan`, `InnerGtpU`. Compose freely.
- **Bidirectional flow tracking** with TCP state machine, history
  string (Zeek-style `ShAdaFf`), idle timeouts, and LRU eviction.
- **TCP reassembly hook** — `Reassembler` trait + `BufferedReassembler`
  for in-process buffering, or plug `protolens` / your own.
- **Per-flow user state** generic over a type `S` (defaults to `()`).

## What it isn't

- Not a packet capture library. Pair with [`netring`](https://crates.io/crates/netring)
  (Linux AF_PACKET / AF_XDP), [`pcap`](https://crates.io/crates/pcap),
  [`pcap-file`](https://crates.io/crates/pcap-file), `tun-tap`, or any
  source of `&[u8]` frames.
- Not a TCP reassembly engine. Provides the integration points;
  pluggable backends (e.g. [`protolens`](https://crates.io/crates/protolens)).
- Not a NetFlow/IPFIX collector. See the
  [netgauze](https://crates.io/crates/netgauze-flow-pkt) family for that.

## Quick start (sync, pcap)

```rust,no_run
use netring_flow::{FlowEvent, FlowTracker, PacketView, Timestamp};
use netring_flow::extract::FiveTuple;
use pcap_file::pcap::PcapReader;
use std::fs::File;

let mut reader = PcapReader::new(File::open("trace.pcap").unwrap()).unwrap();
let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());

while let Some(pkt) = reader.next_packet() {
    let pkt = pkt.unwrap();
    let ts = Timestamp::new(
        pkt.timestamp.as_secs() as u32,
        pkt.timestamp.subsec_nanos(),
    );
    let view = PacketView::new(&pkt.data, ts);
    for evt in tracker.track(view) {
        if let FlowEvent::Started { key, .. } = evt {
            println!("{} <-> {}", key.a, key.b);
        }
    }
}
```

## Async usage

For tokio + AF_PACKET, see [`netring`'s `AsyncCapture::flow_stream`](https://docs.rs/netring/latest/netring/struct.FlowStream.html).
The headline API:

```rust,ignore
let mut events = cap.flow_stream(FiveTuple::bidirectional());
while let Some(evt) = events.next().await { /* ... */ }
```

## Features

| Feature | Pulls | Adds |
|---------|-------|------|
| `extractors` (default) | `etherparse` | Built-in 5-tuple, IpPair, MacPair, decap combinators |
| `tracker` (default) | `ahash`, `smallvec`, `arrayvec`, `lru` | `FlowTracker<E, S>` with TCP state machine + LRU |
| `reassembler` (default) | (none — pure std) | `Reassembler` trait + `BufferedReassembler` + `FlowDriver` |

Disable defaults to get only the bare types (`Timestamp`,
`PacketView`, `Extracted`, the `FlowExtractor` trait) — useful for
embedded contexts where you want to implement everything yourself.

## See also

- Full guide: [`docs/FLOW_GUIDE.md`](docs/FLOW_GUIDE.md) — extractor
  cookbook, custom keys, encap composition, reassembly patterns.
- [`netring`](https://crates.io/crates/netring) — Linux capture/inject
  pair crate.
- [`plans/`](https://github.com/p13marc/netring/tree/master/plans)
  in the repository — design docs and per-phase implementation plans.

## License

Dual MIT / Apache-2.0 (your choice).
