# netring-flow — flow & session tracking guide

A user-facing cookbook for the `netring-flow` crate. Pair with
`netring` for Linux AF_PACKET capture, or use standalone with
`pcap-file`, `tun-tap`, replay buffers, or any source of `&[u8]`
frames.

The guide is organized as recipes: each section is a self-contained
problem + working code. Skip ahead to whichever recipe matches your
need.

---

## 1. Quick start (async, with `netring`)

The headline pattern when capturing on Linux:

```rust,ignore
use futures::StreamExt;
use netring::AsyncCapture;
use netring::flow::extract::FiveTuple;
use netring::flow::FlowEvent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cap = AsyncCapture::open("eth0")?;
    let mut stream = cap.flow_stream(FiveTuple::bidirectional());
    while let Some(evt) = stream.next().await {
        match evt? {
            FlowEvent::Started { key, l4, .. } => {
                println!("+ {l4:?} {a} <-> {b}", l4 = l4, a = key.a, b = key.b);
            }
            FlowEvent::Ended { key, stats, history, .. } => {
                let total = stats.packets_initiator + stats.packets_responder;
                println!("- {a} <-> {b}  pkts={total}  history={history}",
                    a = key.a, b = key.b);
            }
            _ => {}
        }
    }
    Ok(())
}
```

Build with `--features tokio,flow`. See `examples/async_flow_summary.rs`.

---

## 2. Quick start (sync, with pcap)

Same flow tracking, no tokio, no Linux. Reads packets from a file:

```rust,ignore
use netring_flow::{FlowEvent, FlowTracker, PacketView, Timestamp};
use netring_flow::extract::FiveTuple;
use pcap_file::pcap::PcapReader;
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = PcapReader::new(File::open("trace.pcap")?)?;
    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());

    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt?;
        let ts = Timestamp::new(
            pkt.timestamp.as_secs() as u32,
            pkt.timestamp.subsec_nanos(),
        );
        let view = PacketView::new(&pkt.data, ts);
        for evt in tracker.track(view) {
            if let FlowEvent::Ended { key, stats, .. } = evt {
                println!("{} <-> {}: {} pkts",
                    key.a, key.b,
                    stats.packets_initiator + stats.packets_responder);
            }
        }
    }
    Ok(())
}
```

The same `tracker.track(view)` works for any source of frames — use
it from `tun-tap`, `pcap` (libpcap binding), test fixtures, embedded
buffers. See `examples/pcap_flow_summary.rs`.

---

## 3. Built-in extractors

| Extractor | Key | Use it for |
|-----------|-----|------------|
| `FiveTuple` | `proto + (src_ip:port, dst_ip:port)` | Standard TCP/UDP flows. **Bidirectional by default.** |
| `IpPair` | IP address pair (no ports) | ICMP, fragmented IP, host-level conversations. |
| `MacPair` | L2 MAC pair | ARP, BPDU, LLDP, link-local traffic. |

```rust,ignore
use netring_flow::extract::{FiveTuple, IpPair, MacPair};

let _ = FiveTuple::bidirectional();   // A→B and B→A merged (default)
let _ = FiveTuple::directional();     // A→B and B→A separate
let _ = IpPair;                       // proto-agnostic
let _ = MacPair;                      // L2-only
```

**Direction handling**: in `bidirectional()` mode, the canonical key
sorts endpoints so `(a, b)` is always `(lower, higher)`. The
`Extracted` returned reports `Orientation::Forward` (key matches
natural src→dst) or `Orientation::Reverse` (extractor swapped). The
tracker then translates this into [`FlowSide::Initiator`] /
[`FlowSide::Responder`] based on the *first* orientation seen.

---

## 4. Encapsulation: VLAN, MPLS, VXLAN, GTP-U

Wrap any extractor in a decap combinator. Combinators compose
freely:

```rust,ignore
use netring_flow::extract::{FiveTuple, StripVlan, StripMpls, InnerVxlan, InnerGtpU};

// VLAN-tagged → 5-tuple (VLAN handled automatically by etherparse)
let e = StripVlan(FiveTuple::bidirectional());

// MPLS-encapsulated IPv4 → 5-tuple of inner
let e = StripMpls(FiveTuple::bidirectional());

// VXLAN (default UDP/4789) → inner Ethernet → 5-tuple
let e = InnerVxlan::new(FiveTuple::bidirectional());

// VXLAN on a non-default port
let e = InnerVxlan::with_port(FiveTuple::bidirectional(), 8472);

// GTP-U (default UDP/2152) → inner IP → 5-tuple
let e = InnerGtpU::new(FiveTuple::bidirectional());

// Composed: strip VLAN, then peel VXLAN, then 5-tuple inner
let e = StripVlan(InnerVxlan::new(FiveTuple::bidirectional()));
```

If a frame doesn't match the expected encapsulation (wrong port, no
VXLAN header, etc.), `extract` returns `None` and the tracker skips
it (counted in `tracker.stats().packets_unmatched`).

---

## 5. Custom extractors

Implement `FlowExtractor` for any logic you want. Three worked
examples below.

### 5.1 Server-side flow id (5-tuple ignoring source port)

```rust,ignore
use std::net::SocketAddr;
use netring_flow::{Extracted, FlowExtractor, L4Proto, Orientation, PacketView};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct ServerFlowKey {
    proto: L4Proto,
    server: SocketAddr,
    client: std::net::IpAddr, // client port omitted intentionally
}

struct ServerFlow;

impl FlowExtractor for ServerFlow {
    type Key = ServerFlowKey;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<ServerFlowKey>> {
        let parsed = SlicedPacket::from_ethernet(view.frame).ok()?;
        let net = parsed.net?;
        let (src_ip, dst_ip) = match net {
            NetSlice::Ipv4(v4) => (
                std::net::IpAddr::V4(v4.header().source_addr()),
                std::net::IpAddr::V4(v4.header().destination_addr()),
            ),
            NetSlice::Ipv6(v6) => (
                std::net::IpAddr::V6(v6.header().source_addr()),
                std::net::IpAddr::V6(v6.header().destination_addr()),
            ),
        };
        let (sport, dport, proto) = match parsed.transport? {
            TransportSlice::Tcp(t) => (t.source_port(), t.destination_port(), L4Proto::Tcp),
            TransportSlice::Udp(u) => (u.source_port(), u.destination_port(), L4Proto::Udp),
            _ => return None,
        };
        // The "server" is the lower port — stable.
        let (server, client_ip, orientation) = if sport < dport {
            (SocketAddr::new(src_ip, sport), dst_ip, Orientation::Reverse)
        } else {
            (SocketAddr::new(dst_ip, dport), src_ip, Orientation::Forward)
        };
        Some(Extracted {
            key: ServerFlowKey { proto, server, client: client_ip },
            orientation,
            l4: Some(proto),
            tcp: None,
        })
    }
}
```

### 5.2 App-level cookie inside UDP payload

```rust,ignore
use netring_flow::{Extracted, FlowExtractor, L4Proto, Orientation, PacketView};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct CookieFlow(u32);

struct CookieExtractor;

impl FlowExtractor for CookieExtractor {
    type Key = CookieFlow;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<CookieFlow>> {
        let parsed = etherparse::SlicedPacket::from_ethernet(view.frame).ok()?;
        let udp = match parsed.transport? {
            etherparse::TransportSlice::Udp(u) => u,
            _ => return None,
        };
        if udp.destination_port() != 9999 && udp.source_port() != 9999 {
            return None;
        }
        let payload = udp.payload();
        if payload.len() < 4 { return None; }
        let cookie = u32::from_be_bytes(payload[..4].try_into().unwrap());
        let orientation = if udp.destination_port() == 9999 {
            Orientation::Forward
        } else {
            Orientation::Reverse
        };
        Some(Extracted {
            key: CookieFlow(cookie),
            orientation,
            l4: Some(L4Proto::Udp),
            tcp: None,
        })
    }
}
```

### 5.3 DNS query name as flow key

```rust,ignore
// Sketch — pulls in a DNS parser of your choice.
struct DnsQueryFlow;

impl FlowExtractor for DnsQueryFlow {
    type Key = String;
    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<String>> {
        // ... parse DNS, extract first qname ...
        // Return Extracted { key: qname, ... } or None.
        unimplemented!()
    }
}
```

### What about TCP info?

If your custom extractor parses TCP and you want the tracker to
emit `Established` / `StateChange` / FIN-driven `Ended` events, fill
the `tcp: Some(TcpInfo { ... })` field. Built-in extractors do this
automatically.

If you don't fill `tcp`, the tracker still tracks the flow, but
TCP-specific events don't fire — the flow stays in `FlowState::Active`
until idle/eviction.

---

## 6. Per-flow user state

Attach domain state to each flow using the `S` generic. The tracker
calls your initializer once per new flow.

### Sync

```rust,ignore
use netring_flow::{FlowTracker, FlowEntry};
use netring_flow::extract::FiveTuple;

#[derive(Default)]
struct FlowMetrics {
    http_requests: u32,
    last_user_agent: Option<String>,
}

let mut tracker = FlowTracker::<FiveTuple, FlowMetrics>::with_state(
    FiveTuple::bidirectional(),
    |_key| FlowMetrics::default(),
);

// ... drive tracker ...

// Inspect a flow's state:
if let Some(entry): Option<&FlowEntry<FlowMetrics>> = tracker.get(&some_key) {
    println!("{} HTTP requests", entry.user.http_requests);
}
```

### Async (with FlowStream)

```rust,ignore
let mut stream = cap
    .flow_stream(FiveTuple::bidirectional())
    .with_state(|_key| FlowMetrics::default());

// Mid-stream, poke the tracker via FlowStream::tracker_mut():
if let Some(entry) = stream.tracker_mut().get_mut(&some_key) {
    entry.user.http_requests += 1;
}
```

`S` must be `Send + 'static`. The init closure must be
`FnMut(&K) -> S + Send + 'static`.

---

## 7. TCP state events and the history string

The tracker runs a TCP state machine when the extractor supplies
`TcpInfo`:

```
Active ──SYN─→ SynSent ──SYN+ACK─→ SynReceived ──ACK─→ Established
                                                          │
                                       FIN ──────────────┘
                                       ↓
                                   FinWait ──FIN─→ ClosingTcp ──ACK─→ Closed
                                       │
                                       └─RST─→ Reset
```

Lifecycle events: `Started` → `Established` → `Ended`. Non-Established
TCP transitions (e.g. `Established → FinWait`) emit `StateChange`.

The `history` field on `Ended` is a Zeek-style compact string:

| Char | Meaning | Side |
|------|---------|------|
| `S` | SYN | Initiator (uppercase) |
| `s` | SYN-ACK | Responder |
| `D` | Data with payload | Initiator |
| `d` | Data with payload | Responder |
| `F` | FIN | Initiator |
| `f` | FIN | Responder |
| `R` | RST | Initiator |
| `r` | RST | Responder |

A typical HTTP exchange looks like `SsDdFf`. The string is capped at
16 characters (longer histories truncate silently).

```rust,ignore
match evt {
    FlowEvent::Ended { key, history, .. } if history.contains('R') => {
        println!("RST in flow {} <-> {}", key.a, key.b);
    }
    _ => {}
}
```

---

## 8. Reassembly

The tracker doesn't ship a full TCP reassembler — it provides hooks
that you wire up to the reassembler of your choice. Two surfaces
depending on your runtime story.

### 8.1 Sync — `FlowDriver` + `Reassembler` trait

`FlowDriver<E, F, S>` bundles a `FlowTracker` with a
`ReassemblerFactory`. It manages per-(flow, side) reassembler
instances and cleans them up on `Ended`.

```rust,ignore
use netring_flow::{FlowDriver, FlowEvent, PacketView, Timestamp};
use netring_flow::extract::FiveTuple;
use netring_flow::{BufferedReassembler, BufferedReassemblerFactory};

let mut driver = FlowDriver::<_, _>::new(
    FiveTuple::bidirectional(),
    BufferedReassemblerFactory,
);

for view in some_packet_source {
    for evt in driver.track(view) {
        // FlowEvents fire as usual; reassembled byte streams accumulate
        // inside each BufferedReassembler.
    }
}
```

To drain bytes, write your own factory that hands you a handle (e.g.
an `Arc<Mutex<Vec<u8>>>`):

```rust,ignore
use std::sync::{Arc, Mutex};
use netring_flow::{Reassembler, ReassemblerFactory, FlowSide};

struct MyReassembler { sink: Arc<Mutex<Vec<u8>>> }
impl Reassembler for MyReassembler {
    fn segment(&mut self, _seq: u32, payload: &[u8]) {
        self.sink.lock().unwrap().extend_from_slice(payload);
    }
}

struct MyFactory { sinks: Vec<Arc<Mutex<Vec<u8>>>> }
impl<K> ReassemblerFactory<K> for MyFactory {
    type Reassembler = MyReassembler;
    fn new_reassembler(&mut self, _key: &K, _side: FlowSide) -> MyReassembler {
        let sink = Arc::new(Mutex::new(Vec::new()));
        self.sinks.push(sink.clone());
        MyReassembler { sink }
    }
}
```

### 8.2 Async — `AsyncReassembler` + `channel_factory` (recommended for tokio)

The async path provides **end-to-end backpressure**: a slow consumer
holds up `FlowStream::poll_next`, which holds up the kernel ring,
which causes the kernel to drop. No internal unbounded buffering.

The headline pattern: spawn a task per (flow, side), feed bytes via
mpsc with a bounded channel:

```rust,ignore
use bytes::Bytes;
use tokio::sync::mpsc;
use netring::flow::{channel_factory, FlowEvent};
use netring::flow::extract::{FiveTuple, FiveTupleKey};

let mut stream = cap
    .flow_stream(FiveTuple::bidirectional())
    .with_async_reassembler(channel_factory(|_key: &FiveTupleKey, _side| {
        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                // Process bytes asynchronously — could feed a parser,
                // write to disk, push downstream, etc.
                process_chunk(bytes).await;
            }
            // Channel closed (FIN/RST) — clean up.
        });
        tx
    }));

while let Some(evt) = stream.next().await {
    // FlowEvents fire as usual; bytes are routed to the spawned tasks.
}
```

The closure is called per (flow, side) — typically twice per TCP
session (Initiator + Responder).

### 8.3 Custom `AsyncReassembler` for stateful processing

For state that you want kept in the reassembler (not in a spawned
task), implement the trait directly. The `segment` future is
`'static`, so clone or move state in:

```rust,ignore
use std::sync::Arc;
use bytes::Bytes;
use tokio::sync::Mutex;
use netring::flow::{AsyncReassembler, AsyncReassemblerFactory};
use netring_flow::FlowSide;

struct LineParser { buffer: Arc<Mutex<Vec<u8>>> }

impl AsyncReassembler for LineParser {
    fn segment(&mut self, _seq: u32, payload: Bytes)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>
    {
        let buf = self.buffer.clone();
        Box::pin(async move {
            let mut buf = buf.lock().await;
            buf.extend_from_slice(&payload);
            while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..=pos).collect();
                println!("line: {}", String::from_utf8_lossy(&line));
            }
        })
    }
}
```

---

## 9. Backpressure

```
[kernel ring] ←── back-pressure ── [FlowStream] ←── back-pressure ── [reassembler] ←── back-pressure ── [your consumer]
```

The chain works because:

1. `FlowStream::poll_next` only pulls a batch from the kernel ring
   when the consumer polls.
2. With an `AsyncReassembler` attached, `poll_next` awaits the
   reassembler's `segment` future inline before yielding the next
   event.
3. With `channel_factory(|...| mpsc::channel(64))`, a slow consumer
   fills the channel; `tx.send().await` blocks; the stream stops
   making progress; the kernel ring fills; AF_PACKET drops at the
   kernel.

You see the dropped count via `cap.statistics()` (in `netring`) — a
healthy signal that your pipeline is overloaded rather than
silently building up memory.

To avoid drops, increase the mpsc buffer (`mpsc::channel(N)`),
parallelize the consumer (one task per flow as in the headline
example), or capture less aggressively.

---

## 10. Idle timeouts and eviction

`FlowTrackerConfig` controls flow lifetime:

```rust,ignore
use std::time::Duration;
use netring_flow::FlowTrackerConfig;

let config = FlowTrackerConfig {
    idle_timeout_tcp: Duration::from_secs(300),    // default
    idle_timeout_udp: Duration::from_secs(60),     // default
    idle_timeout_other: Duration::from_secs(30),   // default
    max_flows: 100_000,                             // default
    initial_capacity: 1024,                         // default
    sweep_interval: Duration::from_secs(1),         // default (async only)
};
```

Defaults follow Suricata's normal-mode values.

- **Idle timeout**: a flow that hasn't seen a packet in `idle_timeout_*`
  is removed and emits `Ended { reason: IdleTimeout }`.
- **Max flows + LRU**: when the table reaches `max_flows`, inserting
  a new flow evicts the least-recently-used one (emits
  `Ended { reason: Evicted }`).

Async users get auto-sweep via `tokio::time::Interval`. Sync users
call `tracker.sweep(now)` manually:

```rust,ignore
let now = Timestamp::new(/* current time */, 0);
for ev in tracker.sweep(now) {
    // typically Ended { reason: IdleTimeout, ... }
}
```

---

## 11. Performance notes

Rough numbers (untuned, x86_64, 2024 hardware):

| Operation | Cost |
|-----------|------|
| Frame parse (etherparse, IPv4-TCP) | ~50 ns |
| Flow lookup (`HashMap` with ahash, FiveTupleKey) | ~50 ns |
| Tracker `track` (lookup + state transition + 1–2 events) | ~200 ns |
| `BufferedReassembler::segment` (in-order) | ~30 ns + memcpy |
| `Bytes::copy_from_slice` (in async path, per TCP payload) | ~100 ns + alloc |

Tuning knobs:

- `max_flows` — affects HashMap capacity. 100k is a good default for
  general-purpose use; bump for high-fanout hosts (proxies, gateways).
- `initial_capacity` — pre-allocates buckets to avoid rehashes during
  warm-up. Set to `expected_steady_state_flows` if predictable.
- `sweep_interval` — defaults to 1s (async only). Short intervals
  catch idle flows sooner but cost CPU. 1s is reasonable for most.

---

## 12. Limitations

- **No TCP reassembly engine.** We provide hooks; users plug in
  `protolens`, `blatta-stream`, or their own buffer. `BufferedReassembler`
  is a simple in-order accumulator that drops out-of-order segments.
- **No L7 protocol parsing.** Use `httparse`, `protolens`, `rustls`,
  etc. as downstream parsers in your `Reassembler`.
- **No IPv6 fragment reassembly.** `etherparse` parses the first
  fragment but doesn't reassemble across fragments.
- **`Packet<'_>` is `!Send`.** When using `netring`, the flow stream
  task owns the capture; per-flow user state `S` must be `Send` if
  it crosses an `.await`.
- **History string capped at 16 chars.** Long sessions truncate
  silently. Adjust by patching `history.rs` if you need longer.
- **Hash-collision potential.** xxh3-64 collisions are rare (~1 per
  4 billion); irrelevant for typical workloads.

---

## 13. Source-agnosticism: pcap, tun-tap, embedded

`netring-flow` doesn't depend on `netring` or any specific capture
library. Anything that yields `(bytes, timestamp)` works:

```rust,ignore
// pcap-file (pure Rust)
let view = PacketView::new(&pkt.data, ts);
tracker.track(view);

// libpcap binding (`pcap` crate)
let cap = pcap::Capture::from_device("eth0")?.open()?;
while let Ok(pkt) = cap.next_packet() {
    let view = PacketView::new(pkt.data, ts_from_pcap_timeval(&pkt.header.ts));
    tracker.track(view);
}

// tun-tap (raw L3 frames — wrap with synthetic Ethernet)
let mut buf = vec![0u8; 1500];
let n = tun.read(&mut buf)?;
let synth = synthesize_eth(&buf[..n], 0x0800);
let view = PacketView::new(&synth, Timestamp::default());
tracker.track(view);

// Test fixture
let view = PacketView::new(SYNTHETIC_FRAME, Timestamp::default());
tracker.track(view);
```

For embedded / no-runtime contexts, disable defaults:

```toml
[dependencies]
netring-flow = { version = "0.1", default-features = false, features = ["extractors", "tracker"] }
```

This drops `arrayvec`, `lru`, `smallvec`, and `ahash` — though `tracker`
needs them, so the disable here is for users who only need the
extractor types and roll their own table.

---

## 14. Bridging to `protolens`

[`protolens`](https://crates.io/crates/protolens) is a high-perf TCP
reassembly + L7 parser. Its API is callback-based and not naturally
async, but it bridges cleanly behind our `AsyncReassembler` trait.

Sketch (untested — adjust to current `protolens` API):

```rust,ignore
use std::sync::{Arc, Mutex};
use bytes::Bytes;
use netring::flow::{AsyncReassembler, AsyncReassemblerFactory};
use netring_flow::FlowSide;

struct ProtolensReassembler {
    task: Arc<Mutex<protolens::Task<MyPacket>>>,
    seq: u32,
}

impl AsyncReassembler for ProtolensReassembler {
    fn segment(&mut self, seq: u32, payload: Bytes)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>
    {
        let task = self.task.clone();
        Box::pin(async move {
            let pkt = MyPacket::new(seq, payload); // your Packet impl
            let _ = task.lock().unwrap().run(pkt);
        })
    }
}
```

Pair this with `channel_factory`-style spawning if you want the
parser to run on a dedicated task per flow. See `examples/async_flow_channel.rs`
for the spawn pattern.

---

## See also

- Crate docs: <https://docs.rs/netring-flow>
- Sister crate: [`netring`](https://crates.io/crates/netring) — Linux
  AF_PACKET / AF_XDP capture and inject.
- Design docs in the repository: `plans/flow-session-tracking-design.md`
- Per-phase implementation plans: `plans/00-workspace-split.md`
  through `plans/04-flow-release.md`.
- Sources surveyed during the design: gopacket `tcpassembly`, Suricata
  flow manager, Zeek conn.log, Wireshark conversation tracking,
  Linux BPF flow_dissector, DPDK SFT, ntop PF_RING FT, go-flows.
  Full list in `flow-session-tracking-design.md` (Sources consulted
  section).
