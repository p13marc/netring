# Flow & session tracking — design proposal

> **Status**: design report for review. No code shipped yet.
>
> **Audience**: maintainer (you). Mark each section in Part 7 (Decision
> matrix) with **approve** / **change X** / **defer** and I'll execute.
>
> **Scope**: this document supersedes Part 2 of
> [`high-level-features-design.md`](./high-level-features-design.md).
> Loopback dedup remains in that doc; flow & session tracking is here.
>
> **License to break BC.** This revision uses the maintainer's
> permission to break backward compatibility. Where my earlier sketch
> bolted things on additively, this design takes the cleaner shape.

netring captures and injects packets. Once you have a packet stream,
the next 80% of analysis tools want to think in **flows** (5-tuple) and
**sessions** (a flow with state — TCP handshake, FIN, etc.) and
sometimes go further into **protocol parsing** (HTTP requests, TLS
SNI). This document proposes an API spanning all three, structured so
that each layer is useful on its own and the layers compose.

The user's explicit constraint: **let the crate user provide their own
extractor**. The flow-key shape and what counts as a flow are not
hard-coded — netring ships sensible defaults, and users can plug in
custom logic.

The user's standing constraint: **async-first, rust-idiomatic**.

---

## Part 1 — Goals

1. **Pluggable flow keys.** A user must be able to define what a flow
   *is* in their domain. 5-tuple is the default; VXLAN inner, GTP-U
   inner, MAC pair, app-level cookie, custom — all expressible without
   forking netring.
2. **Bidirectional sessions.** A→B and B→A map to one logical flow
   when the user wants that (default), separate when they don't.
3. **TCP lifecycle, built in.** Track SYN / SYN-ACK / ESTABLISHED /
   FIN / RST natively, emit events users can react to. Don't ship a
   full TCP reassembler — but make it trivial to wire one in.
4. **Per-flow user state.** Users can attach custom state to each flow
   (counters, parsers, anything) without netring caring what it is.
5. **Async-first.** `AsyncCapture::flow_stream(...)` is the one-liner;
   the underlying `FlowTracker` is available for users who need
   control of the loop.
6. **Cheap when unused.** Nothing in this module is in the hot path
   unless the user asks for it. Built behind a `flow` feature flag.
7. **Source-agnostic.** Flow tracking shouldn't be tied to AF_PACKET.
   Users feeding pcap, tun-tap, replay tests, or any `&[u8]` should
   be able to use the same tracker. Achieved by splitting out a
   separate `netring-flow` crate (Part 5).

Non-goals for v1:

- Full TCP reassembly (out-of-order buffer + segment reorder). We
  expose a hook; users wire `protolens` / `blatta-stream` / their own.
- L7 protocol parsing (HTTP, TLS handshake, SMTP, …). The ecosystem
  already has `protolens`, `httparse`, `rustls`, etc.
- IPFIX/NetFlow export — `netgauze` already serves the collector side.
- Hardware offload — netring is AF_PACKET / AF_XDP; HW offload belongs
  in the kernel-bypass layer below.

---

## Part 2 — Prior-art survey

Twelve libraries / kernel facilities surveyed. Findings drive the
design choices in Part 3.

### Rust ecosystem

| Crate | Position | Notes |
|-------|----------|-------|
| **`protolens`** | Tracker + reassembler + L7 parser | Callback-only API. Single-threaded per instance. User implements a `Packet` trait with 10 methods (`sip`, `dip`, `seq`, `syn`, `fin`, `payload`, …). Doesn't compose with `Stream`. Powerful but the API style fights tokio. |
| **`rs-flow_reassembler`** | Reassembler | Plain TCP reassembly. Small surface. GPL-3.0 — can't depend on it. |
| **`blatta-stream`** | Reassembler | Reassembly only, smaller scope. |
| **`netgauze-flow-pkt` / `-flow-service`** | NetFlow/IPFIX collector | Different problem — receives flow records. |
| **`fluereflow` / `Fluere`** | Tracker + feature exporter | Full pcap → NetFlow, CICFlowMeter-style. CLI tool more than library. |
| **`RustiFlow`** | eBPF-based tracker + features | 5 built-in feature sets. User extends via `custom_flow.rs`. Trait-based. |
| **`smoltcp`** | Full TCP/IP stack | Different role — implementing TCP, not observing it. |

### Go

| Library | Notes |
|---------|-------|
| **`gopacket/tcpassembly`** | Cleanest separation we found: user implements `StreamFactory.New(key) -> Stream`, the assembler calls `Stream.Reassembled([]Reassembly)` with in-order bytes and `Stream.ReassemblyComplete()` on FIN/RST/timeout. **The model to copy for our `Reassembler`.** |
| **`gopacket/reassembly`** | Newer, adds an `AssemblerContext` (timestamp / metadata) per call. |
| **`go-flows` (CN-TU)** | Pipeline architecture: `source → filter → parse → label → key → table → flow → record → feature → export`. Pluggable via Go init hooks. Flow keys composed from named features. |

### C / C++ / kernel

| Component | Notes |
|-----------|-------|
| **Suricata `flow-hash.c`** | 5-tuple hash table, 65 536 buckets default, chained on collision. Per-protocol timeout (TCP 30s new / 300s established, compressed under memory pressure). State machine: `FLOW_STATE_NEW → ESTABLISHED → CLOSED`. **Single tracker handles flow + TCP state — no separate "session" layer.** |
| **Zeek (Bro)** | `conn.log` records with unique `uid`, history string `ShADadFf` encoding the lifecycle (capitals = originator, lowercase = responder). State labels (`SF`, `OTH`, `S0`, `RSTR`, …) cover bidirectional outcomes. **Conversation tracking is one concept, not three.** |
| **Wireshark** | Two-level mapping: top-level conversation type, second-level array of `conversation_element_t`. **Maximally extensible** — each protocol contributes its own elements. |
| **Linux `flow_dissector.c` + eBPF** | `bpf_flow_keys` struct with flag-driven dissection depth. Per-netns plug-in. **Flow-key shape fixed by ABI; parsing logic fully pluggable.** |
| **Netfilter conntrack / flowtable** | Full stateful CT. `nf_flowtable` for HW offload. |
| **DPDK SFT** | Stateful Flow Table for userspace networking. PMD ops are pluggable per vendor. |
| **VPP** | Classifier tables + n-tuple sessions. VXLAN/GTP support as decap nodes upstream of classification. |
| **PF_RING FT (ntop)** | `pfring_ft_create_table()`, callbacks on new/expire, user metadata, integrates with nDPI for L7. |

### Python

| Library | Notes |
|---------|-------|
| **scapy** | `IPSession`, `TCPSession`, per-protocol `tcp_reassemble` method. Subclass to add a custom session. |
| **pyshark** | Iterates `tshark` output; relies on Wireshark for stream tracking. |

### Cross-cutting feature matrix

|                                  | gopacket | protolens | Suricata | Zeek | Wireshark | Linux fd | go-flows | RustiFlow | nDPI/PF_RING FT |
|----------------------------------|:--------:|:---------:|:--------:|:----:|:---------:|:--------:|:--------:|:---------:|:---------------:|
| Pluggable flow key               |    ●     |     ○     |    ○     |  ○   |     ●     |    ●     |    ●     |     ●     |        ○        |
| Bidirectional default            |    ●     |     ●     |    ●     |  ●   |     ●     |    ○     |    ●     |     ●     |        ●        |
| TCP state machine (built-in)     |    ○     |     ●     |    ●     |  ●   |     ●     |    ○     |    ○     |     ●     |        ●        |
| Reassembly built-in              |    ●     |     ●     |    ●     |  ●   |     ●     |    ○     |    ○     |     ○     |        ○        |
| Per-flow user state              |    ●     |     ●     |    ●     |  ●   |     ●     |    ○     |    ●     |     ●     |        ●        |
| Encap aware (VXLAN/GTP)          |    ○     |     ○     |    ●     |  ●   |     ●     |    ●     |    ○     |     ○     |        ●        |
| Async/Stream-friendly API        |    ○     |     ○     |    ○     |  ○   |     ○     |    n/a   |    ○     |     ○     |        ○        |
| Lib (vs framework)               |    ●     |     ●     |    ○     |  ○   |     ○     |    ●     |    ○     |     ○     |        ●        |
| Permissive license               |    ●     |     ●     |    ○*    |  ●   |     ●     |    ●     |    ●     |     ●     |        ●        |

`●` = first class · `○` = absent / awkward · `*` = GPL-2

### What to copy / what to avoid

**Copy:**

- gopacket's **factory + per-direction reassembler** separation.
- Wireshark's **flow keys are protocol-specific**, not a fixed 5-tuple.
- Linux flow_dissector's **flag-driven dissection depth** style.
- Suricata's **per-protocol timeout + emergency mode**.
- Zeek's **history string** for compact lifecycle representation.
- **Suricata/Zeek's unified tracker** — flow + TCP state in one concept.

**Avoid:**

- protolens's **callback-only API** — fights `Stream`.
- protolens's **single-instance-per-thread** restriction — painful for
  tokio multi-task code.
- Suricata's **global mutable flow table** — wrong for a library.
- go-flows's **JSON-spec configuration** — types are our spec.
- CICFlowMeter's **80+ statistical features hardcoded** — let users
  build features on top of `FlowEvent`.
- My earlier sketch's **separate `SessionTracker` layer** — artificial
  split. Collapse into `FlowTracker`.

---

## Part 3 — Design

Three layers, each useful alone, each composing into the next.

```
┌───────────────────────────────────────────────────────────────┐
│ Layer 3 — Reassembler<R>      protolens / blatta / your own  │
│         (TCP byte streams per session, optional, hook only)  │
├───────────────────────────────────────────────────────────────┤
│ Layer 2 — FlowTracker<E, S>   bidirectional flow accounting │
│         + TCP state machine                                  │
│         (per-flow stats, history, lifecycle, user state S)  │
├───────────────────────────────────────────────────────────────┤
│ Layer 1 — FlowExtractor       trait the user implements      │
│         (built-ins: FiveTuple, IpPair, MacPair, decap combs) │
└───────────────────────────────────────────────────────────────┘
            ↑                                                ↑
            │ user provides                                  │ async stream
            │                                                │
       Custom extractor                                AsyncCapture
       (or built-in + combinator)                     ::flow_stream(...)
```

The earlier sketch had a separate `SessionTracker`. **It's gone.** TCP
state lives in `FlowTracker` and is always-on (cheap when no TCP
packets are seen). Suricata, Zeek, and Wireshark all do it this way.
Two layers were one too many.

---

### 3.1 — `PacketView<'a>` — what extractors see

Extractors take a `PacketView`, not `&[u8]`. The view carries the
frame plus metadata extractors might need (timestamp). Decap
combinators construct inner views without losing context.

```rust
/// What a `FlowExtractor` is given.
///
/// Constructed from a `Packet` for live captures, or built fresh for
/// synthetic / pcap-replay use. Decap combinators build new views
/// pointing into inner frames while preserving timestamp.
#[derive(Debug, Clone, Copy)]
pub struct PacketView<'a> {
    pub frame: &'a [u8],
    pub timestamp: Timestamp,
}

impl<'a> PacketView<'a> {
    /// Build from a netring captured packet.
    pub fn from_packet(p: &'a Packet<'a>) -> Self {
        Self { frame: p.data(), timestamp: p.timestamp() }
    }

    /// Replace the frame, keep timestamp. For decap combinators.
    pub fn with_frame(self, frame: &'a [u8]) -> Self {
        Self { frame, ..self }
    }
}

// Bridge from the existing API:
impl Packet<'_> {
    pub fn view(&self) -> PacketView<'_> { PacketView::from_packet(self) }
}
```

**Why a struct, not just `&[u8]`:** even simple extractors (e.g., a
custom one that timestamps the first packet of a stream) need the
timestamp. Passing `&[u8]` would force them to thread it separately.

**Why not the full `Packet`:** decap combinators can't construct a
synthetic `Packet` (it's tied to `tpacket3_hdr`). `PacketView` is the
abstract view that works for kernel frames, inner frames, and bytes
from anywhere.

---

### 3.2 — `FlowExtractor` trait

```rust
/// Extract a flow descriptor from one packet.
///
/// Implementations must be cheap and stateless — called once per
/// packet on the hot path. Most return `Some(_)`, but malformed,
/// non-IP, or out-of-scope packets return `None` and are skipped.
pub trait FlowExtractor: Send + Sync + 'static {
    /// The flow key. Equality + hashability identify the flow.
    /// The same `Key` value must be produced for both directions of
    /// a bidirectional flow if you want them merged.
    type Key: Eq + Hash + Clone + Send + Sync + 'static;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<Self::Key>>;
}

/// Result of one extraction.
#[derive(Debug, Clone)]
pub struct Extracted<K> {
    pub key: K,

    /// Orientation of THIS packet relative to the canonical form of
    /// `key`. `Forward` if natural src→dst matches the key's a→b;
    /// `Reverse` if the extractor swapped to canonicalize.
    /// (The tracker translates this into `FlowSide::Initiator`/
    /// `Responder` based on which orientation it saw first.)
    pub orientation: Orientation,

    /// L4 protocol if the extractor identified one. Drives the
    /// tracker's choice of timeout and TCP state-machine engagement.
    pub l4: Option<L4Proto>,

    /// Pre-parsed TCP info for TCP packets. If `Some`, the tracker
    /// runs TCP state-machine logic without re-parsing; if `None`,
    /// TCP-specific events (Established, history string) won't fire
    /// for this flow.
    pub tcp: Option<TcpInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Orientation { Forward, Reverse }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L4Proto { Tcp, Udp, Icmp, IcmpV6, Sctp, Other(u8) }

#[derive(Debug, Clone, Copy)]
pub struct TcpInfo {
    pub flags: TcpFlags,
    pub seq: u32,
    pub ack: u32,
    /// Offset into `view.frame` where TCP payload begins.
    pub payload_offset: usize,
    pub payload_len: usize,
}

bitflags::bitflags! {
    pub struct TcpFlags: u8 {
        const FIN = 0b0000_0001;
        const SYN = 0b0000_0010;
        const RST = 0b0000_0100;
        const PSH = 0b0000_1000;
        const ACK = 0b0001_0000;
        const URG = 0b0010_0000;
        const ECE = 0b0100_0000;
        const CWR = 0b1000_0000;
    }
}
```

**Why `tcp: Option<TcpInfo>` and not just `tcp_flags`:** the tracker
needs `seq` (TCP state machine can ignore but the reassembler can't);
the reassembler needs `payload_offset/len`. Built-in extractors fill
all four for ~zero extra cost since they parse the TCP header anyway.
Custom extractors that don't care about TCP set `None` and lose the
TCP-only events — graceful degradation.

---

### 3.3 — Built-in extractors

Module path: `netring::flow::extract`.

```rust
/// 5-tuple extractor.
pub struct FiveTuple { /* private: bidirectional flag */ }

impl FiveTuple {
    /// A→B and B→A are different flows.
    pub fn directional() -> Self;
    /// A→B and B→A merged. (Default and recommended.)
    pub fn bidirectional() -> Self;
}

impl FlowExtractor for FiveTuple {
    type Key = FiveTupleKey;
    fn extract(&self, v: PacketView<'_>) -> Option<Extracted<FiveTupleKey>> { /* … */ }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct FiveTupleKey {
    pub proto: L4Proto,
    /// In bidirectional mode: `a` is the lexicographically lower endpoint.
    pub a: SocketAddr,
    pub b: SocketAddr,
}

/// IP-pair only (proto ignored). Useful for ICMP / ICMPv6 / fragmented
/// flows where ports aren't meaningful.
pub struct IpPair;
pub struct IpPairKey { pub a: IpAddr, pub b: IpAddr }

/// MAC-pair (L2). For BPDU, LLDP, ARP, link-local traffic.
pub struct MacPair;
pub struct MacPairKey { pub a: [u8; 6], pub b: [u8; 6] }
```

#### Decapsulating combinators

Each strips one encapsulation layer and delegates to an inner
extractor. Compose freely.

```rust
pub struct StripVlan<E>(pub E);
pub struct StripMpls<E>(pub E);
pub struct InnerVxlan<E> { pub extractor: E, pub udp_port: u16 }  // default 4789
pub struct InnerGtpU<E>  { pub extractor: E, pub udp_port: u16 }  // default 2152

// Composes:
let ext = StripVlan(InnerVxlan {
    extractor: FiveTuple::bidirectional(),
    udp_port: 4789,
});
```

`InnerGre`, `FlowLabel`, etc. deferred to v0.8+ — niche, easy to add.

#### Custom extractor — full example

A user wants to track sessions by an application-level cookie present
in the first 4 bytes of every UDP/9999 datagram:

```rust
use netring::flow::{FlowExtractor, Extracted, Orientation, L4Proto, PacketView};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct AppSessionId(u32);

struct AppCookieExtractor;

impl FlowExtractor for AppCookieExtractor {
    type Key = AppSessionId;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<AppSessionId>> {
        let parsed = etherparse::SlicedPacket::from_ethernet(view.frame).ok()?;
        let udp = parsed.transport.as_ref()?.udp()?;
        if udp.destination_port() != 9999 && udp.source_port() != 9999 {
            return None;
        }
        let payload = parsed.payload.slice();
        if payload.len() < 4 { return None; }
        let cookie = u32::from_be_bytes(payload[..4].try_into().unwrap());
        let orientation = if udp.destination_port() == 9999 {
            Orientation::Forward
        } else {
            Orientation::Reverse
        };
        Some(Extracted {
            key: AppSessionId(cookie),
            orientation,
            l4: Some(L4Proto::Udp),
            tcp: None,  // not TCP — Established/Closed-on-FIN don't apply
        })
    }
}

let cap = AsyncCapture::open("eth0")?;
let mut events = cap.flow_stream(AppCookieExtractor);
while let Some(evt) = events.next().await { /* … */ }
```

---

### 3.4 — `FlowTracker<E, S>` — the lookup table + lifecycle

One type, no separate session layer. TCP state is built in.

```rust
pub struct FlowTracker<E: FlowExtractor, S = ()> {
    extractor: E,
    flows: HashMap<E::Key, FlowEntry<S>>,
    config: FlowTrackerConfig,
    stats: FlowTrackerStats,
}

#[derive(Debug, Clone)]
pub struct FlowEntry<S> {
    pub stats: FlowStats,
    pub state: FlowState,
    pub history: HistoryString,    // Zeek-style: ShADadFf
    pub user: S,
}

#[derive(Debug, Clone, Default)]
pub struct FlowStats {
    pub packets_initiator: u64,
    pub packets_responder: u64,
    pub bytes_initiator: u64,
    pub bytes_responder: u64,
    pub started: Timestamp,
    pub last_seen: Timestamp,
}

/// Unified state for any flow.
/// TCP-only states (`SynSent`, `Established`, `FinWait`, `Closed`)
/// are reachable only when TcpInfo is supplied by the extractor.
/// UDP / ICMP / unknown flows stay in `Active` until idle or evicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    SynSent, SynReceived, Established, FinWait, ClosingTcp,
    Active,        // non-TCP or pre-TCP-info
    Closed,
    Reset,
    Aborted,
}

#[derive(Debug, Clone)]
pub struct FlowTrackerConfig {
    pub idle_timeout_tcp: Duration,    // default: 5 min
    pub idle_timeout_udp: Duration,    // default: 60 s
    pub idle_timeout_other: Duration,  // default: 30 s
    pub max_flows: usize,              // default: 100_000 (~10 MiB)
    pub initial_capacity: usize,       // default: 1024
    /// Sweep interval used by the async stream adapter. The manual
    /// API (`FlowTracker::track`) doesn't sweep automatically; call
    /// `sweep` yourself when convenient.
    pub sweep_interval: Duration,      // default: 1 s
}

#[derive(Debug, Clone, Default)]
pub struct FlowTrackerStats {
    pub flows_created: u64,
    pub flows_ended: u64,
    pub flows_evicted: u64,
    pub packets_unmatched: u64,
}
```

#### API

```rust
// Always-available — works with any S.
impl<E: FlowExtractor, S: Send + 'static> FlowTracker<E, S> {
    pub fn with_config_and_state<F>(extractor: E, config: FlowTrackerConfig, init: F) -> Self
    where F: FnMut(&E::Key) -> S + Send + 'static;

    /// Process a packet. Returns events emitted by this packet.
    pub fn track_with<F>(
        &mut self,
        view: PacketView<'_>,
        init: F,
    ) -> FlowEvents<'_, E::Key>
    where F: FnOnce(&E::Key) -> S;

    /// Idle-timeout sweep. Returns flows that ended due to timeout.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>>;

    pub fn get(&self, key: &E::Key) -> Option<&FlowEntry<S>>;
    pub fn get_mut(&mut self, key: &E::Key) -> Option<&mut FlowEntry<S>>;
    pub fn flows(&self) -> impl Iterator<Item = (&E::Key, &FlowEntry<S>)>;
    pub fn flow_count(&self) -> usize;
    pub fn stats(&self) -> &FlowTrackerStats;
}

// Convenience for the common case `S: Default`.
impl<E: FlowExtractor, S: Default + Send + 'static> FlowTracker<E, S> {
    pub fn new(extractor: E) -> Self;
    pub fn with_config(extractor: E, config: FlowTrackerConfig) -> Self;

    /// Process a packet. Initializes `S` with `S::default()` for new flows.
    pub fn track(&mut self, view: PacketView<'_>) -> FlowEvents<'_, E::Key>;
}
```

`FlowEvents<'_, K>` is a `SmallVec<[FlowEvent<K>; 2]>` — most packets
emit one event, occasionally two (e.g., `Started` + `Packet`), zero
when the extractor returns `None`. No allocation in the common path.

#### Events emitted

```rust
#[derive(Debug, Clone)]
pub enum FlowEvent<K> {
    Started {
        key: K,
        side: FlowSide,
        ts: Timestamp,
        l4: Option<L4Proto>,
    },
    Packet {
        key: K,
        side: FlowSide,
        len: usize,
        ts: Timestamp,
    },
    /// TCP only: 3WHS completed.
    Established {
        key: K,
        ts: Timestamp,
    },
    /// TCP only: state transition (other than Established).
    StateChange {
        key: K,
        from: FlowState,
        to: FlowState,
        ts: Timestamp,
    },
    Ended {
        key: K,
        reason: EndReason,
        stats: FlowStats,
        history: HistoryString,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSide { Initiator, Responder }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason { Fin, Rst, IdleTimeout, Evicted }
```

**Side is the user-facing concept** — Initiator/Responder, derived from
which orientation the tracker saw first. Orientation (Forward/Reverse)
is the extractor-facing concept. Users who want raw orientation can
get it from `Extracted` if they bypass the tracker.

---

### 3.5 — Reassembler hook (Layer 3)

We don't ship a TCP reassembler. We ship a trait users implement
(`protolens`, `blatta-stream`, or their own buffer) plus the wiring
that calls it.

**Two parallel surfaces:**

- **`netring-flow::Reassembler`** — sync trait, no runtime dep.
  Lives in the computational crate. For sync users (pcap, embedded,
  test fixtures) and for trivial in-process accumulators that don't
  need to await.
- **`netring::AsyncReassembler`** — async trait, gated by
  `tokio`+`flow`. For tokio users who want real backpressure into a
  parser, channel, or downstream task. **The recommended path when
  using `netring` + `netring-flow` together.**

Both share the same `ReassemblerFactory<K>` shape (returning either a
sync or async reassembler), and `FlowStream` accepts either via two
builder methods.

#### Sync trait — `netring-flow`

```rust
/// Receives TCP segments for one direction of one session.
/// Sync — implementors don't await; for blocking consumers (Vec
/// buffer, std mpsc, sync protocol parsers).
pub trait Reassembler: Send + 'static {
    /// `payload` borrows from the ring frame — copy if you need it later.
    fn segment(&mut self, seq: u32, payload: &[u8]);
    fn fin(&mut self) {}
    fn rst(&mut self) {}
}

pub trait ReassemblerFactory<K>: Send + 'static {
    type Reassembler: Reassembler;
    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> Self::Reassembler;
}

/// Built-in: drop OOO, accumulate in-order bytes into a Vec, drain
/// via `take()`. Sync, no channel dep.
pub struct BufferedReassembler { /* … */ }
```

#### Async trait — `netring` (under `flow` + `tokio`)

```rust
use bytes::Bytes;
use std::future::Future;

/// Async-shaped reassembler. The flow stream awaits each call, so
/// returning a slow future propagates backpressure all the way back
/// to the kernel ring. Use this when feeding a tokio channel, an
/// async parser, or any downstream that can be saturated.
///
/// `Bytes` (not `&[u8]`) so the implementor can hold the payload
/// across `.await` points. Cheap to clone.
pub trait AsyncReassembler: Send + 'static {
    fn segment(&mut self, seq: u32, payload: Bytes)
        -> impl Future<Output = ()> + Send + '_;
    fn fin(&mut self) -> impl Future<Output = ()> + Send + '_ {
        async {}
    }
    fn rst(&mut self) -> impl Future<Output = ()> + Send + '_ {
        async {}
    }
}

pub trait AsyncReassemblerFactory<K>: Send + 'static {
    type Reassembler: AsyncReassembler;
    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> Self::Reassembler;
}

/// Common pattern as a free helper: spawn a task per (flow, side),
/// hand it bytes via mpsc. Returns an `AsyncReassemblerFactory`
/// suitable for `FlowStream::with_async_reassembler`.
pub fn channel_factory<K, F>(mut make: F)
    -> impl AsyncReassemblerFactory<K>
where
    F: FnMut(&K, FlowSide) -> tokio::sync::mpsc::Sender<Bytes>
        + Send + 'static,
    K: Clone + Send + 'static;
```

#### How the tracker drives reassembly

Each new TCP flow gets two reassemblers — Initiator and Responder —
created via the factory. Every TCP `Packet` event with
`tcp.payload_len > 0` triggers a `segment(seq, payload)` call. On
`Ended`, `fin()` or `rst()` fires, then the reassemblers drop.

**For sync trait** (`with_reassembler`): the call is inline in
`poll_next` — runs to completion before the next packet is processed.

**For async trait** (`with_async_reassembler`): the future returned
is awaited by the `FlowStream` before yielding the corresponding
`FlowEvent`. A slow reassembler stops `poll_next` from making
progress; the kernel ring fills; the kernel drops. **Backpressure
flows naturally end-to-end.**

---

## Part 4 — Async-first integration

Two surfaces:

1. **One-liner**: `cap.flow_stream(extractor)` for the 80% case.
2. **Builder**: `cap.flow_stream(extractor).with_*(...)` chained for
   user state, custom config, reassembler.

The builder methods consume `self` and shift the type so the final
`Stream` is fully resolved at compile time. Same shape as
`reqwest::Client::get(url).header(...).query(...).send()`.

```rust
impl AsyncCapture {
    /// Start a flow stream. `S` defaults to `()`; use `.with_state()`
    /// to attach per-flow user state.
    pub fn flow_stream<E: FlowExtractor>(self, extractor: E) -> FlowStream<E, ()>;
}

pub struct FlowStream<E: FlowExtractor, S, R = NoReassembler> { /* … */ }

impl<E: FlowExtractor, S, R> FlowStream<E, S, R> {
    pub fn with_config(self, config: FlowTrackerConfig) -> Self;
}

impl<E: FlowExtractor> FlowStream<E, ()> {
    /// Attach per-flow user state.
    pub fn with_state<S, F>(self, init: F) -> FlowStream<E, S>
    where
        S: Send + 'static,
        F: FnMut(&E::Key) -> S + Send + 'static;
}

impl<E: FlowExtractor, S> FlowStream<E, S> {
    /// Attach a reassembler factory. TCP `Packet` events drive the
    /// factory's reassemblers automatically.
    pub fn with_reassembler<R>(self, factory: R) -> FlowStream<E, S, R>
    where R: ReassemblerFactory<E::Key>;
}

// `FlowStream` is itself a `Stream`.
impl<E: FlowExtractor, S, R> Stream for FlowStream<E, S, R> {
    type Item = io::Result<FlowEvent<E::Key>>;
    fn poll_next(...) -> Poll<...>;
}
```

### Headline example

```rust
use futures::StreamExt;
use netring::AsyncCapture;
use netring::flow::FlowEvent;
use netring::flow::extract::{StripVlan, FiveTuple};

let cap = AsyncCapture::open("eth0")?;
let mut events = cap.flow_stream(StripVlan(FiveTuple::bidirectional()));

while let Some(evt) = events.next().await {
    match evt? {
        FlowEvent::Started { key, ts, .. } => println!("[{ts}] + {key:?}"),
        FlowEvent::Established { key, .. } => println!("  3WHS done {key:?}"),
        FlowEvent::Ended { key, stats, history, .. } => {
            println!("- {key:?} {} → {} pkts, history={history}",
                stats.packets_initiator, stats.packets_responder);
        }
        _ => {}
    }
}
```

### Per-flow user state

```rust
struct FlowMetrics { http_requests: u32, last_user_agent: Option<String> }
impl Default for FlowMetrics { /* … */ }

let cap = AsyncCapture::open("eth0")?;
let mut events = cap
    .flow_stream(FiveTuple::bidirectional())
    .with_state(|_key| FlowMetrics::default())
    .with_config(FlowTrackerConfig {
        idle_timeout_tcp: Duration::from_secs(60),
        ..Default::default()
    });
// FlowMetrics is attached to each flow; access via tracker handle (see below)
```

### Reassembler — async path (recommended for tokio users)

The headline pattern: spawn a task per (flow, side), feed it bytes
via mpsc with backpressure.

```rust
use bytes::Bytes;
use tokio::sync::mpsc;
use netring::flow::channel_factory;

let cap = AsyncCapture::open("eth0")?;

let mut events = cap
    .flow_stream(FiveTuple::bidirectional())
    .with_async_reassembler(channel_factory(|key, side| {
        // For each new (flow, side), spawn a task and return its sender.
        // The flow stream awaits `tx.send(bytes).await` on every TCP
        // payload — slow consumer ⇒ kernel-level backpressure.
        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        let key = key.clone();
        tokio::spawn(async move {
            let mut parser = MyAsyncHttpParser::new();
            while let Some(bytes) = rx.recv().await {
                parser.feed(&bytes).await;
            }
            parser.finish().await;
        });
        tx
    }));

while let Some(evt) = events.next().await {
    // FlowEvent::Started / Established / Ended fire here as usual;
    // bytes are routed to the spawned tasks above.
}
```

For users who want a stateful struct rather than a spawned task,
implement `AsyncReassembler` directly:

```rust
struct InlineHttpReassembler { /* ... */ }

impl AsyncReassembler for InlineHttpReassembler {
    async fn segment(&mut self, _seq: u32, payload: Bytes) {
        self.parser.feed(&payload).await;
    }
    async fn fin(&mut self) { self.parser.finish().await; }
}

struct InlineFactory;
impl AsyncReassemblerFactory<FiveTupleKey> for InlineFactory {
    type Reassembler = InlineHttpReassembler;
    fn new_reassembler(&mut self, _key: &FiveTupleKey, _side: FlowSide)
        -> InlineHttpReassembler { InlineHttpReassembler::new() }
}

let events = cap.flow_stream(FiveTuple::bidirectional())
    .with_async_reassembler(InlineFactory);
```

### Reassembler — sync path (rare in async land)

For trivial in-process buffering or test fixtures, the sync trait
from `netring-flow` is available too:

```rust
let events = cap.flow_stream(FiveTuple::bidirectional())
    .with_reassembler(BufferedReassemblerFactory::new());
// Sync segment() — don't block, don't await. Fine for tiny buffers.
```

Most tokio users prefer `with_async_reassembler`.

### Composing with `Stream` combinators

`FlowStream` is a real `Stream` — `futures::StreamExt` works:

```rust
// Only TCP flows that ended
let tcp_ended = cap.flow_stream(FiveTuple::bidirectional())
    .try_filter(|e| std::future::ready(matches!(
        e, FlowEvent::Ended { .. }
    )));

// 1-second windows
let windows = cap.flow_stream(FiveTuple::bidirectional())
    .ready_chunks(64);
```

### Backpressure

The stream consumes from `AsyncCapture::readable()` only when
downstream is polling. If your consumer falls behind, the kernel ring
fills and AF_PACKET drops at the kernel — same backpressure model as
the rest of netring. **No internal mpsc, no unbounded buffering.**

---

## Part 5 — Crate organization

Two crates in one workspace.

```
netring/                       ← workspace root (current repo)
├── Cargo.toml                 ← [workspace]
├── netring/                   ← capture + inject (Linux-only, AF_PACKET / AF_XDP)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── capture.rs         ← unchanged
│       ├── inject.rs
│       ├── packet.rs          ← Timestamp removed; Packet::view() added
│       ├── afpacket/
│       ├── afxdp/
│       └── async_adapters/
│           └── tokio_adapter.rs   ← + AsyncCapture::flow_stream
└── netring-flow/              ← extractor + tracker (cross-platform)
    ├── Cargo.toml
    └── src/
        ├── lib.rs
        ├── timestamp.rs       ← lives here now
        ├── view.rs            ← PacketView
        ├── extractor.rs       ← trait, Extracted, Orientation, L4Proto, TcpInfo, TcpFlags
        ├── extract/
        │   ├── mod.rs
        │   ├── five_tuple.rs
        │   ├── ip_pair.rs
        │   ├── mac_pair.rs
        │   ├── encap_vlan.rs
        │   ├── encap_mpls.rs
        │   ├── encap_vxlan.rs
        │   └── encap_gtp.rs
        ├── tracker.rs         ← FlowTracker<E, S>, FlowEntry, FlowStats, FlowState
        ├── event.rs           ← FlowEvent, FlowSide, EndReason
        ├── tcp_state.rs       ← TCP state machine (private)
        ├── history.rs         ← HistoryString
        └── reassembler.rs     ← Reassembler trait, factory, ChannelReassembler
```

`netring-flow/src/async_stream.rs` does **not** exist. The async
stream wiring lives in `netring` — it requires `AsyncFd<OwnedFd>` and
the AF_PACKET / AF_XDP capture surface, both Linux-specific.
`netring-flow` itself stays cross-platform and library-only.

### Dependency direction

```
netring  ─────────► netring-flow ─────► (etherparse, ahash, smallvec, bitflags)
   │
   └────► nix, libc, tokio (optional), tracing  (Linux-only)
```

`netring-flow` has:

- **Zero Linux-only deps.** Builds on macOS, Windows, WASM with std.
- **Zero async/runtime deps.** No `tokio`, no `futures-core`, no
  `async-std`. The crate is purely computational. All traits and
  built-ins are sync; users who want async ergonomics wrap them
  themselves or use `netring`'s integration.

Consumers of `netring-flow` only (pcap, tun-tap, replay tests,
embedded targets, sync CLI tools) get a small, runtime-free
dependency tree.

Async ergonomics — the `Stream` impl, tokio-channel reassembler
helper, anything `Future`-shaped — live in `netring` and are gated
behind the existing `tokio` feature.

### What moves, what stays

**Moves to `netring-flow`** (BC for paths, soft via re-export):

- `Timestamp` → `netring_flow::Timestamp` (re-exported as `netring::Timestamp`).
- All `flow` types from the prior sketch live in `netring-flow`.

**Stays in `netring`:**

- `Packet`, `PacketBatch`, `PacketDirection`, `OwnedPacket`, `PacketStatus` — capture-shaped, AF_PACKET-tied.
- `Capture`, `Injector`, `AsyncCapture`, `AsyncInjector`, `Bridge`, `XdpSocket`, `AsyncXdpSocket`.
- All `afpacket/`, `afxdp/`, `async_adapters/` modules.

**New integration glue in `netring`:**

```rust
// netring/src/packet.rs
impl Packet<'_> {
    /// View this packet as a netring-flow PacketView.
    pub fn view(&self) -> netring_flow::PacketView<'_> {
        netring_flow::PacketView {
            frame: self.data(),
            timestamp: self.timestamp(),
        }
    }
}

// netring/src/lib.rs
pub use netring_flow::Timestamp;
#[cfg(feature = "flow")]
pub use netring_flow as flow;        // re-export the whole crate as a module

// netring/src/async_adapters/tokio_adapter.rs
#[cfg(feature = "flow")]
impl AsyncCapture {
    pub fn flow_stream<E: netring_flow::FlowExtractor>(self, e: E)
        -> netring_flow::FlowStream<...> { /* drives netring-flow tracker over the AsyncFd */ }
}
```

### Cargo.toml — `netring-flow`

```toml
[package]
name = "netring-flow"
version = "0.1.0"
edition = "2024"
rust-version = "1.85"
license = "MIT OR Apache-2.0"
description = "Pluggable flow & session tracking for packet capture"
keywords = ["flow", "session", "tcp", "packet", "tracking"]
categories = ["network-programming"]

[features]
default = ["extractors", "tracker", "reassembler"]
extractors = ["dep:etherparse"]
tracker    = ["dep:ahash", "dep:smallvec", "dep:bitflags"]
reassembler = []

[dependencies]
etherparse = { version = "0.16", optional = true }
ahash      = { version = "0.8",  optional = true }
smallvec   = { version = "1",    optional = true }
bitflags   = { version = "2",    optional = true }
```

### Cargo.toml — `netring`

```toml
[dependencies]
# Always — provides Timestamp + PacketView. With default-features=false the
# cost is essentially zero (just the type defs, no etherparse, no hashmap).
netring-flow = { version = "0.1", default-features = false }
bytes        = { version = "1", optional = true }   # for AsyncReassembler

# unchanged otherwise (libc, nix, thiserror, tracing, bitflags, …)

[features]
default = []
tokio   = ["dep:tokio", "dep:futures-core"]
parse   = ["netring-flow/extractors"]              # already implied by `flow`
flow    = ["netring-flow/default"]                 # full flow stack (sync)
# When tokio + flow are both on, the AsyncReassembler trait + channel_factory
# helper become available; `bytes` is pulled in transitively.
```

### Build matrix

| User asks for                        | Result |
|--------------------------------------|--------|
| `netring` defaults                   | Capture/inject only. `Timestamp` and `PacketView` types available (cheap). No flow tracker, no etherparse. |
| `netring` + `parse`                  | + per-packet `etherparse::SlicedPacket`; `netring-flow`'s extractor types appear. |
| `netring` + `flow`                   | + `FlowTracker`, all built-in extractors, `Reassembler` trait. **Sync API only.** No tokio. |
| `netring` + `flow` + `tokio`         | + `AsyncCapture::flow_stream(...)` + `FlowStream<E, S, R>` builder + `AsyncReassembler` trait + `channel_factory` helper (uses `bytes::Bytes`). |
| `netring-flow` only                  | Source-agnostic flow tracking. No Linux deps, **no tokio**. Use with pcap, tun-tap, replay, embedded. |
| `netring-flow` `default-features=false` | Just the bare types (`Timestamp`, `PacketView`, `Extracted`). |

The headline: **`netring-flow` never pulls a runtime.** A user can
build it for embedded / WASM / sync-only contexts with confidence.

### Using `netring-flow` with pcap

```toml
[dependencies]
netring-flow = "0.1"
pcap-file    = "2"
```

```rust
use netring_flow::{FlowTracker, PacketView, Timestamp};
use netring_flow::extract::FiveTuple;
use pcap_file::pcap::PcapReader;

let mut reader = PcapReader::new(File::open("trace.pcap")?)?;
let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());

while let Some(pkt) = reader.next_raw_packet() {
    let pkt = pkt?;
    let view = PacketView {
        frame: pkt.data,
        timestamp: Timestamp::new(pkt.timestamp.as_secs() as u32,
                                   pkt.timestamp.subsec_nanos()),
    };
    for evt in tracker.track(view) {
        // …
    }
}
```

5-line adapter. Same shape works for `pcap` (libpcap binding),
`tun-tap`, replay buffers, eBPF userspace ring readers, anything that
yields `(bytes, timestamp)`.

### Versioning

- `netring-flow` 0.1.x and `netring` 0.7.x are coupled in this repo
  and released together.
- `netring` 0.7.x depends on `netring-flow ^0.1`.
- Patch bumps independent if the change is fully internal to one
  crate; minor bumps coordinated.

### Why two crates, not three

Single-crate (`netring` only) keeps flow tied to Linux capture — the
core motivation against. Three-crate (`netring-core` + `netring` +
`netring-flow`) is over-engineered until there's a shared type heavy
enough to need its own home. Currently the only shared type is
`Timestamp`, which lives fine inside `netring-flow`. Tokio went 1 → 3
crates only after `tokio-util` proved its weight; we'll do the same
if it ever comes up.

---

## Part 6 — Phasing

Each phase ships the async stream adapter alongside the primitive,
per the async-first preference.

### Phase 0 — workspace + crate split (no new functionality, ~1 day)

- Convert repo to a Cargo workspace. Move existing `src/` to
  `netring/netring/src/`. Add `netring/netring-flow/` skeleton.
- Move `Timestamp` from `netring` to `netring-flow`. Re-export from
  `netring` so `netring::Timestamp` keeps working.
- Wire `netring`'s `Cargo.toml` to depend on
  `netring-flow = { version = "0.1.0-alpha", default-features = false }`.
- CI: extend matrix to build/test both crates, run clippy on both.
- All existing `netring` tests must pass unchanged.
- Bump `netring` to `0.7.0-alpha.0`. Tag `netring-flow` `0.1.0-alpha.0`.
- No publish yet — alpha versions on git only.

### Phase 1 — `netring-flow` core: extractor + built-ins (~600 LOC)

- In `netring-flow`:
  - `PacketView`, `FlowExtractor` trait, `Extracted`, `Orientation`,
    `L4Proto`, `TcpInfo`, `TcpFlags`.
  - `FiveTuple`, `IpPair`, `MacPair`.
  - `StripVlan`, `StripMpls`, `InnerVxlan`, `InnerGtpU`.
- In `netring`:
  - `Packet::view()` bridge method.
  - Re-export `netring::flow as netring_flow` under `flow` feature.
- Tests: unit tests in `netring-flow` against synthetic frames + a
  pcap-based integration test using `pcap-file` to prove the
  source-agnostic claim.
- Example: `netring/examples/async_flow_keys.rs` — built-ins + custom
  extractor in one file (live capture).
- Example: `netring-flow/examples/pcap_flow_keys.rs` — same extractor
  applied to a pcap input. Demonstrates source-agnosticism.

### Phase 2 — `netring-flow` tracker + `netring` async stream (~700 LOC)

- In `netring-flow`:
  - `FlowTracker<E, S>` with TCP state machine, history string, sweep.
  - `FlowEvent`, `FlowSide`, `EndReason`, `FlowState`.
- In `netring`:
  - `AsyncCapture::flow_stream` + `FlowStream<E, S, R>` builder
    (`with_state`, `with_config`).
  - Internally drives `netring_flow::FlowTracker` from the AsyncFd
    poll loop.
- Examples (in `netring`, since they're tokio-driven):
  - `examples/async_flow_summary.rs` — print one line per ended flow.
  - `examples/async_flow_filter.rs` — capture only matching flows.
  - `examples/async_flow_history.rs` — Zeek-style `conn.log` output.
- Example (in `netring-flow`):
  - `examples/pcap_flow_summary.rs` — same as `async_flow_summary` but
    over pcap input. No tokio.

### Phase 3 — reassembler hooks, sync + async (~450 LOC + examples)

- In `netring-flow` (sync, runtime-free):
  - `Reassembler` trait, `ReassemblerFactory<K>`,
    `BufferedReassembler`.
- In `netring` (under `flow` + `tokio`):
  - `AsyncReassembler` trait (Rust 2024 `async fn` in trait, returns
    `impl Future + Send`).
  - `AsyncReassemblerFactory<K>` trait.
  - `channel_factory<K, F>(F)` helper — wraps a per-flow
    `Sender<Bytes>` factory into an `AsyncReassemblerFactory`.
  - `FlowStream::with_reassembler` (sync) and
    `FlowStream::with_async_reassembler` (async).
- Examples:
  - `netring-flow/examples/pcap_buffered_reassembly.rs` — sync,
    over pcap input.
  - `netring/examples/async_flow_channel.rs` — async, headline
    backpressure pattern with `channel_factory` + spawned tasks.
  - `netring/examples/async_flow_protolens.rs` — bridge to
    `protolens` via `AsyncReassembler` (gated behind a dev-feature).

### Phase 4 — docs + 0.7.0 release

- `netring-flow/docs/FLOW_GUIDE.md`: extractor cookbook (custom
  5-tuple variant, custom L7-cookie key, encap composition,
  pcap/tun-tap usage).
- `netring/CHANGELOG.md`: 0.7.0 entry covering the workspace split,
  re-exports, new flow API.
- Coordinated publish: `netring-flow` 0.1.0 + `netring` 0.7.0.

Total: ~1 600 LOC across both crates + 6 examples + 1 doc.

---

## Part 7 — Decision matrix

Items needing your call before implementation. My recommendation in
the right column.

### Extractor design

| # | Question | Recommendation |
|---|----------|---------------|
| 1.1 | Trait input: `&[u8]` vs `PacketView<'_>` vs `&Packet` | **`PacketView<'_>`** — composes through decap, carries timestamp |
| 1.2 | Return `Extracted<K>` with `orientation`, `l4`, `tcp` | **Yes** — single struct, optional richness |
| 1.3 | Include `TcpInfo` in `Extracted` | **Yes** — built-ins fill it free; reassembler reuses |
| 1.4 | `FiveTuple` default mode | **`bidirectional()`** |
| 1.5 | Built-in extractors at v1 | **`FiveTuple`, `IpPair`, `MacPair`** (defer `FlowLabel`) |
| 1.6 | Built-in encap combinators at v1 | **`StripVlan`, `StripMpls`, `InnerVxlan`, `InnerGtpU`** (defer `InnerGre`) |
| 1.7 | Provide `dyn FlowExtractor` adapter | **No initially** — generic-only; revisit if asked |
| 1.8 | Add `Packet::view()` helper | **Yes** — bridges existing API to extractor input |

### Tracker design

| # | Question | Recommendation |
|---|----------|---------------|
| 2.1 | Collapse `SessionTracker` into `FlowTracker` | **Yes** (the BC break this revision uses) |
| 2.2 | Generic over user state `S` (default `()`) | **Yes** |
| 2.3 | Two impl blocks: `track_with` (any S) + `track` (S: Default) | **Yes** |
| 2.4 | Default `max_flows` | **100 000** (~10 MiB at full) |
| 2.5 | Default idle timeouts (TCP / UDP / other) | **5 min / 60 s / 30 s** (Suricata-style) |
| 2.6 | Eviction policy on overflow | **LRU** (no `OverflowPolicy` enum) |
| 2.7 | `HashMap` impl: std vs `ahash` | **`ahash`** (private, behind `flow`) |
| 2.8 | Zeek-style `HistoryString` in events | **Yes** |
| 2.9 | Track TCP window scaling / SACK | **Defer** — reassembler hook covers this |

### Reassembler design

| # | Question | Recommendation |
|---|----------|---------------|
| 3.1 | Build vs depend for TCP reassembly | **Hook only.** Trait + `BufferedReassembler`. No reassembly engine in netring. |
| 3.2 | `Reassembler` trait shape | **gopacket-inspired** (`segment`/`fin`/`rst`); not protolens-style |
| 3.3 | Ship a `protolens` integration crate | **No** — example only, gated behind dev-feature |
| 3.4 | Ship a simple in-order reassembler (drops OOO) | **Yes** — `BufferedReassembler` covers the 70% case |
| 3.5 | Async-shaped reassembler trait | **Yes** — `AsyncReassembler` in `netring` (under `flow`+`tokio`) for backpressure-friendly tokio integration |
| 3.6 | `AsyncReassembler` payload type | **`Bytes`** — owned, cheap clone, survives `.await` |
| 3.7 | Ship a `channel_factory` helper for spawn-task-per-flow pattern | **Yes** — most idiomatic tokio pattern; should be the headline path |
| 3.8 | Pull in `bytes` crate as a dep | **Yes**, only when `tokio`+`flow` are both on |

### Async API

| # | Question | Recommendation |
|---|----------|---------------|
| 4.1 | `flow_stream` consumes `AsyncCapture` | **Yes** — matches `into_stream()` shape |
| 4.2 | Builder methods on `FlowStream` (`.with_state`/`.with_reassembler`/`.with_config`) | **Yes** — keeps the one-liner short, lets advanced cases scale |
| 4.3 | `FlowStream` impls `Stream` directly | **Yes** — no separate `.start()` / `.into_stream()` |
| 4.4 | Internal mpsc between ring task and stream consumer | **No** — direct over `AsyncFd`; kernel ring is the buffer |
| 4.5 | Sweep automatically on a `tokio::time::interval` inside `FlowStream` | **Yes** — interval from `FlowTrackerConfig::sweep_interval` |
| 4.6 | Sync `Capture::flow_iter` | **No** — power users use `FlowTracker::track` directly |

### Crate organization

| # | Question | Recommendation |
|---|----------|---------------|
| 5.1 | Split `netring-flow` from `netring` | **Yes** (you've approved) |
| 5.2 | Workspace in same repo vs separate repo | **Same repo, workspace** |
| 5.3 | Where does `Timestamp` live | **`netring-flow`**, re-exported by `netring` |
| 5.4 | `netring-flow` features (extractors / tracker / reassembler) | **Three features, all on by default**; user can opt out for tiny builds |
| 5.5 | `netring`'s `flow` feature pulls in `netring-flow` defaults | **Yes** |
| 5.6 | Ship a `netring-flow-pcap` integration crate | **No** — example only; pcap users add `pcap-file` themselves |
| 5.7 | Independent vs coupled versioning | **Coupled** — bump together while pre-1.0 |

### Packaging & release

| # | Question | Recommendation |
|---|----------|---------------|
| 6.1 | `flow` implies `parse` | **Yes** |
| 6.2 | Initial release version | **`netring-flow` 0.1.0** + **`netring` 0.7.0**, coordinated |
| 6.3 | Ship after / alongside dedup | **Alongside** — both in 0.7.0 |
| 6.4 | Alpha period (test the workspace before publishing) | **Yes** — `0.1.0-alpha.0` / `0.7.0-alpha.0` on git for at least one cycle before crates.io |

---

## Part 8 — Risks, open questions, things I'm unsure about

1. **Generic explosion.** `FlowTracker<E, S>` and `FlowStream<E, S, R>`
   are generic over multiple parameters. The simple case
   `cap.flow_stream(FiveTuple::bidirectional())` resolves to
   `FlowStream<FiveTuple, (), NoReassembler>` — fine, but error
   messages can get noisy. Mitigation: type aliases for the common
   shapes, focused docs on the one-liner case first.

2. **Hot-path cost of `HashMap` lookup.** At 1 Mpps with `ahash` and
   `FiveTupleKey` (~40 bytes), a lookup costs ~50 ns. Visible in
   benchmarks. **Open**: add an LRU-cache fast-path for the
   most-recently-seen flow (Suricata does this). Defer to perf
   testing.

3. **`Extracted::tcp` cost for non-TCP packets.** Built-in `FiveTuple`
   parses TCP only when proto == TCP, so this is free for UDP/ICMP.
   But the field is always present in the `Extracted` struct,
   widening it by ~32 bytes. Could box the TCP info. Probably not
   worth it.

4. **Per-flow user state vs separate side-table.** `FlowTracker<E, S>`
   couples user state to flow lifetime. For users who want state to
   outlive the flow (long-term flow stats across reconnections), an
   external map is better. Both supported (`S = ()` + external map).

5. **Encap depth.** `StripVlan(StripMpls(InnerVxlan(FiveTuple)))`
   composes but is verbose. An `AutoDetectEncap<E>` that walks any
   common combination would be nice. Defer until we have user demand.

6. **IPv6 fragmentation.** `etherparse` parses the first fragment but
   doesn't reassemble. Document the limitation; users who need it can
   reassemble ahead of the extractor.

7. **`Packet<'_>` is `!Send`.** The async stream task owns the capture;
   `FlowTracker` runs inside that task. Per-flow user state `S` must
   be `Send` if any of it crosses an `.await`. Bounds reflect this.

8. **`ChannelReassembler` drops OOO.** Trade-off acknowledged in the
   type's name. Documentation must spell out that for in-order
   guarantees you need a real reassembler (`protolens`/etc.).

9. **Workspace coordination cost.** Two crates means coordinated
   release + matching versions in CI + slightly more `Cargo.toml`
   boilerplate. Mitigation: a small `xtask` or justfile recipe that
   bumps both versions together. The cost is real but bounded.

10. **`netring-flow` MSRV drift.** `netring` is `rust-version = 1.85`
    (edition 2024). `netring-flow` should match, even though it could
    technically support older Rust. Picking the same MSRV avoids
    confusing matrix issues; we revisit if there's user demand for
    older Rust.

11. **Re-export discoverability.** `netring::Timestamp` continues to
    work via re-export, but rustdoc may show it as
    `pub use netring_flow::Timestamp` rather than the type directly.
    Acceptable; standard pattern in the Rust ecosystem (e.g.,
    `tokio::time::Duration` is `std::time::Duration`).

---

## Part 9 — Async friction audit

Most users of `netring + netring-flow` will be in tokio. This table
walks every place an async user could hit friction and confirms how
the design avoids it.

| # | Friction point | Status | Mitigation |
|---|----------------|:------:|------------|
| F1 | `flow_stream` is itself a `Stream` | ✅ none | Direct `impl Stream`, full `futures::StreamExt` composability |
| F2 | Sync `Reassembler::segment` blocks the runtime if you await | ✅ fixed | `AsyncReassembler` trait in `netring` (Rust 2024 `async fn` in trait) is the headline path for tokio users; sync trait stays for non-tokio cases |
| F3 | Reassembler payload `&[u8]` doesn't survive `.await` | ✅ fixed | `AsyncReassembler::segment` takes `Bytes` (owned, cheap clone) |
| F4 | Backpressure all the way to the kernel ring | ✅ designed in | Stream awaits reassembler futures inline; slow consumer ⇒ ring fills ⇒ kernel drops. No internal unbounded buffering. |
| F5 | Per-flow state init is sync (`FnMut(&K) -> S`) | ⚠️ documented | State init should be cheap. Users needing async init can construct a handle synchronously and spawn the work asynchronously inside it. v2 if asked. |
| F6 | `Packet<'_>` is `!Send` | ✅ enforced by bounds | Per-flow `S` and reassembler types must be `Send + 'static`; the borrowed `Packet` never crosses an `.await` (tracker step is synchronous) |
| F7 | Multiple subscribers / fan-out | ⚠️ documented | `flow_stream` consumes the capture; users wrap with `tokio::sync::broadcast` for fan-out. Documented recipe in `FLOW_GUIDE.md`. |
| F8 | Cancellation: dropping `FlowStream` mid-flow | ✅ clean | Per-flow spawned tasks (in `channel_factory` pattern) see closed senders, exit naturally. Tracker frees state on drop. |
| F9 | Long-running per-flow tasks not cleaned up on `Ended` | ✅ designed in | When `Ended` fires, the reassembler's `fin()`/`rst()` is awaited then dropped, closing any internal sender; spawned task exits. Integration test in Phase 3. |
| F10 | Bounded vs unbounded mpsc in `channel_factory` | ✅ bounded by default | Helper takes capacity argument; default 64. Unbounded must be opt-in. |
| F11 | Sweep timing not user-controllable | ⚠️ partial | `FlowTrackerConfig::sweep_interval` covers most needs. Manual `tick()` for tests deferred to v2. |
| F12 | `Send + 'static` bounds error messages | ⚠️ documented | Standard Rust friction. Type aliases for common shapes; one focused docs page on bounds. |
| F13 | `flow_stream` consumes `AsyncCapture` | ✅ documented | Matches existing `into_stream()` shape. Users who need to keep capturing manually can split before calling `flow_stream`. |
| F14 | Custom extractor parsing must be sync | ✅ correct by design | Header parsing is fast; sync is right. No friction; only inflexibility for hypothetical async extractors which we explicitly don't support. |
| F15 | Stream combinators (`filter`, `chunks`, etc.) | ✅ none | All `futures::StreamExt` works on `FlowStream` |

✅ = fully resolved · ⚠️ = documented limitation, deliberate

The two ⚠️ items deferred to v2 (F5 async state init, F11 manual
sweep) are both rare requests; we'll add them when there's real
demand rather than design for hypothetical use.

---

## Sources consulted

- [gopacket `tcpassembly`](https://pkg.go.dev/github.com/google/gopacket/tcpassembly)
  · [assembly.go source](https://github.com/google/gopacket/blob/master/tcpassembly/assembly.go)
  — StreamFactory + Stream pattern.
- [protolens crate](https://crates.io/crates/protolens)
  · [docs](https://docs.rs/protolens/latest/protolens/)
  · [Packet trait](https://docs.rs/protolens/latest/protolens/trait.Packet.html)
  · [GitHub](https://github.com/chunhuitrue/protolens)
  — Rust TCP reassembly + L7 parsing, callback-based, single-instance-per-thread.
- [Suricata Flow Management](https://deepwiki.com/OISF/suricata/3.3-flow-management)
  · [`flow-hash.c`](https://github.com/OISF/suricata/blob/master/src/flow-hash.c)
  · [`flow-manager.c`](https://github.com/OISF/suricata/blob/main/src/flow-manager.c)
  — flow table, hash, timeouts, emergency mode, **single tracker**.
- [Zeek conn.log](https://docs.zeek.org/en/master/logs/conn.html)
  · [Tracking Communication State](https://corelight.com/blog/using-zeek-to-track-communication-state)
  — history strings, conn states, uid correlation.
- [Wireshark Conversation and Flow Tracking](https://deepwiki.com/wireshark/wireshark/3.5-conversation-and-flow-tracking)
  — `conversation_element_t` extensible key arrays.
- [Linux BPF Flow Dissector](https://docs.kernel.org/6.0/bpf/prog_flow_dissector.html)
  · [`bpf_flow.c`](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/bpf_flow.c)
  — `bpf_flow_keys` ABI, encap-aware flags, **flag-driven dissection**.
- [Netfilter flowtable](https://docs.kernel.org/networking/nf_flowtable.html)
  · [conntrack-tools](https://conntrack-tools.netfilter.org/manual.html)
  — kernel CT, hardware offload model.
- [DPDK SFT RFC](https://inbox.dpdk.org/dev/MWHPR1201MB252570BC3057DCC7D97146E5DB100@MWHPR1201MB2525.namprd12.prod.outlook.com/T/)
  — Stateful Flow Table, pluggable PMD ops.
- [PF_RING FT (ntop)](https://www.ntop.org/introducing-pf_ring-ft-ndpi-based-flow-classification-and-filtering-for-pf_ring-and-dpdk/)
  — capture-agnostic flow table API, callbacks, custom metadata.
- [go-flows (CN-TU)](https://pkg.go.dev/github.com/CN-TU/go-flows)
  — pipeline architecture, flow-key as composed features.
- [RustiFlow](https://github.com/idlab-discover/RustiFlow)
  — eBPF flow exporter, pluggable feature sets.
- [scapy sessions](https://scapy.readthedocs.io/en/latest/api/scapy.sessions.html)
  · [TCPSession](https://github.com/secdev/scapy/blob/master/scapy/layers/tls/session.py)
  — `IPSession`/`TCPSession`, per-protocol `tcp_reassemble`.
- [Wireshark Follow Stream](https://www.qacafe.com/resources/using-follow-stream-for-analysis/)
  — bidirectional stream UX.
- [CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter)
  · [feature comparison paper](https://arxiv.org/pdf/2501.13004)
  — 80+ statistical flow features, bidirectional.
- [tokio mpsc](https://docs.rs/tokio/latest/tokio/sync/mpsc/index.html)
  · [Async Rust with Tokio I/O Streams](https://biriukov.dev/docs/async-rust-tokio-io/1-async-rust-with-tokio-io-streams-backpressure-concurrency-and-ergonomics/)
  — Stream adapter patterns, backpressure semantics.
