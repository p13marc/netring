# High-level features — design proposal

> **Status**: design report for review. No code shipped yet.
>
> **Audience**: maintainer (you) — review before I start implementing.
> Mark sections "approve" / "change X" / "skip" and I'll execute.

netring's current public surface is plumbing — capture frames, inject
frames, get statistics. Two recurring pain points keep coming up that
sit one layer above the plumbing:

1. **Following a session** (TCP / UDP). Group packets by 5-tuple,
   optionally reassemble TCP byte streams.
2. **Loopback deduplication.** When you capture on `lo`, every packet
   appears at least twice (`PACKET_OUTGOING` + `PACKET_HOST`).
   Sometimes more.

This document proposes an API for both. It's deliberately layered so
you can ship the cheap, high-value bits first and revisit the
expensive ones when there's pressure.

### Design constraints

- **Async first (tokio).** `AsyncCapture`/`AsyncInjector` are the main
  API. Every new feature must compose with them via `futures::Stream`
  or `async fn`. Sync `Capture` keeps working but isn't where new
  ergonomics land.
- **Rust idiomatic.** Builders, `Result`-returning fallible ops,
  borrowed types where mmap allows, no callback APIs unless we wrap
  them in a `Stream`.
- **Layered.** Each feature ships as a free-standing primitive plus an
  ergonomic adapter on `AsyncCapture`. Users who need control take the
  primitive; the 90% case takes the adapter.

---

## Part 1 — Loopback deduplication

### Problem statement

When you `tcpdump -i lo` (or netring's equivalent on `lo`), every
"packet" you'd think you sent appears multiple times in the capture.
Concretely:

```
$ ping -c1 127.0.0.1
$ # netring sees:
[1] 127.0.0.1 → 127.0.0.1 ICMP echo request   direction=Outgoing
[2] 127.0.0.1 → 127.0.0.1 ICMP echo request   direction=Host       ← same packet
[3] 127.0.0.1 → 127.0.0.1 ICMP echo reply     direction=Outgoing
[4] 127.0.0.1 → 127.0.0.1 ICMP echo reply     direction=Host       ← same packet
```

Why: the kernel's loopback driver re-injects every outgoing packet as
incoming. AF_PACKET captures both halves. This isn't a netring bug —
it's how Linux loopback works — but most users running a packet
analysis tool want to see each *logical* packet once.

### Existing tools — prior art

- **tcpdump** — does nothing. Shows every duplicate.
- **Wireshark** — shows duplicates; suggests display filters
  (`not tcp.analysis.duplicate_ack and not tcp.analysis.retransmission`)
  but doesn't dedup at capture time.
- **`editcap -w`** (Wireshark suite) — post-capture pcap dedup. Uses
  **MD5 hash + length + time window**, comparing against up to N
  previous packets. Time window is `seconds[.fractional]`, default
  comparing only adjacent packets. Order-sensitive (assumes
  chronological).
- **PACKET_IGNORE_OUTGOING** — kernel-level. Drops the OUTGOING
  variant entirely. netring already exposes via
  `.ignore_outgoing(true)`. Works for "I only want one direction" but
  not for "I want both directions, deduplicated".

The `editcap` model is the canonical pcap-deduplication primitive.
It's what we should mirror.

### Approaches considered

#### A. Kernel-level (already shipped)

`Capture::builder().ignore_outgoing(true).build()` sets
`PACKET_IGNORE_OUTGOING`. Free at runtime; drops one direction.

**When to use:** you only care about one direction (typical for
analyzing traffic into/out of the local host).

**Limitation:** not the same as deduplicating bidirectional capture.

#### B. Direction-based filtering for `lo` (heuristic)

On `lo`, every "real" packet appears as `Outgoing` first then `Host`
(or sometimes the reverse). Drop the `Host` variant if we just saw an
`Outgoing` of the same content within Δt.

Pros: cheap; respects bidirectional flows (you see both A→B and B→A,
each once).
Cons: heuristic; needs content matching to avoid false dedup with
genuinely-coincident-but-distinct packets.

#### C. Content-hash dedup (general, à la `editcap -w`)

Hash each packet (FNV-1a / xxhash over the data slice), keep a
small ring of recent (hash, ts) entries, drop a packet whose hash
appears in the ring within the configured time window.

Pros: works for any interface, not just `lo`. Simple model.
Cons: per-packet hash cost; false dedup on genuinely-identical
packets (e.g., a heartbeat repeated in <Δt). Mitigated by a
*tight* default window (e.g., 1 ms — long enough to catch
loopback re-injection, short enough that real duplicate flows
don't suffer).

#### D. Combined: direction + content (recommended)

For each packet:

1. Compute `(hash(data), len)` — cheap with `xxhash` or even FNV-1a
   for typical ~1500-byte packets.
2. Look in a fixed-size ring buffer (tunable, default 256 entries) for
   matching `(hash, len, ts within window)`.
3. On `lo`, if the matching entry has `direction=Outgoing` and
   current is `direction=Host` (or vice versa), drop with high
   confidence.
4. On other interfaces, dedup based on hash + window only.

This gives the best of both: aggressive dedup on `lo` where the
direction signal is meaningful, conservative dedup elsewhere.

### Proposed API

Three layers: a free-standing `Dedup` primitive, an async `Stream`
adapter (the headline ergonomics), and a builder shorthand.

#### Layer 1 — `AsyncCapture::dedup_stream()` (the headline)

The case we want to be a one-liner. Async first.

```rust
use futures::StreamExt;

let cap = AsyncCapture::open("lo")?;
let mut stream = cap.dedup_stream(Dedup::loopback());

while let Some(pkt) = stream.next().await {
    let pkt = pkt?;
    // each logical packet, exactly once
}
```

`dedup_stream` returns `impl Stream<Item = Result<OwnedPacket>>`,
consumes the `AsyncCapture`, and runs the filter inline so the user
never sees duplicates.

For the zero-copy case (avoiding `OwnedPacket` allocation), we expose
`dedup_batches()` returning a `Stream<Item = Result<DedupBatch<'_>>>`
where `DedupBatch` is an iterator of borrowed `Packet<'_>` already
filtered.

#### Layer 2 — standalone `Dedup` primitive

For users who want control of the loop (multi-source merging, custom
batching, sync `Capture`):

```rust
// Behind feature `dedup`. No new transitive deps.
pub struct Dedup { /* ring buffer of (hash, len, ts, direction) */ }

impl Dedup {
    /// Configured for loopback: 1ms window, 256-entry ring,
    /// Outgoing/Host direction matching enabled.
    pub fn loopback() -> Self;

    /// Generic content dedup: configurable window, no direction matching.
    pub fn content(window: Duration, ring_size: usize) -> Self;

    /// Returns true if the packet should be kept; false to drop.
    /// Updates internal state.
    pub fn keep(&mut self, pkt: &Packet<'_>) -> bool;

    /// Stats: how many we've dropped so far.
    pub fn dropped(&self) -> u64;
}
```

Async manual loop (when `dedup_stream()` is too rigid):

```rust
let mut cap = AsyncCapture::open("lo")?;
let mut dedup = Dedup::loopback();
loop {
    let mut g = cap.readable().await?;
    if let Some(batch) = g.next_batch() {
        for pkt in &batch {
            if dedup.keep(&pkt) { /* process */ }
        }
    }
}
```

Sync (less common — secondary path):

```rust
let mut cap = Capture::open("lo")?;
let mut dedup = Dedup::loopback();
for pkt in cap.packets() {
    if dedup.keep(&pkt) { /* process */ }
}
```

#### Layer 3 — builder integration (auto-applied)

```rust
let cap = AsyncCapture::builder()
    .interface("lo")
    .dedup(DedupMode::Loopback)         // or Content { window, ring }
    .build()?;

// stream/recv/readable() now transparently drop duplicates.
// Stats: cap.dedup_stats().
```

Convenient, but pushes filtering into the hot path. **Recommendation:
ship Layers 1+2 in 0.7.0 (the stream adapter is the idiomatic
answer); revisit Layer 3 only if users ask.**

### Implementation notes

- **Hash function**: `xxhash-rust` (~zero-cost, no_std-friendly,
  ~no transitive deps) or roll FNV-1a inline. xxhash is faster on
  >64B inputs which dominates packet sizes.
- **Memory**: `Dedup::loopback()` default — 256 entries × ~24 bytes =
  ~6 KiB per dedup instance.
- **Time source**: each entry's timestamp comes from the packet's
  kernel timestamp (`pkt.timestamp()`) — no syscall cost, monotonic
  enough for our window comparison.
- **Cost per packet**: 1 hash (xxhash on ~1500 B is ~100 ns), plus
  256-entry linear scan in the worst case (cache-friendly, also
  ~100 ns). Total ≤ 1 μs/packet, well below netring's per-packet
  overhead today.

### Open questions for review

1. **Ring size + window defaults.** 256 entries × 1 ms window for
   `lo`. Reasonable?
2. **`Dedup` as struct vs free function.** Free function would be
   stateless, but content-hash dedup is fundamentally stateful —
   can't avoid the struct.
3. **Layer 2 (builder integration) — yes or no.** Adds API surface
   but saves users a one-line wrap.
4. **Naming.** `Dedup`? `Dedupe`? `PacketDeduplicator`? I prefer
   `Dedup` for brevity.
5. **Feature flag.** New `dedup` feature, off by default? Or always
   on? It has zero cost when not constructed — a no-op feature flag
   is mostly bookkeeping. **My vote: always on** (no feature flag),
   gated behind the type's existence rather than a cargo feature.

---

## Part 2 — Session / flow tracking

> **Moved.** Session/flow tracking has its own design now. See
> [`flow-session-tracking-design.md`](./flow-session-tracking-design.md)
> for the full design — pluggable `FlowExtractor` trait, tracker
> generic over user state, TCP session machine, reassembly hook,
> async streams, and 13 decision-matrix items.

The text below is the original sketch, kept for reference until the
new design is approved. **Treat the new doc as the source of truth.**

---

### (Original sketch — superseded)

### Problem statement

Users who do anything beyond raw packet inspection want to think in
**flows** (5-tuple: `proto + src_ip:port + dst_ip:port`) or **sessions**
(bidirectional flows — both halves of a TCP conversation).

Concrete tasks:

- **Filter:** "show me only packets in TCP session
  10.0.0.1:5432 → 10.0.0.2:54321"
- **Group:** "for each unique flow, count bytes/packets/duration"
- **Reassemble:** "give me the HTTP request bytes that came over this
  TCP session, in order, as a single byte stream"

These three differ wildly in cost:

| Tier | Cost per packet | Output |
|------|-----------------|--------|
| 5-tuple extraction | ~50 ns (parse headers) | `FlowKey` |
| Flow tracking (counters per flow) | ~100 ns (hash + lookup) | `FlowEvent` |
| TCP reassembly | ~1 μs (sequence tracking + buffer) | byte stream |

### Existing tools — prior art

- **gopacket** (Go) — `tcpassembly` package. Defines a `StreamFactory`
  trait; user provides factory that creates `Stream` objects per
  5-tuple; assembler feeds reassembled `Reassembled([]Reassembly)`
  into the user's stream. `tcpreader.ReaderStream` adapts that into
  `io.Reader`. **Clean separation** between the assembler (state) and
  the user code (what to do with bytes).

- **`protolens`** (Rust crate, active development). High-perf TCP
  reassembly with built-in protocol parsers (HTTP/SMTP/FTP). Per-task
  callbacks. Single-threaded per instance. Packet cache (default 128)
  before protocol detection. Targets 2–5 GiB/s payload throughput.
  *No async story.*

- **`blatta-stream`** (Rust) — TCP stream reassembly library, lower
  profile, focused on reassembly only.

- **`rs-flow_reassembler`** (Rust) — TCP flow reassembly, smaller scope.

- **`smoltcp`** — full TCP/IP stack for embedded; not relevant for
  capture-side reassembly.

### Design choice: build vs depend

This is the biggest question in this section.

**Buy (depend on `protolens`)**

- Saves us writing TCP reassembly — significant work, error-prone.
- Drawback: callback-based API doesn't compose well with iterators or
  Streams. Single-threaded per instance fights tokio's multi-task
  story.
- License compatible (MIT/Apache-2.0).
- Adds a substantial dep tree.

**Build (own implementation, layered)**

- Layer 1 (5-tuple extraction) and Layer 2 (flow counters) are tiny —
  ~300 lines, no deps beyond `etherparse` (already optional).
- Layer 3 (TCP reassembly) is bigger but the payload (out-of-order
  buffer + simple state machine) is well-understood. ~600 lines.
- API can be designed for tokio — async streams of flow events,
  iterator-style consumption.

**Hybrid (recommended)**

- Build Layer 1 + Layer 2 ourselves (cheap, high value).
- For Layer 3, **expose a hook** so users can wire in `protolens` (or
  their own reassembler) without netring depending on it.

This matches how netring handles BPF: we don't ship an eBPF loader,
but we expose `attach_ebpf_filter(impl AsFd)` so users can wire `aya`
in. Same pattern: ship the integration point, not the heavyweight
implementation.

### Proposed API

#### Layer 1 — 5-tuple extraction (free function)

```rust
/// Behind feature `flow`. Pulls in `etherparse` (already optional).
pub fn flow_key(data: &[u8]) -> Option<FlowKey>;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub proto: IpProto,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum IpProto { Tcp, Udp, Icmp, IcmpV6, Other(u8) }

impl FlowKey {
    /// Bidirectional canonical form: src/dst sorted so both halves
    /// of a TCP session map to the same key.
    pub fn canonical(self) -> Self;
}
```

Convenience method on `Packet`:

```rust
impl Packet<'_> {
    /// Behind feature `flow`. Same as `flow_key(self.data())`.
    #[cfg(feature = "flow")]
    pub fn flow_key(&self) -> Option<FlowKey>;
}
```

Same for `OwnedPacket`.

#### Layer 2 — flow tracker

```rust
pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowState>,
    config: FlowTrackerConfig,
}

pub struct FlowTrackerConfig {
    /// Drop a flow after this much idle time. Default: 60s for UDP,
    /// 5min for TCP (or until FIN/RST observed).
    pub idle_timeout: Duration,
    /// Cap on flows tracked. Beyond this, oldest is evicted.
    /// Default: 100_000.
    pub max_flows: usize,
    /// Track bidirectional sessions (canonicalize keys). Default: true.
    pub bidirectional: bool,
}

#[derive(Debug, Clone)]
pub enum FlowEvent {
    /// First packet of a flow.
    NewFlow {
        key: FlowKey,
        ts: Timestamp,
    },
    /// Subsequent packet on a known flow.
    Packet {
        key: FlowKey,
        direction: FlowDirection,
        len: usize,
        ts: Timestamp,
    },
    /// Flow ended (FIN/RST for TCP, idle timeout for UDP).
    EndedFlow {
        key: FlowKey,
        reason: EndReason,
        stats: FlowStats,
    },
}

pub enum FlowDirection {
    /// First-seen direction (initiator → responder)
    Forward,
    /// Reverse direction
    Reverse,
}

pub enum EndReason { Fin, Rst, IdleTimeout, Evicted }

pub struct FlowStats {
    pub packets_fwd: u64,
    pub packets_rev: u64,
    pub bytes_fwd: u64,
    pub bytes_rev: u64,
    pub started: Timestamp,
    pub last_seen: Timestamp,
}

impl FlowTracker {
    pub fn new() -> Self;
    pub fn with_config(c: FlowTrackerConfig) -> Self;

    /// Process a packet. May emit zero, one, or two events
    /// (NewFlow + Packet on first sight; EndedFlow when FIN/RST).
    pub fn track(&mut self, pkt: &Packet<'_>) -> FlowTrackerEvents;

    /// Sweep stale flows. Call periodically.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<FlowEvent>;

    /// Snapshot current flow stats.
    pub fn flows(&self) -> impl Iterator<Item = (&FlowKey, &FlowStats)>;
}
```

`FlowTrackerEvents` is a small inline-stack collection (up to 2
events) so we don't allocate per packet.

#### Layer 3 — TCP reassembly hook (no implementation)

We don't ship a TCP reassembler. Instead, document the integration
points:

```rust
// 1. Use FlowTracker to demultiplex.
// 2. Per flow, hand bytes to your chosen reassembler (protolens, blatta,
//    or your own). Example skeleton:

let mut tracker = FlowTracker::new();
let mut reassemblers: HashMap<FlowKey, Box<dyn YourReassembler>> = HashMap::new();

for pkt in cap.packets() {
    let evt = tracker.track(&pkt);
    for e in evt {
        match e {
            FlowEvent::NewFlow { key, .. } if key.proto == IpProto::Tcp => {
                reassemblers.insert(key, your_factory(key));
            }
            FlowEvent::Packet { key, direction, .. } => {
                // Find the TCP payload via etherparse and hand it to the
                // reassembler:
                if let Some(r) = reassemblers.get_mut(&key) {
                    r.feed(direction, &pkt);
                }
            }
            FlowEvent::EndedFlow { key, .. } => {
                reassemblers.remove(&key);
            }
        }
    }
}
```

Plus an example showing `protolens` integration end-to-end (in
`examples/flow_protolens.rs` if we go this route).

### Async integration — first-class

`flow_stream()` is the headline API, not sugar. It's the form most
users will reach for and what we should optimize the docs around.

```rust
use futures::StreamExt;

let cap = AsyncCapture::open("eth0")?;
let mut events = cap.flow_stream(FlowTrackerConfig::default());

while let Some(evt) = events.next().await {
    match evt? {
        FlowEvent::NewFlow { key, .. } => println!("+ {key:?}"),
        FlowEvent::EndedFlow { key, stats, .. } => {
            println!("- {key:?}: {} pkts, {} bytes",
                stats.packets_fwd + stats.packets_rev,
                stats.bytes_fwd + stats.bytes_rev);
        }
        _ => {}
    }
}
```

Filter / select via the standard `Stream` combinators:

```rust
let cap = AsyncCapture::open("eth0")?;
let mut tcp_only = cap
    .flow_stream(Default::default())
    .filter(|e| std::future::ready(matches!(
        e, Ok(FlowEvent::NewFlow { key, .. }) if key.proto == IpProto::Tcp
    )));
```

For users who need the raw tracker (multi-source merging, custom
batching, sync `Capture`), `FlowTracker` is plain stateful Rust:

```rust
let mut cap = AsyncCapture::open("eth0")?;
let mut tracker = FlowTracker::new();

loop {
    let mut g = cap.readable().await?;
    if let Some(batch) = g.next_batch() {
        for pkt in &batch {
            for evt in tracker.track(&pkt) {
                handle(evt).await;
            }
        }
    }
}
```

Sync works too (`for pkt in cap.packets()`) but isn't the primary
path.

### Open questions for review

1. **Buy vs build for TCP reassembly.** I'm proposing build for
   Layers 1+2 (cheap), document for Layer 3 (no netring code). Do you
   want us to also ship a Layer 3 implementation? If yes:
   - Roll our own (~600 lines, ~2 days)
   - Wrap `protolens` behind a feature flag (cheap dep, but their
     callback API doesn't fit our iterator/Stream model nicely)
   - Wrap `blatta-stream` (smaller dep, plain reassembly)

2. **`FlowKey` structure.** Use `std::net::SocketAddr` (which carries
   IPv4/IPv6 distinction) or split into `(IpAddr, u16)`? Former is
   tighter; latter is more flexible (e.g., IP-only flows for ICMP).

3. **Bidirectional canonicalization.** Default to bidirectional
   (matching gopacket / Wireshark "Conversation" view) or default to
   unidirectional and let users canonicalize? **My vote: bidirectional
   default**.

4. **Tracker eviction policy.** LRU? FIFO? Just timeout-based? **My
   vote: timeout + max_flows (oldest evicted on overflow)**.

5. **Memory management.** A `FlowTracker` with `max_flows = 100_000`
   uses ~10 MiB at full capacity (plus overhead). Tunable via config.
   Reasonable default?

6. **Naming.** `FlowTracker` vs `FlowDemux` vs `Sessions`. I prefer
   `FlowTracker` (matches industry convention).

7. **`flow_stream()` adapter — yes or no.** Adds API surface; the
   manual loop is short.

8. **Feature flag.** New `flow` feature pulling in `etherparse`
   automatically. (Currently `etherparse` is gated behind `parse`.)
   Should `flow` imply `parse` or share it?

---

## Part 3 — Feature flag layout

Proposed (additive):

```toml
[features]
default = []
tokio = ["dep:tokio", "dep:futures-core"]
af-xdp = []
channel = ["dep:crossbeam-channel"]
parse = ["dep:etherparse"]
pcap = ["dep:pcap-file"]
metrics = ["dep:metrics"]

# NEW
dedup = []                              # no extra deps
flow = ["parse", "dep:xxhash-rust"]     # implies parse (etherparse)
```

`dedup` is dep-free (FNV-1a inlined or xxhash-rust internal).
`flow` requires `parse` for header extraction.

Alternative: roll both under a single `analysis` feature. Cleaner from
the user's perspective ("turn on the analysis stuff") but coarser. **My
vote: separate features — they cost nothing.**

---

## Part 4 — Suggested phasing

Each phase ships the async stream adapter alongside the primitive —
not after. That's the user-facing API; sync support is a fallout.

### Phase 1 — `dedup` (~250 LOC)

- `Dedup` primitive: `loopback()`, `content(window, ring)`,
  `keep(&Packet) -> bool`
- **`AsyncCapture::dedup_stream(Dedup)`** + `dedup_batches(Dedup)`
- Unit tests + integration test on `lo` (paired async sender)
- Example: `examples/async_lo_dedup.rs` (async, headline)
- Sync example only as a small section in the doc, not its own file

### Phase 2 — `flow` extraction + tracker (~400 LOC)

- `flow_key(&[u8]) -> Option<FlowKey>`, `Packet::flow_key()`
- `FlowKey`, `IpProto`, `FlowDirection`
- `FlowTracker` + `FlowEvent` + `FlowStats`
- **`AsyncCapture::flow_stream(FlowTrackerConfig)`** in the same phase
- Example: `examples/async_flow_summary.rs` — print one line per flow
- Example: `examples/async_flow_filter.rs` — only matching flows

### Phase 3 — TCP reassembly hook (docs + example)

- `docs/FLOW_GUIDE.md` covering: async-first usage, filter combinators,
  feeding payloads to a third-party reassembler from a `flow_stream()`
- Example: `examples/async_flow_protolens.rs` (or chosen reassembler)
  showing how to bridge protolens's callbacks into a `Stream`

### Phase 4 — bump 0.7.0, CHANGELOG, publish

---

## Part 5 — Decision matrix

Items needing your call before I start:

| # | Question | My recommendation |
|---|----------|-------------------|
| 1.1 | Ring size + window for `Dedup::loopback()` | 256 entries, 1 ms |
| 1.2 | Ship `dedup_stream()` adapter in Phase 1 | **Yes** (async-first) |
| 1.3 | Builder integration (Layer 3) for dedup | Defer; revisit if asked |
| 1.4 | `Dedup` naming | Keep `Dedup` |
| 1.5 | Dedup feature flag | Always on (no flag) |
| 2.* | Flow / session tracking decisions | See [`flow-session-tracking-design.md`](./flow-session-tracking-design.md) Part 7 (13 items) |
| 3 | Combined `analysis` feature vs separate | Separate (`dedup`, `flow`) |

---

## Sources consulted

- [Wireshark `editcap` man page](https://www.wireshark.org/docs/man-pages/editcap.html)
  — canonical pcap-dedup primitive (MD5 + length + window).
- [Wireshark DuplicatePackets wiki](https://wiki.wireshark.org/DuplicatePackets)
  — context on why duplicates appear.
- [gopacket `tcpassembly`](https://pkg.go.dev/github.com/google/gopacket/tcpassembly)
  — StreamFactory pattern for TCP reassembly.
- [gopacket `reassembly`](https://pkg.go.dev/github.com/google/gopacket/reassembly)
  — newer reassembler with assembler context.
- [protolens](https://github.com/chunhuitrue/protolens)
  — Rust TCP reassembly + protocol analysis (callback-based, sync).
- [blatta-stream](https://github.com/bazz-066/blatta-stream),
  [rs-flow_reassembler](https://github.com/DominoTree/rs-flow_reassembler)
  — alternative Rust reassembly crates, smaller scope.
