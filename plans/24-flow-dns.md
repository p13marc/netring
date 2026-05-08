# Plan 24 — `netring-flow-dns` companion crate

## Summary

Bridge DNS query/response observation into `FlowStream`. Most DNS
runs over UDP/53 (no reassembly needed) but some uses TCP/53 or
DNS-over-TLS (DoT, port 853) where the L7 parser sits behind our
reassembler. This crate handles both, correlates queries with
responses by 16-bit transaction ID, and emits `DnsQuery` /
`DnsResponse` events.

## Status

Not started.

## Prerequisites

- Plans 00–04 published.
- Plan 12 fixtures (`dns_queries.pcap`).

## Out of scope

- DNS-over-HTTPS (DoH). That's HTTP/2 over TLS — way out of scope.
- DNSSEC validation. We surface RRSIG/DNSKEY records as opaque
  bytes; we don't verify signatures.
- DNS spoofing detection. We could detect mismatched query/response
  pairs as a v0.2 feature.

---

## Why this crate

DNS is the most common L7 protocol that does NOT live behind TCP
reassembly. UDP/53 traffic is one packet → one query (or response).
That makes the integration shape different from HTTP/TLS:

- **HTTP/TLS**: byte stream from a Reassembler → events.
- **DNS over UDP**: per-packet → events. We hook the **flow tracker
  directly**, not the reassembler.
- **DNS over TCP** (rare, for large responses): reassembler-based,
  with a 2-byte length prefix per message.

This crate covers both transports.

---

## Files

### NEW

```
netring-flow-dns/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs
│   ├── handler.rs          # DnsHandler trait
│   ├── parser.rs           # parse_dns_message wrapper
│   ├── udp_observer.rs     # FlowExtractor wrapper that fires DNS events
│   ├── tcp_reassembler.rs  # AsyncReassembler for DoT / TCP/53
│   └── correlator.rs       # query/response matching by transaction ID
└── examples/
    └── dns_log.rs          # live: log every query + response
```

---

## API

### Events

```rust
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub transaction_id: u16,
    pub flags: DnsFlags,
    pub questions: Vec<DnsQuestion>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub transaction_id: u16,
    pub flags: DnsFlags,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
    pub rcode: DnsRcode,
    pub timestamp: Timestamp,
    /// Time elapsed between matching `DnsQuery` and this response.
    /// `None` if no matching query was seen (response without query).
    pub elapsed: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: DnsRecordType,
    pub qclass: DnsClass,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: DnsRecordType,
    pub rclass: DnsClass,
    pub ttl: u32,
    pub data: DnsRdata,
}

#[derive(Debug, Clone)]
pub enum DnsRdata {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    NS(String),
    MX { priority: u16, exchange: String },
    TXT(Vec<Vec<u8>>),
    SOA { /* ... */ },
    Other { rtype: u16, data: Bytes },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode {
    NoError, FormErr, ServFail, NXDomain, NotImpl, Refused, /* ... */ Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsFlags(pub u16);
impl DnsFlags {
    pub fn is_response(&self) -> bool { self.0 & 0x8000 != 0 }
    pub fn is_authoritative(&self) -> bool { self.0 & 0x0400 != 0 }
    pub fn is_truncated(&self) -> bool { self.0 & 0x0200 != 0 }
    pub fn is_recursion_desired(&self) -> bool { self.0 & 0x0100 != 0 }
    pub fn is_recursion_available(&self) -> bool { self.0 & 0x0080 != 0 }
}

pub trait DnsHandler: Send + Sync + 'static {
    fn on_query(&self, _q: &DnsQuery) {}
    fn on_response(&self, _r: &DnsResponse) {}
    /// Called when a query is observed but no response is seen
    /// within `query_timeout` (config option).
    fn on_unanswered(&self, _q: &DnsQuery) {}
}
```

### UDP observer

UDP/53 doesn't go through a reassembler. We hook into the
`FlowTracker` via a side channel — a custom flow extractor that
*also* fires DNS events on the way through:

```rust
/// A `FlowExtractor` wrapper that intercepts UDP/53 packets, fires
/// DNS events via the handler, and delegates flow extraction to
/// `inner`.
pub struct DnsUdpObserver<E: FlowExtractor, H: DnsHandler> {
    pub inner: E,
    pub handler: Arc<H>,
    pub config: DnsConfig,
    correlator: Arc<Mutex<Correlator>>,
}

impl<E, H> FlowExtractor for DnsUdpObserver<E, H>
where E: FlowExtractor, H: DnsHandler
{
    type Key = E::Key;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        // First, parse the inner extractor (so the FlowTracker still
        // sees the flow normally).
        let result = self.inner.extract(view);

        // Now, peek for DNS over UDP/53.
        if let Some(parsed_udp) = peek_udp(view.frame)
            && (parsed_udp.src_port == 53 || parsed_udp.dst_port == 53)
        {
            if let Ok(msg) = parser::parse_dns_message(parsed_udp.payload) {
                if msg.flags.is_response() {
                    let elapsed = self.correlator.lock().unwrap().match_response(msg.transaction_id, view.timestamp);
                    self.handler.on_response(&msg.into_response(view.timestamp, elapsed));
                } else {
                    self.correlator.lock().unwrap().record_query(msg.transaction_id, view.timestamp);
                    self.handler.on_query(&msg.into_query(view.timestamp));
                }
            }
        }

        result
    }
}
```

This is unconventional — using the extractor as a "tap" — but it
fits naturally because UDP/53 is per-packet. Document the pattern
clearly.

### TCP reassembler

For TCP/53 and DoT (port 853 with TLS):

```rust
pub struct DnsTcpReassembler {
    handler: Arc<dyn DnsHandler>,
    buffer: BytesMut,
    side: FlowSide,
    correlator: Arc<Mutex<Correlator>>,
}

impl AsyncReassembler for DnsTcpReassembler {
    fn segment(&mut self, _seq: u32, payload: Bytes) -> /* ... */ {
        // TCP/53 prefixes each DNS message with a 2-byte length.
        // Loop: peek len, if buffer has len+2 bytes, parse, emit, advance.
        Box::pin(async move { /* ... */ })
    }
}
```

### Factory

```rust
pub struct DnsFactory<H: DnsHandler> { ... }

impl<H: DnsHandler> DnsFactory<H> {
    /// For DNS over UDP — wraps an existing FlowExtractor.
    pub fn udp_observer<E: FlowExtractor>(handler: H, inner: E)
        -> DnsUdpObserver<E, H>;

    /// For DNS over TCP (port 53) or DoT (port 853) — used as
    /// AsyncReassemblerFactory.
    pub fn tcp(handler: H) -> DnsTcpFactory<H>;
}

pub struct DnsTcpFactory<H>(...);
impl<K, H> AsyncReassemblerFactory<K> for DnsTcpFactory<H>
where K: ..., H: DnsHandler { ... }
```

### Correlator

```rust
struct Correlator {
    pending: HashMap<u16, Timestamp>,  // tx_id -> query timestamp
    timeout: Duration,
}

impl Correlator {
    fn record_query(&mut self, tx_id: u16, ts: Timestamp);
    fn match_response(&mut self, tx_id: u16, ts: Timestamp) -> Option<Duration>;
    fn sweep_unanswered(&mut self, now: Timestamp) -> Vec<u16>;
}
```

The correlator runs a sweep periodically (driven by the FlowStream's
existing sweep tick — or by a separate task; see implementation
step 9).

---

## DNS parsing library choice

Two reasonable options:

### Option A: `simple-dns`

- Lightweight, supports parsing + building.
- API: `Packet::parse(buf)` returns the structured form.
- ~300 KB compiled.

### Option B: `hickory-proto`

- Part of the `hickory-dns` family (formerly `trust-dns`).
- Heaviest of the bunch but most complete.
- Has built-in support for many record types.

**Decision: `simple-dns`** for v1. Lower dep weight. If users need
more record types, we add an `Other { rtype, data: Bytes }` variant
and they parse the tail themselves.

---

## Cargo.toml

```toml
[package]
name = "netring-flow-dns"
version = "0.1.0"
# ... workspace inheritance

description = "Passive DNS observer for netring-flow"
keywords = ["dns", "netring", "flow", "passive", "monitoring"]
categories = ["network-programming", "parser-implementations"]

[dependencies]
netring-flow = { version = "0.1", path = "../netring-flow", default-features = false, features = ["tracker", "reassembler"] }
simple-dns = "0.7"
bytes = { workspace = true }
thiserror = { workspace = true }

[dev-dependencies]
netring-flow-pcap = { version = "0.1", path = "../netring-flow-pcap" }
```

---

## Implementation steps

1. **Skeleton crate.**
2. **Define event types** (`DnsQuery`, `DnsResponse`, `DnsRecord`,
   etc.). Wrap simple-dns types into our owned forms (we want a
   stable user-facing API independent of simple-dns version).
3. **`parser.rs`** — `parse_dns_message(bytes) -> Result<DnsMessage>`
   that wraps simple-dns and converts to our types.
4. **`correlator.rs`** — query/response matching by transaction ID.
   Bounded to `max_pending = 10_000` to avoid memory blowup.
5. **UDP observer**:
   - Implement `peek_udp(frame) -> Option<UdpInfo>` (a tiny
     etherparse-based helper).
   - Implement `DnsUdpObserver<E, H>` as a `FlowExtractor` wrapper.
6. **TCP reassembler**:
   - Implement `DnsTcpReassembler` (length-prefixed DNS messages).
   - Implement `DnsTcpFactory`.
7. **Factory** — `DnsFactory::udp_observer` + `DnsFactory::tcp`.
8. **Correlator sweep**: simplest is to sweep on every UDP DNS
   packet (cheap, since it's `HashMap::retain` bounded by
   `max_pending`). Document.
9. **Examples**:
   - `dns_log.rs` — live capture, print queries + responses.
10. **Integration test** using `dns_queries.pcap` from Plan 12.

---

## Edge cases

- **Truncated UDP DNS responses** (TC bit set). The full response
  follows over TCP/53. Document; users who care correlate by
  (client, query_name) across UDP+TCP.
- **DNS over QUIC (DoQ, RFC 9250).** Out of scope. Mention in
  README.
- **EDNS(0) / OPT records.** Visible as additional records. simple-dns
  parses them; our `DnsRecord::data` will be `DnsRdata::Other`.
- **Compression pointers in name fields.** simple-dns handles. If a
  pointer points to garbage (malformed packet), parse fails → we
  silently drop and increment a counter.
- **Unanswered queries.** If a query has no response within
  `query_timeout` (default 30s), `on_unanswered` fires. Useful for
  tracking lost DNS traffic.
- **Mixed-direction observation.** On `lo` you see queries and
  responses both. On a typical resolver-side capture you see
  responses but not the upstream queries. The correlator handles
  both — responses without matching queries fire with
  `elapsed = None`.

---

## Tests

### Unit

- `parse_a_query` — synthetic A-record query, expect 1 question.
- `parse_a_response` — A-record response, expect 1 answer of type
  `DnsRdata::A`.
- `parse_nxdomain` — expect `DnsRcode::NXDomain`.
- `parse_aaaa` — IPv6 record.
- `correlator_matches_query_response` — record query, match
  response, verify elapsed > 0.
- `correlator_sweep_emits_unanswered` — record query, advance
  past timeout, sweep, verify entry returned.

### Integration

- `dns_queries_pcap` — using Plan 12's fixture, expect ≥1 query
  + 1 response.

---

## Acceptance criteria

- [ ] Crate builds, ≥6 unit tests pass.
- [ ] ≥1 integration test using `dns_queries.pcap`.
- [ ] `dns_log.rs` example runs against a real `dig` capture.
- [ ] Both UDP and TCP transports tested.
- [ ] README documents the unconventional UDP-via-extractor pattern
      with a clear diagram.
- [ ] `cargo publish -p netring-flow-dns --dry-run` succeeds.

---

## Risks

1. **The "extractor as tap" pattern is unusual.** Document
   thoroughly. Alternative: add a `FlowTracker::on_packet` hook
   that runs synchronously per-packet regardless of L4. v0.2
   discussion.
2. **simple-dns API churn.** Pin a minor version.
3. **Correlator memory.** Pending queries grow until matched or
   timed out. Bound at `max_pending = 10_000` (rough cap on
   in-flight DNS traffic). Document.
4. **Mutex contention on the correlator.** Per-packet `lock()` —
   could matter at high QPS. v0.2 might use a shard-by-tx_id
   approach. v1: accept the cost.
5. **Transaction ID collisions.** Resolvers reuse 16-bit IDs
   across hosts; our correlator scopes per (tracker instance), not
   per (flow). Two simultaneous queries with the same ID from
   different clients would mis-correlate. **Fix**: key the
   correlator by (flow_key, tx_id), not by tx_id alone. Ensures
   per-flow correctness.

---

## Effort

- LOC: ~700.
- Time: 1.5 days.

---

## What this unlocks

- DNS observability — passive resolver monitoring, NXDOMAIN
  tracking, slow-query detection.
- A reference for "non-byte-stream L7 protocol" wiring (UDP-based,
  no reassembly).
- Cross-protocol pattern: the (tx_id, query, response, elapsed)
  pattern generalizes to any request/response protocol with a
  correlation field — RADIUS, NTP, SIP. Documented as such.
