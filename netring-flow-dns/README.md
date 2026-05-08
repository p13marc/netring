# netring-flow-dns

Passive DNS observer for [`netring-flow`](https://crates.io/crates/netring-flow).

[![crates.io](https://img.shields.io/crates/v/netring-flow-dns.svg)](https://crates.io/crates/netring-flow-dns)
[![docs.rs](https://img.shields.io/docsrs/netring-flow-dns)](https://docs.rs/netring-flow-dns)

## What it is

A DNS message parser plus a [`FlowExtractor`] tap (`DnsUdpObserver`)
that wraps any inner extractor and fires DNS events on every UDP/53
packet it sees. Built on [`simple-dns`](https://crates.io/crates/simple-dns).

Includes a per-flow query/response correlator that pairs responses
with their queries by 16-bit transaction ID and reports round-trip
latency.

**Passive only** — no resolution, no validation, no DNSSEC checks.

## Scope

- **UDP/53 only** in v0.1. TCP/53 (large responses, AXFR/IXFR) and
  DoT (TLS/853) are deferred.
- **Common record types** decoded: A, AAAA, CNAME, NS, PTR, MX. TXT
  surfaces with empty bodies (current `simple-dns` API limitation —
  raw TXT is on the roadmap). Everything else lands in
  `DnsRdata::Other { rtype, data }`.
- **No reassembly** is required — UDP datagrams parse standalone.

## Quick start — parser only

```rust,no_run
use netring_flow_dns::{parse_message, DnsParseResult};

let payload: &[u8] = b"";  // your UDP/53 payload
match parse_message(payload) {
    Ok(DnsParseResult::Query(q))    => println!("Q  id={:#x} {}", q.transaction_id, q.questions.len()),
    Ok(DnsParseResult::Response(r)) => println!("R  id={:#x} rcode={:?}", r.transaction_id, r.rcode),
    Err(_) => {}  // malformed — ignore
}
```

## Integrated tap — `DnsUdpObserver`

`DnsUdpObserver<E, H>` implements `FlowExtractor`. Slot it in where
your extractor would have gone; flow tracking continues unchanged
and DNS events fire as a side effect.

```rust,no_run
use netring_flow::extract::FiveTuple;
use netring_flow::FlowTracker;
use netring_flow_dns::{DnsHandler, DnsQuery, DnsResponse, DnsUdpObserver};

struct Logger;
impl DnsHandler for Logger {
    fn on_query(&self, q: &DnsQuery) {
        println!("Q  {:#x} q={}", q.transaction_id, q.questions.len());
    }
    fn on_response(&self, r: &DnsResponse) {
        println!("R  {:#x} rcode={:?} answers={}", r.transaction_id, r.rcode, r.answers.len());
    }
    fn on_unanswered(&self, q: &DnsQuery) {
        println!("⏱  {:#x}", q.transaction_id);
    }
}

let observer = DnsUdpObserver::new(FiveTuple::bidirectional(), Logger);
let mut tracker: FlowTracker<_, ()> = FlowTracker::new(observer);
// drive packets through `tracker.track(...)` as usual
```

See [`examples/dns_log.rs`](examples/dns_log.rs) for a complete pcap
replay tool.

## Query/response correlation

The observer keeps a bounded `HashMap<(flow_key, tx_id), DnsQuery>`
internally. When a response with a matching `(flow, tx_id)` arrives,
the elapsed time is attached as `DnsResponse::elapsed`.

Periodically call `observer.sweep_unanswered(now)` to flush queries
that exceeded `DnsConfig::query_timeout` (default 30 s); the handler's
`on_unanswered` runs for each.

Scoping by flow key prevents cross-flow ID collisions when multiple
clients reuse the same 16-bit space.

## What's not done (yet)

- TCP/53 reassembly (large responses, zone transfer)
- DoT / DoH / DoQ
- TXT record body decoding
- DNSSEC signature validation
- EDNS(0) option decoding (the OPT pseudo-record falls into `Other`)

## License

Dual MIT / Apache-2.0 (your choice).
