# Test pcap fixtures

These three pcaps drive the integration tests in
`netring-flow/tests/pcap_*.rs` and the L7 bridges in Tier-2 crates.

| File | Contents | Bytes |
|------|----------|-------|
| `http_session.pcap`  | A complete TCP HTTP/1.1 exchange (3WHS, GET / 200 OK, FIN/FIN/ACK) | ~880 |
| `dns_queries.pcap`   | UDP/53 query/response pairs, NXDOMAIN, plus a lone unanswered query | ~620 |
| `mixed_short.pcap`   | TCP exchange, UDP one-way, ICMP echo, more UDP DNS — for filter-style tests | ~525 |

## Privacy

All packets are **synthetic**. Generated programmatically from
`netring-flow/examples/generate_fixtures.rs` using
`extract::parse::test_frames` (the same builders used by unit
tests). No real network traffic, no real hosts, no MAC addresses
that would identify a real machine.

## Regenerating

```
cargo run -p netring-flow --example generate_fixtures --features test-helpers
```

The output is deterministic — re-running produces byte-identical
files. Re-run only when you want to change the synthetic traffic
shape.
