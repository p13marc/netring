# Migrating netring 0.29 → 0.30

0.30 adopts **flowscope 0.23** — the inline-proxy / sans-IO L7 cycle — and
exposes its HTTP/2 surface as a netring `Protocol` marker.

> **Version note.** This ships as **`0.30.0`** — a pre-1.0 minor. The `1.0`
> API-freeze is deferred and tracked in
> [#37](https://github.com/p13marc/netring/issues/37).

**There is nothing to do.** No netring API changed, and none of flowscope
0.23's breaking changes reach netring's surface — verified by building and
testing the whole workspace against 0.23 before the bump. Bump the version and
rebuild.

The rest of this document is what you *gain*, and one behaviour change
inherited from flowscope that is worth knowing about.

---

## 1. New: the `Http2` protocol marker (`http2` feature)

```rust
use netring::protocol::builtin::Http2;

monitor.on::<Http2>(|ev, ctx| {
    if let flowscope::http2::Http2Event::Head(head) = ev {
        println!("stream {} -> {:?}", head.stream_id, head.authority());
    }
});
```

Three things to internalise before using it.

**The stream is the key, not the side.** h2 multiplexes: one connection
carries many concurrent requests in both directions. `ctx`'s side tells you
which peer sent the bytes; what identifies a request is `stream_id` on the
event. A handler that correlates on the flow alone will interleave unrelated
requests.

**Dispatch is by signature, and that widens the kernel prefilter.** There is
no port to match: cleartext h2 (h2c) has no standard one, and h2 over TLS is
opaque to a passive tap. `Http2::dispatch()` is therefore
`Dispatch::Signature`, over flowscope's exact 24-byte preface check — and the
subscription engine maps any signature dispatch to `Predicate::Always`,
because a signature cannot be evaluated in the kernel. On a busy link that is
the difference between a narrow BPF filter and none at all.

That is why `http2` is in `all-parsers` but **not** in the curated `monitor` /
`monitor-quickstart` umbrellas: enabling the feature costs nothing, but paying
the prefilter should be a deliberate `.on::<Http2>()`.

**A gRPC call that failed still returns HTTP `200`.** The real status is
`grpc-status`, in the trailers — or, for a Trailers-Only response, in the
stream's single `HEADERS` block, which arrives as a `Head` rather than as
`Trailers`. `flowscope::http2::grpc_status_of(&head)` covers that case. A
handler that logs `:status` records every application failure as a success.

## 2. Inherited: TCP reassembly is now bounded by default

`FlowTrackerConfig::max_reassembler_buffer` changed in flowscope 0.23 from
`None` to `Some(1 MiB)` per side. Any netring pipeline that did not set it
explicitly was previously unbounded and now is not.

The existing `OverflowPolicy::SlidingWindow` default applies, so a flow that
exceeds the cap **survives** — the oldest bytes are dropped and counted in
`FlowStats::reassembly_bytes_dropped_oversize_initiator` / `_responder`.
Truncation is visible rather than silent. If a parser starts seeing gaps it
did not see under 0.29, check those counters and raise the cap:

```rust
let mut cfg = FlowTrackerConfig::default();
cfg.max_reassembler_buffer = Some(16 * 1024 * 1024);
```

`None` still means unbounded and is still supported — it is only safe when you
control the traffic.

## 3. Inherited fixes, no action needed

flowscope 0.23 fixed several things netring gets for free:

- **Chunked HTTP/1 bodies are framed.** They were not decoded at all before;
  a clean FIN no longer looks like a parse error either.
- **RFC 9112 §6.3 request-smuggling defense** in the streaming HTTP path.
- **Per-flow cleanup no longer depends on `Ended` being emitted**, so shedding
  events under load no longer leaks a reassembler pair and a parser per flow.
- **`MemcapPolicy` behaves as each variant documents** — `DropPacket` actually
  refuses the segment, `PassThrough` actually keeps the flow.
- **QUIC CRYPTO reassembly is bounded** on connections, TTL, bytes, and frames.
- **`PortScanDetector` is capacity-bounded** (10 000 sources, LRU).

See flowscope's
[`docs/migration-0.22-to-0.23.md`](https://docs.rs/crate/flowscope/0.23.0)
for the full list.
