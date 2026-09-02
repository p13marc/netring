# Migrating netring 0.29 → 0.30

0.30 adopts **flowscope 0.24** — the inline-proxy / sans-IO L7 cycle — and
exposes its HTTP/2 surface as a netring `Protocol` marker.

> **Version note.** This ships as **`0.30.0`** — a pre-1.0 minor. The `1.0`
> API-freeze is deferred and tracked in
> [#37](https://github.com/p13marc/netring/issues/37).

**The flowscope bump asks nothing of you.** No netring API changed because of
it, and none of flowscope 0.23/0.24's breaking changes reach netring's surface
— they are confined to the inline-proxy types (`HttpProxyParser`,
`RequestHead`) that netring does not consume. Verified by building and testing
the whole workspace against 0.24 before the bump.

There *is* one break in this release, and it is netring's own: the publicly
re-exported `etherparse` moved 0.16 → 0.21. See §4.

The rest of this document is what you *gain*, and one behaviour change
inherited from flowscope that is worth knowing about.

---

## 1. New: the `Http2` protocol marker (`http2` feature)

```rust
use netring::prelude::Http2;   // also `netring::protocol::Http2`

Monitor::builder()
    .interface("eth0")
    .protocol::<Http2>()       // declares the marker AND installs the parser slot
    .on::<Http2>(|ev: &flowscope::http2::Http2Event| {
        if let flowscope::http2::Http2Event::Head(head) = ev {
            println!("stream {} -> {:?}", head.stream_id, head.authority());
        }
        Ok(())
    })
    .build()?;
```

`.on::<Http2>()` on its own is not enough — as for every other marker, the
`.protocol::<Http2>()` call is what installs the parser slot, and `build()`
rejects a handler for an undeclared protocol with
`BuildError::HandlerForUnregisteredProtocol` rather than letting it silently
never fire.

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

The prefilter is not the whole bill: a signature dispatch also probes **every
TCP flow**, holding one probe state per flow (map capped at 65 536) and up to
16 KiB of buffered frames for replay. Size that before enabling it on a busy
tap.

Note also that this covers **prior-knowledge h2c**, not h2c negotiated over an
HTTP/1 `Upgrade` — there the preface only arrives after the `101`, by which
point the probe (4 packets, 64 bytes per side) has already given up.

That is why `http2` is in `all-parsers` but **not** in the curated `monitor` /
`monitor-quickstart` umbrellas: enabling the feature costs nothing, but paying
the prefilter should be a deliberate `.protocol::<Http2>()`.

**A gRPC call that failed still returns HTTP `200`.** The real status is
`grpc-status`, in the trailers — or, for a Trailers-Only response, in the
stream's single `HEADERS` block, which arrives as a `Head` rather than as
`Trailers`. `flowscope::http2::grpc_status_of(&head)` covers that case. A
handler that logs `:status` records every application failure as a success.

## 2. New: network-namespace capture on `MonitorBuilder` (#135)

0.29 shipped `NetNs` and `CaptureBuilder::netns`, but only on the low-level
`Capture` path — so watching a container meant rebuilding your capture on the
raw builder and giving up the Monitor's flow table, detectors and bandwidth
accounting. Now:

```rust
use std::sync::Arc;
use netring::{monitor::{Monitor, Backend}, netns::NetNs};

let ns = Arc::new(NetNs::from_pid(container_pid)?);
Monitor::builder()
    .capture("eth0", Backend::af_packet())              // host namespace
    .capture_in_netns("eth0", Backend::af_packet(), ns) // container namespace
    .protocol::<Tcp>()
    .build()?;
```

**Read this before relying on it: flow keys still alias across namespaces.**
A `Monitor` is fan-in — every source feeds one shared flow tracker — and the
flow key is a bare 5-tuple with no namespace dimension. Two containers using
the same RFC1918 range produce *identical* keys, and the tracker merges them
into one flow, silently. Nothing you can configure changes that; separating
them needs a tracker per namespace, which means **one `Monitor` per
namespace**.

What you do get is per-source attribution. Every event already carries
`ctx.source`, and the new `Monitor::capture_sources()` returns the sources in
`SourceIdx` order so you can map that index back:

```rust
let sources = monitor.capture_sources();
// in a handler:
let src = &sources[ctx.source.0 as usize];
tracing::info!(iface = %src.interface, netns = ?src.netns_label, "event");
```

Three more things worth knowing:

- **AF_PACKET only.** `Backend::Auto` resolves to AF_PACKET for a namespaced
  source rather than preferring AF_XDP as it usually would. Naming AF_XDP
  *explicitly* is `BuildError::NetnsBackendUnsupported` — an error, not a
  silent downgrade.
- **`build()` fails fast on privilege.** It probes each distinct namespace with
  one `setns`, so a missing `CAP_SYS_ADMIN` (which is on top of `CAP_NET_RAW`)
  surfaces at build rather than on the first poll of a spawned run loop.
- **New `Error::Netns { label, source }`**, also returned by
  `CaptureBuilder::netns`. If you were matching `Error::Io` or
  `Error::PermissionDenied` to detect a namespace failure, match this instead
  — the old bare `EPERM` named `CAP_NET_RAW`, which is the wrong capability for
  `setns`, and could not tell you which namespace failed.

## 3. Inherited: TCP reassembly is now bounded by default

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

## 4. Breaking: the re-exported `etherparse` moved 0.16 → 0.21

netring re-exports `etherparse` in its own public API — `Packet::parse` and
`PacketOwned::parse` return `etherparse::SlicedPacket` and
`etherparse::err::packet::SliceError` — so the bump is visible to you and your
`etherparse` dependency has to move with netring's.

In practice the break is two new enum variants, both of which an exhaustive
`match` has to account for:

- `NetSlice::Arp(_)` (etherparse 0.17, ARP support)
- `TransportSlice::Igmp(_)` (etherparse 0.21, IGMP support)

0.18 also renamed `SlicedPacket`'s `vlan` field to `link_exts` and
`Ipv4Ecn`/`Ipv4Dscp` to `IpEcn`/`IpDscp`; netring never surfaced those, but
code that reached into a `SlicedPacket` directly will see them.

Note that flowscope still pins etherparse 0.16, so the dependency tree carries
both versions. Nothing crosses the boundary — flowscope exposes no etherparse
type in its public API — but `cargo deny` will report the duplicate.

## 5. Inherited fixes, no action needed

flowscope 0.23/0.24 fixed several things netring gets for free:

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
[`docs/migration-0.22-to-0.23.md`](https://docs.rs/crate/flowscope/0.24.1)
for the full list.
