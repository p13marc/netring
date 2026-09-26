# Migrating netring 0.30 → 0.31

0.31 adopts **flowscope 0.25**, whose session engine was redesigned,
and rebuilds netring's session / datagram streams on it. Until 0.30 the
streams carried their own copy of flowscope's engine (a tracker, a
reassembler map and a parser loop), and the copy had drifted: parser
poison was ignored, `DropFlow` wedged flows silently, reassembly stats
never reached `FlowStats`, datagram `side` was derived from address
order. Now `SessionStream` *is* flowscope's `SessionDriver` behind an
async front, and behaves exactly like `PcapSessionStream`, flowscope's
typed `Driver`, and therefore the `Monitor`.

> **Version note.** `0.31.0` is a pre-1.0 minor; `netring-exporters`
> moves to `0.7.0` for the dependency bump (its API is unchanged).

See also flowscope's
[`migration-0.24-to-0.25.md`](https://github.com/p13marc/flowscope/blob/master/docs/migration-0.24-to-0.25.md).

---

## 1. `SessionEvent` is flowscope's

`netring::flow::SessionEvent` now re-exports `flowscope::SessionEvent`.
Differences from netring 0.30's own type:

- `Started` gains `l4`; `Closed` gains `ts`.
- New `ParserClosed { key, parser_kind, reason, detail, ts }` — the
  parser gave up early (see §2).
- New `Tick { key, stats, ts }` — only when
  `FlowTrackerConfig::flow_tick_interval` is set.

Add `..` to struct patterns that listed every field:

```rust
// Before
SessionEvent::Started { key, side, orientation, ts } => {}
// After
SessionEvent::Started { key, side, orientation, ts, .. } => {}
```

The module `netring::async_adapters::session_event` is gone; import
from `netring::flow`.

## 2. Parser failures close the parser, not the flow

| Situation | 0.30 | 0.31 |
|---|---|---|
| parser `is_poisoned()` | ignored — kept feeding | `ParserClosed { reason: ParseError, detail: poison_reason }`, never fed again |
| parser `is_done()` | ignored | `ParserClosed { reason: ParserDone }` |
| bytes missing (lost packet) | every later byte of the side silently dropped | reported via `SessionParser::on_gap`; default closes the parser (`StreamGap`) |
| `OverflowPolicy::DropFlow` cap hit | side silently wedged, flow ended as `Fin` | `ParserClosed { reason: BufferOverflow }`, `Closed.stats.reassembly_stop_*` set |

The flow itself always ends later with its transport reason
(`Closed { reason: Fin | Rst | IdleTimeout | Evicted | ForceClosed }`).
A parser is never re-created mid-flow.

If your parser used to emit an in-band "desync" message because
poisoning had no effect, poisoning now works: return `true` from
`is_poisoned()` and read `ParserClosed`.

A parser that can resynchronise after missing bytes should override
`on_gap` and return `GapResponse::Continue`.

## 3. Anomalies are opt-in per stream

Reassembly anomalies (`StreamGap`, `BufferOverflow`,
`RetransmittedSegment`, `OutOfOrderSegment`, `ReassemblerHighWatermark`,
`TcpRexmitInconsistency`), parser poison (`SessionParseError`) and
tracker pressure are emitted when you ask:

```rust
let stream = cap
    .flow_stream(FiveTuple::bidirectional())
    .session_stream(MyParser::default())
    .with_emit_anomalies(true);
```

(0.30's streams never produced most of them.)

## 4. Stats

`Closed.stats` and `snapshot_flow_stats()` now include the reassembly
diagnostics: `reassembly_gaps_*`, `reassembly_gap_bytes_*`,
`retransmits_*`, `reassembler_high_watermark_*`,
`reassembly_bytes_dropped_oversize_*`, `reassembly_dropped_ooo_*`,
`reassembly_stop_*`. `snapshot_flow_stats()` yields owned
`(K, FlowStats)` pairs.

## 5. Offline replay

- Idle timeouts fire mid-replay: the pcap streams sweep on packet time
  every `sweep_interval`. A long pause in the capture ends the flow as
  it would have live (0.30 kept every flow open until EOF).
- `PcapFlowStream` / `PcapSessionStream` / `PcapDatagramStream` gain
  `with_dedup` (use `Dedup::content`: capture files carry no packet
  direction) and `with_monotonic_timestamps`.
- pcapng timestamps are correct for every `if_tsresol` (0.30 read a
  µs-resolution pcapng 1000× too early).

## 6. Monitor

No API change beyond `ParserClosed<P>` gaining `detail` (and
`ParserClosed::new` taking it). Behaviour: the builder's reassembly
settings (`reassembly_memcap`, `tcp_overlap_policy`,
`infer_tcp_initiator`, …) now reach the L7 parsers, and a protocol's
`ParserClosed<P>` fires only for flows its parser actually received
data on, before that flow's `FlowEnded`.

## 7. Per-source multi-capture

To configure sources individually (a BPF filter per interface, a pcap
tap per interface, dedup only on `lo`), build the per-source streams
yourself and fan them in:

```rust
let lo = AsyncCapture::open("lo")?
    .flow_stream(FiveTuple::bidirectional())
    .with_dedup(Dedup::loopback())
    .session_stream(MyParser::default());
let eth = AsyncCapture::open_with_filter("eth0", filter)?
    .flow_stream(FiveTuple::bidirectional())
    .with_pcap_tap(writer)
    .session_stream(MyParser::default());
let mut merged = MultiSessionStream::from_streams([
    ("lo".to_string(), lo),
    ("eth0".to_string(), eth),
]);
```

`SessionStream` and `DatagramStream` are now also re-exported at the
crate root.
