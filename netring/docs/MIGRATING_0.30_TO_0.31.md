# Migrating netring 0.30 → 0.31

0.31 adopts **flowscope 0.25**, whose session engine was redesigned,
and rebuilds netring's session / datagram streams and the Monitor's
lifecycle on it. Until 0.30 the streams carried their own copy of
flowscope's engine (a tracker, a reassembler map and a parser loop),
and the copy had drifted: parser poison was ignored, `DropFlow` wedged
flows silently, reassembly stats never reached `FlowStats`, datagram
`side` came from address order. The Monitor never swept its flow table,
routed `ParserClosed<P>` by transport, and could deliver a flow's last
messages after its `FlowEnded`.

Now `SessionStream` *is* flowscope's `SessionDriver` behind an async
front, and behaves exactly like `PcapSessionStream`, flowscope's typed
`Driver`, and therefore the `Monitor`.

> **Version note.** `0.31.0` is a pre-1.0 minor; `netring-exporters`
> moves to `0.7.0` for the dependency bump (its API is unchanged).

See also flowscope's
[`migration-0.24-to-0.25.md`](https://github.com/p13marc/flowscope/blob/master/docs/migration-0.24-to-0.25.md)
if you use flowscope directly.

---

## 1. `SessionEvent` is flowscope's

`netring::flow::SessionEvent` re-exports `flowscope::SessionEvent`.
Differences from netring 0.30's own type:

- `Started` gains `l4`; `Closed` gains `ts`.
- New `ParserClosed { key, parser_kind, reason, detail, ts }` — the
  parser stopped for this flow (§2).
- New `ParserSideStopped { key, parser_kind, side, reason, detail, ts }`
  — the parser stopped reading one side (§2).
- New `Tick { key, stats, ts }` — only when
  `FlowTrackerConfig::flow_tick_interval` is set.

Add `..` to struct patterns that listed every field, and a `_` arm
(the enum is `#[non_exhaustive]`):

```rust
// Before
SessionEvent::Started { key, side, orientation, ts } => {}
// After
SessionEvent::Started { key, side, orientation, ts, .. } => {}
```

The module `netring::async_adapters::session_event` is gone; import
from `netring::flow`.

## 2. Parser failures stop the parser, never the flow

| Situation | 0.30 | 0.31 |
|---|---|---|
| parser `is_poisoned()` | ignored — kept feeding | `ParserClosed { reason: ParseError, detail: poison_reason }`, never fed again |
| parser `is_done()` | ignored | `ParserClosed { reason: ParserDone }` |
| bytes missing (lost packet) | every later byte of the side silently dropped | `SessionParser::on_gap` decides; the default stops that **side**: `ParserSideStopped { reason: StreamGap }` — the other side keeps being parsed |
| a side's buffer cap / memcap hit | side silently wedged, flow ended as `Fin` | `ParserSideStopped { reason: BufferOverflow }`, `Closed.stats.reassembly_stop_*` set |
| both sides stopped | — | `ParserClosed` (detail `"both sides stopped"`) |

The flow always ends later with its **transport** reason
(`Closed { reason: Fin | Rst | IdleTimeout | Evicted | ForceClosed }`).
A parser is never re-created mid-flow. Code that matched
`Closed { reason: BufferOverflow | ParseError }` (or the same on
`FlowEvent::Ended` / `FlowEnded<P>`) matches nothing now — watch
`ParserClosed` / `ParserSideStopped` instead.

At flow end each side still being parsed gets its own `fin_*` or
`rst_*` call, by that side's FIN / RST.

A parser that can resynchronise after missing bytes should override
`on_gap` and return `GapResponse::Continue`; one that cannot parse
either side after a gap returns `GapResponse::Stop`. Several built-in
parsers now resync (HTTP/1, FTP, SMTP, SMB, Modbus, DNP3).

If your parser used to emit an in-band "desync" message because
poisoning had no effect, poisoning now works: return `true` from
`is_poisoned()` and read `ParserClosed`.

## 3. Anomalies are opt-in per stream

Reassembly anomalies (`StreamGap`, `BufferOverflow`,
`RetransmittedSegment`, `OutOfOrderSegment`, `OutOfWindowSegment`,
`ReassemblerHighWatermark`, `TcpRexmitInconsistency`), parser poison
(`SessionParseError`) and tracker pressure are emitted when you ask:

```rust
let stream = cap
    .flow_stream(FiveTuple::bidirectional())
    .session_stream(MyParser::default())
    .with_emit_anomalies(true);
```

Multi-streams: `MultiStreamConfig::new().with_emit_anomalies(true)`.
Monitor: see §7.

## 4. Stats snapshots are owned

`Closed.stats` and `snapshot_flow_stats()` include the reassembly
diagnostics (`reassembly_gaps_*`, `reassembly_gap_bytes_*`,
`retransmits_*`, `reassembler_high_watermark_*`,
`reassembly_bytes_dropped_oversize_*`, `reassembly_dropped_ooo_*`,
`reassembly_stop_*`, `reassembly_out_of_window_*`,
`reassembly_ack_confirmed_gaps_*`, `reassembly_origin_resets_*`, …).

`snapshot_flow_stats()` yields **owned** `(K, FlowStats)` pairs on
every stream (it yielded `(&K, &FlowStats)` on `FlowStream` /
`MergedFlowStream`): drop the `&` / `*` in your closures. For borrowed
access, use `stream.tracker().iter_active()`.

## 5. Transports: UDP parsers see UDP, ICMP parsers see ICMP

A `DatagramParser` declares its transports (`transports()`; default
UDP, `IcmpParser` ICMP + ICMPv6). `.protocol::<Icmp>()` no longer runs
on UDP payloads (0.30 produced fake `IcmpMessage` / `IcmpError` events
from DNS or QUIC bytes and a `ParserClosed<Icmp>` per UDP flow), and a
UDP `datagram_stream` no longer sees ICMP. A custom parser that really
wants both overrides `transports()`.

## 6. Async reassembly and `Conversation`

`with_async_reassembler` now **reassembles**: consumers get in-order
bytes, gaps, and one close with the real end reason (0.30 forwarded
raw segments in arrival order — retransmissions twice, reordering,
silent loss — and reported an idle timeout as FIN).

```rust
// Before
impl AsyncReassembler for Mine {
    fn segment(&mut self, seq: u32, payload: Bytes) -> BoxFut { .. }
    fn fin(&mut self) -> BoxFut { .. }
    fn rst(&mut self) -> BoxFut { .. }
}
// After
impl AsyncReassembler for Mine {
    fn data(&mut self, bytes: Bytes) -> ConsumerFuture { .. }
    fn gap(&mut self, len: u64) -> ConsumerFuture { .. }          // optional
    fn close(&mut self, reason: EndReason) -> ConsumerFuture { .. } // optional
}
```

- It returns a `ReassemblyStream` (still a stream of `FlowEvent`s);
  `FlowStream` lost its `R` parameter, and `NoReassembler` /
  `AsyncReassemblerSlot` are gone — write `FlowStream<C, E>` /
  `FlowStream<C, E, U>`.
- `channel_factory` senders are `mpsc::Sender<ReassembledChunk>`
  (`Data(Bytes)` / `Gap(u64)`), not `Sender<Bytes>`.
- `ConversationChunk` gains `Gap { side, len }` and
  `SideStopped { side, reason }`; `Closed { reason }` is the flow's
  reason. `ConversationStream<C, E>` is generic over the source (was
  `<S, E>` over the AF_PACKET `PacketSource`).
- Bytes only flow while the conversation stream is polled: consume
  each `Conversation` on its own task (the 0.30 doc example awaited it
  inline and hung).

## 7. Monitor

- **Sweeps.** The Monitor now sweeps its flow table (it never did):
  idle flows end with `FlowEnded { reason: IdleTimeout }` during the
  run, parsers' `on_tick` runs, out-of-order holes expire, and exporters
  / ML / RED see flows end. On `replay()` sweeps — and tick handlers,
  which never ran on replay — run on packet time. Expect `FlowEnded`
  events you did not get before, earlier than before.
- **Order.** A flow's messages (including what a parser flushes at
  FIN) are delivered before its `FlowEnded`.
- **Parser events.** `ParserClosed<Http>` (any `P`) now fires for that
  protocol's parser; `ParserClosed<Tcp>` / `<Udp>` / `<Icmp>` still
  fire for every parser on the transport. It fires once per (parser,
  flow): early, with the stop reason (the flow goes on), or right
  before `FlowEnded` with the flow's reason. New
  `ParserSideStopped<P>`, routed the same way. `ParserClosed::new` takes
  `detail`.
- **Anomalies.** Registering an `AnyFlowAnomaly` handler turns
  flowscope's anomalies on; `MonitorBuilder::emit_anomalies(bool)`
  forces it either way. `emit_packet_details(true)` fills
  `FlowPacket::tcp`.
- **Side.** L7 handlers can read `ctx.side()` / `ctx.orientation()`.
- **Per-flow state** from `ctx.flow_state_mut` is freed after the
  flow's `FlowEnded` handlers (it lived forever).
- **Ticks** carry packet time (`ctx.ts`), live and on replay.
- **Custom `ProtocolSlot` impls** (rare): the trait is `Send + Sync`
  and drives messages through `fetch` / `next_order` / `dispatch_next`
  (so the run loop can merge them with lifecycle events), plus
  `slot_id` and `dispatch_parser_event(_async)` for parser events;
  `ParserEvent` borrows its detail.
- Sinks and exporters are flushed on every exit path.

## 8. Capture: stopping a blocked reader

`Packets::next_packet` / `for_each` block across poll timeouts. To stop
one from another thread, take a `StopHandle` before iterating:

```rust
let mut cap = netring::Capture::open("eth0")?;
let stop = cap.stop_handle()?;          // clone freely, Send
std::thread::spawn(move || { /* … */ stop.stop(); });
cap.packets().for_each(|pkt| { /* … */ }); // returns on stop()
```

Or use `Packets::next_packet_timeout()`, which returns `Ok(None)` on
every poll timeout so you can check your own flag. `ChannelCapture`
now stops even when its channel is full.

## 9. Offline replay

- pcap streams and `Monitor::replay()` sweep on packet time: a pause in
  the capture ends idle flows where it happened (0.30 kept every flow
  open until EOF).
- Linux cooked (SLL / SLL2), raw-IP and BSD-loopback captures are read
  correctly (0.30 treated every file as Ethernet); other link types are
  skipped with a warning. The recorded direction reaches
  `OwnedPacket::direction`, so `Dedup::loopback` works on captures that
  carry it; otherwise use `Dedup::content`.
- pcapng timestamps honour `if_tsresol` / `if_tsoffset` (µs pcapng
  replayed 1000× early).
- `loop_at_eof` stops when the consumer is gone, does not loop an empty
  or broken file, and shifts each pass forward in time.
- The pcap streams gain `with_dedup`, `dedup_mut`,
  `with_monotonic_timestamps`; `PcapFlowStream` gains
  `snapshot_flow_stats`.

## 10. Stream conversions and multi-capture

- `flow_stream(..).session_stream(..)` / `.datagram_stream(..)` and the
  `PcapFlowStream` conversions keep events already queued (in their
  session form); a queued `Ended` used to vanish.
- The monotonic clamp keeps the whole RX metadata (hardware timestamp,
  RSS hash, VLAN, checksum), not only `source_idx`.
- To configure sources individually (a BPF filter per interface, a pcap
  tap per interface, dedup only on `lo`), build the per-source streams
  yourself and fan them in with `from_streams` — on
  `Multi{Flow,Session,Datagram}Stream` and the AF_XDP
  `XdpMulti*Stream`s:

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

`SessionStream`, `DatagramStream`, `ReassemblyStream` and `StopHandle`
are re-exported at the crate root.
