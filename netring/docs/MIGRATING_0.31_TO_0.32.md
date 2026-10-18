# Migrating netring 0.31 → 0.32

0.32 makes the capture layer do what its knobs say (one meaning for
capture statistics, a snap length that cuts, VLAN filters that match and
tags that stay in the frame), names every flow from the endpoint that
**opened** it in every output, and makes async reads and the Monitor
notice a removed interface. It adopts **flowscope 0.26**.

Most code needs only the mechanical changes in §1–§5. §6–§8 are
behaviour changes: nothing stops compiling, but numbers, strings or
timings you may have relied on move.

> **Version note.** `netring-exporters` moves to `0.9.0` (§9). See also
> flowscope's
> [`migration-0.25-to-0.26.md`](https://github.com/p13marc/flowscope/blob/master/docs/migration-0.25-to-0.26.md)
> if you use flowscope directly (custom detectors, `FlowStats` byte
> counts).

---

## 1. Capture statistics (#186)

`CaptureStats` has one meaning everywhere: `u64` totals since the source
was opened. Reading never resets anything.

| 0.31 | 0.32 |
|---|---|
| `stats.packets` (received, incl. drops; `u32`) | `stats.received()` — or `stats.delivered` for what reached userspace |
| `stats.drops` (`u32`) | `stats.drops` (`u64`) |
| `stats.freeze_count` | `stats.freezes` |
| `cap.stats()` — a delta; resets the kernel counters | `cap.stats()` — lifetime totals |
| `cap.cumulative_stats()` | `cap.stats()` (removed) |
| `stream.capture_cumulative_stats()` | `stream.capture_stats()` (removed) |
| `MultiSource::capture_stats()` (`fanin.source(i)?.capture_stats()`) | `ring_stats()` |
| `metrics::record_capture_delta(iface, &cap.stats()?)` | one capture per `iface` label: `metrics::record_capture_stats(iface, &cap.stats()?)`; several under one label (fanout workers): `metrics::record_capture_delta(iface, &now.delta_since(&before))` — **feeding it `stats()` now double counts** |
| `CaptureStats { packets, drops, freeze_count }` (tests, mocks) | `CaptureStats::new(delivered, drops, freezes)` |
| `CaptureStats::from(raw_tpacket_stats_v3)` | `cap.stats()?` (the `From` impl is removed) |
| `drops as f64 / packets as f64` | `stats.drop_ratio()` |

```rust
// 0.31 — each read is a delta and resets the kernel counters
let delta = cap.stats()?;
let total = cap.cumulative_stats()?;
println!("{} {} {}", total.packets, total.drops, total.freeze_count);
netring::metrics::record_capture_delta("eth0", &delta);

// 0.32 — totals; take a window's counts yourself
let before = cap.stats()?;
// … later
let now = cap.stats()?;
let window = now.delta_since(&before);
println!("{} {} {}", now.delivered, now.drops, now.freezes);
netring::metrics::record_capture_stats("eth0", &now);
```

The same applies to `PacketSource::stats`, `AsyncCapture::stats`,
`StreamCapture::capture_stats`, the fan-ins' `capture_stats` /
`per_source_capture_stats`, the AF_XDP `capture_stats` accessors and
`Bridge::stats` (`Bridge::cumulative_stats` is gone). With
`StreamCapture` and `MultiSource` both in scope, `stream.capture_stats()`
compiles again (0.31: E0034).

## 2. Snap length, truncation and drop notification (#210, #222)

`CaptureBuilder::snap_len(n)` now cuts packets to `n` bytes — through the
socket filter, the only thing TPACKET_V3 cuts by. `snap_len(0)` is an
`Error::Config`.

| 0.31 | 0.32 |
|---|---|
| `snap_len(n)` set the frame size; nothing was cut | packets are cut to `n` bytes; `pkt.len() <= n`, `pkt.original_len()` is the wire length |
| `pkt.status().truncated` (always `false`) | `true` when `len() < original_len()` |
| `pkt.status().losing` (always `false`) | `batch.losing()` on the `PacketBatch` (block status) |
| builder filters ended in `ret #65535` | `ret #4294967295` (whole packet) |
| — | `Capture::snap_len()`, `BpfFilter::with_snap_len(snap)` |

If you used `snap_len` to change the ring's frame size, set
`frame_size(..)` instead. `Capture::detach_filter()` with a snap length
leaves a `ret #snap` filter installed. An eBPF socket filter attached with
`attach_ebpf_filter` sets the capture length itself — return
`min(skb->len, snap)` to keep a snap length.

## 3. VLAN tags (#208, #209)

The capture re-inserts the outer VLAN tag the kernel stripped, in front of
the EtherType, as libpcap does. Tagged frames are 4 bytes longer than in
0.31 (`len()` stays within the snap length) and carry the `0x8100` /
`0x88a8` tag at bytes 12..16. `Bridge` forwards the tag; a full-size frame
with an outer 802.1ad tag no longer fits the other side's MTU and is
dropped (counted in `*_dropped_too_large`) — `BridgeBuilder::vlan_reinsert(false)`
forwards untagged as 0.31 did.

| 0.31 | 0.32 |
|---|---|
| `pkt.vlan_tci()` / `pkt.vlan_tpid()` | `pkt.vlan()` → `Option<VlanTag>` (`.vid()`, `.tci`, `.proto`) |
| `owned.vlan_tci` / `owned.vlan_tpid` | `owned.vlan: Option<VlanTag>` |
| `OwnedPacket { .., vlan_tci: 0, vlan_tpid: 0, .. }` | `OwnedPacket { .., vlan: None, .. }` |
| EtherType always at byte 12 | a tag there on tagged traffic — parse VLAN-aware (etherparse does), or `CaptureBuilder::vlan_reinsert(false)` for the old layout (the tag is then in `pkt.stripped_vlan()`) |
| `filter.matches(pkt.data())` to predict the kernel's verdict | `filter.matches_with(pkt.data(), &pkt.bpf_ancillary())`; `matches(frame)` is the offline (tcpdump-on-a-file) verdict |
| `.vlan()` / `.vlan_id(n)` matched nothing live; workarounds with `eth_type(0x8100)` | use `.vlan()` / `.vlan_id(n)` — they match the stripped tag |

Flow byte counts follow the frame: a tagged packet counts its tag when it
was re-inserted, not when it stays stripped (`vlan_reinsert(false)`, a
kernel before 3.14, AF_XDP with the NIC stripping it) — 4 bytes per packet
apart.

`BpfAncillary` is `#[non_exhaustive]`: build it with `BpfAncillary::NONE`,
`stripped(tag)` or `reinserted(tag)`. Code reading the raw ring through
`Capture::ring_ptr()` must use `tp_mac`: a 4-byte `PACKET_RESERVE` moves
every packet 4 bytes further into its frame.

## 4. AF_XDP placement and RSS (#213)

```rust
// 0.31
XdpCapture::builder().interface("eth0").numa_auto();
let mode = RssConfig::new("eth0").set_symmetric()?;

// 0.32
XdpCapture::builder().interface("eth0").numa_auto(true);
// set_symmetric() restores the NIC's previous RSS configuration when the
// guard drops — keep it alive for as long as the capture runs …
let guard = RssConfig::new("eth0").set_symmetric()?;
let mode = guard.mode();
// … or keep the symmetric configuration for good:
let mode = RssConfig::new("eth0").set_symmetric()?.persist();
```

`set_symmetric()` now fails on a NIC it cannot make symmetric (it used to
return `Ok(SymmetricKey)` there). Check that a NUMA / hugepage request
took effect with `sock.umem_placement()` / `cap.umem_placements()`.

## 5. Monitor API

### `Ctx.source` (#216)

```rust
// 0.31
let iface = &ifaces[ctx.source.0 as usize];
// 0.32 — None for ticks, tracker-wide anomalies, and housekeeping events
// whose flow has no capture leg
if let Some(s) = ctx.source {
    let iface = &ifaces[s.0 as usize];
}
```

`ctx.source == SourceIdx(0)` becomes `ctx.source == Some(SourceIdx(0))`.
`FlowStats::source_idx_forward` / `_reverse` are now set (leg = source
index + 1; a replay is leg 1).

### Packet-tier `ctx.flow` (#216)

A packet subscription's `ctx.flow` is the flow's canonical (address-sorted)
key, the one `FlowEnded` carries. Take the packet's direction from
`ctx.orientation()`, and the flow's `(initiator, responder)` from
`ctx.initiator_responder()`:

```rust
// 0.31: ctx.flow.a was this packet's source
// 0.32
let key = ctx.flow.expect("a packet-tier event has a flow");
let (src, dst) = match ctx.orientation() {
    Some(Orientation::Reverse) => (key.b, key.a),
    _ => (key.a, key.b),
};
```

### `state_init` takes `Fn`; `take_dyn` → `take_reset` (#216, #227)

The factory re-seeds the slot after each sharded merge, so it must be
re-runnable:

```rust
// 0.31
let handle = open_handle()?;
builder.state_init(move || MyState::new(handle))
// 0.32
let handle = Arc::new(open_handle()?);
builder.state_init(move || MyState::new(Arc::clone(&handle)))
// a one-off value that is never merged across shards:
builder.state_with(MyState::new(open_handle()?))
```

`StateMap::take_dyn` → `StateMap::take_reset` (same signature; re-seeds
the slot). A second `merge_state` / `state_auto_merge` for the same type
fails with `BuildError::DuplicateMergeState` — keep one.

### Anomaly sinks: `AnomalySink::write(&AnomalyRecord)` (#215)

```rust
// 0.31
impl AnomalySink for MySink {
    fn write(&mut self, kind: &'static str, severity: Severity, ts: Timestamp,
             key: Option<&dyn Key>, observations: &[(&'static str, Cow<'_, str>)],
             metrics: &[(&'static str, f64)]) { /* … */ }
}

// 0.32
impl AnomalySink for MySink {
    fn write(&mut self, r: &AnomalyRecord<'_>) {
        // r.kind, r.severity, r.ts, r.key, r.observations, r.metrics
        if let Some(e) = r.endpoints {
            // e.src() is the flow's initiator when e.directional
        }
    }
}
```

| 0.31 | 0.32 |
|---|---|
| `sink.write(kind, sev, ts, key, &obs, &metrics)` | `sink.write(&AnomalyRecord::new(kind, sev, ts).with_key(&k).with_observations(&obs).with_metrics(&metrics))` |
| downcast `key` to `FiveTupleKey`, print `key.a` / `key.b` as src / dst | read `record.endpoints` (initiator first when `directional`); `record.flow_key()` for the key |
| `ctx.sink_mut().begin(..).with_key(&flow)` | as before — but it doesn't know the current flow; add `.with_flow(&flow, initiator)` (or emit with `ctx.emit(..)`) |

`ctx.emit(..).with_key(&flow_key)` needs no change: the writer knows the
current flow and reads it initiator-first.

**Forwarding layers.** A sink that wraps another one (a filter, a tee, a
rate limiter) passes `record` on as it is: `self.inner.write(record)`. The
endpoints were resolved when the record was built — rebuilding it with
`AnomalyRecord::new(..).with_key(..)` loses the initiator (the key alone
reads as stored, `directional: false`); if you must rebuild, copy them
with `.with_endpoints(e)` for `Some(e) = record.endpoints`.

**Owned anomalies.** An `OwnedAnomaly` doesn't say how its 5-tuple was
filled, so `publish_owned` / `Endpoints::from_owned` keep it as stored and
mark it `directional: false`. When it is the flow being dispatched (an
effect's anomaly, a `pattern_detector!` score, `ctx.publish_owned(&a)`),
the Monitor reads it from that flow's initiator. Build one for another
flow — or to be sure — from the initiator yourself:

```rust
// 0.31
let a = OwnedAnomaly::new(kind, sev, ts).with_key(&key);
// 0.32 — the initiator first
let a = OwnedAnomaly::new(kind, sev, ts).with_flow(&key, ctx.initiator().unwrap_or_default());
```

### `Dedup::keep_raw` (#217)

```rust
// 0.31
dedup.keep_raw(&data, direction, ts)
// 0.32 — the wire length (data.len() when the frame was not cut)
dedup.keep_raw(&data, original_len, direction, ts)
// or, from a view:
dedup.keep_view(&view, direction)
```

### `#[non_exhaustive]` types

`MonitorHealthSnapshot`, `AggregateSnapshot`, `TlsFingerprint` and
`export::FlowRecord` can no longer be built with struct literals or
destructured exhaustively outside netring: add `..` to patterns, and build
a `FlowRecord` with `FlowRecord::from_stats(&key, &stats, reason)`.

## 6. Flow outputs name the initiator (#215, #217)

### `export::FlowRecord`

| 0.31 | 0.32 |
|---|---|
| `rec.a` / `rec.b` | `rec.initiator` / `rec.responder` (the endpoint that opened the flow first); `rec.key` for the flow's address-sorted identity |
| `bytes_*` (captured bytes) | `bytes_*` (wire bytes) and new `ip_bytes_*` (IP octets); `total_ip_bytes()` |
| struct literal | `FlowRecord::from_stats(&key, &stats, Some(reason))` (`None` for an interim active-timeout record) |
| NDJSON (`JsonFlowExporter`) fields `a`, `b` | `key` (`{"proto", "a", "b"}`), `initiator`, `responder`, `ip_bytes_initiator`, `ip_bytes_responder` |

```rust
// 0.31
.export_flows(|r: &FlowRecord| println!("{} -> {}", r.a, r.b))
// 0.32
.export_flows(|r: &FlowRecord| println!("{} -> {}", r.initiator, r.responder))
```

### IPFIX

`sourceIPv4Address` / `sourceTransportPort` (and IPv6) are the initiator;
`octetDeltaCount` (IE 1) and `octetTotalCount` (IE 85) are **IP octets**
(smaller than 0.31's by the link-layer header per packet, and no longer
shrunk by a snap length); the canonical record's IE 352 / 353 carry the
wire bytes.

### Everything else that read the sorted key

| Output | 0.31 (key `a` / `b`) | 0.32 |
|---|---|---|
| EVE `src_ip` / OCSF `src_endpoint` | lower address | the initiator (or the anomaly's subject) |
| `ChannelSink` / `emit_owned` `OwnedAnomaly::src_*` | lower address | the initiator |
| `eve_tls_record` `src_ip` | lower address | the TLS client (`TlsFingerprint::client`) |
| `flow::<P>()` / `session::<P>()` `.src_port()` / `.src_host()` filters | lower address | the initiator |
| IOC host match `side` observation | `src` = lower address | `src` = initiator, `dst` = responder |
| `AggregateReport::top_pairs` / `AggregateSnapshot::pairs` | `(lower, higher)` | `(initiator, responder)` — two hosts opening flows to each other form two pairs |
| YARA `ScanDirection` | the lower address's bytes were `Initiator` | the side that sent them (#215) |

### Text anomaly sinks: `src=` / `dst=` instead of `key=`

0.31's `StdoutSink`, `TracingSink`, `SyslogSink` and `StdoutJsonSink` had
no source field: they printed the key's `Debug` text. In 0.32 a record
with endpoints prints them, initiator first when known — log parsers
matching `key=FiveTupleKey { … }` need updating:

| Sink | 0.31 | 0.32 |
|---|---|---|
| `StdoutSink` line, `TracingSink` message | `key=FiveTupleKey { proto: Tcp, a: …, b: … }` | `src=10.0.0.9:40000 dst=10.0.0.1:80 proto=TCP` |
| `SyslogSink` structured data | `key="FiveTupleKey { … }"` | `src="10.0.0.9:40000" dst="10.0.0.1:80" proto="TCP"` |
| `StdoutJsonSink` | `"key"` only | `"key"` plus `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `directional` |

A key that is not a flow (a host `IpAddr`, a counter key) still prints as
`key=…`. `directional: false` (JSON) means `src` is only the key's lower
address.

## 7. flowscope 0.26

- Byte counts in `FlowStats` (and everything built on them) are **wire
  lengths** (Ethernet header included), plus new `ip_bytes_*`; packets a
  snap length cut are now tracked (they produced no flow).
- `FlowStarted::orientation` is the initiator's (it was the first packet
  seen's); `FlowStarted::initiator()` / `responder()` /
  `FlowEnded::initiator()` / `responder()` read the endpoints.
- A custom `flowscope::detect::Detector` registered with
  `MonitorBuilder::detector` implements the new signatures
  (`on_flow_start(key, initiator, ts, out)`,
  `on_dns_query(key, sender, ..)`) — see flowscope's migration guide.

## 8. Behaviour changes

### Dead interfaces (#212, #225)

Async reads (`AsyncCapture::readable` / `recv`, `PacketStream`, every
flow / session / datagram stream, `AsyncXdpSocket`, `AsyncXdpCapture`,
`AsyncInjector` waits and kicks, `Bridge::run_async`) now end with
`Error::Io(ENETDOWN)` when the interface is **removed** — 0.31 waited
forever. A down interface is still waited out. To survive an interface
being re-created, re-open on `ENETDOWN`:

```rust
loop {
    let mut cap = AsyncCapture::open("eth0")?;
    loop {
        match cap.readable().await {
            Ok(mut guard) => { if let Some(batch) = guard.next_batch() { /* … */ } }
            Err(Error::Io(e)) if e.raw_os_error() == Some(libc::ENETDOWN) => break,
            Err(e) => return Err(e),
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
}
```

A custom `PacketSource` gets `check_health()` with a default of `Ok(())`;
override it if the source can die silently.

### `BackendErrorPolicy`

| Policy | 0.31 | 0.32 |
|---|---|---|
| `FailFast` (default) | a removed interface: kept waiting until the deadline | the run ends promptly with `ENETDOWN` |
| `SkipSource` | slept 50 ms and polled the dead source again; 64 errors ended the run | retires the source and runs on the others; ends only when no source is left |
| `Reopen` | re-opened while the old backend held the queue (`EBUSY` on AF_XDP) | drops the old backend first, retries every 500 ms; 64 failed re-opens end the run |

Drain errors go through the policy too (0.31 returned them directly).

### TX kicks (#228)

`AsyncInjector::flush().await` (and `send` on a full ring, `send_stream`)
means **handed to the device**, not transmitted — await
`wait_drained(timeout)` where you relied on completion. It returns the
number of frames the kick handed over (0.31: the frames queued when it
started); frames a full send buffer kept back stay queued
(`Injector::queued_count`) for the next kick. The sync `Injector::flush`
still waits; `Injector::flush_nonblocking` kicks without waiting. The async `Bridge` loops no longer wait for the device either;
the blocking `Bridge::run` still does (its backpressure).

A frame the kernel refuses (longer than the device accepts, a malformed
header) is now dropped by the kernel and the kick goes on — 0.31's kick
stopped there with `EMSGSIZE` / `EINVAL` and left the frames behind it
queued. `InjectorBuilder::drop_rejected(false)` restores the
stop-and-report behaviour (`Injector::rejected_slots()` counts the
refused slots).

### Reads, statistics, timing

- A `Packets` loop stopped mid-block no longer discards the rest of the
  block: the next read continues with it (#211). Drain explicitly
  (`while let Some(_) = cap.next_batch() {}`) if "skip what's buffered" was
  the intent.
- `DedupeAnomalies` / `RateLimitAnomalies` windows are packet time (a fast
  replay no longer collapses an hour into one window).
- Traffic aggregation keeps at most `AggregateConfig::max_keys` (4096)
  keys per bucket per dimension; `report.overflow()` counts the rest
  (cumulative). Set `max_keys = usize::MAX` for the old unbounded tables.
- YARA buffers are bounded by `yara_memory_budget` (default 256 MiB).
- The Monitor keeps its kernel prefilter with `reassemble_ip_fragments()`
  (non-first fragments skip the port terms), instead of capturing
  everything.
- `with_broadcast::<P>()` and `protocol::<P>()` compose in any order
  (0.31 delivered messages twice after `protocol` then `with_broadcast`).
- `ShardedRunner::run_*` returns `Err` when a `merge_state` / `on_merge`
  closure panicked (0.31: `Ok`, the panic only logged by the thread).
- `TcpRst::zero_payload` is `true` for a reset flow that moved no data
  (0.31: never). Handlers that ranked resets by it now see refused
  connections.

## 9. netring-exporters 0.9.0

- `KafkaSink` / `OtlpAnomalySink`: the messages gain the anomaly's
  endpoints — Kafka `src_ip` / `src_port` / `dest_ip` / `dest_port` /
  `proto` / `directional`, OTLP `source.address` / `source.port` /
  `destination.address` / `destination.port` / `network.transport` and
  `netring.endpoints.directional`. OTLP names `source` / `destination`
  only directional endpoints (the initiator, or the anomaly's subject); a
  bare flow key read as stored goes to `netring.flow.a.*` /
  `netring.flow.b.*`.
- `ParquetFlowExporter`: `source.*` is the initiator, `destination.*` the
  responder (0.8: the key's `a` / `b`); new `source.ip_bytes` /
  `destination.ip_bytes` columns; `*.bytes` are wire bytes. Queries that
  grouped by `source.address` as "the lower address" now group by the
  client.
