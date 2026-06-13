# netring monitor — primitives by use case

A one-page tour of the `Monitor` toolkit, grouped by what you're trying
to do. Everything here is in `netring::prelude::*` unless noted. Mirrors
flowscope's `docs/discoverability.md` on the flow-tracking side.

## Build a monitor

```rust
use netring::prelude::*;
Monitor::builder().interface("eth0") /* … */ .build()?.run_until_signal().await?;
```

- `.interface(s)` / `.interfaces([…])` — capture source(s).
- `.all_l4()` — register Tcp + Udp + Icmp in one call (no "forgot Icmp"
  foot-gun). `.all_l7()` — Http + Dns + Tls + TlsHandshake (feature-gated).
- `.protocol::<P>()` — register one protocol explicitly.
- `.name(s)` — label surfaced on `ctx.monitor_name`.
- `.label_table(t)` — custom well-known port → app-label table.
- Run: `.run_for(d)` / `.run_until(deadline)` / `.run_until_signal()` /
  `.run_until_idle(window)` / `.replay()` (pcap).

## React to protocol roles (0.22 R1)

The type system enforces which events a protocol can produce:

- **`FlowProtocol`** (`Tcp`, `Udp`, `Icmp`) — emit lifecycle events
  `FlowStarted` / `FlowEstablished` / `FlowEnded` / `FlowTick<P>` and the
  flat `FlowPacket`. `on::<FlowStarted<Tcp>>(…)`.
- **`MessageProtocol`** (`Http`, `Dns`, `Tls`, `TlsHandshake`, `Icmp`) —
  deliver parsed messages. `on::<Http>(|msg, ctx| …)`.
- `on::<Tcp>` and `FlowStarted<Http>` are **compile errors** — the roles
  make invalid combinations unrepresentable.

## Handle events

- `.on::<E>(|payload| …)` — payload only.
- `.on_ctx::<E>(|payload, ctx| …)` — payload + `&mut Ctx`.
- `.on_async::<E>(handler)` — async handler.
- `.tick(period, |tick, ctx| …)` — periodic.
- `.detect(…)` / `detector!` / `pattern_detector!` — scored detectors.

## Per-packet & per-flow data (0.22 R2)

- `FlowPacket { proto, key, side, len, tcp, ts }` — one flat event for
  every L4 packet; branch on `evt.proto`.
- `FlowTick<P>` — periodic per-flow `FlowStats` snapshot.
- `FlowStats` throughput helpers: `throughput_bps[_for(side)]`,
  `throughput_pps[_for]`, `bytes_for`, `pkts_for`, `direction_skew`
  (safe-divide; zero-duration → `0.0`).

## Bandwidth by application (0.22 §2.3)

```rust
.on_bandwidth(Duration::from_secs(5), |bw| {
    for (app, bps) in bw.top(10) { println!("{app}: {bps:.0} B/s"); }
    Ok(())
})
```

- `bandwidth_by_app()` / `bandwidth_windowed(window, bucket)` — register
  the primitive; read via `ctx.bandwidth() -> Option<BandwidthReport>`.
- `on_bandwidth(period, f)` — fused: auto-register + periodic report.
- `BandwidthReport`: `top(n)`, `rate(app)`, `total()`, `app_count()` —
  no `Timestamp`/`RollingRate`/`Option` at the call site.

## ICMP triage (0.22 §2.4/2.5)

```rust
.on_icmp_error(|err, ctx| {
    if let Some(flow) = err.correlated_flow { /* … */ }
    ctx.emit("Icmp", Severity::Warning).with("kind", err.kind.as_str()).emit();
    Ok(())
})
```

- `IcmpError { family, kind, correlated_flow, stats, ts }` — unified
  v4/v6, pre-classified, with the originating flow joined.
- `IcmpErrorKind`: `DestUnreachable(DestUnreachableKind)` / `TimeExceeded`
  / `ParameterProblem` / `MtuSignal(MtuSignalKind)`; `.as_str()`.
- `ctx.lookup_icmp_flow(inner)` — manual inner-tuple → flow + stats join.

## TCP resets (0.22 §2.6)

- `.on_tcp_reset(|rst, ctx| …)` — `TcpRst { key, stats, ts, zero_payload }`,
  synthesised from `FlowEnded<Tcp>` with `reason == Rst`. `zero_payload`
  separates "connection refused" from a mid-transfer abort.

## Sliding-window state (`netring::correlate`)

| Primitive | Shape | Use |
|---|---|---|
| `RollingRate<K, V>` | per-key per-second rate | bandwidth, request rates |
| `TimeBucketedCounter<K>` | per-key sliding count | bursts, storms |
| `TimeBucketedSet` | per-key distinct set | cardinality (port scans) |
| `TopK` | top-N by score | talkers, domains |
| `Ewma` | smoothed average | latency, jitter |
| `BurstDetector` | burst onset | beacons, floods |
| `KeyIndexed<K, V>` | TTL map (`iter_fresh` / `drain_expired`) | "expected B after A" |
| `FlowStateMap` | per-flow state, auto-evict | per-conversation accumulators |

## Emit anomalies

- `ctx.emit(kind, severity).with(k, v).with_metric(k, f).with_key(&key).emit()`.
- Sinks: `StdoutSink`, `StdoutJsonSink` (serde), `TracingSink`,
  `ChannelSink`, `EveSink` (eve-sink), `MetricsSink` (metrics).
- Layers: `MinSeverity`, `DedupeAnomalies`, `RateLimitAnomalies`,
  `Sample`, `Tee` — stack via `.layer(…)` (first = outermost).

## Stream consumers

- `.with_broadcast::<P>()` + `monitor.subscribe::<P>()` →
  `EventStream<P::Message>` (`futures_core::Stream`). Both bounded to
  `MessageProtocol`.

## Scale out

- `ShardedRunner::new(iface, mode, group_id, n, build_shard)` — per-CPU
  AF_PACKET fanout, one Monitor per shard.
