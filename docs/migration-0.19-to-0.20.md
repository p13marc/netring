# Migrating from netring 0.19 → 0.20

> ⚠️ **Historical.** This guide covers 0.19 → 0.20 and describes the
> legacy `ProtocolMonitor` / `AnomalyMonitor` / `AnomalyRule` API as
> still-present. That API was **removed in 0.22** — go straight to the
> declarative `Monitor::builder()` (see
> [netring/docs/MIGRATING_0.21_TO_0.22.md](../netring/docs/MIGRATING_0.21_TO_0.22.md)).

netring 0.20 adds a new declarative `Monitor` builder alongside
the 0.19 `ProtocolMonitor` / `AnomalyMonitor` surface. The legacy
API still works in 0.20.0 — you can migrate one detector at a
time. A future 0.21.x will add `#[deprecated]` attributes; 0.22.0
will remove them.

## TL;DR

Add the prelude import and reach for `Monitor::builder()`:

```rust
use netring::prelude::*;

Monitor::builder()
    .interface("eth0")
    .protocol::<Http>()
    .on::<Http, _, _>(|msg: &flowscope::http::HttpMessage, ctx: &mut Ctx<'_>| {
        // your logic
        Ok(())
    })
    .sink(StdoutJsonSink::default())
    .run_until_signal()
    .await?;
```

## Concept mapping

| 0.19                                   | 0.20                                  |
|----------------------------------------|---------------------------------------|
| `ProtocolMonitorBuilder::new()`        | `Monitor::builder()`                  |
| `.flow()` / `.http()` / `.dns()` …     | `.protocol::<Tcp>()` / `::<Http>()` …  |
| `ProtocolEvent<K>` match arms          | typed handlers: `.on::<E>(...)` per event |
| `AnomalyMonitor::with_rule(R)`         | `.on::<E>(detector)` (sync handler)   |
| `Anomaly<K>` value + `with_observation` | `ctx.sink_mut().begin(...).with(...).emit()` |
| `Severity::Warning`                    | unchanged — same enum                 |
| `FlowAnomalyRule::with_min_severity(…)` | `.layer(MinSeverity::at_least(…))`    |

## Recipe 1 — convert an `AnomalyRule` to a `detector!`

**Before (0.19):**

```rust
struct DnsBurstRule { threshold: u64 }

impl AnomalyRule<FiveTupleKey> for DnsBurstRule {
    fn name(&self) -> &'static str { "DnsBurst" }
    fn observe(&mut self, evt: &ProtocolEvent<FiveTupleKey>,
               emit: &mut Vec<Anomaly<FiveTupleKey>>) {
        if let ProtocolEvent::Message {
            message: ProtocolMessage::Dns(DnsMessage::Query(q)), ts, ..
        } = evt {
            // ... burst-counting logic
            if count > self.threshold {
                emit.push(
                    Anomaly::new("DnsBurst", Severity::Warning, *ts)
                        .with_observation("source", source.to_string())
                        .with_metric("queries_per_10s", count as f64)
                );
            }
        }
    }
}

let monitor = AnomalyMonitor::new().with_rule(DnsBurstRule { threshold: 50 });
```

**After (0.20):**

```rust
use netring::prelude::*;

#[derive(Default)]
struct BurstState { /* per-key counters */ }

let dns_burst = detector! {
    name: "DnsBurst",
    severity: Warning,
    event: Dns,
    matches: |msg| matches!(msg, flowscope::dns::DnsMessage::Query(_)),
    emit: |msg, ctx| {
        let burst = ctx.state_mut::<BurstState>();
        // ... burst-counting logic
        if count > 50 {
            let now = ctx.ts;
            ctx.sink_mut()
                .begin("DnsBurst", Severity::Warning, now)
                .with("source", source.to_string())
                .with_metric("queries_per_10s", count as f64)
                .emit();
        }
    },
};

Monitor::builder()
    .interface("eth0")
    .protocol::<Dns>()
    .state::<BurstState>()
    .detect(dns_burst)
    .sink(StdoutJsonSink::default())
    .run_until_signal()
    .await?;
```

Key differences:

- The detector body now reaches into `ctx.state_mut::<T>()` for
  per-monitor state instead of `&mut self` on the rule struct.
  Use multiple `state_mut::<T>()` calls (each is its own bounded
  borrow) or `ctx.split_state_sink::<T>()` for simultaneous
  `(&mut T, &mut dyn AnomalySink)`.
- Emission goes through `sink_mut().begin(...).emit()` rather
  than pushing an owned `Anomaly<K>` to a `Vec`. The framework
  never materialises an `Anomaly` value on the hot path.

## Recipe 2 — `ProtocolEvent` match → typed handlers

**Before:**

```rust
while let Some(evt) = monitor.next().await {
    match evt? {
        ProtocolEvent::FlowStarted { .. } => { /* … */ }
        ProtocolEvent::FlowEnded { l4, .. } => { /* … */ }
        ProtocolEvent::Message {
            message: ProtocolMessage::Http(req), ..
        } => { /* … */ }
        _ => {}
    }
}
```

**After:** one handler per event type. The dispatcher routes
by `TypeId` — no match overhead.

```rust
Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()
    .protocol::<Http>()
    .on::<FlowStarted<Tcp>, _, _>(|_evt, _ctx| { /* … */; Ok(()) })
    .on::<FlowEnded<Tcp>, _, _>(|_evt, _ctx| { /* … */; Ok(()) })
    .on::<Http, _, _>(|_msg, _ctx| { /* … */; Ok(()) })
    .run_until_signal()
    .await?;
```

`FlowStarted<Tcp>` only fires on TCP flow starts; `FlowStarted<Udp>`
needs its own `.on::<FlowStarted<Udp>>()`. Same for `FlowEnded<P>`
and `FlowEstablished<Tcp>` (TCP only).

## Recipe 3 — `FlowAnomalyRule` → `MinSeverity` layer

**Before:**

```rust
let rule = FlowAnomalyRule::new().with_min_severity(Severity::Warning);
let monitor = AnomalyMonitor::new().with_rule(rule);
```

**After:** anomalies from the central flowscope tracker surface
as `AnyFlowAnomaly` events. Filter through a `MinSeverity` layer:

```rust
Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()
    .on::<AnyFlowAnomaly, _, _>(|anom, ctx| {
        let now = ctx.ts;
        ctx.sink_mut()
            .begin(anom.kind.short_kind(), Severity::Warning, now)
            .emit();
        Ok(())
    })
    .layer(MinSeverity::warning())  // drops Info before sink writes
    .sink(StdoutJsonSink::default())
    .run_until_signal()
    .await?;
```

## Recipe 4 — async I/O from a detector

In 0.19 you needed a hand-rolled async task + mpsc channel. In
0.20 use `on_async`:

```rust
let redis_pool: Arc<RedisPool> = Arc::new(/* … */);

Monitor::builder()
    .interface("eth0")
    .protocol::<Http>()
    .on_async::<Http, _>(move |msg: &flowscope::http::HttpMessage| {
        let pool = Arc::clone(&redis_pool);
        async move {
            tokio::spawn_local(async move {
                pool.publish(msg).await
            });
            Ok(())
        }
    })
    .run_until_signal()
    .await?;
```

Async handlers receive **payload only** — no `&mut Ctx`. Capture
state via `Arc<…>` in the closure. Each dispatch costs one boxed
future allocation.

## What hasn't changed

- `Severity`, `Anomaly<K>::Display`, `Anomaly::to_json_line()` —
  same API, same output.
- Protocol parsers — `flowscope::http`, `flowscope::dns`, etc.
  are unchanged.
- Flow tracking primitives — `KeyIndexed<K, V>`,
  `TimeBucketedCounter<K>`, `FiveTupleKey`.
- Low-level capture: `AsyncCapture`, `Capture`, `XdpSocket`.

## Deprecation timeline

- **0.20.0** — new API ships; legacy API works unchanged.
- **0.21.x** — legacy API gets `#[deprecated]` attributes pointing
  to the new equivalents.
- **0.22.0** — legacy API removed.

If you need backward compat past 0.22.0, plan to maintain a
local fork or pin to 0.21.x.
