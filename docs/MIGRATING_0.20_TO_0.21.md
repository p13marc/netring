# Migrating from netring 0.20 to 0.21

> ⚠️ **Historical.** This guide covers 0.20 → 0.21. The legacy
> `ProtocolMonitor` / `AnomalyMonitor` / `AnomalyRule` API it references
> was **removed in 0.22** — see
> [netring/docs/MIGRATING_0.21_TO_0.22.md](../netring/docs/MIGRATING_0.21_TO_0.22.md).

netring 0.21 is API-additive over 0.20 — your existing 0.20
monitor code keeps compiling. The notable changes are:

1. **`Monitor` is now `Send`.** Drop `flavor = "current_thread"`
   from `#[tokio::main(…)]`.
2. **Legacy `ProtocolMonitor` / `AnomalyMonitor` / `AnomalyRule`
   are `#[deprecated]`.** Continue compiling on 0.21; **removed
   in 0.22.0**. Migrate at your leisure.
3. **`AnomalySink::write` key type** narrowed from
   `Option<&dyn Debug>` to `Option<&dyn Key>`. Custom sink impls
   need to update one type bound.
4. **`TimeBucketedCounter::new` → `new_unbounded`** at call sites
   (or pull flowscope's 3-arg `new` directly).
5. **`Protocol` and `Event` traits** grow trait methods with
   defaults — existing impls compile unchanged.

This guide walks each change with before / after recipes.

---

## 1. Drop `current_thread` from your `#[tokio::main]`

netring 0.20's `Monitor` held a flowscope `SlotHandle` that
used `Rc<RefCell<…>>` internally → `!Send` → forced the runtime
into single-thread mode. flowscope 0.13 made the typed driver
`Send + Sync`, so 0.21's `Monitor` is also `Send`.

```rust
// 0.20 — required current_thread runtime
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Monitor::builder()
        .interface("eth0")
        .protocol::<Http>()
        .build()?
        .run_until_signal()
        .await?;
    Ok(())
}

// 0.21 — default multi-thread runtime
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Monitor::builder()
        .interface("eth0")
        .protocol::<Http>()
        .build()?
        .run_until_signal()
        .await?;
    Ok(())
}
```

`netring/tests/monitor_send.rs` is a compile-time assertion
that `Monitor`, `MonitorBuilder`, `ShardedRunner`, and
`EventStream<M>` all carry the `Send` bound. If a future change
reintroduces a `Rc` somewhere, that test fails before users
hit the silent multi-thread breakage.

If your `subscribe::<P>()` consumer uses `tokio::task::spawn_local`,
switch to `tokio::spawn` — `EventStream<M>` is `Send` for
`M: Send + Sync + Clone + 'static`.

---

## 2. Migrate `ProtocolMonitor + AnomalyMonitor + AnomalyRule` → `Monitor::builder` + `detector!`

The 0.19 detection API was three coupled types:

- `ProtocolMonitor<K>` — a single stream emitting
  `ProtocolEvent<K>` values
- `AnomalyMonitor<K>` — a sequence of `AnomalyRule<K>` impls
- `AnomalyRule<K>` — an `observe(evt) + on_tick(now)` trait

In 0.20 the typed `Monitor::builder()` collapsed those into a
fluent registration surface around the `Handler` trait.

```rust
// 0.19/0.20 legacy — still works on 0.21 but emits #[deprecated] warnings
let mut monitor = ProtocolMonitorBuilder::new("eth0")
    .flow()
    .http()
    .build(FiveTuple::bidirectional())?;
let mut anomalies = AnomalyMonitor::<FiveTupleKey>::new()
    .with(SynFloodRule::default())
    .with(SlowTlsHandshakeRule::default());

while let Some(event) = monitor.next().await {
    let mut emit = Vec::new();
    anomalies.observe(&event?, &mut emit);
    for a in emit {
        println!("{a}");
    }
}
```

```rust
// 0.21 idiomatic
Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()
    .protocol::<Http>()
    .detect(netring::detector! {
        name: "SynFlood",
        event: FlowStarted<Tcp>,
        severity: Warning,
        counters: [IpAddr],
        emit: |evt, ctx| {
            // …
        },
    })
    .detect(netring::detector! {
        name: "SlowTlsHandshake",
        event: TlsHandshake,
        severity: Warning,
        emit: |hs, ctx| {
            // …
        },
    })
    .sink(StdoutSink::default())
    .build()?
    .run_until_signal()
    .await?;
```

For stateful detectors with heterogeneous input shapes
(port-scan, beacon, DGA, custom ML models), the new
**`pattern_detector!`** macro wraps any `flowscope::DetectorScore`-
implementing detector:

```rust
use flowscope::detect::patterns::PortScanDetector;

let scan = netring::pattern_detector! {
    name: "PortScanTRW",
    event: FlowEnded<Tcp>,
    detector: PortScan::new(),
    feed: |evt, w| {
        let success = matches!(evt.reason, EndReason::Fin | EndReason::IdleTimeout);
        w.last_score = Some(w.detector.observe(evt.key, success));
    },
    verdict: |_evt, w| w.last_score.as_ref().and_then(|s| {
        if matches!(s.verdict, ScanVerdict::Scanner) {
            Some(s.clone())
        } else {
            None
        }
    }),
};

Monitor::builder().interface("eth0").protocol::<Tcp>().detect(scan).build()?
```

See `examples/monitor/port_scan.rs`, `beacon_detector.rs`,
`dga_query.rs`, `file_hash_dfir.rs`, `ech_adoption.rs` for the
full set.

### Removal timeline

- **0.21.x** — legacy types emit `#[deprecated]` warnings.
- **0.22.0** — legacy types deleted.

If you can't migrate before 0.22, pin netring to a 0.21.x
patch release. The migration is mechanical; we'd rather absorb
the churn at this stage than carry two parallel APIs through 1.0.

---

## 3. `AnomalySink::write` key type narrowed

Custom sink impls need to update the `write` signature:

```rust
// 0.20
impl AnomalySink for MySink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn std::fmt::Debug>,            // <-- old
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) { … }
}

// 0.21
impl AnomalySink for MySink {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn netring::anomaly::Key>,      // <-- new
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) { … }
}
```

`netring::anomaly::Key` is a super-trait bundling
`KeyFields + Debug + Send + Sync`. The `Debug` impl is still
there for unstructured printing; new is `KeyFields`, which lets
sinks downcast to the typed key (e.g. `FiveTupleKey`) for
structured emission. EveSink uses this to fill the
`src_ip` / `dst_port` / `proto` JSON fields directly instead of
stringifying.

For your own sink: if you only need `Debug`, no logic change —
`Key: Debug` is implied. If you want structured access, downcast:

```rust
fn write(&mut self, ..., key: Option<&dyn netring::anomaly::Key>, ...) {
    if let Some(k) = key {
        if let Some(ft) = k.as_any().downcast_ref::<FiveTupleKey>() {
            // …structured 5-tuple emission…
        } else {
            // …unstructured Debug-based emission…
        }
    }
}
```

---

## 4. `TimeBucketedCounter` re-exported from flowscope

netring's local `TimeBucketedCounter` is gone. Re-exported from
`flowscope::correlate` at `netring::correlate::TimeBucketedCounter`
(unchanged at the user import path). flowscope's 0.13
constructor grew a 3rd argument (`capacity`), so the 2-arg shape
moved to a new method:

```rust
// 0.20
let counter = TimeBucketedCounter::new(
    Duration::from_secs(60),
    Duration::from_secs(1),
);

// 0.21 — pick one
let counter = TimeBucketedCounter::new_unbounded(
    Duration::from_secs(60),
    Duration::from_secs(1),
);
// or, with a capacity ceiling:
let counter = TimeBucketedCounter::new(
    Duration::from_secs(60),
    Duration::from_secs(1),
    100_000,
);
```

`KeyIndexed` stays netring-side (`netring::correlate::KeyIndexed`)
because flowscope's version lacks the `drain_expired(now) ->
impl Iterator<Item = (K, V)>` semantics that netring's
"expected B-after-A didn't happen" detectors rely on. No user
change needed.

---

## 5. `Protocol` and `Event` trait additions

Both trait additions have default impls, so existing user
implementations compile unchanged. The new methods are:

```rust
trait Protocol {
    // ...existing items unchanged...

    fn register_broadcast(builder: &mut DriverBuilder<FiveTuple>)
        -> Result<BroadcastSlotHandle<Self::Message, FiveTupleKey>, ProtocolInitError>
    where Self::Message: Send + Sync + Clone + 'static
    {
        Err(ProtocolInitError(format!("{} does not support broadcast", Self::NAME)))
    }
}

trait Event {
    // ...existing items unchanged...

    fn protocol_marker() -> Option<std::any::TypeId> { None }
    fn protocol_name() -> &'static str { "unknown" }
}
```

Custom `Protocol` impls that want broadcast delivery (so
`monitor.subscribe::<P>()` can yield events from them) override
`register_broadcast`. Custom `Event` impls override
`protocol_marker` if they should participate in the new
`BuildError::HandlerForUnregisteredProtocol` build-time check.

The defaults preserve 0.20 behavior:
- Default `register_broadcast` returns `Err` → `with_broadcast::<P>()`
  is a no-op for that protocol → `subscribe::<P>()` returns
  `BuildError::ProtocolNotBroadcast` if called.
- Default `protocol_marker = None` → the event is exempt from
  the handler-protocol check (same shape as `Tick`,
  `AnyFlowAnomaly`, `FlowStarted<P>`, …).

---

## 6. New opt-in features

Drop into your `Cargo.toml` to wire the new sinks/detectors:

```toml
# Full-stack quickstart
netring = { version = "0.21", features = ["monitor-quickstart"] }

# Or cherry-pick:
netring = { version = "0.21", features = [
    "tokio", "flow", "http",
    "eve-sink",     # Suricata EVE JSON sink
    "metrics",      # metrics-rs facade sink
    "file-hash",    # Sha256Sink + FileType from flowscope::detect::file
] }
```

The new feature flags introduced in 0.21:

| Feature | Description |
|---|---|
| `monitor-quickstart` | Everything: tokio, channel, flow, parse, pcap, metrics, all parsers, emit, eve-sink, file-hash, serde |
| `eve-sink` | Suricata EVE JSON sink via flowscope/emit-eve |
| `file-hash` | Sha256Sink + FileType from flowscope/file-hash |

The existing `monitor` feature (introduced in 0.20) is
unchanged — lean-build users keep that.

---

## 7. New Monitor builder surfaces

The 0.21 cycle added several setters that are all optional —
your existing code compiles. Reach for these when you need them:

- `MonitorBuilder::name("monitor-name")` — propagates to
  `ctx.monitor_name` so multi-monitor processes can disambiguate.
- `MonitorBuilder::fanout(FanoutMode::Cpu, group_id)` — AF_PACKET
  fanout tag for interop with other consumers or sharding.
- `MonitorBuilder::with_broadcast::<P>()` — enables
  `monitor.subscribe::<P>()`. Use **instead of** `.protocol::<P>()`,
  not both.
- `MonitorBuilder::pcap_source(path)` + `pcap_speed_factor(f)` —
  offline replay over `Monitor::replay()`. Skips the
  `NoInterface` build check.
- `MonitorBuilder::drain_timeout(Duration::from_secs(2))` —
  graceful drain budget after the stop condition fires.
  Defaults to 1s; `Duration::ZERO` skips the drain entirely.
- `MonitorBuilder::flow_state::<T>(idle_timeout)` — register a
  per-flow `T: Default + Send + 'static` slot, accessed inside
  handlers via `ctx.flow_state_mut::<T>()`.
- `MonitorBuilder::pcap_speed_factor(2.0)` — replay at 2× wire
  speed (or `1.0` for real-time, `0.5` for half-speed).

New stop conditions on `Monitor`:

- `Monitor::run_until_idle(window)` — exits after `window` of
  inactivity. Pairs cleanly with `pcap_source` for "replay to
  EOF then stop".

For per-CPU sharding:

```rust
use netring::config::FanoutMode;
use netring::monitor::{Monitor, ShardedRunner};

ShardedRunner::new("eth0", FanoutMode::Hash, 42, 4, |cpu| {
    Monitor::builder()
        .interface("eth0")
        .fanout(FanoutMode::Hash, 42)
        .name(format!("shard-{cpu}"))
        .protocol::<Tcp>()
        .build()
})
.run_until_signal()?;
```

Each closure invocation builds an independent `Monitor` on its
own OS thread. AF_PACKET fanout distributes packets across
shards by the configured `FanoutMode`. Cross-shard state
aggregation is deferred to a follow-up release; for now, route
per-shard anomalies through a `Tee + ChannelSink` collator if
you need a global view, or use a sharded metrics backend.

---

## See also

- `CHANGELOG.md` — full per-phase list of additions.
- `netring/tests/monitor_send.rs` — Send contract test.
- `netring/examples/monitor/` — 11 worked examples covering the
  new API surface.
- `docs/migration-0.19-to-0.20.md` — the prior migration guide.
