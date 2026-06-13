# Migrating netring 0.21 → 0.22

0.22 is a **breaking release**. It reshapes the type model (typed
protocol roles, a flat `FlowPacket`), removes the legacy 0.19 API, and
adds a high-level operations toolkit (bandwidth-by-app, ICMP-error
correlation, custom labels). This guide is recipe-by-recipe.

> **flowscope floor:** 0.22 needs **flowscope ≥ 0.14.1** (the ICMP
> datagram-routing fix that makes `on_icmp_error` work).

---

## 1. Legacy 0.19 API removed

`ProtocolMonitor` / `ProtocolMonitorBuilder`, `AnomalyMonitor`,
`AnomalyRule`, `FlowAnomalyRule`, and the `ProtocolEvent` /
`ProtocolMessage` sum-type are **gone**. Use `Monitor::builder()`.

```rust
// before (0.19/0.21):
let mut m = ProtocolMonitorBuilder::new().interface("eth0").flow().http().build(ext)?;
while let Some(evt) = m.next().await { match evt? { /* ProtocolEvent */ } }

// after (0.22):
Monitor::builder()
    .interface("eth0")
    .protocol::<Http>()
    .on::<Http>(|msg: &flowscope::http::HttpMessage| { /* … */ Ok(()) })
    .sink(StdoutSink::default())
    .build()?
    .run_until_signal().await?;
```

Detectors that were `AnomalyRule` impls become `detector!` /
`pattern_detector!` registrations or plain `on_ctx` handlers that call
`ctx.emit(kind, severity)`. The `Anomaly` / `AnomalyContext` / `Severity`
value types are unchanged.

## 2. Typed protocol roles (`FlowProtocol` / `MessageProtocol`)

The type system now encodes which events a protocol can produce:

| Was | Now |
|---|---|
| `on::<Tcp>(…)` (dispatched `()`) | **compile error** — use `on::<FlowStarted<Tcp>>` etc. |
| `FlowStarted<Http>` / `<Dns>` / `<Tls>` | **compile error** — HTTP rides a TCP flow; use `FlowStarted<Tcp>` + scope by parser with `on::<Http>` |
| `subscribe::<Tcp>()` / `with_broadcast::<Tcp>()` | **compile error** — both are bounded to `MessageProtocol` now |

`Tcp`/`Udp` are `FlowProtocol`; `Http`/`Dns`/`Tls`/`TlsHandshake` are
`MessageProtocol`; `Icmp` is both.

## 3. `FlowPacket` is flat (no `<P>`)

```rust
// before:
.on::<FlowPacket<Tcp>>(|e: &FlowPacket<Tcp>| { … })
.on::<FlowPacket<Udp>>(|e: &FlowPacket<Udp>| { … })

// after — one handler, branch on proto:
.on::<FlowPacket>(|e: &FlowPacket| match e.proto {
    L4Proto::Tcp => { … }
    L4Proto::Udp => { … }
    _ => {}
})
```

`FlowPacket` now carries a `proto: L4Proto` field. (`FlowStarted` /
`FlowEnded` / `FlowEstablished` / `FlowTick<P>` stay parameterised.)

## 4. `Layer: Sync` + `Tee::factory` removed

The `Layer` trait gained a `Sync` supertrait (no shipped layer is
affected; only external `Layer` impls with a non-`Sync` field break).
`Tee::factory(f)` is removed — pass the factory closure to
`ShardedRunner::layer(spec)` (a `LayerSpec`) for per-shard minting.

## 5. `KeyIndexed` stays netring-side (richer API)

flowscope 0.14 shipped its own `KeyIndexed`, but it's an LRU cache
(`get(&mut self)`) — netring's is a TTL map (`get(&self)` +
`iter_fresh` / `contains_fresh` / `get_with_ts`). `netring::correlate::KeyIndexed`
is unchanged; it gained `drain_expired_into(now, &mut buf)`.

## 6. Misc API changes

- `on_with_marker::<E, _, _>(…)` removed → `.on::<E>(…)` / `.on_ctx::<E>(…)`.
- `report`-style closures return `Result<()>` (tail `Ok(())`).
- `.tick(period, |ctx| …)` is ambiguous (payload-only vs ctx-only are
  both arity-1) → use `.tick_ctx(period, |ctx| …)` for the elided form,
  or annotate `|_t: &Tick, ctx: &mut Ctx<'_>|`.

## 7. New high-level toolkit (opt-in, additive)

- `.on_bandwidth(period, |bw| …)` — per-app bytes/sec; `bw.top(n)` /
  `rate(app)` / `total()`. Or `.bandwidth_by_app()` + `ctx.bandwidth()`.
- `.on_icmp_error(|err, ctx| …)` — unified v4/v6 ICMP errors, flow-joined.
- `.on_tcp_reset(|rst, ctx| …)` — TCP RSTs with a `zero_payload` flag.
- `.label_table(t)` — custom well-known port labels.
- `.all_l4()` / `.all_l7()` — register every L4 / L7 protocol at once.
- `MinSeverity::info()` + a `const` constructor family.

See `examples/monitor/net_diagnostic.rs` (the 306→70-LoC headline) and
`docs/discoverability.md`.

## 8. The `!Send` run-loop future (unchanged caveat)

`Monitor` is `Send` (use plain `#[tokio::main]`), but the **future**
returned by `Monitor::run_for(..).await` is `!Send` — it borrows the
`!Sync` capture ring across awaits. Keep the run loop on the main task
(`tokio::select!`); to fan work out across spawned tasks use
`ChannelSink` or `monitor.subscribe::<P>()` (both `Send`). This is
structural, not a regression — see `docs/ASYNC_GUIDE.md`.
