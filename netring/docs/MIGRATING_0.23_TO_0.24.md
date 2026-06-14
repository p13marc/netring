# Migrating netring 0.23 → 0.24

0.24 ("Zero-Copy Core + Production Trust") is **additive** — existing 0.23
monitors compile unchanged. The one dependency bump is **flowscope 0.15**
(JA4S). This guide tours what's new and the few things worth adopting.

## Dependency

netring 0.24 requires **flowscope ≥ 0.15.0** (was 0.14.1). No code change
on your side — it's pulled transitively. The bump adds JA4S server
fingerprinting and a FoxIO-correct JA4 ALPN encoding (`http/1.1` → `h1`);
if you stored JA4 strings for multi-char ALPNs, recompute them.

## New: capture telemetry & health (Phase C)

```rust
use std::time::Duration;
let monitor = Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()
    // "is my capture keeping up?" — windowed drop_rate per source
    .on_capture_stats(Duration::from_secs(5), |t, _ctx| {
        if t.is_degraded(0.01) { eprintln!("losing >1% on {:?}", t.source); }
        Ok(())
    })
    // or the no-code forms:
    .capture_health(Duration::from_secs(10), StdoutReportSink) // CaptureHealth report
    // .capture_metrics(Duration::from_secs(10))               // Prometheus gauges (feature `metrics`)
    .build()?;

// Readiness / liveness for a /healthz endpoint:
let health = monitor.health();      // cheap, cloneable, lock-free
// health.is_ready(); health.is_live(Duration::from_secs(10));
```

See `docs/METRICS.md` for every `netring_*` metric and
`examples/monitor/health_endpoint.rs` for a dependency-free probe server.

## New: resilience (Phase B)

```rust
Monitor::builder()
    .handler_error_policy(HandlerErrorPolicy::Isolate)   // a bad detector can't tear down the pipeline
    .backend_error_policy(BackendErrorPolicy::SkipSource) // one NIC failing doesn't kill the others
    // ...
```

Defaults (`Propagate` / `FailFast`) match 0.23 behavior, so this is opt-in.

## New: bounded backpressure (Phase C)

`ChannelSink::bounded(capacity)` drops-with-count instead of growing
unbounded, so the capture task never blocks on a slow anomaly consumer:

```rust
let (sink, rx, dropped) = ChannelSink::bounded(10_000);
```

## New: flow export (Phase D)

A fourth output shape beside anomalies / reports / broadcast streams — one
record per completed flow:

```rust
Monitor::builder()
    .interface("eth0")
    .protocol::<Tcp>()
    .export_flows(|rec: &netring::export::FlowRecord| {
        println!("{:?} {} ↔ {} : {} bytes", rec.proto, rec.a, rec.b, rec.total_bytes());
    })
    // ...
```

- `JsonFlowExporter<W>` writes NDJSON (feature `serde`).
- `SyslogSink<W>` (feature `syslog`) — RFC 5424 anomaly sink.
- `IpfixExporter<W>` (feature `ipfix`) — IPFIX / NetFlow v10 flow export.

## New: TLS fingerprinting (Phase E)

```rust
Monitor::builder()
    .interface("eth0")
    .on_fingerprint(|fp, _ctx| {          // auto-registers TlsHandshake
        // fp: TlsFingerprint { sni, alpn, ja3, ja4, ja4s, key }
        if let Some(ja4s) = &fp.ja4s { /* match a blocklist */ }
        Ok(())
    })
    // ...
```

JA4S (server fingerprint) is new in flowscope 0.15. See
`docs/FINGERPRINTS.md` (incl. the JA4-BSD vs JA4+-FoxIO licensing note) and
`examples/monitor/ja4_fingerprint.rs`.

## New: AF_XDP reaches the Monitor (Phase B)

The run loop is now backend-agnostic (`AnyBackend`). Add an AF_XDP capture
source alongside (or instead of) AF_PACKET:

```rust
# #[cfg(feature = "af-xdp")]
Monitor::builder()
    .interface("eth0")           // AF_PACKET
    .xdp_interface("eth1")       // AF_XDP (feature `af-xdp`)
    // ...
```

A bare `xdp_interface` needs an attached XDP redirect program to receive
traffic (build the socket with `XdpSocketBuilder::with_default_program`,
feature `xdp-loader`); tighter in-Monitor loader integration is a follow-up.

## Nothing removed

No 0.23 API was removed or renamed. The planned breaking redesign
(subscriptions + async-effect model) lands in **0.25**.
