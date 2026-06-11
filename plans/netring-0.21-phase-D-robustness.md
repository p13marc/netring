# netring 0.21 Phase D — Robustness

## 1. Summary

Build-time validation (catch "handler references unregistered protocol" and "counter not registered" early), graceful drain on shutdown (sink flush + protocol-slot drain + bounded `drain_timeout`), an integration test for the layered-sink chain, and `MonitorBuilder::name(s)` for multi-monitor tracing.

## 2. Status

Not started. Independent of other phases except Phase A.6 (counter validation lands here, not Phase A).

## 3. Prerequisites

- Phase A.8 — typed `FlowPacket`/`FlowTick`/`ParserClosed` events (validation walks every registered TypeId).
- Phase B.1 — `KeyFields`/`AnomalyFields` re-exports for the validation module's introspection.

## 4. Out of scope

- Runtime assertion of zero-alloc on user-supplied handlers. Caught by the bench, not the runtime.
- Per-handler timeout enforcement. Out of scope; `Handler::call` is sync and finite by contract.

## 5. Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/monitor/validate.rs` | Build-time validation: `HandlerForUnregisteredProtocol` + `CounterNotRegistered` |
| Modify | `src/monitor/mod.rs` | `MonitorBuilder::build()` calls `validate::*`; `MonitorBuilder::name(&str)` |
| Modify | `src/monitor/run.rs` | Graceful drain on shutdown: per-protocol-slot drain + `sink.flush()` + bounded `drain_timeout` |
| Modify | `src/error.rs` | `BuildError::HandlerForUnregisteredProtocol { event_type, missing_protocol }`, `BuildError::CounterNotRegistered { type_name }` |
| New | `tests/monitor_layer_chain_integration.rs` | Full prelude-imported chain (MinSeverity + Dedupe + RateLimit + Sample + StdoutSink) driven through synthetic events |
| New | `tests/build_validation.rs` | Negative-path tests for both new BuildError variants |
| New | `tests/graceful_drain.rs` | Run-loop drain test under simulated SIGINT |

## 6. API

### D.1 — Build-time validation

```rust
// src/monitor/validate.rs
pub(crate) fn validate(builder: &MonitorBuilder) -> Result<(), BuildError> {
    validate_handler_protocols(builder)?;
    validate_counter_registrations(builder)?;
    Ok(())
}

fn validate_handler_protocols(b: &MonitorBuilder) -> Result<(), BuildError> {
    // For each TypeId registered in the dispatcher, walk Event::protocol_marker()
    // (added in Phase A.8). If the protocol marker isn't in the registered protocol
    // slot set, return BuildError::HandlerForUnregisteredProtocol.
}

fn validate_counter_registrations(b: &MonitorBuilder) -> Result<(), BuildError> {
    // For each handler, walk its statically-known counter references (via macro
    // metadata if available, otherwise opt-in via Detector::declared_counters).
    // If any K isn't in the counter registry, return BuildError::CounterNotRegistered.
}
```

Limitation: counter validation needs declared metadata. For raw closures registered via `.on::<E>`, we can't see inside the body — those skip counter validation. The `detector!` macro grows a `counters: [K1, K2]` field that exposes the declared counter types. Detectors registered via the macro get full validation; raw closures get protocol validation only.

### D.2 — Graceful drain

```rust
impl MonitorBuilder {
    /// Maximum time to spend draining before forcibly exiting.
    /// Default: 1 second.
    pub fn drain_timeout(mut self, t: Duration) -> Self { … }
}

// run.rs — at the end of the run loop, before returning:
async fn drain_phase(monitor: &mut Monitor, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    // 1. Drain each protocol slot's residual messages.
    for slot in &mut monitor.protocol_slots {
        slot.drain_and_dispatch(&mut monitor.dispatcher, &mut /* fresh ctx */)?;
    }
    // 2. Flush the sink.
    monitor.sink.flush()?;
    Ok(())
}
```

### D.3 — Layer-chain integration test

`tests/monitor_layer_chain_integration.rs` constructs the full prelude-imported chain end-to-end through synthetic events. Asserts exact emit count + per-layer drop counts via a `CaptureSink` at the bottom.

### D.4 — `MonitorBuilder::name(s)`

```rust
impl MonitorBuilder {
    /// Human-readable name for tracing/metrics. Default: `None`.
    /// Plumbs through `Ctx::monitor_name` so handlers, sinks, and detectors
    /// can disambiguate multi-monitor processes.
    pub fn name(mut self, name: impl Into<Box<str>>) -> Self {
        self.monitor_name = Some(name.into());
        self
    }
}

// src/ctx/mod.rs
pub struct Ctx<'a> {
    // … existing fields …
    pub monitor_name: Option<&'a str>,   // NEW — borrowed from Monitor at dispatch time
}
```

Consumers:
- **`TracingSink::write`** — emits `target: "netring::anomaly"` + `monitor: %name` field (omitted when `None`).
- **`MetricsSink::write`** — emits `"monitor" => name` label (low cardinality; one value per Monitor instance; default to `"default"` when `None` to keep label dimensionality stable).
- **User handlers** — can read `ctx.monitor_name` for cross-monitor logging.

`Box<str>` for the storage shape: a single allocation for the lifetime of the Monitor; `&str` view at dispatch time. Avoids `String`'s capacity overhead.

## 7. Implementation steps

1. **D.1** — write `validate.rs`. Add `Event::protocol_marker() -> Option<TypeId>` to the `Event` trait (default `None` for non-protocol-scoped events like `Tick`). Implement on `FlowStarted<P>` / `FlowEnded<P>` etc. as `TypeId::of::<P>()`. Wire validation into `build()`.
2. **D.2** — `drain_timeout` setter; `drain_phase` impl in run loop. Tests with simulated SIGINT.
3. **D.3** — layer-chain integration test.
4. **D.4** — `name(s)` setter + sink integration.

## 8. Tests

- `tests/build_validation::handler_for_unregistered_protocol` — `.on::<HttpMessage>(...)` without `.protocol::<Http>()` returns `BuildError::HandlerForUnregisteredProtocol { event_type: "HttpMessage", missing_protocol: "Http" }`.
- `tests/build_validation::counter_not_registered_detector_only` — `detector! { counters: [u32], … }` without `.counter::<u32>(...)` returns `BuildError::CounterNotRegistered { type_name: "u32" }`. Raw `.on::<E>(closure)` users are exempt (no metadata).
- `tests/graceful_drain::sigint_flushes_sink` — register a `ChannelSink`, send SIGINT mid-stream, assert drained anomalies arrive on the channel.
- `tests/graceful_drain::drain_timeout_honored` — slow drain finishes within `drain_timeout + 100ms` jitter.
- `tests/monitor_layer_chain_integration::full_stack_drops_match_expected` — exact drop counts at each layer.

## 9. Acceptance criteria

- New tests pass; existing tests unaffected.
- `BuildError` variants surface in the `Display` impl with the offending type name.
- Drain doesn't leak past `drain_timeout`.
- Multi-monitor processes with `.name("ingress").name("egress")` show distinct tracing/metrics labels.

## 10. Risks

- **R1 — Validation false positives.** A user might register a handler whose `E::Payload` doesn't carry a protocol marker (e.g., `Tick`). `protocol_marker()` returns `None` for those; validation skips them. Document the contract.
- **R2 — Drain phase blocks shutdown.** A slow sink (e.g., network-bound `EveSink` to a remote Filebeat) can block past `drain_timeout`. Mitigation: `drain_timeout` is the hard ceiling — any remaining drain work is dropped with a `tracing::warn!`.

## 11. Effort

- LoC delta: +400 (validate.rs ~200, drain phase ~80, builder name ~30, tests ~90).
- Time estimate: **~3 days**.

## 12. Provenance

- §2.10 (no BuildError for unregistered protocol) → D.1.
- §2.9 (counter::<K> panics if not pre-registered, revised) → D.1.
- §2.11 (no graceful shutdown drain) → D.2.
- §2.19 (no integration test for layered-sink ordering) → D.3.
- §4.1 (`MonitorBuilder::name`) → D.4.
