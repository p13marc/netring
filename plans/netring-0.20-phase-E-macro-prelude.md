# netring 0.20 — Phase E: detector! macro + prelude + multi-interface

**Effort:** 3–4 days
**Predecessor:** [`Phase D`](./netring-0.20-phase-D-middleware.md) — async + middleware
**Successor:** [`Phase F`](./netring-0.20-phase-F-percpu-sharding.md) — per-CPU sharding

## 1. Goal

Three independent ergonomic features:

1. **`detector!` macro.** A `macro_rules!` declarative DSL for stateless detectors. Closes the Suricata-rule terseness gap for the long tail of "match this shape, emit this anomaly."
2. **`netring::prelude`.** Re-exports the canonical 12 types. Collapses 5–8 `use` lines per detector to one.
3. **Multi-interface support.** `MonitorBuilder::interfaces([...])` accepts >1 interface; internally constructs `AsyncMultiCapture`. Each event carries its source-interface index.

After this phase the canonical example looks like:

```rust
use netring::prelude::*;

let truncated_tls = detector! {
    name: "TruncatedTls",
    severity: Warning,
    event: TlsHandshake,
    matches: |hs| hs.outcome == HandshakeOutcome::Truncated,
    emit: |hs, sink: Sink<()>, ts: Now| {
        sink.begin("TruncatedTls", Severity::Warning, ts)
            .with("sni", hs.sni.as_deref().unwrap_or(""))
            .emit();
    },
};

Monitor::builder()
    .interfaces(["eth0", "eth1"])  // multi-iface
    .protocol::<TlsHandshake>()
    .detect(truncated_tls)
    .layer(MinSeverity::warning())
    .sink(StdoutJsonSink::with_capacity(4096))
    .run_until_signal()
    .await?;
```

## 2. Scope

### In
- `detector!` `macro_rules!` macro — declarative stateless detector definition.
- `MonitorBuilder::detect(detector)` — accepts a detector and registers its closure.
- `netring::prelude` module re-exporting the canonical API surface.
- `MonitorBuilder::interfaces<I>([...])` multi-interface accepting `IntoIterator<Item = impl Into<String>>`.
- `AsyncMultiCapture` integration in the run loop.
- `SourceIdx` populated correctly per-event.
- New `monitor` umbrella feature collapsing `tokio + flow + parse + http + dns + tls + icmp + emit + serde`.

### Out
- Per-CPU sharding — Phase F (the `fanout_per_cpu` method).
- Migration recipes / docs — Phase G.

## 3. Dependencies

- Phase D merged: `AsyncHandler`, `Layer`, 5 shipped middleware.
- No new external dependencies.
- `AsyncMultiCapture` already exists in `src/async_adapters/multi_capture.rs` from netring 0.13.

## 4. Module layout

```
src/
├── detector_macro.rs             A  — `macro_rules!` detector!
├── prelude.rs                    A  — re-export canonical 12+ types
├── monitor/
│   ├── mod.rs                    M  — MonitorBuilder::detect + multi-iface
│   └── run.rs                    M  — switch single-AsyncCapture → AsyncMultiCapture
├── lib.rs                        M  — pub mod prelude; pub use detector_macro::*;
│
tests/
├── detector_macro.rs             A  — macro expansion + register works
├── prelude.rs                    A  — assert `use prelude::*;` brings everything
└── multi_interface.rs            A  — 2-iface monitor; SourceIdx correctness
```

**LoC estimates:** ~600 LoC new (~200 LoC macro + tests, ~80 LoC prelude, ~200 LoC multi-iface plumbing, ~120 LoC tests).

## 5. Detailed deliverables

### 5.1 `detector!` macro — `src/detector_macro.rs`

```rust
//! Declarative stateless detector. Expands to a closure that
//! implements `Handler<E, M>` for the appropriate event type.
//!
//! Grammar:
//!
//! ```text
//! detector! {
//!     name: <string literal>,
//!     severity: <Severity variant>,
//!     event: <Event type>,
//!     // Optional pattern guard. Receives `&E::Payload`, returns bool.
//!     matches: |<payload binding>| <expression>,
//!     // Mandatory emit closure. Receives the payload + extractors.
//!     emit: |<payload binding>, <extractors>| <emit expression>,
//! }
//! ```

#[macro_export]
macro_rules! detector {
    (
        name: $name:literal,
        severity: $sev:ident,
        event: $ev:ty,
        $( matches: |$guard_pat:pat_param| $guard_expr:expr, )?
        emit: |$payload:pat_param, $($extractor:ident: $extr_ty:ty),+ $(,)?| $emit_body:expr $(,)?
    ) => {
        move |
            __payload: &<$ev as $crate::protocol::event_typed::Event>::Payload,
            $($extractor: <$extr_ty as $crate::ctx::FromCtx>::Target<'_>),+
        | -> $crate::error::Result<()> {
            $(
                {
                    let $guard_pat = __payload;
                    if !($guard_expr) { return Ok(()); }
                }
            )?
            let $payload = __payload;
            // The user expression — typically calls sink.begin().emit()
            $emit_body;
            #[allow(unreachable_code)]
            { Ok(()) }
        }
    };
}
```

**Notes:**
- The macro is *just* `macro_rules!` — no proc-macro. Compile-time cost is negligible.
- The expansion is a closure that satisfies `Handler<E, (P1, P2, ...)>` for whatever extractor types the user specified. Phase B's blanket impls do the rest.
- The `matches` guard is optional; the `emit` closure is required.
- The macro doesn't construct an `Anomaly` value — it expects the user's `emit_body` to call `sink.begin(...).emit()` directly.
- The `$name` literal is currently unused in the expansion (the kind is whatever the user passes to `sink.begin`). Keep `name:` in the grammar for documentation/IDE-completion reasons; consider using it to set the `kind` arg in a future revision.

**Usage:**

```rust
let det = detector! {
    name: "TruncatedTls",
    severity: Warning,
    event: TlsHandshake,
    matches: |hs| hs.outcome == HandshakeOutcome::Truncated,
    emit: |hs, sink: Sink<()>, ts: Now| {
        sink.begin("TruncatedTls", Severity::Warning, ts)
            .with("sni", hs.sni.as_deref().unwrap_or("<none>"))
            .emit();
    },
};

monitor.detect(det);
```

### 5.2 `MonitorBuilder::detect`

```rust
impl MonitorBuilder {
    /// Register a detector produced by the `detector!` macro
    /// (or by any other handler-shaped closure).
    ///
    /// Equivalent to `.on::<E>(detector)` — the method exists for
    /// readability of detector-heavy code.
    pub fn detect<E, H, M>(self, handler: H) -> Self
    where E: Event, H: Handler<E, M>, M: 'static
    {
        self.on::<E, H, M>(handler)
    }
}
```

The `detect` method is sugar for `on`. The macro itself doesn't need a separate registration path; it just produces a closure that satisfies `Handler<E, M>` like any other.

### 5.3 `netring::prelude` — `src/prelude.rs`

```rust
//! Glob-importable re-exports of the canonical netring API.
//!
//! ```no_run
//! use netring::prelude::*;
//! ```
//!
//! This brings in everything needed to write a typical monitor
//! + detector. Power users reach past this module to
//! `netring::protocol`, `netring::ctx`, `netring::layer`, etc.,
//! directly.

// Core builder + run modes
pub use crate::monitor::Monitor;

// Protocol markers (built-in)
pub use crate::protocol::builtin::{Dns, Http, Icmp, Tcp, Tls, TlsHandshake, Udp};

// Event types
pub use crate::protocol::event_typed::{
    AnyFlowAnomaly, FlowEnded, FlowEstablished, FlowStarted, Tick,
};

// Context + extractors
pub use crate::ctx::{Counter, Now, Sink, State};

// Anomaly emission
pub use crate::anomaly::sink::AnomalySink;
pub use crate::anomaly::severity::Severity;
pub use crate::anomaly::shipped_sinks::{
    ChannelSink, OwnedAnomaly, StdoutJsonSink, StdoutSink, TracingSink,
};

// Middleware
pub use crate::layer::{
    DedupeAnomalies, MinSeverity, RateLimitAnomalies, Sample, Tee,
};

// `detector!` macro
pub use crate::detector;

// Flow types
pub use crate::protocol::FlowKey;
pub use flowscope::{EndReason, FlowSide, L4Proto, Timestamp};

// Re-export commonly-used external types
pub use std::time::Duration;
```

That's about 30 names. A user who writes `use netring::prelude::*;` gets the entire canonical surface.

### 5.4 Multi-interface support

Update `MonitorBuilder::build`:

```rust
impl MonitorBuilder {
    pub fn build(self) -> Result<Monitor, BuildError> {
        if self.interfaces.is_empty() {
            return Err(BuildError::NoInterface);
        }

        let driver = self.driver_builder
            .unwrap_or_else(|| Driver::builder(FiveTuple::bidirectional()))
            .build();

        let dispatcher = self.handlers.into_dispatcher()?;
        let sink = self.sink.unwrap_or_else(|| Box::new(NoopSink));

        Ok(Monitor {
            interfaces: self.interfaces,
            driver,
            dispatcher,
            protocol_slots: self.protocol_slots,
            state_map: self.state_map,
            counters: self.counters,
            sink,
            tick_handlers: self.tick_handlers,
        })
    }
}
```

Update `src/monitor/run.rs`:

```rust
pub(crate) async fn run_loop(mut monitor: Monitor, stop: StopCondition) -> Result<()> {
    use crate::async_adapters::AsyncMultiCapture;

    let multi = AsyncMultiCapture::open_interfaces(&monitor.interfaces)?;
    let mut multi_stream = multi.into_stream();

    while let Some(tagged) = multi_stream.next().await {
        // ... StopCondition check ...

        let tagged = tagged?;
        let source = SourceIdx(tagged.source_idx as u8);
        let view = flowscope::PacketView::new(&tagged.event.data, tagged.event.timestamp);

        // (1) Lifecycle dispatch — same as Phase B, but with
        //     the source tag plumbed into Ctx.
        monitor.lifecycle_buf.clear();
        monitor.driver.track_into(view, &mut monitor.lifecycle_buf);
        for evt in monitor.lifecycle_buf.drain(..) {
            dispatch_lifecycle(&mut monitor, evt, source)?;
        }

        // (2) Slot drain.
        for slot in &mut monitor.protocol_slots {
            let mut ctx = make_ctx(&mut monitor, None, flowscope::Timestamp::default(), source);
            slot.drain_and_dispatch(&mut monitor.dispatcher, &mut ctx)?;
        }
    }
    Ok(())
}

fn make_ctx<'a>(
    monitor: &'a mut Monitor,
    flow: Option<&'a FlowKey>,
    ts: flowscope::Timestamp,
    source: SourceIdx,
) -> Ctx<'a> {
    Ctx {
        flow, ts, source,
        state_map: &mut monitor.state_map,
        sink: monitor.sink.as_mut(),
        counters: &mut monitor.counters,
    }
}
```

The single-interface path falls out as a degenerate case of multi-interface (single-element `Vec<String>`).

### 5.5 `monitor` umbrella Cargo feature

`Cargo.toml`:

```toml
[features]
# NEW: monitor umbrella for app users.
monitor = [
    "tokio", "channel", "flow", "parse", "metrics",
    "http", "dns", "tls", "icmp",
    "emit", "serde",
]
```

Document in CHANGELOG: "App users who just want a working monitor add `features = [\"monitor\"]`. Embedded users who need fine-grained features keep using the granular set."

### 5.6 `lib.rs` exposure

```rust
#[cfg(all(feature = "flow", feature = "tokio"))]
pub mod prelude;

// Re-export the macro so `netring::detector!` works:
#[macro_use]
mod detector_macro;
```

## 6. Tests

`tests/detector_macro.rs`:

```rust
use netring::prelude::*;

#[derive(Default)] struct Hits { n: u64 }

#[test]
fn detector_macro_no_guard() {
    let _det = detector! {
        name: "AlwaysFires",
        severity: Info,
        event: Http,
        emit: |_msg, _sink: Sink<()>, _ts: Now| {
            // do something
        },
    };
    // Type assertion: the closure satisfies Handler<Http, (Sink<()>, Now)>.
    fn assert_handler<F, M>(_: F) where F: netring::monitor::Handler<Http, M> {}
    assert_handler(_det);
}

#[test]
fn detector_macro_with_guard() {
    let _det = detector! {
        name: "TruncatedTls",
        severity: Warning,
        event: TlsHandshake,
        matches: |hs| hs.outcome == flowscope::tls::HandshakeOutcome::Truncated,
        emit: |_hs, _sink: Sink<()>, _ts: Now| { },
    };
}

#[test]
fn detector_macro_registers_via_detect() {
    let _m = Monitor::builder()
        .interface("lo")
        .protocol::<Http>()
        .detect(detector! {
            name: "Test",
            severity: Info,
            event: Http,
            emit: |_msg, _sink: Sink<()>, _ts: Now| { },
        })
        .build();
}
```

`tests/prelude.rs`:

```rust
use netring::prelude::*;

#[test]
fn prelude_brings_everything() {
    // Just needs to compile. If any expected name is missing,
    // the symbol lookup fails.
    let _ = Severity::Warning;
    let _ = Duration::from_secs(1);
    let _: Option<&Tcp> = None;
    let _: Option<&Http> = None;
    let _: Option<DedupeAnomalies<StdoutSink>> = None;
    let _: Option<StdoutJsonSink> = None;
}
```

`tests/multi_interface.rs`:

```rust
#[test]
fn multi_interface_build_records_count() {
    let m = Monitor::builder()
        .interfaces(["eth0", "eth1", "eth2"])
        .protocol::<Http>()
        .on::<Http>(|_msg| Ok(()))
        .build();
    // Build succeeds — actual capture would need root.
    // Verify interface list shape.
    assert!(m.is_ok());
}

#[test]
fn single_interface_via_interfaces_works() {
    let m = Monitor::builder()
        .interfaces(["lo"])
        .protocol::<Http>()
        .on::<Http>(|_msg| Ok(()))
        .build();
    assert!(m.is_ok());
}
```

## 7. Acceptance criteria

- [ ] `cargo build --features monitor` clean.
- [ ] `cargo nextest run` — 360+ tests pass.
- [ ] `cargo +stable clippy --all-targets -- -D warnings` clean.
- [ ] `cargo fmt --check` clean.
- [ ] dhat bench still passes (≤512 B / 100k events).
- [ ] `use netring::prelude::*;` works from a downstream crate without additional `use` statements for the canonical monitor recipe.
- [ ] `detector! {...}` macro expands; registers via `.detect(...)`; runs.
- [ ] `Monitor::builder().interfaces([...])` with N>1 builds + runs (capture path tested with pcap source under `#[cfg(test)]` since we can't open real interfaces without root).

## 8. Risks + mitigations

1. **Macro hygiene issues.**
   `macro_rules!` is hygienic by default. The internal `__payload` identifier may collide with a user's `__payload` — unusual but possible. Use `$crate::__hygiene::payload` if needed, or rename to a UUID-suffixed identifier.

2. **Macro grammar drift.**
   Some users will want extractors like `Counter<IpAddr>` whose type expression includes `<>`. `pat_param` and `:ident` for extractors should handle the simple case; for `Counter<IpAddr>` the `:ty` capture handles the type expression. Verify with a test.

3. **`AsyncMultiCapture` opening N captures takes time.**
   For 2–3 interfaces this is fast (~10ms total). For more, the build may take noticeable wall-clock time. Document in `interfaces` rustdoc.

4. **Multi-interface fanout strategy.**
   Default is round-robin: events from each capture are interleaved. Document and make the choice configurable in a follow-up (Phase F's per-CPU sharding may swap fanout strategies).

5. **`SourceIdx` exhaustion at >256 interfaces.**
   `SourceIdx(u8)` caps at 256. Realistic monitors have 1–16 interfaces. If we hit 256, bump to `u16` — small breaking change.

6. **`prelude` glob-importing too much.**
   Conservative: 30 names is enough to write a monitor, but small enough not to shadow user code unintentionally. Resist the urge to add every netring type — keep prelude curated.

## 9. Estimated effort + commit shape

**Total: 3–4 working days.** ~600 LoC new code + ~250 LoC tests.

**Commits (3):**

- `netring 0.20 (E.1): detector! macro + MonitorBuilder::detect + tests` — ~250 LoC.
- `netring 0.20 (E.2): netring::prelude module + monitor umbrella Cargo feature` — ~100 LoC.
- `netring 0.20 (E.3): multi-interface support via AsyncMultiCapture + SourceIdx plumbing` — ~250 LoC + tests.

## 10. Cross-phase notes

- **Phase F** per-CPU sharding wraps the multi-interface monitor at a deeper level — each interface can itself be sharded across N CPUs.
- **Phase G** migration recipes show users replacing their hand-rolled `match` statements with `detector! { ... }` declarations.
- **Phase G** also updates the existing examples to use `netring::prelude::*` consistently.
- The `monitor` umbrella feature is the recommended feature set in `Cargo.toml` examples after Phase G.

Ready to execute once Phase D is merged.
