# netring 0.21 Phase I — flowscope 0.12 + 0.13 bonus-feature adoption

## 1. Summary

flowscope 0.12.0 and 0.13.0 shipped six bonus features beyond what netring asked for. This phase adopts each: a unified `pattern_detector!` macro extension (one wrapper covering `PortScanDetector`, `BeaconDetector`, `DgaScorer` via the `DetectorScore` trait), a DFIR file-hash example, an ECH signal detector, the `Event::tcp()` cross-variant simplification in `run.rs`, and per-flow state via `FlowStateMap`.

## 2. Status

Not started. Depends on Phase H.1 (flowscope 0.13.0).

## 3. Prerequisites

- Phase H.1 — flowscope 0.13.0 dep bump.
- Phase B.1 — `pub use flowscope::DetectorScore;` and `OwnedAnomaly` re-exports.
- Phase A.9 — `Detector::name` field for the macro to populate.

## 4. Out of scope

- Re-implementing the legacy `lateral_movement.rs` detector against `BeaconDetector`. Document the conceptual difference (BeaconDetector = single-C2 periodicity; lateral_movement = N→N port enumeration); ship `beacon_detector.rs` as the BeaconDetector demo and leave the legacy example.
- Adding broadcast variants for datagram protocols (DNS, ICMP). Wait for flowscope 0.14.

## 5. Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/detector_macro.rs` | Add `pattern_detector!` macro variant — generic over `D: Detector<K>` + `S: DetectorScore` |
| Modify | `src/monitor/run.rs` | Use `Event::tcp()` (cross-variant accessor) in `dispatch_lifecycle` |
| Modify | `src/ctx/mod.rs` | `ctx.flow_state_mut::<T>()` exposed as a wrapper over flowscope's `FlowStateMap` |
| Modify | `src/monitor/mod.rs` | `MonitorBuilder::flow_state::<T>(idle_timeout)` registration |
| New | `examples/monitor/port_scan.rs` | Rewrite of legacy port-scan example using `PortScanDetector` |
| New | `examples/monitor/beacon_detector.rs` | BeaconDetector demo |
| New | `examples/monitor/dga_query.rs` | DgaScorer demo |
| New | `examples/monitor/file_hash_dfir.rs` | Sha256Sink + FileType demo |
| New | `examples/monitor/ech_adoption.rs` | ECH outcome detector |

## 6. API

### I.1 — `pattern_detector!` macro

flowscope's `DetectorScore` trait carries `into_anomaly(ts) -> OwnedAnomaly` so the macro can emit through a uniform path; detector heterogeneity sits behind the `feed:` body the user writes. Grammar:

```text
pattern_detector! {
    name: <string literal>,                          // detector slug
    event: <Event type>,                             // e.g. FlowStarted<Tcp>
    detector: <expr returning a stateful detector>,  // PortScanDetector::default() etc.
    feed: |payload, detector_mut| <statement-list>,  // feed the detector this event
    verdict: |payload, detector_ref| <Option<S: DetectorScore>>,  // produce a score, or None
}
```

Because `Detector` holds the per-shard handler state, `pattern_detector!` moves the detector instance into the handler closure. Phase A.1's `Arc<dyn Fn>` storage requires `Fn` (not `FnMut`), so internal mutation goes through interior mutability — typically a `std::sync::Mutex<D>` inside the macro expansion:

```rust
#[macro_export]
macro_rules! pattern_detector {
    (
        name: $name:literal,
        event: $ev:ty,
        detector: $detector_expr:expr,
        feed: |$evt_pat:pat_param, $det_pat:pat_param| $feed_body:expr,
        verdict: |$evt_pat2:pat_param, $det_ref_pat:pat_param| $verdict_body:expr $(,)?
    ) => {{
        let detector = ::std::sync::Mutex::new($detector_expr);
        let __handler = move |
            __payload: &<$ev as $crate::protocol::event_typed::Event>::Payload,
            __ctx: &mut $crate::ctx::Ctx<'_>,
        | -> $crate::error::Result<()> {
            let mut guard = detector.lock().expect("detector mutex poisoned");
            {
                let $evt_pat = __payload;
                let $det_pat = &mut *guard;
                $feed_body;
            }
            let score_opt: ::std::option::Option<_> = {
                let $evt_pat2 = __payload;
                let $det_ref_pat = &*guard;
                $verdict_body
            };
            drop(guard);
            if let ::std::option::Option::Some(score) = score_opt {
                let owned = <_ as $crate::anomaly::DetectorScore>::into_anomaly(score, __ctx.ts);
                $crate::anomaly::sink::AnomalySinkExt::emit_owned(__ctx.sink_mut(), &owned);
            }
            ::std::result::Result::Ok(())
        };
        $crate::detector_macro::Detector::<$ev, _>::new(__handler)
            .with_name($name)
    }};
}
```

**Why Mutex (not RefCell):** the handler must be `Send + Sync` (per A.1's `Arc<dyn Fn + Send + Sync>` storage). `RefCell: !Sync` — won't compile. `Mutex` is `Send + Sync` and uncontended cost is ~10ns. For per-shard handlers in sharded mode, each shard's `Arc<dyn Fn>` points to a distinct `Mutex<D>` instance — no cross-shard lock traffic.

The macro is intentionally lower-level than `detector!` because the detection patterns have heterogeneous input shapes (PortScan = `ConnectionOutcome`, Beacon = `(key, ts, bytes)` tuple, DGA = `&str`). Users write the `feed:` body each time.

### I.2 — `Event::tcp()` simplification

```rust
// src/monitor/run.rs (before — manual match):
let tcp_info = match &evt {
    FsEvent::FlowPacket { tcp, .. } => tcp.as_ref(),
    _ => None,
};

// (after — flowscope 0.13's cross-variant accessor):
let tcp_info = evt.tcp();
```

Cosmetic; reduces match arms.

### I.3 — `ctx.flow_state_mut::<T>()`

```rust
// src/ctx/mod.rs
impl<'a> Ctx<'a> {
    pub fn flow_state_mut<T>(&mut self) -> Option<&mut T>
    where T: Default + Send + 'static {
        let key = self.flow?;
        Some(self.flow_state_map.get_or_default(&key, self.ts))
    }
}

// src/monitor/mod.rs
impl MonitorBuilder {
    pub fn flow_state<T>(mut self, idle_timeout: Duration) -> Self
    where T: Default + Send + 'static {
        self.flow_state_specs.push(FlowStateSpec::new::<T>(idle_timeout));
        self
    }
}
```

Each `FlowStateMap` is keyed by `FiveTupleKey`. The map evicts entries automatically when the run loop dispatches `FlowEnded<P>` for a key.

### I.4 — Examples

#### `port_scan.rs`

```rust
use netring::prelude::*;
use flowscope::detect::patterns::{PortScanDetector, ScanScore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port_scan = netring::pattern_detector! {
        name: "PortScanTRW",
        event: FlowStarted<Tcp>,
        detector: PortScanDetector::<FiveTupleKey>::default(),
        feed: |evt, det| det.record(evt.key, /* outcome */ … ),
        verdict: |evt, score| det.score_for(&evt.key.a.ip()),
    };

    Monitor::builder()
        .interface("eth0")
        .protocol::<Tcp>()
        .detect(port_scan)
        .sink(EveSink::new(std::io::stdout(), Default::default()))
        .build()?
        .run_until_signal()
        .await
}
```

#### `beacon_detector.rs` — same shape with `BeaconDetector` + `(inter-arrival, bytes)` tuple feed.

#### `dga_query.rs` — DNS query → `DgaScorer::score(name)` → threshold → `score.into_anomaly(ts, Some(&key))`.

#### `file_hash_dfir.rs` — HTTP body bytes → `Sha256Sink::update(chunk)` → on session end → `FileHashEvent` → `FileType::Pe | Elf | MachO` over plain HTTP → emit anomaly.

#### `ech_adoption.rs` — `TlsHandshake::ech_outcome` matching:
- `EchOutcome::Accepted` → `Severity::Info` "ECH active for this connection."
- `EchOutcome::Rejected` → `Severity::Warning` "possible ECH downgrade attack."
- `EchOutcome::NotOffered` / `Unknown` → no emit.

## 7. Implementation steps

1. **I.6** — Switch `dispatch_lifecycle` arms to `evt.tcp()`. Run zero-alloc bench.
2. **I.1** — Write `pattern_detector!` macro. Test against all three detectors.
3. **I.7** — Add `ctx.flow_state_mut::<T>` + `MonitorBuilder::flow_state::<T>`. Wire eviction via `FlowEnded` dispatch.
4. **I.2** — Write `port_scan.rs` using the macro.
5. **I.3** — Write `beacon_detector.rs`.
6. **I.4** — Write `dga_query.rs`.
7. **I.5** — Write `file_hash_dfir.rs` behind `--features "monitor-quickstart,file-hash"`.
8. **I.8** — Write `ech_adoption.rs`.

## 8. Tests

- `tests/pattern_detector_macro::port_scan_fires_on_threshold_cross` — synthetic ScanScore above threshold emits an OwnedAnomaly via the macro.
- `tests/pattern_detector_macro::beacon_detector_emit_via_score` — similarly for BeaconScore.
- `tests/flow_state_mut::lazy_creates_per_flow` — `ctx.flow_state_mut::<T>()` returns the same `&mut T` for the same flow key across handler invocations.
- `tests/flow_state_mut::eviction_on_flow_ended` — after `FlowEnded` dispatch, the slot is gone.
- Examples build with `cargo build --example monitor_port_scan --features monitor-quickstart`.

## 9. Acceptance criteria

- Five new examples build + run smoke-test on `lo`.
- `pattern_detector!` macro proven against all three detectors with the same wrapper code shape.
- `ctx.flow_state_mut::<T>()` integration test passes.

## 10. Risks

- **R1 — `Detector` trait heterogeneity.** The three patterns have different feed signatures (PortScan = ConnectionOutcome, Beacon = (key, ts, bytes), DGA = &str). The `pattern_detector!` macro takes a `feed:` body the user writes; the macro doesn't try to unify the input type. Document.
- **R2 — `FlowStateMap` eviction interlock.** Eviction must happen AFTER the `FlowEnded<P>` handler runs (otherwise users can't read final state in the end handler). Order: dispatch `FlowEnded` first, then evict.
- **R3 — Per-flow state memory growth.** Long-lived flows accumulate state. The TTL sweep (driven by `MonitorBuilder::flow_state::<T>(idle_timeout)`) bounds growth.
- **R4 — `pattern_detector!` Mutex vs per-shard.** The macro wraps the detector in `Arc<Mutex<D>>` so the resulting `Arc<dyn Fn>` is `Send + Sync` (Phase A.1's storage requirement). In **sharded mode** (Phase C), each shard's `Arc<dyn Fn>` points to its OWN `Mutex<D>` — but if the user shares the `pattern_detector! { ... }` invocation result across shards via clone-of-the-Detector-struct, all shards point to the same Mutex. **Document the contract**: pattern detectors must be re-instantiated per shard (or built via `Detector::factory(|| pattern_detector! { ... })` once C.6's `LayerSpec`-style instantiation lands).
- **R5 — Mutex contention on the dispatch hot path.** Each event acquires the detector's Mutex once. For a single-shard monitor at 1 Mpps that's 1M lock ops/sec ≈ 10ms/s ≈ 1% CPU. Negligible. For a sharded monitor with per-shard detectors, contention is zero (each shard has its own Mutex). Document.

## 11. Effort

- LoC delta: +600 (macro ~150, ctx.flow_state_mut ~80, 5 examples ~250, tests ~120).
- Time estimate: **~2 days** (was 3, then 2; `DetectorScore` upstream collapsed the macro work).

## 12. Provenance

- flowscope 0.12.0 plan 143 (`detect::patterns`) → I.1, I.2, I.3, I.4 examples.
- flowscope 0.12.0 plan 144 (ECH signals) → I.8 ECH example.
- flowscope 0.12.0 plan 146 (`detect::file`) → I.5 file-hash example.
- flowscope 0.13.0 plan 130 (`Event::tcp()`) → I.6 simplification.
- flowscope 0.13.0 plan 154 (`FlowStateMap`) → I.7 per-flow state.
- flowscope 0.13.0 plan 147 (`DetectorScore` trait) → I.1 unified macro shape.
- Round-1 wishlist §2.12 (per-flow `ctx.flow_state_mut::<T>()`) — reactivated from "deferred to 0.22" now that flowscope ships the foundation.
