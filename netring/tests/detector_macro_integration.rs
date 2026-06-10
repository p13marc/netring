//! Integration tests for the `detector!` macro + `MonitorBuilder::detect`.
//!
//! Verifies that the macro's `Detector<E, F>` return type lets
//! `.detect(…)` infer the event type without a turbofish, and
//! that the resulting handler dispatches correctly through the
//! registry.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use flowscope::Timestamp;
use netring::anomaly::Severity;
use netring::anomaly::sink::NoopSink;
use netring::ctx::{CounterRegistry, Ctx, SourceIdx, StateMap};
use netring::monitor::HandlerRegistry;
use netring::prelude::*;

fn dummy_flow_started() -> FlowStarted<Tcp> {
    let key = flowscope::extract::FiveTupleKey {
        proto: flowscope::L4Proto::Tcp,
        a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 22),
        b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 53456),
    };
    FlowStarted::<Tcp>::new(key, Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0))
}

fn fresh_ctx<'a>(
    state: &'a mut StateMap,
    sink: &'a mut NoopSink,
    counters: &'a mut CounterRegistry,
) -> Ctx<'a> {
    Ctx::new(
        None,
        Timestamp::new(0, 0),
        SourceIdx(0),
        state,
        sink,
        counters,
    )
}

#[test]
fn macro_returns_typed_detector_inferred_by_detect() {
    // Compile-only: the .detect(…) call uses inference from the
    // Detector<E, F> return type rather than .detect::<E, _, _>(…).
    let _m = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .detect(netring::detector! {
            name:     "InferenceCheck",
            severity: Info,
            event:    FlowStarted<Tcp>,
            emit:     |_evt, _ctx| {
                // body intentionally empty
            },
        })
        .build();
}

#[test]
fn detector_macro_drives_dispatch_path() {
    let count = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&count);

    let det = netring::detector! {
        name:     "Counter",
        severity: Info,
        event:    FlowStarted<Tcp>,
        emit:     |_evt, _ctx| {
            c.fetch_add(1, Ordering::Relaxed);
        },
    };

    // Detector<E, F> impls Handler<E, PayloadCtx> so the raw
    // registry takes it directly.
    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(det);
    let mut disp = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut ctx = fresh_ctx(&mut state, &mut sink, &mut counters);

    let evt = dummy_flow_started();
    for _ in 0..6 {
        disp.dispatch::<FlowStarted<Tcp>>(&evt, &mut ctx).unwrap();
    }
    assert_eq!(count.load(Ordering::Relaxed), 6);
}

#[test]
fn detector_macro_guard_short_circuits_emit() {
    let fired = Arc::new(AtomicU32::new(0));
    let f = Arc::clone(&fired);

    // Guard: only fire when src port is 22 (SSH).
    let det = netring::detector! {
        name:     "SshGuarded",
        severity: Info,
        event:    FlowStarted<Tcp>,
        matches:  |evt| evt.key.either_port(22),
        emit:     |_evt, _ctx| {
            f.fetch_add(1, Ordering::Relaxed);
        },
    };

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(det);
    let mut disp = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut ctx = fresh_ctx(&mut state, &mut sink, &mut counters);

    // dummy_flow_started uses port 22 → fires.
    disp.dispatch::<FlowStarted<Tcp>>(&dummy_flow_started(), &mut ctx)
        .unwrap();
    assert_eq!(fired.load(Ordering::Relaxed), 1);

    // Same payload but with a non-22 port → guard rejects, no fire.
    let key = flowscope::extract::FiveTupleKey {
        proto: flowscope::L4Proto::Tcp,
        a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
        b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
    };
    let non_ssh = FlowStarted::<Tcp>::new(key, Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0));
    disp.dispatch::<FlowStarted<Tcp>>(&non_ssh, &mut ctx)
        .unwrap();
    assert_eq!(fired.load(Ordering::Relaxed), 1, "guard short-circuited");
}

#[test]
fn detector_macro_emit_body_can_early_return() {
    // Uses `if let … else { return }` — the macro's `()`-returning
    // inner closure absorbs the early `return;`.
    let det = netring::detector! {
        name:     "EarlyReturn",
        severity: Info,
        event:    FlowStarted<Tcp>,
        emit:     |evt, ctx| {
            // Bail without emitting if l4 isn't Tcp.
            let Some(flowscope::L4Proto::Tcp) = evt.l4 else { return };
            let now = ctx.ts;
            ctx.sink_mut()
                .begin("EarlyReturn", Severity::Info, now)
                .emit();
        },
    };
    // Just needs to compile + register without panic.
    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(det);
    let _ = reg.into_dispatcher().unwrap();
}
