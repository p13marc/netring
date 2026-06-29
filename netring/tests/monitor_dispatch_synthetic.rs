//! End-to-end Monitor dispatch path under fully synthetic events.
//!
//! Doesn't open AF_PACKET, doesn't need CAP_NET_RAW — drives the
//! [`Dispatcher`] directly with crafted `FlowStarted<P>` / `Http`
//! payloads. Exercises the sync + async + layered-sink chain
//! together.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use flowscope::Timestamp;
use netring::anomaly::sink::NoopSink;
use netring::ctx::{CounterRegistry, Ctx, SourceIdx, StateMap};
use netring::monitor::{Dispatcher, HandlerRegistry};
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowStarted;

fn dummy_flow_started(port_a: u16, port_b: u16) -> FlowStarted<Tcp> {
    let key = flowscope::extract::FiveTupleKey::new(
        flowscope::L4Proto::Tcp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port_a),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), port_b),
    );
    FlowStarted::<Tcp>::new(key, Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0))
}

fn fresh_ctx<'a>(
    state: &'a mut StateMap,
    sink: &'a mut NoopSink,
    counters: &'a mut CounterRegistry,
    flow_states: &'a mut netring::ctx::FlowStateRegistry,
) -> Ctx<'a> {
    Ctx::new(
        None,
        Timestamp::new(0, 0),
        SourceIdx(0),
        state,
        sink,
        counters,
        flow_states,
    )
}

#[test]
fn sync_dispatch_fires_handler_once_per_event() {
    let count = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&count);

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>| {
        c.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let mut disp: Dispatcher = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut flow_states = netring::ctx::FlowStateRegistry::default();
    let mut ctx = fresh_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);

    for _ in 0..7 {
        disp.dispatch::<FlowStarted<Tcp>>(&dummy_flow_started(12345, 80), &mut ctx)
            .unwrap();
    }
    assert_eq!(count.load(Ordering::Relaxed), 7);
}

#[test]
fn sync_two_handlers_same_event_fire_in_registration_order() {
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let o1 = Arc::clone(&order);
    let o2 = Arc::clone(&order);

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>| {
        o1.lock().unwrap().push("a");
        Ok(())
    });
    reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>| {
        o2.lock().unwrap().push("b");
        Ok(())
    });
    let mut disp = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut flow_states = netring::ctx::FlowStateRegistry::default();
    let mut ctx = fresh_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);

    disp.dispatch::<FlowStarted<Tcp>>(&dummy_flow_started(12345, 80), &mut ctx)
        .unwrap();
    assert_eq!(*order.lock().unwrap(), vec!["a", "b"]);
}

#[test]
fn sync_handler_error_short_circuits_remaining() {
    let fired_after = Arc::new(AtomicU32::new(0));
    let f = Arc::clone(&fired_after);

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(|_evt: &FlowStarted<Tcp>| {
        Err(netring::Error::Config("synthetic".into()))
    });
    reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>| {
        f.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let mut disp = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut flow_states = netring::ctx::FlowStateRegistry::default();
    let mut ctx = fresh_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);

    let res = disp.dispatch::<FlowStarted<Tcp>>(&dummy_flow_started(12345, 80), &mut ctx);
    assert!(res.is_err());
    assert_eq!(
        fired_after.load(Ordering::Relaxed),
        0,
        "second handler must not fire after first errored"
    );
}

#[test]
fn unknown_event_type_is_a_silent_noop() {
    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(|_evt: &FlowStarted<Tcp>| Ok(()));
    let mut disp = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut flow_states = netring::ctx::FlowStateRegistry::default();
    let mut ctx = fresh_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);

    // Dispatch a payload type that has no handlers — quiet success.
    let unrelated: u64 = 42;
    assert!(disp.dispatch::<u64>(&unrelated, &mut ctx).is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn async_dispatch_runs_arc_capturing_handler() {
    let pool_count = Arc::new(AtomicU32::new(0));
    let p = Arc::clone(&pool_count);

    let mut reg = HandlerRegistry::default();
    reg.register_async::<FlowStarted<Tcp>, _>(move |_evt: &FlowStarted<Tcp>| {
        let p = Arc::clone(&p);
        async move {
            tokio::task::yield_now().await;
            p.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    });
    let mut disp = reg.into_dispatcher().unwrap();

    for _ in 0..3 {
        disp.dispatch_async::<FlowStarted<Tcp>>(&dummy_flow_started(12345, 80))
            .await
            .unwrap();
    }
    assert_eq!(pool_count.load(Ordering::Relaxed), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn sync_and_async_handlers_for_same_event_both_fire() {
    let sync_count = Arc::new(AtomicU32::new(0));
    let async_count = Arc::new(AtomicU32::new(0));
    let s = Arc::clone(&sync_count);
    let a = Arc::clone(&async_count);

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>| {
        s.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    reg.register_async::<FlowStarted<Tcp>, _>(move |_evt: &FlowStarted<Tcp>| {
        let a = Arc::clone(&a);
        async move {
            a.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    });
    let mut disp = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut flow_states = netring::ctx::FlowStateRegistry::default();
    let mut ctx = fresh_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);

    let evt = dummy_flow_started(12345, 80);
    for _ in 0..5 {
        disp.dispatch::<FlowStarted<Tcp>>(&evt, &mut ctx).unwrap();
        disp.dispatch_async::<FlowStarted<Tcp>>(&evt).await.unwrap();
    }
    assert_eq!(sync_count.load(Ordering::Relaxed), 5);
    assert_eq!(async_count.load(Ordering::Relaxed), 5);
}

#[test]
fn dispatcher_routes_tick_payload_to_on_tick_handler() {
    // Phase F.2: users may register tick handlers via either
    // `.tick(period, handler)` (boxed registration; run loop
    // drives) OR `.on::<Tick>(handler)` (dispatcher slot).
    // The latter is what gets exercised here — verifies the run
    // loop's `dispatcher.dispatch::<Tick>` call hits the right
    // slot for a synthetic Tick payload.
    use netring::protocol::event_typed::Tick;
    let count = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&count);
    let mut reg = HandlerRegistry::default();
    reg.register::<Tick, _, _>(move |_t: &Tick| {
        c.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let mut disp = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut flow_states = netring::ctx::FlowStateRegistry::default();
    let mut ctx = fresh_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);

    // `Tick` is `#[non_exhaustive]` so external code can't use
    // field-init syntax; the `#[doc(hidden)] pub fn new` lets
    // integration tests synthesise one (same pattern as
    // `FlowStarted::<P>::new` used by the dispatcher tests
    // above).
    let tick = Tick::new(
        Timestamp::new(123, 456),
        std::time::Duration::from_millis(100),
    );
    for _ in 0..4 {
        disp.dispatch::<Tick>(&tick, &mut ctx).unwrap();
    }
    assert_eq!(count.load(Ordering::Relaxed), 4);
}

#[test]
fn dispatcher_carries_correct_type_and_handler_counts() {
    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(|_evt: &FlowStarted<Tcp>| Ok(()));
    reg.register::<FlowStarted<Tcp>, _, _>(|_evt: &FlowStarted<Tcp>| Ok(()));
    reg.register_async::<FlowStarted<Tcp>, _>(|_evt: &FlowStarted<Tcp>| async { Ok(()) });
    let disp = reg.into_dispatcher().unwrap();

    assert_eq!(disp.type_count(), 1);
    assert_eq!(disp.handler_count(), 2);
    assert_eq!(disp.async_handler_count(), 1);
}
