//! 0.21 I.7: per-flow state slot accessible via
//! `ctx.flow_state_mut::<T>()`. Verifies the lazy-create path and
//! that the same `&mut T` is returned across handler invocations
//! for the same flow key.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use flowscope::Timestamp;
use netring::anomaly::sink::NoopSink;
use netring::ctx::{CounterRegistry, Ctx, FlowStateRegistry, SourceIdx, StateMap};
use netring::monitor::{Dispatcher, HandlerRegistry};
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowStarted;

#[derive(Default)]
struct PerFlowBytes {
    bytes: u64,
}

fn key() -> flowscope::extract::FiveTupleKey {
    flowscope::extract::FiveTupleKey::new(
        flowscope::L4Proto::Tcp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
    )
}

#[test]
fn flow_state_mut_lazy_creates_then_returns_same() {
    let last_seen = Arc::new(AtomicU64::new(0));
    let l = Arc::clone(&last_seen);

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
        let s = ctx
            .flow_state_mut::<PerFlowBytes>()
            .expect("flow_state registered + ctx has a flow key");
        s.bytes += 100;
        l.store(s.bytes, Ordering::Relaxed);
        Ok(())
    });
    let mut disp: Dispatcher = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut flow_states = FlowStateRegistry::default();
    flow_states.register::<PerFlowBytes>(Duration::from_secs(60));

    let evt = FlowStarted::<Tcp>::new(key(), Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0));

    let mut ctx = Ctx::new(
        Some(key()),
        Timestamp::new(0, 0),
        SourceIdx(0),
        &mut state,
        &mut sink,
        &mut counters,
        &mut flow_states,
    );

    disp.dispatch::<FlowStarted<Tcp>>(&evt, &mut ctx).unwrap();
    assert_eq!(last_seen.load(Ordering::Relaxed), 100);

    disp.dispatch::<FlowStarted<Tcp>>(&evt, &mut ctx).unwrap();
    // Same flow → same T slot → accumulates.
    assert_eq!(last_seen.load(Ordering::Relaxed), 200);

    disp.dispatch::<FlowStarted<Tcp>>(&evt, &mut ctx).unwrap();
    assert_eq!(last_seen.load(Ordering::Relaxed), 300);
}

#[test]
fn flow_state_mut_returns_none_without_flow_key() {
    let observed = Arc::new(std::sync::Mutex::new(None::<bool>));
    let o = Arc::clone(&observed);

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
        let opt = ctx.flow_state_mut::<PerFlowBytes>();
        *o.lock().unwrap() = Some(opt.is_some());
        Ok(())
    });
    let mut disp: Dispatcher = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut flow_states = FlowStateRegistry::default();
    flow_states.register::<PerFlowBytes>(Duration::from_secs(60));

    let evt = FlowStarted::<Tcp>::new(key(), Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0));

    // No flow key on the ctx → flow_state_mut returns None.
    let mut ctx = Ctx::new(
        None,
        Timestamp::new(0, 0),
        SourceIdx(0),
        &mut state,
        &mut sink,
        &mut counters,
        &mut flow_states,
    );
    disp.dispatch::<FlowStarted<Tcp>>(&evt, &mut ctx).unwrap();
    assert_eq!(*observed.lock().unwrap(), Some(false));
}

#[test]
fn flow_state_mut_returns_none_for_unregistered_type() {
    let observed = Arc::new(std::sync::Mutex::new(None::<bool>));
    let o = Arc::clone(&observed);

    #[derive(Default)]
    struct Unregistered {
        _x: u32,
    }

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
        let opt = ctx.flow_state_mut::<Unregistered>();
        *o.lock().unwrap() = Some(opt.is_some());
        Ok(())
    });
    let mut disp: Dispatcher = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut flow_states = FlowStateRegistry::default();
    // Note: NOT registering Unregistered.

    let evt = FlowStarted::<Tcp>::new(key(), Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0));

    let mut ctx = Ctx::new(
        Some(key()),
        Timestamp::new(0, 0),
        SourceIdx(0),
        &mut state,
        &mut sink,
        &mut counters,
        &mut flow_states,
    );
    disp.dispatch::<FlowStarted<Tcp>>(&evt, &mut ctx).unwrap();
    assert_eq!(*observed.lock().unwrap(), Some(false));
}

#[test]
fn flow_state_separate_per_key() {
    let key2 = flowscope::extract::FiveTupleKey::new(
        flowscope::L4Proto::Tcp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 12345),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)), 443),
    );

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut flow_states = FlowStateRegistry::default();
    flow_states.register::<PerFlowBytes>(Duration::from_secs(60));

    let mut ctx = Ctx::new(
        Some(key()),
        Timestamp::new(0, 0),
        SourceIdx(0),
        &mut state,
        &mut sink,
        &mut counters,
        &mut flow_states,
    );
    {
        let s = ctx.flow_state_mut::<PerFlowBytes>().unwrap();
        s.bytes = 100;
    }
    // Switch ctx to a different flow key — fresh slot.
    ctx.flow = Some(key2);
    {
        let s = ctx.flow_state_mut::<PerFlowBytes>().unwrap();
        assert_eq!(
            s.bytes, 0,
            "second flow gets its own default-initialized slot"
        );
        s.bytes = 7;
    }
    // Back to the first key — value persisted.
    ctx.flow = Some(key());
    {
        let s = ctx.flow_state_mut::<PerFlowBytes>().unwrap();
        assert_eq!(s.bytes, 100);
    }
}
