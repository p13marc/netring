//! Steady-state allocation regression bench, gated by `dhat`.
//!
//! Runs 100k synthetic dispatches through a fully-wired
//! `Dispatcher` (3 event types + state mutation + counter bump +
//! sink emission) and asserts the heap delta is below a small
//! threshold.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p netring --features bench-zero-alloc --bench zero_alloc
//! ```
//!
//! On regression, `dhat-heap.json` is dropped in CWD with the
//! per-callsite allocation profile.

#![cfg(feature = "bench-zero-alloc")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use flowscope::Timestamp;
use netring::anomaly::Severity;
use netring::anomaly::shipped_sinks::StdoutSink;
use netring::anomaly::sink::AnomalySink;
use netring::correlate::TimeBucketedCounter;
use netring::ctx::{CounterRegistry, Ctx, FlowStateRegistry, StateMap};
use netring::monitor::{Dispatcher, HandlerRegistry};
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowStarted;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Default)]
struct Counters {
    flows: u64,
}

fn build_dispatcher() -> Dispatcher {
    let mut reg = HandlerRegistry::default();
    // 3 handlers wired to the same event — exercises multi-handler
    // dispatch per event type.
    reg.register::<FlowStarted<Tcp>, _, _>(|_evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
        ctx.state_mut::<Counters>().flows += 1;
        Ok(())
    });
    reg.register::<FlowStarted<Tcp>, _, _>(|_evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
        let now = ctx.ts;
        ctx.counter_mut::<u32>().bump(1u32, now);
        Ok(())
    });
    reg.register::<FlowStarted<Tcp>, _, _>(|_evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
        // Read ctx.ts before reborrowing the sink — the sink_mut
        // borrow would block any other ctx access otherwise.
        let now = ctx.ts;
        ctx.sink_mut()
            .write("FlowStartedTcp", Severity::Info, now, None, &[], &[]);
        Ok(())
    });
    reg.into_dispatcher()
        .expect("dispatcher build under MAX_EVENT_TYPES")
}

fn dummy_event() -> FlowStarted<Tcp> {
    let key = flowscope::extract::FiveTupleKey {
        proto: flowscope::L4Proto::Tcp,
        a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
        b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
    };
    FlowStarted::<Tcp>::new_for_bench(key, Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0))
}

fn drive(
    dispatcher: &mut Dispatcher,
    state: &mut StateMap,
    sink: &mut dyn AnomalySink,
    counters: &mut CounterRegistry,
    flow_states: &mut FlowStateRegistry,
    evt: &FlowStarted<Tcp>,
) {
    let mut ctx = Ctx::new_for_bench(Timestamp::new(0, 0), state, sink, counters, flow_states);
    dispatcher
        .dispatch::<FlowStarted<Tcp>>(evt, &mut ctx)
        .expect("dispatch");
}

fn main() {
    // dhat 0.3 canonical: testing-mode profiler emits
    // `dhat-heap.json` in CWD on assert failure / Drop. Pinning
    // `Alloc` as the global allocator above is the prerequisite.
    let _profiler = dhat::Profiler::builder().testing().build();

    let mut dispatcher = build_dispatcher();
    let mut state = StateMap::default();
    let mut sink = StdoutSink::with_capacity(4096);
    let mut counters = CounterRegistry::default();
    counters.register::<u32>(TimeBucketedCounter::<u32>::new_unbounded(
        Duration::from_secs(60),
        Duration::from_secs(1),
    ));

    let mut flow_states = FlowStateRegistry::default();
    let evt = dummy_event();

    // Warm-up: let any one-time allocations settle (Vec growth,
    // hashmap insert, sink scratch buffer, …). Without this, the
    // first-iteration startup costs would dominate the steady-state
    // measurement.
    for _ in 0..10_000 {
        drive(
            &mut dispatcher,
            &mut state,
            &mut sink,
            &mut counters,
            &mut flow_states,
            &evt,
        );
    }

    let before = dhat::HeapStats::get();
    for _ in 0..100_000 {
        drive(
            &mut dispatcher,
            &mut state,
            &mut sink,
            &mut counters,
            &mut flow_states,
            &evt,
        );
    }
    let after = dhat::HeapStats::get();

    let delta_bytes = after.curr_bytes as i64 - before.curr_bytes as i64;
    let delta_blocks = after.curr_blocks as i64 - before.curr_blocks as i64;

    eprintln!("100k synthetic dispatches: Δ {delta_bytes} bytes, Δ {delta_blocks} blocks");

    // Threshold: 512 bytes of net heap growth and ≤100 new live
    // blocks. The TimeBucketedCounter buckets churn on bump() —
    // that's the only legitimate source of slow drift in steady
    // state. Tightening past this would have to lift the bucket
    // churn out of the bench.
    assert!(
        delta_bytes < 512,
        "allocation regression: Δ {delta_bytes} bytes (limit 512). See dhat-heap.json."
    );
    assert!(
        delta_blocks < 100,
        "block regression: Δ {delta_blocks} blocks (limit 100). See dhat-heap.json."
    );
}
