//! Issue #17 (M0 spike) — **measure before building** the `subscribe!`
//! compile-time specialization.
//!
//! Retina's efficiency win is compiling dispatch *tailored* to the
//! subscription so unneeded work is eliminated. netring does runtime dispatch:
//! a `TypeId`-keyed slot table (`Dispatcher::dispatch::<E>`) plus boxed `dyn`
//! handler calls. A `subscribe!` proc-macro would monomorphize that into a
//! direct call. **This bench quantifies the headroom** so we don't build
//! codegen against a guessed cost — the issue's hard gate.
//!
//! Three numbers in one report:
//!
//! - `track_into_per_frame` — flowscope flow tracking, the dominant per-packet
//!   cost the run loop pays *regardless* of dispatch (the denominator).
//! - `runtime_dispatch` — one event through the `TypeId` slot table + a boxed
//!   handler (today's path).
//! - `monomorphic_direct` — the same handler called directly (what the macro
//!   would emit). The difference `runtime_dispatch − monomorphic_direct` is the
//!   per-event overhead a `subscribe!` macro could remove.
//!
//! If that overhead is a small fraction of `track_into`, monomorphizing dispatch
//! buys negligible end-to-end throughput → ship the ergonomic macro only, or
//! shelve. Run:
//!
//! ```sh
//! cargo bench --features bench-zero-alloc --bench dispatch_specialization
//! ```

#![cfg(feature = "bench-zero-alloc")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use etherparse::PacketBuilder;
use flowscope::Timestamp;
use flowscope::driver::Driver;
use flowscope::extract::{FiveTuple, FiveTupleKey};
use netring::anomaly::sink::NoopSink;
use netring::ctx::{CounterRegistry, Ctx, FlowStateRegistry, StateMap};
use netring::monitor::{Dispatcher, HandlerRegistry};
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowStarted;

#[derive(Default)]
struct Counters {
    flows: u64,
}

/// One trivial handler body — a state bump. Identical work in both the
/// dispatcher path and the direct path, so the delta is pure dispatch
/// mechanism (slot-table lookup + boxed `dyn` call).
#[inline]
fn handler_body(ctx: &mut Ctx<'_>) {
    ctx.state_mut::<Counters>().flows += 1;
}

fn dummy_event() -> FlowStarted<Tcp> {
    let key = FiveTupleKey::new(
        flowscope::L4Proto::Tcp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
    );
    FlowStarted::<Tcp>::new_for_bench(key, Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0))
}

fn tcp_frame(sport: u16, dport: u16) -> Vec<u8> {
    let b = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(sport, dport, 0, 1024);
    let mut frame = Vec::with_capacity(64);
    b.write(&mut frame, &[]).unwrap();
    frame
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("specialization");
    group.throughput(Throughput::Elements(1));

    // ── denominator: the per-frame flow-tracking cost ───────────────────────
    let frames: Vec<Vec<u8>> = (0..64).map(|i| tcp_frame(20000 + i, 443)).collect();
    let ts = Timestamp::from_unix_f64(1000.0);
    group.bench_function("track_into_per_frame", |b| {
        let mut driver = Driver::builder(FiveTuple::bidirectional()).build();
        let mut events = Vec::with_capacity(8);
        let mut i = 0usize;
        b.iter(|| {
            events.clear();
            let f = &frames[i % frames.len()];
            driver.track_into(flowscope::PacketView::new(f, ts), &mut events);
            i += 1;
            std::hint::black_box(driver.tracker().flow_count());
        });
    });

    // ── today's runtime dispatch: TypeId slot table + boxed dyn handler ─────
    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(|_evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
        handler_body(ctx);
        Ok(())
    });
    let mut dispatcher: Dispatcher = reg.into_dispatcher().expect("dispatcher build");
    let evt = dummy_event();

    {
        let mut state = StateMap::default();
        let mut sink = NoopSink;
        let mut counters = CounterRegistry::default();
        let mut flow_states = FlowStateRegistry::default();
        group.bench_function("runtime_dispatch", |b| {
            b.iter(|| {
                let mut ctx = Ctx::new_for_bench(
                    Timestamp::new(0, 0),
                    &mut state,
                    &mut sink,
                    &mut counters,
                    &mut flow_states,
                );
                dispatcher
                    .dispatch::<FlowStarted<Tcp>>(std::hint::black_box(&evt), &mut ctx)
                    .expect("dispatch");
            });
        });
    }

    // ── the macro target: the same handler called directly (monomorphic) ────
    {
        let mut state = StateMap::default();
        let mut sink = NoopSink;
        let mut counters = CounterRegistry::default();
        let mut flow_states = FlowStateRegistry::default();
        group.bench_function("monomorphic_direct", |b| {
            b.iter(|| {
                let mut ctx = Ctx::new_for_bench(
                    Timestamp::new(0, 0),
                    &mut state,
                    &mut sink,
                    &mut counters,
                    &mut flow_states,
                );
                let _ = std::hint::black_box(&evt);
                handler_body(&mut ctx);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
