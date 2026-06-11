//! 0.21 A.8: integration test for the per-packet / per-tick / parser-close
//! typed events. Drives the dispatcher directly with synthetic
//! `FlowPacket<P>`, `FlowTick<P>`, and `ParserClosed<P>` payloads
//! and asserts handlers scoped to the right `P` fire — TCP-typed
//! handler doesn't see UDP events and vice versa.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use flowscope::{EndReason, FlowSide, FlowStats, L4Proto, Timestamp};
use netring::anomaly::sink::NoopSink;
use netring::ctx::{CounterRegistry, Ctx, SourceIdx, StateMap};
use netring::monitor::{Dispatcher, HandlerRegistry};
use netring::protocol::builtin::{Tcp, Udp};
use netring::protocol::event_typed::{FlowPacket, FlowTick, ParserClosed};

fn key(proto: L4Proto) -> flowscope::extract::FiveTupleKey {
    flowscope::extract::FiveTupleKey {
        proto,
        a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
        b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
    }
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
fn flow_packet_tcp_handler_fires_only_for_tcp_payloads() {
    let tcp_count = Arc::new(AtomicU32::new(0));
    let udp_count = Arc::new(AtomicU32::new(0));
    let t = Arc::clone(&tcp_count);
    let u = Arc::clone(&udp_count);

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowPacket<Tcp>, _, _>(move |_evt: &FlowPacket<Tcp>| {
        t.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    reg.register::<FlowPacket<Udp>, _, _>(move |_evt: &FlowPacket<Udp>| {
        u.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let mut disp: Dispatcher = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut ctx = fresh_ctx(&mut state, &mut sink, &mut counters);

    let tcp_pkt = FlowPacket::<Tcp>::new(
        key(L4Proto::Tcp),
        FlowSide::Initiator,
        64,
        None,
        Timestamp::new(0, 0),
    );
    let udp_pkt = FlowPacket::<Udp>::new(
        key(L4Proto::Udp),
        FlowSide::Responder,
        128,
        None,
        Timestamp::new(0, 0),
    );

    for _ in 0..3 {
        disp.dispatch::<FlowPacket<Tcp>>(&tcp_pkt, &mut ctx)
            .unwrap();
    }
    for _ in 0..2 {
        disp.dispatch::<FlowPacket<Udp>>(&udp_pkt, &mut ctx)
            .unwrap();
    }

    assert_eq!(tcp_count.load(Ordering::Relaxed), 3);
    assert_eq!(udp_count.load(Ordering::Relaxed), 2);
}

#[test]
fn flow_tick_handler_receives_stats_payload() {
    let last_pkts = Arc::new(AtomicU32::new(0));
    let l = Arc::clone(&last_pkts);

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowTick<Tcp>, _, _>(move |evt: &FlowTick<Tcp>| {
        let total = evt.stats.packets_initiator + evt.stats.packets_responder;
        l.store(total as u32, Ordering::Relaxed);
        Ok(())
    });
    let mut disp: Dispatcher = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut ctx = fresh_ctx(&mut state, &mut sink, &mut counters);

    let mut stats = FlowStats::default();
    stats.packets_initiator = 7;
    stats.packets_responder = 3;
    let tick = FlowTick::<Tcp>::new(key(L4Proto::Tcp), stats, Timestamp::new(0, 0));

    disp.dispatch::<FlowTick<Tcp>>(&tick, &mut ctx).unwrap();

    assert_eq!(last_pkts.load(Ordering::Relaxed), 10);
}

#[test]
fn parser_closed_handler_observes_kind_and_reason() {
    let observed = Arc::new(std::sync::Mutex::new(None::<(&'static str, EndReason)>));
    let o = Arc::clone(&observed);

    let mut reg = HandlerRegistry::default();
    reg.register::<ParserClosed<Tcp>, _, _>(move |evt: &ParserClosed<Tcp>| {
        *o.lock().unwrap() = Some((evt.parser_kind, evt.reason));
        Ok(())
    });
    let mut disp: Dispatcher = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut ctx = fresh_ctx(&mut state, &mut sink, &mut counters);

    let evt = ParserClosed::<Tcp>::new(
        key(L4Proto::Tcp),
        "http",
        EndReason::Fin,
        Timestamp::new(0, 0),
    );
    disp.dispatch::<ParserClosed<Tcp>>(&evt, &mut ctx).unwrap();

    let got = *observed.lock().unwrap();
    assert_eq!(got, Some(("http", EndReason::Fin)));
}
