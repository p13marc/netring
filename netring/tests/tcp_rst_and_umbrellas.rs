//! 0.22 §2.6 + §2.7 — `TcpRst` typed event + `all_l4`/`all_l7`
//! umbrellas.
//!
//! The FlowEnded→TcpRst *synthesis* lives in the run loop (exercised
//! by the live/replay paths); here we pin the type's `zero_payload`
//! logic, the dispatch wiring, and that the umbrella builders build.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use flowscope::{FlowStats, L4Proto, Timestamp};
use netring::anomaly::sink::NoopSink;
use netring::ctx::{CounterRegistry, Ctx, FlowStateRegistry, SourceIdx, StateMap};
use netring::monitor::{Dispatcher, HandlerRegistry, Monitor};
use netring::protocol::event_typed::TcpRst;

fn key() -> flowscope::extract::FiveTupleKey {
    flowscope::extract::FiveTupleKey {
        proto: L4Proto::Tcp,
        a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5555),
        b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
    }
}

#[test]
fn tcp_rst_zero_payload_reflects_total_bytes() {
    let empty = TcpRst::new(key(), FlowStats::default(), Timestamp::new(0, 0));
    assert!(empty.zero_payload, "no bytes → zero_payload");

    let mut stats = FlowStats::default();
    stats.bytes_initiator = 120;
    let moved = TcpRst::new(key(), stats, Timestamp::new(0, 0));
    assert!(!moved.zero_payload, "bytes moved → not zero_payload");
}

#[test]
fn tcp_rst_dispatches_to_handler() {
    let hits = Arc::new(AtomicU32::new(0));
    let h = Arc::clone(&hits);

    let mut reg = HandlerRegistry::default();
    reg.register::<TcpRst, _, _>(move |rst: &TcpRst| {
        assert!(rst.zero_payload);
        h.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let mut disp: Dispatcher = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut flow_states = FlowStateRegistry::default();
    let mut ctx = Ctx::new(
        None,
        Timestamp::new(0, 0),
        SourceIdx(0),
        &mut state,
        &mut sink,
        &mut counters,
        &mut flow_states,
    );

    let rst = TcpRst::new(key(), FlowStats::default(), Timestamp::new(0, 0));
    disp.dispatch::<TcpRst>(&rst, &mut ctx).unwrap();
    assert_eq!(hits.load(Ordering::Relaxed), 1);
}

#[test]
fn all_l4_builds_and_on_tcp_reset_builds() {
    // `all_l4` registers Tcp + Udp (+ Icmp under feature); `on_tcp_reset`
    // accepts both closure shapes. Both must produce a buildable monitor.
    let _m: Monitor = Monitor::builder()
        .interface("lo")
        .all_l4()
        .on_tcp_reset(|_rst: &TcpRst, _ctx: &mut Ctx<'_>| Ok(()))
        .build()
        .expect("all_l4 + on_tcp_reset builds");
}

#[cfg(any(feature = "http", feature = "dns", feature = "tls"))]
#[test]
fn all_l7_builds() {
    let _m: Monitor = Monitor::builder()
        .interface("lo")
        .all_l7()
        .build()
        .expect("all_l7 builds");
}
