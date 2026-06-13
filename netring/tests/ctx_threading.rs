//! 0.22 §1.2 — `Ctx` cross-cutting infrastructure: the immutable
//! `state::<T>()` read and the always-present `label_table()`
//! accessor (with the built-in default).
//!
//! `tracker` / `lookup_icmp_flow` are exercised by the ICMP synthesis
//! integration test (§2.5) where a live tracker exists; here we only
//! assert the non-tracker accessors on a synthetic `Ctx`.

#![cfg(all(feature = "flow", feature = "tokio"))]

use netring::ctx::{CounterRegistry, Ctx, FlowStateRegistry, StateMap};

#[derive(Default)]
struct Demo {
    n: u64,
}

#[test]
fn state_read_is_none_before_touch_then_some_after() {
    let mut state = StateMap::default();
    let mut counters = CounterRegistry::default();
    let mut sink = netring::anomaly::sink::NoopSink;
    let mut flow_states = FlowStateRegistry::default();
    let mut ctx = Ctx::new(
        None,
        flowscope::Timestamp::new(0, 0),
        netring::ctx::SourceIdx(0),
        &mut state,
        &mut sink,
        &mut counters,
        &mut flow_states,
    );

    // Non-creating read: nothing registered yet.
    assert!(ctx.state::<Demo>().is_none());

    // Touch via the mutable accessor, then the immutable read sees it.
    ctx.state_mut::<Demo>().n = 7;
    assert_eq!(ctx.state::<Demo>().map(|d| d.n), Some(7));
}

#[test]
fn label_table_defaults_to_builtin_and_resolves_well_known_ports() {
    let mut state = StateMap::default();
    let mut counters = CounterRegistry::default();
    let mut sink = netring::anomaly::sink::NoopSink;
    let mut flow_states = FlowStateRegistry::default();
    let ctx = Ctx::new(
        None,
        flowscope::Timestamp::new(0, 0),
        netring::ctx::SourceIdx(0),
        &mut state,
        &mut sink,
        &mut counters,
        &mut flow_states,
    );

    // The default table inherits flowscope's built-in well-known
    // ports, so a TCP/80 flow labels as "http".
    let table = ctx.label_table();
    assert_eq!(
        table.lookup(flowscope::L4Proto::Tcp, 12345, 80),
        Some("http")
    );
}
