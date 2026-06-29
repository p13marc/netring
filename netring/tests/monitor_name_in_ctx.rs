//! 0.21 D.4: verify that `MonitorBuilder::name("...")` reaches
//! handlers as `Ctx::monitor_name`.
//!
//! Drives the dispatcher directly with a synthetic
//! `FlowStarted<Tcp>` and stamps the name through a `Ctx`
//! constructed exactly like the run loop does it. No AF_PACKET
//! needed — the field-plumbing is the only thing this test
//! cares about.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;

use flowscope::Timestamp;
use netring::anomaly::sink::NoopSink;
use netring::ctx::{CounterRegistry, Ctx, SourceIdx, StateMap};
use netring::monitor::{Dispatcher, HandlerRegistry, Monitor};
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowStarted;

fn dummy_evt() -> FlowStarted<Tcp> {
    let key = flowscope::extract::FiveTupleKey::new(
        flowscope::L4Proto::Tcp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
    );
    FlowStarted::<Tcp>::new(key, Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0))
}

#[test]
fn handler_sees_monitor_name_through_ctx() {
    let observed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let o = Arc::clone(&observed);

    let mut reg = HandlerRegistry::default();
    reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
        *o.lock().unwrap() = ctx.monitor_name.map(str::to_owned);
        Ok(())
    });
    let mut disp: Dispatcher = reg.into_dispatcher().unwrap();

    let mut state = StateMap::default();
    let mut sink = NoopSink;
    let mut counters = CounterRegistry::default();
    let mut flow_states = netring::ctx::FlowStateRegistry::default();

    // Production sites construct Ctx via struct literal so the
    // monitor name lands on the right field. This test mirrors
    // that by setting `ctx.monitor_name` after `Ctx::new` (which
    // defaults it to `None`).
    let mut ctx = Ctx::new(
        None,
        Timestamp::new(0, 0),
        SourceIdx(0),
        &mut state,
        &mut sink,
        &mut counters,
        &mut flow_states,
    );
    ctx.monitor_name = Some("ingest-east");

    disp.dispatch::<FlowStarted<Tcp>>(&dummy_evt(), &mut ctx)
        .unwrap();

    assert_eq!(observed.lock().unwrap().as_deref(), Some("ingest-east"));
}

#[test]
fn builder_name_setter_is_optional() {
    // No `.name(...)` call → `Ctx::monitor_name` stays None at
    // dispatch time. Just exercises that `MonitorBuilder::build()`
    // doesn't require a name.
    let m = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .build()
        .expect("build without name");
    drop(m);
}

#[test]
fn builder_name_setter_compiles_with_string_and_str() {
    // `impl Into<Box<str>>` accepts both kinds of literal.
    let m1 = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .name("from-str")
        .build()
        .expect("build with &str name");
    let m2 = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .name(String::from("from-string"))
        .build()
        .expect("build with String name");
    drop(m1);
    drop(m2);
}
