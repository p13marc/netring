//! 0.21 H.2: compile-time assertion that `Monitor`, `MonitorBuilder`,
//! `ShardedRunner`, and `EventStream<M>` are `Send`.
//!
//! flowscope 0.13's `Driver<E>: Send + Sync` cleared the last
//! `!Send` field on `Monitor` (`Rc<RefCell<…>>` in the typed-slot
//! tree). Asserting it here freezes the contract — future
//! regressions (someone reintroducing a `Rc` somewhere) will fail
//! the test instead of silently breaking multi-thread users.

#![cfg(all(feature = "tokio", feature = "flow", feature = "http"))]

use netring::monitor::{EventStream, Monitor, MonitorBuilder, ShardedRunner};
use netring::protocol::builtin::Tcp;

fn assert_send<T: Send>() {}

#[test]
fn monitor_is_send() {
    assert_send::<Monitor>();
}

#[test]
fn monitor_builder_is_send() {
    assert_send::<MonitorBuilder>();
}

#[test]
fn sharded_runner_is_send() {
    assert_send::<ShardedRunner>();
}

#[test]
fn event_stream_is_send() {
    assert_send::<EventStream<flowscope::http::HttpMessage>>();
}

/// 0.23: the *future* returned by `run_for` / `run_until` /
/// `run_until_signal` / `run_until_idle` is `Send + 'static`, so the
/// run loop can be `tokio::spawn`'d onto a multi-thread runtime.
///
/// Before 0.23 it was `!Send`: the async-dispatch path held a
/// type-erased `*const ()` and a non-`Send` boxed future across
/// `.await`. The fix (`BoxFuture: + Send` + lexically scoping the
/// pointer in `Dispatcher::dispatch_async`) removed both. This is a
/// compile-time assertion — the body is type-checked but never run.
#[allow(dead_code)]
fn run_loop_future_is_spawnable() {
    use netring::ctx::Ctx;
    use netring::monitor::Effects;
    use netring::protocol::event_typed::FlowStarted;

    fn assert_spawnable<F: std::future::Future + Send + 'static>(_: F) {}
    // 0.25-B1: register an `on_effect` handler so the assertion actually covers
    // the effect path, where the dispatcher holds `&mut Ctx` across `.await`
    // (Send-safe only because every `Ctx` field is `Send` — see effect.rs). A
    // `!Send` Ctx field would break this and fail compilation here.
    let build = || {
        Monitor::builder()
            .interface("lo")
            .protocol::<Tcp>()
            .on_effect::<FlowStarted<Tcp>>(|_evt: &FlowStarted<Tcp>, ctx: &Ctx<'_>| {
                let key = ctx.flow;
                async move {
                    tokio::task::yield_now().await;
                    let _ = key;
                    Ok::<Effects, netring::error::Error>(Effects::none())
                }
            })
            .build()
            .unwrap()
    };
    assert_spawnable(build().run_for(std::time::Duration::ZERO));
    assert_spawnable(build().run_until(std::time::Instant::now()));
    assert_spawnable(build().run_until_signal());
    assert_spawnable(build().run_until_idle(std::time::Duration::ZERO));
}
