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
