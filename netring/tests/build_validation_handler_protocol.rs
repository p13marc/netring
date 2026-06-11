//! 0.21 D.1: build-time validation of handler → protocol pairing.
//!
//! Build the monitor without ever calling `run_for` so AF_PACKET
//! permissions don't matter — the validation runs in
//! `MonitorBuilder::build()`.

#![cfg(all(feature = "tokio", feature = "flow", feature = "http"))]

use netring::error::{BuildError, Error};
use netring::monitor::Monitor;
use netring::protocol::builtin::{Http, Tcp};

#[test]
fn handler_without_protocol_registration_fails_build() {
    // `on::<Http>` registers a handler for parser-emitted HttpMessage.
    // Without `.protocol::<Http>()` the parser slot never gets
    // installed → handler can't fire. D.1 surfaces this at build
    // time instead of runtime silence.
    let r = Monitor::builder()
        .interface("lo")
        .on::<Http>(|_msg: &flowscope::http::HttpMessage| Ok(()))
        .build();
    match r {
        Err(Error::Build(BuildError::HandlerForUnregisteredProtocol { protocol_name })) => {
            assert_eq!(protocol_name, "http/1");
        }
        Ok(_) => panic!("expected build failure"),
        Err(other) => panic!("expected HandlerForUnregisteredProtocol; got: {other:?}"),
    }
}

#[test]
fn handler_with_matching_protocol_registration_succeeds() {
    let _m = Monitor::builder()
        .interface("lo")
        .protocol::<Http>()
        .on::<Http>(|_msg: &flowscope::http::HttpMessage| Ok(()))
        .build()
        .expect("build with matching .protocol::<Http>()");
}

#[test]
fn lifecycle_event_handler_does_not_require_protocol_call() {
    use netring::protocol::event_typed::FlowStarted;

    // `FlowStarted<Tcp>` is a lifecycle event driven by the
    // central tracker — Event::protocol_marker returns None for
    // it, so D.1 skips validation. Build should succeed without
    // calling `.protocol::<Tcp>()`.
    let _m = Monitor::builder()
        .interface("lo")
        .on::<FlowStarted<Tcp>>(|_e: &FlowStarted<Tcp>| Ok(()))
        .build()
        .expect("FlowStarted<Tcp> doesn't require .protocol::<Tcp>()");
}

#[test]
fn tick_handler_does_not_require_protocol_call() {
    use netring::protocol::event_typed::Tick;

    let _m = Monitor::builder()
        .interface("lo")
        .on::<Tick>(|_t: &Tick| Ok(()))
        .build()
        .expect("Tick doesn't require any .protocol::<P>()");
}

#[test]
fn protocol_registered_but_no_handler_is_fine() {
    // Just registering a protocol without a handler doesn't fail
    // — the user might want the parser running for its side effect
    // (slot drain feeds the central tracker's anomaly path).
    let _m = Monitor::builder()
        .interface("lo")
        .protocol::<Http>()
        .build()
        .expect("registering Http without a handler is fine");
}

#[test]
fn error_message_names_the_missing_protocol() {
    let r = Monitor::builder()
        .interface("lo")
        .on::<Http>(|_msg: &flowscope::http::HttpMessage| Ok(()))
        .build();
    let e = r.expect_err("must error");
    let s = format!("{e}");
    assert!(
        s.contains("http/1"),
        "expected error message to name the missing protocol \"http/1\"; got: {s}"
    );
}
