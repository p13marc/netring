//! HTTP/2 protocol surfacing (0.30, the first signature-dispatched marker).
//!
//! Cap-free wiring test: build a `Monitor` with the `Http2` marker and a typed
//! `.on::<Http2>()` handler, and assert the registration path — flowscope
//! `session_heuristic` install behind the 24-byte preface signature, slot-handle
//! creation, dispatcher wiring — succeeds. `.build()` opens no capture, so no
//! CAP_NET_RAW is needed. Frame/HPACK parsing is covered by flowscope's suite.

#![cfg(all(feature = "tokio", feature = "flow", feature = "http2"))]

use flowscope::http2::Http2Event;
use netring::monitor::Monitor;
use netring::prelude::Http2;
use netring::protocol::{Dispatch, Protocol};

#[test]
fn dispatch_is_by_preface_signature() {
    assert!(matches!(Http2::dispatch(), Dispatch::Signature(_)));
    assert_eq!(Http2::NAME, "http/2");
}

#[test]
fn the_marker_is_reachable_by_every_documented_import_path() {
    // Regression: 0.30 shipped `Http2` in `protocol::builtin` only, so the two
    // paths the crate documents everywhere else — `netring::protocol::Http2`
    // and the prelude — did not resolve.
    use netring::protocol::Http2 as ViaProtocol;
    use netring::protocol::builtin::Http2 as ViaBuiltin;
    assert_eq!(
        std::any::TypeId::of::<ViaProtocol>(),
        std::any::TypeId::of::<ViaBuiltin>(),
    );
    assert_eq!(
        std::any::TypeId::of::<Http2>(),
        std::any::TypeId::of::<ViaBuiltin>()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_registers_http2_behind_the_preface_signature() {
    let built = Monitor::builder()
        .interface("lo")
        .protocol::<Http2>()
        .on::<Http2>(|e: &Http2Event| {
            // Pin the payload type. h2 multiplexes, so the routing key is the
            // event's `stream_id`, not the flow side.
            if let Http2Event::Head(head) = e {
                let _ = head.stream_id;
            }
            Ok(())
        })
        .build();

    assert!(
        built.is_ok(),
        "HTTP/2 registration should build cleanly: {:?}",
        built.err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_handler_without_the_protocol_declaration_is_rejected() {
    // `.on::<Http2>()` alone does not declare the protocol — the parser slot
    // would never be installed and the handler would silently never fire, so
    // `build()` refuses it. This is why the docs must say `.protocol::<Http2>()`.
    let built = Monitor::builder()
        .interface("lo")
        .on::<Http2>(|_e: &Http2Event| Ok(()))
        .build();

    assert!(
        built.is_err(),
        "a handler for an undeclared protocol must not build",
    );
}
