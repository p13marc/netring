//! 0.21 F: `Monitor::subscribe::<P>()` smoke tests.
//!
//! Pure build-side tests — they construct monitors but never run
//! a live capture so `CAP_NET_RAW` isn't required.

#![cfg(all(feature = "tokio", feature = "flow", feature = "http"))]

use netring::error::{BuildError, Error};
use netring::monitor::Monitor;
use netring::protocol::builtin::Http;

#[test]
fn subscribe_without_with_broadcast_returns_not_broadcast() {
    let m = Monitor::builder()
        .interface("lo")
        .protocol::<Http>() // regular, not broadcast
        .build()
        .expect("build with .protocol::<Http>()");
    match m.subscribe::<Http>() {
        Err(Error::Build(BuildError::ProtocolNotBroadcast { protocol_name })) => {
            assert_eq!(protocol_name, "http/1");
        }
        Ok(_) => panic!("expected ProtocolNotBroadcast"),
        Err(other) => panic!("expected ProtocolNotBroadcast; got: {other:?}"),
    }
}

#[test]
fn subscribe_with_broadcast_succeeds() {
    let m = Monitor::builder()
        .interface("lo")
        .with_broadcast::<Http>()
        .build()
        .expect("build with .with_broadcast::<Http>()");
    let stream = m
        .subscribe::<Http>()
        .expect("subscribe to broadcast-registered Http");
    // Initial state: this is the only subscriber other than the
    // dispatcher's clone (which sits behind protocol_slots).
    assert_eq!(stream.pending(), 0);
    assert!(stream.subscribers() >= 1);
    assert_eq!(stream.parser_kind(), "http/1");
}

#[test]
fn cloned_subscribers_each_have_their_own_queue() {
    let m = Monitor::builder()
        .interface("lo")
        .with_broadcast::<Http>()
        .build()
        .expect("build");
    let a = m.subscribe::<Http>().expect("subscribe a");
    let b = m.subscribe::<Http>().expect("subscribe b");
    // Two subscribers: each independently pending 0; broadcast set
    // sees ≥3 (dispatcher + a + b).
    assert_eq!(a.pending(), 0);
    assert_eq!(b.pending(), 0);
    assert!(a.subscribers() >= 3);
}

#[test]
fn event_stream_satisfies_futures_core_stream_trait() {
    // 0.21 F.4 — compile-time check that `EventStream<M>` implements
    // `futures_core::Stream<Item = M>` so consumers can plug it into
    // standard combinators (`StreamExt::next()`, `tokio::select!`, …).
    fn _accept_stream<S: futures_core::Stream + Unpin>(_s: S) {}

    let m = Monitor::builder()
        .interface("lo")
        .with_broadcast::<Http>()
        .build()
        .expect("build");
    let stream = m.subscribe::<Http>().expect("subscribe");
    _accept_stream(stream);
}

// 0.22 R1: the former Tcp-specific `ProtocolNotBroadcast` test is
// gone — `subscribe::<Tcp>()` / `with_broadcast::<Tcp>()` are now
// *compile* errors (Tcp is flow-only, not a `MessageProtocol`). The
// runtime error path (message protocol without broadcast enrolment)
// is covered by `subscribe_without_with_broadcast_returns_not_broadcast`
// above.
