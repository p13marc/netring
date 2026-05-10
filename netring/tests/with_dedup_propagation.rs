//! Integration tests for [`Dedup`] propagation through the async-stream
//! builder chain.
//!
//! Closes feedback item F7 / plan 17: `cap.flow_stream(ext).with_dedup(d)`
//! carries the dedup forward through `session_stream` /
//! `datagram_stream` / `with_async_reassembler` / `with_state`. The
//! dedup primitive itself is exercised end-to-end against real `lo`
//! traffic in `dedup_lo.rs`; this file just validates that the
//! plumbing keeps the dedup attached across each transition.
//!
//! Requires `CAP_NET_RAW` on the test binary (provided by `just setcap`).
//! The tests build the stream chain but never poll it — no packets are
//! captured, so behaviour is independent of network state.

#![cfg(all(
    feature = "integration-tests",
    feature = "flow",
    feature = "tokio",
    feature = "parse"
))]

mod helpers;

use flowscope::{DatagramParser, FlowSide, SessionParser, SessionParserFactory};
use netring::flow::extract::FiveTuple;
use netring::{AsyncCapture, CaptureBuilder, Dedup};

#[derive(Default, Clone)]
struct StubParser;

impl SessionParser for StubParser {
    type Message = ();
    fn feed_initiator(&mut self, _: &[u8]) -> Vec<()> {
        Vec::new()
    }
    fn feed_responder(&mut self, _: &[u8]) -> Vec<()> {
        Vec::new()
    }
}

impl DatagramParser for StubParser {
    type Message = ();
    fn parse(&mut self, _: &[u8], _: FlowSide) -> Vec<()> {
        Vec::new()
    }
}

#[derive(Default, Clone)]
struct StubFactory;

impl<K> SessionParserFactory<K> for StubFactory {
    type Parser = StubParser;
    fn new_parser(&mut self, _key: &K) -> StubParser {
        StubParser
    }
}

impl<K> flowscope::DatagramParserFactory<K> for StubFactory {
    type Parser = StubParser;
    fn new_parser(&mut self, _key: &K) -> StubParser {
        StubParser
    }
}

fn build_async_capture() -> AsyncCapture<netring::Capture> {
    let rx = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build rx");
    AsyncCapture::new(rx).expect("wrap in AsyncFd")
}

#[tokio::test]
async fn with_dedup_attaches_to_flow_stream() {
    let stream = build_async_capture()
        .flow_stream(FiveTuple::bidirectional())
        .with_dedup(Dedup::loopback());

    assert!(
        stream.dedup().is_some(),
        "with_dedup() should attach a Dedup"
    );
}

#[tokio::test]
async fn with_dedup_carries_through_session_stream() {
    let session = build_async_capture()
        .flow_stream(FiveTuple::bidirectional())
        .with_dedup(Dedup::loopback())
        .session_stream(StubFactory);

    assert!(
        session.dedup().is_some(),
        "session_stream() should preserve the dedup set on FlowStream"
    );
}

#[tokio::test]
async fn with_dedup_carries_through_datagram_stream() {
    let datagram = build_async_capture()
        .flow_stream(FiveTuple::bidirectional())
        .with_dedup(Dedup::loopback())
        .datagram_stream(StubFactory);

    assert!(
        datagram.dedup().is_some(),
        "datagram_stream() should preserve the dedup set on FlowStream"
    );
}

#[tokio::test]
async fn session_stream_with_dedup_after_construction() {
    let session = build_async_capture()
        .flow_stream(FiveTuple::bidirectional())
        .session_stream(StubFactory)
        .with_dedup(Dedup::loopback());

    assert!(
        session.dedup().is_some(),
        "SessionStream::with_dedup() should attach a Dedup"
    );
}

#[tokio::test]
async fn datagram_stream_with_dedup_after_construction() {
    let datagram = build_async_capture()
        .flow_stream(FiveTuple::bidirectional())
        .datagram_stream(StubFactory)
        .with_dedup(Dedup::loopback());

    assert!(
        datagram.dedup().is_some(),
        "DatagramStream::with_dedup() should attach a Dedup"
    );
}

#[tokio::test]
async fn dedup_counters_reachable_via_accessor() {
    let mut stream = build_async_capture()
        .flow_stream(FiveTuple::bidirectional())
        .with_dedup(Dedup::loopback());

    let dedup = stream.dedup().expect("dedup attached");
    assert_eq!(dedup.seen(), 0);
    assert_eq!(dedup.dropped(), 0);

    // dedup_mut() lets users reset / inspect counters.
    let dedup_mut = stream.dedup_mut().expect("dedup attached");
    assert_eq!(dedup_mut.dropped(), 0);
}
