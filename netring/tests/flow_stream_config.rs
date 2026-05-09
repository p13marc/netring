//! Integration tests for `FlowTrackerConfig` propagation through the
//! async-stream builder chain.
//!
//! Closes feedback item F2 from des-rs (`plans/feedback-from-des-rs-2026-05-09.md`):
//! before plan 14, `cap.flow_stream(ext).with_config(cfg).session_stream(parser)`
//! silently dropped `cfg` when transitioning into `SessionStream`. Now
//! the tracker config is preserved across the conversion, and
//! `SessionStream::with_config` lets users set it directly.
//!
//! Requires `CAP_NET_RAW` on the test binary (provided by `just setcap`).
//! The tests build the stream chain but never poll it — no packets are
//! captured, so behavior is independent of network state.

#![cfg(all(
    feature = "integration-tests",
    feature = "flow",
    feature = "tokio",
    feature = "parse"
))]

mod helpers;

use std::time::Duration;

use flowscope::{FlowTrackerConfig, OverflowPolicy, SessionParser, SessionParserFactory};
use netring::flow::extract::FiveTuple;
use netring::{AsyncCapture, CaptureBuilder};

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

#[derive(Default, Clone)]
struct StubFactory;

impl<K> SessionParserFactory<K> for StubFactory {
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

fn make_cfg(idle: Duration, buf: usize) -> FlowTrackerConfig {
    // FlowTrackerConfig is `#[non_exhaustive]` — start from default and
    // assign fields by name.
    let mut cfg = FlowTrackerConfig::default();
    cfg.idle_timeout_tcp = idle;
    cfg.max_reassembler_buffer = Some(buf);
    cfg.overflow_policy = OverflowPolicy::DropFlow;
    cfg
}

#[tokio::test]
async fn config_propagates_from_flow_stream_to_session_stream() {
    let cfg = make_cfg(Duration::from_secs(123), 1 << 20);

    let session = build_async_capture()
        .flow_stream(FiveTuple::bidirectional())
        .with_config(cfg)
        .session_stream(StubFactory);

    let got = session.tracker().config();
    assert_eq!(got.idle_timeout_tcp, Duration::from_secs(123));
    assert_eq!(got.max_reassembler_buffer, Some(1 << 20));
    assert!(matches!(got.overflow_policy, OverflowPolicy::DropFlow));
}

#[tokio::test]
async fn session_stream_with_config_overrides_default() {
    let cfg = make_cfg(Duration::from_secs(7), 4096);

    let session = build_async_capture()
        .flow_stream(FiveTuple::bidirectional())
        .session_stream(StubFactory)
        .with_config(cfg);

    let got = session.tracker().config();
    assert_eq!(got.idle_timeout_tcp, Duration::from_secs(7));
    assert_eq!(got.max_reassembler_buffer, Some(4096));
    assert!(matches!(got.overflow_policy, OverflowPolicy::DropFlow));
}
