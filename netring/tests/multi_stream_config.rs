//! Plan 26 — `MultiStreamConfig` propagation through
//! `AsyncMultiCapture::*_stream_with` constructors.
//!
//! Requires `CAP_NET_RAW` (multi captures use AF_PACKET sockets).

#![cfg(all(
    feature = "integration-tests",
    feature = "tokio",
    feature = "flow",
    feature = "parse"
))]

mod helpers;

use std::time::Duration;

use flowscope::{FlowTrackerConfig, OverflowPolicy, Timestamp};
use netring::flow::extract::{FiveTuple, FiveTupleKey};
use netring::{AsyncMultiCapture, Dedup, MultiStreamConfig};

#[test]
fn empty_config_matches_default_constructor() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // Two `lo` captures, no config → fall through to defaults.
        let multi = AsyncMultiCapture::open([helpers::LOOPBACK, helpers::LOOPBACK]).unwrap();
        let stream = multi.flow_stream_with(
            FiveTuple::bidirectional(),
            MultiStreamConfig::<FiveTupleKey>::default(),
        );
        // Stats accessors work; alive_sources reflects the two
        // inner captures.
        assert_eq!(stream.alive_sources(), 2);
        let stats = stream.per_source_tracker_stats();
        assert_eq!(stats.len(), 2);
    });
}

#[test]
fn tracker_config_propagates_per_source() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut tc = FlowTrackerConfig::default();
        tc.idle_timeout_tcp = Duration::from_secs(42);
        tc.overflow_policy = OverflowPolicy::DropFlow;

        let multi = AsyncMultiCapture::open([helpers::LOOPBACK]).unwrap();
        let stream = multi.flow_stream_with(
            FiveTuple::bidirectional(),
            MultiStreamConfig::new().with_tracker_config(tc),
        );

        // Stream is alive after construction (we can drop without
        // running it). The integration confirms the chain compiles
        // + builds without panicking.
        assert_eq!(stream.alive_sources(), 1);
    });
}

#[test]
fn dedup_template_clones_per_source() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let multi = AsyncMultiCapture::open([helpers::LOOPBACK, helpers::LOOPBACK]).unwrap();
        let stream = multi.flow_stream_with(
            FiveTuple::bidirectional(),
            MultiStreamConfig::new().with_dedup(Dedup::loopback()),
        );
        // Compile-only smoke: dedup propagated without panic, and
        // each source got an independent clone.
        assert_eq!(stream.alive_sources(), 2);
    });
}

#[test]
fn idle_timeout_fn_shared_across_sources() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let multi = AsyncMultiCapture::open([helpers::LOOPBACK]).unwrap();
        let stream = multi.flow_stream_with(
            FiveTuple::bidirectional(),
            MultiStreamConfig::<FiveTupleKey>::new().with_idle_timeout_fn(|k, _l4| {
                if k.either_port(15987) {
                    Some(Duration::from_secs(600))
                } else {
                    None
                }
            }),
        );
        assert_eq!(stream.alive_sources(), 1);
    });
}

#[test]
fn monotonic_timestamps_toggle() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let multi = AsyncMultiCapture::open([helpers::LOOPBACK]).unwrap();
        let stream = multi.flow_stream_with(
            FiveTuple::bidirectional(),
            MultiStreamConfig::<FiveTupleKey>::new().with_monotonic_timestamps(true),
        );
        assert_eq!(stream.alive_sources(), 1);
    });
}

#[test]
fn session_stream_with_compiles_with_full_config() {
    use flowscope::{SessionParser, SessionParserFactory};

    #[derive(Clone, Debug, Default)]
    struct StubFactory;
    #[derive(Clone, Debug)]
    struct StubParser;

    impl SessionParser for StubParser {
        type Message = ();

        fn feed_initiator(&mut self, _: &[u8], _: Timestamp, _out: &mut Vec<Self::Message>) {}
        fn feed_responder(&mut self, _: &[u8], _: Timestamp, _out: &mut Vec<Self::Message>) {}
    }

    impl SessionParserFactory<FiveTupleKey> for StubFactory {
        type Parser = StubParser;
        fn new_parser(&mut self, _key: &FiveTupleKey) -> Self::Parser {
            StubParser
        }
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let multi = AsyncMultiCapture::open([helpers::LOOPBACK]).unwrap();
        let stream = multi.session_stream_with(
            FiveTuple::bidirectional(),
            StubFactory,
            MultiStreamConfig::<FiveTupleKey>::new()
                .with_dedup(Dedup::loopback())
                .with_monotonic_timestamps(true),
        );
        assert_eq!(stream.alive_sources(), 1);
    });
}
