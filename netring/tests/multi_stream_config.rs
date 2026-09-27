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

/// One `MultiSessionStream` over a live `lo` source (`from_streams`) and
/// a pcap replay (`push_source`) — the des-capture shape (#177). The
/// live source has a kernel ring, the replay has none; the replay ends
/// and stays introspectable.
#[cfg(feature = "pcap")]
#[test]
fn live_and_replay_share_one_multi_session_stream() {
    use flowscope::SessionParser;
    use futures::StreamExt;
    use netring::{AsyncCapture, AsyncPcapSource, MultiSessionStream};

    #[derive(Clone, Default)]
    struct Nop;
    impl SessionParser for Nop {
        type Message = ();
        fn feed_initiator(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
        fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let live = AsyncCapture::open(helpers::LOOPBACK)
            .unwrap()
            .flow_stream(FiveTuple::bidirectional())
            .session_stream(Nop);
        let dir = tempfile::tempdir().unwrap();
        let path = helpers::pcap::write_pcap(
            dir.path(),
            "a",
            &helpers::pcap::flow(&[(0, b"hello".to_vec())]),
        );
        let replay = AsyncPcapSource::open(&path)
            .await
            .unwrap()
            .sessions(FiveTuple::bidirectional(), Nop);

        let mut m = MultiSessionStream::from_streams([(helpers::LOOPBACK.to_string(), live)]);
        let idx = m.push_source("a.pcap", replay);
        assert_eq!(idx, 1);
        assert_eq!(m.alive_sources(), 2);
        assert!(
            m.source(0).unwrap().capture_stats().is_some(),
            "the live source has a kernel ring"
        );
        assert!(m.source(idx).unwrap().capture_stats().is_none());
        assert_eq!(m.source(idx).unwrap().packets_read(), Some(0));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while m.is_alive(idx) == Some(true) && tokio::time::Instant::now() < deadline {
            let _ = tokio::time::timeout(Duration::from_millis(200), m.next()).await;
        }
        assert_eq!(
            m.is_alive(idx),
            Some(false),
            "the replay reached end-of-file"
        );
        assert_eq!(m.is_alive(0), Some(true));
        assert_eq!(m.alive_sources(), 1);
        assert_eq!(m.source(idx).unwrap().tracker_stats().flows_ended, 1);
        assert_eq!(m.source(idx).unwrap().packets_read(), Some(7));
        assert_eq!(m.per_source_snapshot_flow_stats().len(), 2);
    });
}
