//! Integration tests for plan 22: `AsyncMultiCapture` + multi-streams.
//!
//! Requires `CAP_NET_RAW`. Run with:
//!   cargo test --features integration-tests,tokio,flow,parse

#![cfg(all(
    feature = "integration-tests",
    feature = "tokio",
    feature = "flow",
    feature = "parse"
))]

mod helpers;

use std::time::Duration;

use futures::StreamExt;
use netring::AsyncMultiCapture;
use netring::flow::extract::FiveTuple;

#[test]
fn open_two_lo_captures_yields_tagged_events() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let port = helpers::unique_port();
        let marker = format!("multi_{port}");

        // Two captures on `lo` — same interface twice. Both receive
        // any UDP packet sent to 127.0.0.1; the merged stream tags
        // each with its source index.
        let multi = AsyncMultiCapture::open([helpers::LOOPBACK, helpers::LOOPBACK])
            .expect("AsyncMultiCapture::open");
        assert_eq!(multi.len(), 2);
        assert_eq!(multi.label(0), Some(helpers::LOOPBACK));
        assert_eq!(multi.label(1), Some(helpers::LOOPBACK));

        let mut stream = multi.flow_stream(FiveTuple::bidirectional());

        let marker_clone = marker.clone();
        let _sender = tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(50));
            helpers::send_udp_to_loopback(port, marker_clone.as_bytes(), 3);
        });

        let mut saw_src0 = false;
        let mut saw_src1 = false;
        let deadline = tokio::time::sleep(Duration::from_secs(3));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                biased;
                _ = &mut deadline => break,
                evt = stream.next() => match evt {
                    Some(Ok(tagged)) => {
                        match tagged.source_idx {
                            0 => saw_src0 = true,
                            1 => saw_src1 = true,
                            other => panic!("unexpected source_idx {other}"),
                        }
                        if saw_src0 && saw_src1 { break; }
                    }
                    Some(Err(e)) => panic!("stream error: {e}"),
                    None => break,
                }
            }
        }

        assert!(saw_src0, "no events from source 0");
        assert!(saw_src1, "no events from source 1");
    });
}

#[test]
fn open_workers_creates_n_captures_in_fanout_group() {
    // `lo` has no RSS so FanoutMode::Cpu will collapse to one
    // worker — use LoadBalance for the test instead so we get
    // round-robin and can observe distribution.
    use netring::FanoutMode;

    let multi = AsyncMultiCapture::open_workers_with_mode(
        helpers::LOOPBACK,
        4,
        0xBEEF,
        FanoutMode::LoadBalance,
    )
    .expect("open_workers_with_mode");

    assert_eq!(multi.len(), 4);
    assert_eq!(multi.label(0), Some("worker-0"));
    assert_eq!(multi.label(3), Some("worker-3"));
}

#[test]
fn aggregate_capture_stats_combines_per_source() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let multi = AsyncMultiCapture::open([helpers::LOOPBACK, helpers::LOOPBACK])
            .expect("AsyncMultiCapture::open");
        let stream = multi.flow_stream(FiveTuple::bidirectional());

        // Fresh capture — stats should be zero.
        let agg = stream.capture_stats();
        assert_eq!(agg.packets, 0);
        assert_eq!(agg.drops, 0);

        let per = stream.per_source_capture_stats();
        assert_eq!(per.len(), 2);
        for (label, stats) in per {
            assert!(label == helpers::LOOPBACK);
            let s = stats.expect("alive").expect("stats");
            assert_eq!(s.packets, 0);
        }
    });
}

#[test]
fn from_captures_round_trips_with_labels() {
    use netring::{AsyncCapture, Capture, CaptureBuilder};

    let cap_a: Capture = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .build()
        .expect("build a");
    let cap_b: Capture = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .build()
        .expect("build b");

    let multi = AsyncMultiCapture::from_captures(
        vec![
            AsyncCapture::new(cap_a).expect("a"),
            AsyncCapture::new(cap_b).expect("b"),
        ],
        Some(vec!["alpha".into(), "beta".into()]),
    )
    .expect("from_captures");

    assert_eq!(multi.label(0), Some("alpha"));
    assert_eq!(multi.label(1), Some("beta"));
    let (caps, labels) = multi.into_captures();
    assert_eq!(caps.len(), 2);
    assert_eq!(labels, vec!["alpha".to_string(), "beta".into()]);
}
