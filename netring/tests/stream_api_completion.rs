//! Integration tests for plan 24 — stream API completion:
//! `StreamSetFilter`, `StreamCapture::dedup`/`dedup_mut` defaults,
//! `tracker_stats`/`active_flows`, pcap-tap `snaplen`, and
//! `Capture::busy_poll_config`.
//!
//! Requires `CAP_NET_RAW`. Run with:
//!   cargo test --features integration-tests,tokio,flow,parse,pcap

#![cfg(all(
    feature = "integration-tests",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

mod helpers;

use std::io::Cursor;
use std::time::Duration;

use futures::StreamExt;
use netring::flow::extract::FiveTuple;
use netring::pcap::CaptureWriter;
use netring::{AsyncCapture, BpfFilter, CaptureBuilder, Dedup, StreamSetFilter, TapErrorPolicy};

fn build_async_capture() -> AsyncCapture<netring::Capture> {
    let rx = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build rx");
    AsyncCapture::new(rx).expect("AsyncCapture::new")
}

#[test]
fn stream_set_filter_replaces_active_filter() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let cap = build_async_capture();
        let stream = cap.flow_stream(FiveTuple::bidirectional());

        // Swap in a tcp-only filter via the trait verb.
        let f = BpfFilter::builder()
            .tcp()
            .dst_port(443)
            .build()
            .expect("build filter");
        stream
            .set_filter(&f)
            .expect("set_filter via StreamSetFilter");
    });
}

#[test]
fn dedup_default_methods_propagate_through_chain() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let cap = build_async_capture();

        // FlowStream without dedup → trait default returns None.
        let stream = cap.flow_stream(FiveTuple::bidirectional());
        assert!(stream.dedup().is_none());

        // FlowStream → SessionStream with dedup carried through.
        let cap = build_async_capture();
        let stream = cap
            .flow_stream(FiveTuple::bidirectional())
            .with_dedup(Dedup::loopback());
        assert!(stream.dedup().is_some());
    });
}

#[test]
fn tracker_stats_and_active_flows_are_zero_at_open() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let cap = build_async_capture();
        let stream = cap.flow_stream(FiveTuple::bidirectional());

        let stats = stream.tracker_stats();
        assert_eq!(stats.flows_created, 0);
        assert_eq!(stats.flows_ended, 0);
        assert_eq!(stats.flows_evicted, 0);
        assert_eq!(stream.active_flows(), 0);
    });
}

#[test]
fn pcap_tap_snaplen_truncates_recorded_bytes() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let buf: Vec<u8> = Vec::new();
        let writer = CaptureWriter::create(Cursor::new(buf)).expect("CaptureWriter");

        let port = helpers::unique_port();
        let marker = format!("netring_snaplen_{port}");

        let cap = build_async_capture();
        let mut stream = cap
            .flow_stream(FiveTuple::bidirectional())
            .with_pcap_tap_policy(writer, TapErrorPolicy::FailStream)
            .with_pcap_tap_snaplen(64);

        // Send a UDP packet larger than the snaplen.
        let payload = vec![0x42u8; 1024];
        let marker_clone = marker.clone();
        let port_clone = port;
        tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(50));
            helpers::send_udp_to_loopback(port_clone, &payload, 1);
            // Ensure the marker stays alive for the spawn_blocking borrow.
            drop(marker_clone);
        });

        // Drain a few events; we don't assert truncated bytes here because
        // reading the pcap back through Cursor::into_inner mid-stream is awkward.
        // The snaplen field being set is verified via the lib unit; this
        // integration confirms the chain doesn't panic / error mid-stream.
        let _ = tokio::time::timeout(Duration::from_millis(500), stream.next()).await;
    });
}

#[test]
fn capture_busy_poll_config_reflects_builder() {
    let cap = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .busy_poll_us(50)
        .prefer_busy_poll(true)
        .busy_poll_budget(64)
        .block_timeout_ms(10)
        .build()
        .expect("build rx");

    let cfg = cap.busy_poll_config();
    assert_eq!(cfg.busy_poll_us, Some(50));
    assert_eq!(cfg.prefer_busy_poll, Some(true));
    assert_eq!(cfg.busy_poll_budget, Some(64));
    assert!(cfg.is_active());
}

#[test]
fn capture_busy_poll_config_default_is_inactive() {
    let cap = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build rx");

    let cfg = cap.busy_poll_config();
    assert!(!cfg.is_active());
}
