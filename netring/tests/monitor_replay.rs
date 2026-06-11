//! 0.21 E.1: `Monitor::replay` from a synthetic pcap file.
//!
//! Builds a small UDP-only pcap, points the monitor at it, asserts
//! the FlowStarted<Udp> handler fired at least once.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::error::{BuildError, Error};
use netring::monitor::Monitor;
use netring::protocol::builtin::Udp;
use netring::protocol::event_typed::FlowStarted;
use tempfile::NamedTempFile;

fn synthetic_udp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 14 + 20 + 8 + payload.len();
    let mut frame = Vec::with_capacity(total_len);
    // Ethernet
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    frame.extend_from_slice(&[0x08, 0x00]);
    // IPv4
    frame.push(0x45);
    frame.push(0x00);
    let ip_total = (20 + 8 + payload.len()) as u16;
    frame.extend_from_slice(&ip_total.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0, 0]);
    frame.push(64);
    frame.push(17); // UDP
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[10, 0, 0, 1]);
    frame.extend_from_slice(&[10, 0, 0, 2]);
    // UDP
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(payload);
    frame
}

fn write_synthetic_pcap() -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let file = NamedTempFile::new().expect("tempfile");
    let header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: u32::MAX,
        datalink: pcap_file::DataLink::from(1),
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        endianness: pcap_file::Endianness::native(),
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).expect("writer");
    for i in 0..3u32 {
        let frame = synthetic_udp_frame(54321, 80, &[i as u8; 4]);
        let pkt =
            PcapPacket::new_owned(Duration::new(100 + i as u64, 0), frame.len() as u32, frame);
        w.write_packet(&pkt).expect("write");
    }
    drop(w);
    file
}

#[tokio::test(flavor = "current_thread")]
async fn replay_fires_flow_started_for_udp_traffic() {
    let pcap = write_synthetic_pcap();
    let started_count = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&started_count);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Udp>()
        .on::<FlowStarted<Udp>>(move |_e: &FlowStarted<Udp>| {
            counter.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");

    // The 3 UDP packets share a flow → exactly one FlowStarted.
    assert!(
        started_count.load(Ordering::Relaxed) >= 1,
        "expected at least one FlowStarted<Udp> from replay"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn replay_without_pcap_source_returns_error() {
    // Build with an interface (so NoInterface doesn't fire) but
    // no pcap_source; calling replay should surface the new
    // PcapSourceRequired variant.
    let monitor = Monitor::builder()
        .interface("lo")
        .protocol::<Udp>()
        .build()
        .expect("build");
    match monitor.replay().await {
        Err(Error::Build(BuildError::PcapSourceRequired)) => {}
        other => panic!("expected PcapSourceRequired, got: {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn replay_with_pcap_speed_factor_setter() {
    let pcap = write_synthetic_pcap();
    let counter = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&counter);

    // 0.21 E.1: builder-side `pcap_speed_factor(2.0)` should land
    // in the `AsyncPcapConfig::replay_speed` consumed by replay().
    // Smoke-test: at 2× speed the 3-packet pcap replays quickly
    // and at least one FlowStarted fires.
    Monitor::builder()
        .pcap_source(pcap.path())
        .pcap_speed_factor(2.0)
        .protocol::<Udp>()
        .on::<FlowStarted<Udp>>(move |_e: &FlowStarted<Udp>| {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build with pcap_speed_factor")
        .replay()
        .await
        .expect("replay completes");

    assert!(counter.load(Ordering::Relaxed) >= 1);
}

#[test]
fn builder_pcap_source_relaxes_no_interface_check() {
    let pcap = write_synthetic_pcap();
    let _m = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Udp>()
        .build()
        .expect("build with pcap_source and no interface");
}
