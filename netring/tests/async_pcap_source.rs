//! Integration tests for plan 23: `AsyncPcapSource` + `PcapFlowStream`.
//!
//! No privileges required — these tests only do file I/O.
//!
//! Run with:
//!   cargo test --features tokio,flow,parse,pcap --test async_pcap_source

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::time::Duration;

use futures::StreamExt;
use netring::flow::extract::FiveTuple;
use netring::pcap::CaptureWriter;
use netring::{AsyncPcapSource, PcapFormat, Timestamp};
use tempfile::NamedTempFile;

/// Build a fake Ethernet+IPv4+UDP frame so the flow extractor has
/// something to work with.
fn synthetic_udp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = 14 + 20 + 8 + payload.len();
    let mut frame = Vec::with_capacity(total_len);
    // Ethernet: dst MAC, src MAC, EtherType=0x0800 (IPv4)
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    frame.extend_from_slice(&[0x08, 0x00]);
    // IPv4 header (no options)
    frame.push(0x45); // version + IHL
    frame.push(0x00); // TOS
    let ip_total = (20 + 8 + payload.len()) as u16;
    frame.extend_from_slice(&ip_total.to_be_bytes());
    frame.extend_from_slice(&[0, 0]); // ID
    frame.extend_from_slice(&[0, 0]); // flags + frag
    frame.push(64); // TTL
    frame.push(17); // UDP
    frame.extend_from_slice(&[0, 0]); // checksum (skipped)
    frame.extend_from_slice(&[10, 0, 0, 1]); // src IP
    frame.extend_from_slice(&[10, 0, 0, 2]); // dst IP
    // UDP header
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0, 0]); // checksum
    frame.extend_from_slice(payload);
    frame
}

fn write_pcap_with_frames(frames: &[(Timestamp, Vec<u8>)]) -> NamedTempFile {
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
    for (ts, data) in frames {
        let pkt = PcapPacket::new_owned(
            Duration::new(ts.sec as u64, ts.nsec),
            data.len() as u32,
            data.clone(),
        );
        w.write_packet(&pkt).expect("write");
    }
    drop(w);
    file
}

#[tokio::test]
async fn flow_events_from_offline_pcap() {
    let frames: Vec<(Timestamp, Vec<u8>)> = (0..5u32)
        .map(|i| {
            (
                Timestamp::new(100 + i, 0),
                synthetic_udp_frame(54321, 80, &[i as u8; 4]),
            )
        })
        .collect();
    let f = write_pcap_with_frames(&frames);

    let source = AsyncPcapSource::open(f.path()).await.expect("open");
    assert_eq!(source.format(), PcapFormat::LegacyPcap);
    let mut events = source.flow_events(FiveTuple::bidirectional());

    let mut started = 0;
    let mut packets = 0;
    let mut ended = 0;
    while let Some(evt) = events.next().await {
        use flowscope::FlowEvent;
        match evt.expect("event") {
            FlowEvent::Started { .. } => started += 1,
            FlowEvent::Packet { .. } => packets += 1,
            FlowEvent::Ended { .. } => ended += 1,
            _ => {}
        }
    }
    // 5 packets from the same UDP 5-tuple → one Started, then
    // packets, then Ended on EOF-sweep.
    assert_eq!(started, 1, "expected one Started event");
    assert!(packets > 0, "expected at least one Packet event");
    assert_eq!(ended, 1, "expected one Ended event on EOF sweep");
    assert_eq!(events.packets_read(), 5);
}

#[tokio::test]
async fn legacy_pcap_format_detected() {
    let f = NamedTempFile::new().expect("tempfile");
    let _w = CaptureWriter::create(f.reopen().unwrap()).expect("writer");
    drop(_w);
    let source = AsyncPcapSource::open(f.path()).await.expect("open");
    assert_eq!(source.format(), PcapFormat::LegacyPcap);
}

#[tokio::test]
async fn unified_pipeline_via_generic_function() {
    use flowscope::FlowEvent;
    use futures::Stream;

    /// Generic consumer that takes any stream of FlowEvents.
    async fn count_started<S>(stream: S) -> usize
    where
        S: Stream<Item = Result<FlowEvent<flowscope::extract::FiveTupleKey>, netring::Error>>
            + Unpin,
    {
        let mut started = 0;
        let mut s = stream;
        while let Some(evt) = s.next().await {
            if let Ok(FlowEvent::Started { .. }) = evt {
                started += 1;
            }
        }
        started
    }

    let frames = vec![(
        Timestamp::new(1, 0),
        synthetic_udp_frame(1000, 2000, b"hello"),
    )];
    let f = write_pcap_with_frames(&frames);

    let source = AsyncPcapSource::open(f.path()).await.expect("open");
    let events = source.flow_events(FiveTuple::bidirectional());
    let started = count_started(events).await;
    assert_eq!(started, 1);
}
