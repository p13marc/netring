//! flowscope 0.26 (#219 / #212 there): packets a capture's snap length
//! cut are tracked, and counted at their length on the wire. The Monitor
//! hands flowscope each record's original length (`with_wire_len`); before
//! 0.32 such packets were skipped — no flow at all.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowscope::extract::parse::test_frames::ipv4_udp;
use netring::monitor::Monitor;
use netring::protocol::builtin::Udp;
use netring::protocol::event_typed::FlowEnded;
use tempfile::NamedTempFile;

/// A pcap of `(frame, snap)`: each record stores the first `snap` bytes
/// and the whole frame's length as its original length.
fn snapped_pcap(frames: &[(Vec<u8>, usize)]) -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let file = NamedTempFile::new().unwrap();
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        snaplen: 64,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).unwrap();
    for (i, (frame, snap)) in frames.iter().enumerate() {
        let captured = frame[..(*snap).min(frame.len())].to_vec();
        w.write_packet(&PcapPacket::new_owned(
            Duration::from_millis(1_000 + i as u64),
            frame.len() as u32,
            captured,
        ))
        .unwrap();
    }
    file
}

/// Two UDP datagrams of 542 bytes on the wire, captured with a 64-byte
/// snap length: one flow, both packets, wire bytes counted.
#[tokio::test(flavor = "current_thread")]
async fn snap_length_cut_packets_are_tracked_at_their_wire_length() {
    let payload = [0x5au8; 500];
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 40_000, 9_999, &payload);
    let wire = frame.len() as u64;
    let file = snapped_pcap(&[(frame.clone(), 64), (frame, 64)]);
    let ended: Arc<Mutex<Vec<(u64, u64)>>> = Arc::default();
    let e = Arc::clone(&ended);
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .on::<FlowEnded<Udp>>(move |f: &FlowEnded<Udp>| {
            e.lock()
                .unwrap()
                .push((f.stats.packets_initiator, f.stats.bytes_initiator));
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(
        *ended.lock().unwrap(),
        vec![(2, 2 * wire)],
        "one flow: both packets, counted at their wire length"
    );
}
