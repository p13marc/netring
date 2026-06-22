//! Issue #28: end-to-end CDP detection over pcap replay.
//!
//! Writes a pcap with a minimal Cisco Discovery Protocol frame (802.3 LLC/SNAP
//! plus a Device-ID TLV), replays it through a Monitor with `.on_cdp`, and asserts
//! the handler fires with the decoded fields — exercising the real
//! `replay → dispatch_cdp → cdp::parse_frame` path. Cap-free; runs in the
//! ordinary integration CI job.

#![cfg(all(
    feature = "cdp",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::monitor::Monitor;
use tempfile::NamedTempFile;

const SRC_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const DEVICE_ID: &[u8] = b"switch01.example";

/// Pack a CDP TLV: `type:16 | length:16` (length covers the 4-byte header) + value.
fn tlv(ty: u16, value: &[u8]) -> Vec<u8> {
    let len = (value.len() + 4) as u16;
    let mut out = Vec::new();
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// Full Ethernet/802.3 frame carrying CDP with a Device-ID TLV.
fn cdp_frame() -> Vec<u8> {
    // CDP payload: version(2) + ttl(180) + checksum(0,0) + Device-ID TLV.
    let mut payload = vec![2u8, 180u8, 0u8, 0u8];
    payload.extend(tlv(0x0001, DEVICE_ID));

    let mut f = Vec::new();
    // Ethernet: dst = CDP multicast, src.
    f.extend_from_slice(&[0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]);
    f.extend_from_slice(&SRC_MAC);
    // 802.3 length field (informational — parser doesn't validate it).
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    // LLC: aa aa 03, SNAP OUI 00 00 0c, PID 0x2000.
    f.extend_from_slice(&[0xaa, 0xaa, 0x03]);
    f.extend_from_slice(&[0x00, 0x00, 0x0c]);
    f.extend_from_slice(&0x2000u16.to_be_bytes());
    f.extend_from_slice(&payload);
    f
}

fn write_cdp_pcap() -> NamedTempFile {
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
    let frame = cdp_frame();
    let pkt = PcapPacket::new_owned(Duration::new(100, 0), frame.len() as u32, frame);
    w.write_packet(&pkt).expect("write");
    drop(w);
    file
}

#[tokio::test(flavor = "current_thread")]
async fn replay_parses_cdp_neighbor() {
    let pcap = write_cdp_pcap();
    let msgs = Arc::new(AtomicU32::new(0));
    let m = Arc::clone(&msgs);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .on_cdp(move |msg, _ctx| {
            assert_eq!(msg.version, 2);
            assert_eq!(msg.ttl_seconds, 180);
            assert_eq!(msg.device_id.as_deref(), Some(DEVICE_ID));
            m.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");

    assert_eq!(msgs.load(Ordering::Relaxed), 1, "one parsed CDP message");
}
