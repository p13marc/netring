//! Issue #31: end-to-end p0f TCP/OS fingerprinting over pcap replay.
//!
//! Replays a single TCP **SYN** (with a Linux-shaped MSS option) through a
//! Monitor with `.on_p0f`, and asserts the handler fires once with
//! `direction == Syn`, the MSS extracted, and a non-empty p0f-3 signature —
//! exercising the real `replay → dispatch_p0f → fingerprint_from_layers` path.
//! Cap-free.

#![cfg(all(
    feature = "p0f",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use flowscope::TcpDirection;
use netring::monitor::Monitor;
use tempfile::NamedTempFile;

/// Ethernet/IPv4/TCP SYN frame with an MSS=1460 option (DF set, ttl 64).
fn syn_frame() -> Vec<u8> {
    // TCP header (20 bytes) + MSS option (4 bytes) = 24 → data offset 6.
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&44321u16.to_be_bytes()); // src port
    tcp.extend_from_slice(&443u16.to_be_bytes()); // dst port
    tcp.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // seq
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
    tcp.extend_from_slice(&(((6u16) << 12) | 0x002).to_be_bytes()); // offset 6, SYN
    tcp.extend_from_slice(&64240u16.to_be_bytes()); // window
    tcp.extend_from_slice(&[0, 0]); // checksum (not validated)
    tcp.extend_from_slice(&[0, 0]); // urgent
    tcp.extend_from_slice(&[0x02, 0x04, 0x05, 0xb4]); // MSS = 1460

    let mut f = Vec::new();
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // dst MAC
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src MAC
    f.extend_from_slice(&[0x08, 0x00]); // IPv4
    // IPv4 header (20 bytes).
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00]); // id
    f.extend_from_slice(&[0x40, 0x00]); // flags: DF
    f.push(64); // ttl
    f.push(6); // TCP
    f.extend_from_slice(&[0, 0]); // checksum
    f.extend_from_slice(&[10, 0, 0, 1]); // src
    f.extend_from_slice(&[10, 0, 0, 2]); // dst
    f.extend_from_slice(&tcp);
    f
}

fn write_pcap() -> NamedTempFile {
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
    let frame = syn_frame();
    let pkt = PcapPacket::new_owned(Duration::new(100, 0), frame.len() as u32, frame);
    w.write_packet(&pkt).expect("write");
    drop(w);
    file
}

#[tokio::test(flavor = "current_thread")]
async fn replay_extracts_p0f_from_syn() {
    let pcap = write_pcap();
    let hits = Arc::new(AtomicU32::new(0));
    let h = Arc::clone(&hits);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .on_p0f(move |fp, _ctx| {
            assert_eq!(fp.direction, TcpDirection::Syn);
            assert_eq!(fp.mss, Some(1460));
            assert!(!fp.to_p0f_signature().is_empty());
            h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");

    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "one p0f fingerprint from the SYN"
    );
}
