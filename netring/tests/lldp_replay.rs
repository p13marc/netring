//! Issue #28: end-to-end LLDP detection over pcap replay.
//!
//! Writes a pcap with a minimal IEEE 802.1AB LLDP frame (chassis-ID / port-ID /
//! TTL mandatory triple), replays it through a Monitor with `.on_lldp`, and
//! asserts the handler fires with the decoded fields — exercising the real
//! `replay → dispatch_lldp → lldp::parse_frame` path. Cap-free; runs in the
//! ordinary integration CI job.

#![cfg(all(
    feature = "lldp",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::monitor::Monitor;
use netring::prelude::{ChassisId, MacAddr};
use tempfile::NamedTempFile;

const SRC_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const CHASSIS_MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

/// Pack an LLDP TLV: `type:7 | length:9` header (big-endian) + value.
fn tlv(ty: u8, value: &[u8]) -> Vec<u8> {
    let header = (((ty as u16) & 0x7f) << 9) | ((value.len() as u16) & 0x01ff);
    let mut out = header.to_be_bytes().to_vec();
    out.extend_from_slice(value);
    out
}

/// Full Ethernet frame carrying the mandatory LLDP triple + End TLV.
fn lldp_frame() -> Vec<u8> {
    let mut f = Vec::new();
    // Ethernet: dst = LLDP nearest-bridge multicast, src, EtherType 0x88cc.
    f.extend_from_slice(&[0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
    f.extend_from_slice(&SRC_MAC);
    f.extend_from_slice(&0x88ccu16.to_be_bytes());
    // Chassis ID TLV (type 1): subtype 4 (MAC) + 6 bytes.
    let mut cid = vec![4u8];
    cid.extend_from_slice(&CHASSIS_MAC);
    f.extend(tlv(1, &cid));
    // Port ID TLV (type 2): subtype 5 (interface name) + name.
    let mut pid = vec![5u8];
    pid.extend_from_slice(b"Gi0/1");
    f.extend(tlv(2, &pid));
    // TTL TLV (type 3): 2 bytes.
    f.extend(tlv(3, &120u16.to_be_bytes()));
    // End TLV (type 0).
    f.extend(tlv(0, &[]));
    f
}

fn write_lldp_pcap() -> NamedTempFile {
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
    let frame = lldp_frame();
    let pkt = PcapPacket::new_owned(Duration::new(100, 0), frame.len() as u32, frame);
    w.write_packet(&pkt).expect("write");
    drop(w);
    file
}

#[tokio::test(flavor = "current_thread")]
async fn replay_parses_lldp_neighbor() {
    let pcap = write_lldp_pcap();
    let msgs = Arc::new(AtomicU32::new(0));
    let m = Arc::clone(&msgs);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .on_lldp(move |msg, _ctx| {
            assert_eq!(msg.chassis_id, ChassisId::MacAddress(MacAddr(CHASSIS_MAC)));
            assert_eq!(msg.ttl_seconds, 120);
            m.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");

    assert_eq!(msgs.load(Ordering::Relaxed), 1, "one parsed LLDP message");
}
