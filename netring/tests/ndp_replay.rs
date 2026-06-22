//! Issue #24: end-to-end NDP detection over pcap replay.
//!
//! Writes a pcap with an Ethernet/IPv6/ICMPv6 **unsolicited override Neighbor
//! Advertisement** (the SLAAC-poisoning pattern), replays it through a Monitor
//! with `.on_ndp` + `.on_ndp_anomaly`, and asserts both the raw message hook
//! and the `SpoofSuspected` anomaly fire — exercising the real
//! `replay → dispatch_ndp → layers → ndp::parse_icmpv6 → detector` path.
//!
//! Cap-free; runs in the ordinary integration CI job.

#![cfg(all(
    feature = "ndp",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::monitor::Monitor;
use netring::monitor::ndp::NdpAnomalyKind;
use netring::prelude::MacAddr;
use tempfile::NamedTempFile;

const SENDER_MAC: [u8; 6] = [0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb];
const TARGET_IP: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x50);

/// Build the ICMPv6 Neighbor Advertisement message (S=0, O=1 + TLLA option).
fn na_icmpv6() -> Vec<u8> {
    let mut m = Vec::new();
    m.push(136); // type: NA
    m.push(0); // code
    m.extend_from_slice(&[0, 0]); // checksum (passive view doesn't verify)
    m.push(0x20); // flags: O=1, S=0, R=0 (unsolicited override)
    m.extend_from_slice(&[0, 0, 0]); // reserved
    m.extend_from_slice(&TARGET_IP.octets());
    m.extend_from_slice(&[2, 1]); // option: Target LL Addr, len=1 (8 bytes)
    m.extend_from_slice(&SENDER_MAC);
    m
}

/// Wrap the ICMPv6 message in IPv6 + Ethernet → a full frame.
fn ndp_frame() -> Vec<u8> {
    let icmp = na_icmpv6();
    let mut f = Vec::new();
    // Ethernet: dst = IPv6 all-nodes multicast MAC, src, ethertype IPv6.
    f.extend_from_slice(&[0x33, 0x33, 0, 0, 0, 1]);
    f.extend_from_slice(&SENDER_MAC);
    f.extend_from_slice(&0x86ddu16.to_be_bytes());
    // IPv6 header.
    f.extend_from_slice(&[0x60, 0, 0, 0]); // version 6, tc/flow 0
    f.extend_from_slice(&(icmp.len() as u16).to_be_bytes()); // payload length
    f.push(58); // next header: ICMPv6
    f.push(255); // hop limit
    f.extend_from_slice(&TARGET_IP.octets()); // src
    f.extend_from_slice(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).octets()); // dst all-nodes
    f.extend_from_slice(&icmp);
    f
}

fn write_ndp_pcap() -> NamedTempFile {
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
    let frame = ndp_frame();
    let pkt = PcapPacket::new_owned(Duration::new(100, 0), frame.len() as u32, frame);
    w.write_packet(&pkt).expect("write");
    drop(w);
    file
}

#[tokio::test(flavor = "current_thread")]
async fn replay_detects_ndp_spoof() {
    let pcap = write_ndp_pcap();
    let msgs = Arc::new(AtomicU32::new(0));
    let spoofs = Arc::new(AtomicU32::new(0));
    let m = Arc::clone(&msgs);
    let s = Arc::clone(&spoofs);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .ndp_warmup(Duration::from_millis(0))
        .on_ndp(move |msg, _ctx| {
            assert_eq!(msg.target, TARGET_IP);
            assert_eq!(msg.lladdr, Some(MacAddr(SENDER_MAC)));
            m.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .on_ndp_anomaly(move |a, _ctx| {
            if a.kind == NdpAnomalyKind::SpoofSuspected {
                s.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");

    assert_eq!(msgs.load(Ordering::Relaxed), 1, "one parsed NDP message");
    assert_eq!(
        spoofs.load(Ordering::Relaxed),
        1,
        "one SpoofSuspected anomaly"
    );
}
