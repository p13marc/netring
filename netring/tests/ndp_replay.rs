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

const HOST_A: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xa);
const MAC_A: [u8; 6] = [0xaa; 6];
const HOST_B: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xb);
const MAC_B: [u8; 6] = [0xb0; 6];

/// Ethernet / IPv6 / ICMPv6 frame `src_mac, src → dst` around `icmp`.
fn ipv6_frame(src_mac: [u8; 6], src: Ipv6Addr, dst: Ipv6Addr, icmp: &[u8]) -> Vec<u8> {
    let mut f = vec![0x33, 0x33, 0, 0, 0, 1];
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&0x86ddu16.to_be_bytes());
    f.extend_from_slice(&[0x60, 0, 0, 0]);
    f.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    f.extend_from_slice(&[58, 255]);
    f.extend_from_slice(&src.octets());
    f.extend_from_slice(&dst.octets());
    f.extend_from_slice(icmp);
    f
}

/// Address resolution, twice: A solicits B (NS, target B, A's MAC in the
/// SLLA option), B answers (solicited override NA, target B, B's MAC).
fn resolution_pcap() -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
    ns.extend_from_slice(&HOST_B.octets());
    ns.extend_from_slice(&[1, 1]);
    ns.extend_from_slice(&MAC_A);
    let mut na = vec![136, 0, 0, 0, 0x60, 0, 0, 0]; // S=1, O=1
    na.extend_from_slice(&HOST_B.octets());
    na.extend_from_slice(&[2, 1]);
    na.extend_from_slice(&MAC_B);
    let frames = [
        ipv6_frame(MAC_A, HOST_A, HOST_B, &ns),
        ipv6_frame(MAC_B, HOST_B, HOST_A, &na),
    ];
    let file = NamedTempFile::new().expect("tempfile");
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).expect("writer");
    for t in [100, 200] {
        for f in &frames {
            w.write_packet(&PcapPacket::new(Duration::new(t, 0), f.len() as u32, f))
                .expect("write");
        }
    }
    drop(w);
    file
}

/// RFC 4861 §4.3: an NS's target is the address being resolved, not the
/// sender's — ordinary resolution must not look like B changing MAC.
#[tokio::test(flavor = "current_thread")]
async fn address_resolution_raises_no_ndp_anomaly() {
    let pcap = resolution_pcap();
    let anomalies = Arc::new(AtomicU32::new(0));
    let a = Arc::clone(&anomalies);
    Monitor::builder()
        .pcap_source(pcap.path())
        .ndp_warmup(Duration::from_millis(0))
        .on_ndp_anomaly(move |_, _ctx| {
            a.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build")
        .replay()
        .await
        .expect("replay");
    assert_eq!(anomalies.load(Ordering::Relaxed), 0);
}

/// The asset inventory follows the same rule: B's address is never put on
/// A's MAC; each host gets its own.
#[cfg(feature = "asset")]
#[tokio::test(flavor = "current_thread")]
async fn address_resolution_binds_each_host_to_its_own_mac() {
    let pcap = resolution_pcap();
    let assets = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&assets);
    Monitor::builder()
        .pcap_source(pcap.path())
        .on_asset(move |asset, _ctx| {
            log.lock().unwrap().push((asset.mac, asset.ipv6.clone()));
            Ok(())
        })
        .build()
        .expect("build")
        .replay()
        .await
        .expect("replay");
    let assets = assets.lock().unwrap();
    for (mac, ipv6) in assets.iter() {
        if *mac == MacAddr(MAC_A) {
            assert!(!ipv6.contains(&HOST_B), "{assets:?}");
        }
    }
    assert!(
        assets
            .iter()
            .any(|(mac, ipv6)| *mac == MacAddr(MAC_B) && ipv6.contains(&HOST_B)),
        "{assets:?}"
    );
    assert!(
        assets
            .iter()
            .any(|(mac, ipv6)| *mac == MacAddr(MAC_A) && ipv6.contains(&HOST_A)),
        "{assets:?}"
    );
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
