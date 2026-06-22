//! Issue #28: asset inventory fed from an mDNS response.
//!
//! Replays an mDNS (UDP/5353) response advertising an A record for a `.local`
//! hostname and asserts `on_asset` fires with the device keyed by its Ethernet
//! source MAC, the hostname and IPv4 learned — proving the per-frame mDNS path
//! (`absorb_frame_assets` → `layers().udp()` → `dns::parse_message` →
//! `Asset::from_mdns`). Cap-free.

#![cfg(all(
    feature = "asset",
    feature = "mdns",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::monitor::Monitor;
use netring::prelude::MacAddr;
use tempfile::NamedTempFile;

const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x07];
const HOST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

/// Minimal mDNS response: one A record for `myhost.local`.
fn mdns_payload() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0x00, 0x00]); // ID
    p.extend_from_slice(&[0x84, 0x00]); // flags: QR=1, AA=1
    p.extend_from_slice(&[0x00, 0x00]); // QDCOUNT
    p.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    // Answer NAME: "myhost.local".
    p.push(6);
    p.extend_from_slice(b"myhost");
    p.push(5);
    p.extend_from_slice(b"local");
    p.push(0);
    p.extend_from_slice(&[0x00, 0x01]); // TYPE A
    p.extend_from_slice(&[0x00, 0x01]); // CLASS IN
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL 120
    p.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
    p.extend_from_slice(&HOST_IP.octets()); // RDATA
    p
}

fn mdns_frame() -> Vec<u8> {
    let payload = mdns_payload();
    let mut f = Vec::new();
    // Ethernet: dst = IPv4 mDNS multicast MAC, src = device.
    f.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
    f.extend_from_slice(&SRC_MAC);
    f.extend_from_slice(&[0x08, 0x00]); // IPv4
    // IPv4 header.
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.push(64);
    f.push(17); // UDP
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&[10, 0, 0, 7]);
    f.extend_from_slice(&[224, 0, 0, 251]); // mDNS multicast
    // UDP header.
    f.extend_from_slice(&5353u16.to_be_bytes());
    f.extend_from_slice(&5353u16.to_be_bytes());
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&payload);
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
    let frame = mdns_frame();
    let pkt = PcapPacket::new_owned(Duration::new(100, 0), frame.len() as u32, frame);
    w.write_packet(&pkt).expect("write");
    drop(w);
    file
}

#[tokio::test(flavor = "current_thread")]
async fn inventory_absorbs_mdns_hostname() {
    let pcap = write_pcap();
    let events = Arc::new(AtomicU32::new(0));
    let e = Arc::clone(&events);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .asset_inventory(64)
        .on_asset(move |asset, _ctx| {
            assert_eq!(asset.mac, MacAddr(SRC_MAC));
            assert_eq!(asset.hostname.as_deref(), Some("myhost"));
            assert!(asset.ipv4.contains(&HOST_IP));
            e.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");

    assert_eq!(events.load(Ordering::Relaxed), 1, "one mDNS-sourced asset");
}
