//! Issue #28 (part 2c): asset inventory fed from a UDP discovery datagram.
//!
//! Replays an SSDP `NOTIFY` (UDP/1900) through a Monitor with
//! `.asset_inventory()` + `.on_asset()`. The handler must fire with the device
//! keyed by its Ethernet source MAC and the firmware `SERVER` banner captured,
//! proving the per-frame UDP-payload asset path (`absorb_frame_assets` →
//! `layers().udp()` → `ssdp::parse` → `Asset::from_ssdp`). Cap-free.

#![cfg(all(
    feature = "asset",
    feature = "ssdp",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::monitor::Monitor;
use netring::prelude::MacAddr;
use tempfile::NamedTempFile;

// Ethernet source MAC of the synthetic frame — the device the asset is keyed by.
const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const SERVER: &str = "Linux/4.19 UPnP/1.0 TestDevice/1.0";

fn ssdp_frame() -> Vec<u8> {
    let payload = format!(
        "NOTIFY * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         NT: upnp:rootdevice\r\n\
         NTS: ssdp:alive\r\n\
         USN: uuid:test-device::upnp:rootdevice\r\n\
         SERVER: {SERVER}\r\n\
         \r\n"
    );
    let payload = payload.as_bytes();

    let mut f = Vec::new();
    // Ethernet: dst = SSDP multicast MAC, src = device.
    f.extend_from_slice(&[0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa]);
    f.extend_from_slice(&SRC_MAC);
    f.extend_from_slice(&[0x08, 0x00]); // IPv4
    // IPv4 header (20 bytes).
    f.push(0x45);
    f.push(0x00);
    let ip_total = (20 + 8 + payload.len()) as u16;
    f.extend_from_slice(&ip_total.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.push(64);
    f.push(17); // UDP
    f.extend_from_slice(&[0, 0]); // checksum (not validated)
    f.extend_from_slice(&[10, 0, 0, 9]); // src ip
    f.extend_from_slice(&[239, 255, 255, 250]); // dst ip (multicast)
    // UDP header.
    f.extend_from_slice(&1900u16.to_be_bytes()); // src port
    f.extend_from_slice(&1900u16.to_be_bytes()); // dst port
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]); // checksum
    f.extend_from_slice(payload);
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
    let frame = ssdp_frame();
    let pkt = PcapPacket::new_owned(Duration::new(100, 0), frame.len() as u32, frame);
    w.write_packet(&pkt).expect("write");
    drop(w);
    file
}

#[tokio::test(flavor = "current_thread")]
async fn inventory_absorbs_ssdp_keyed_by_src_mac() {
    let pcap = write_pcap();
    let events = Arc::new(AtomicU32::new(0));
    let e = Arc::clone(&events);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .asset_inventory(64)
        .on_asset(move |asset, _ctx| {
            assert_eq!(asset.mac, MacAddr(SRC_MAC));
            assert_eq!(asset.vendor_banner.as_deref(), Some(SERVER));
            e.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");

    assert_eq!(events.load(Ordering::Relaxed), 1, "one SSDP-sourced asset");
}
