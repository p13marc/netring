//! Issue #28: end-to-end asset inventory over pcap replay.
//!
//! Replays two *identical* LLDP frames through a Monitor with
//! `.asset_inventory()` + `.on_asset()` and asserts the handler fires **exactly
//! once** — the first frame creates the MAC-keyed asset; the second, being
//! identical, doesn't change the record, so `on_asset` (an inventory-event
//! stream, not a per-packet one) stays quiet. Exercises the real
//! `replay → absorb_frame_assets → Inventory::absorb` path. Cap-free.

#![cfg(all(
    feature = "asset",
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
use netring::prelude::MacAddr;
use tempfile::NamedTempFile;

const SRC_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const CHASSIS_MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

fn tlv(ty: u8, value: &[u8]) -> Vec<u8> {
    let header = (((ty as u16) & 0x7f) << 9) | ((value.len() as u16) & 0x01ff);
    let mut out = header.to_be_bytes().to_vec();
    out.extend_from_slice(value);
    out
}

fn lldp_frame() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
    f.extend_from_slice(&SRC_MAC);
    f.extend_from_slice(&0x88ccu16.to_be_bytes());
    let mut cid = vec![4u8];
    cid.extend_from_slice(&CHASSIS_MAC);
    f.extend(tlv(1, &cid));
    let mut pid = vec![5u8];
    pid.extend_from_slice(b"Gi0/1");
    f.extend(tlv(2, &pid));
    f.extend(tlv(3, &120u16.to_be_bytes()));
    f.extend(tlv(0, &[]));
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
    let frame = lldp_frame();
    // Two identical frames at the SAME timestamp → the second is a no-op merge.
    for _ in 0..2 {
        let pkt = PcapPacket::new_owned(Duration::new(100, 0), frame.len() as u32, frame.clone());
        w.write_packet(&pkt).expect("write");
    }
    drop(w);
    file
}

#[tokio::test(flavor = "current_thread")]
async fn inventory_absorbs_lldp_and_dedups_identical_frames() {
    let pcap = write_pcap();
    let events = Arc::new(AtomicU32::new(0));
    let e = Arc::clone(&events);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .asset_inventory(64)
        .on_asset(move |asset, _ctx| {
            // The LLDP chassis MAC is the asset's key.
            assert_eq!(asset.mac, MacAddr(CHASSIS_MAC));
            e.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");

    assert_eq!(
        events.load(Ordering::Relaxed),
        1,
        "on_asset fires once for the new asset, not again for the identical repeat"
    );
}
