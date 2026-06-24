//! Issue #53: hot-reload of the IOC blocklist without dropping packets.
//!
//! Builds a Monitor armed with `.ioc(..)`, swaps the live set through a
//! [`ReloadHandle`] *before* replay, and asserts the match arms read the
//! **swapped-in** set — proving the per-flow `ArcSwap::load()` sees reloads.
//! Cap-free (pcap replay).

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::net::Ipv4Addr;
use std::time::Duration;

use netring::anomaly::shipped_sinks::ChannelSink;
use netring::monitor::Monitor;
use netring::monitor::ioc::IocSet;
use tempfile::NamedTempFile;

const BAD_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 5);
const OTHER_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

/// UDP frame `10.0.0.1 → dst_ip:4444`.
fn udp_to(dst_ip: Ipv4Addr) -> Vec<u8> {
    let payload = b"beacon";
    let mut f = Vec::new();
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    f.extend_from_slice(&[0x08, 0x00]);
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.push(64);
    f.push(17); // UDP
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&dst_ip.octets());
    f.extend_from_slice(&40000u16.to_be_bytes());
    f.extend_from_slice(&4444u16.to_be_bytes());
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    f
}

fn write_pcap(dst: Ipv4Addr) -> NamedTempFile {
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
    let frame = udp_to(dst);
    w.write_packet(&PcapPacket::new_owned(
        Duration::new(100, 0),
        frame.len() as u32,
        frame,
    ))
    .expect("write");
    drop(w);
    file
}

async fn replay_count_matches(set_up: impl FnOnce(&netring::monitor::ReloadHandle)) -> usize {
    let pcap = write_pcap(BAD_IP);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // Arm with a set that does NOT match BAD_IP, so any match proves the reload.
    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .ioc(IocSet::new().ip(OTHER_IP.into()))
        .sink(ChannelSink::new(tx))
        .build()
        .expect("build");

    set_up(&monitor.reload_handle());
    monitor.replay().await.expect("replay completes");

    let mut n = 0;
    while let Ok(a) = rx.try_recv() {
        if a.kind == "ioc_match" {
            n += 1;
        }
    }
    n
}

#[tokio::test(flavor = "current_thread")]
async fn reload_swaps_in_a_matching_set() {
    // Swap the original (OTHER_IP) set for one that matches BAD_IP → the flow
    // to BAD_IP now matches, proving the closures read the live (reloaded) set.
    let n = replay_count_matches(|h| {
        assert!(h.has_ioc());
        assert!(h.set_ioc(IocSet::new().ip(BAD_IP.into())));
    })
    .await;
    assert_eq!(n, 1, "reloaded set should match the BAD_IP flow");
}

#[tokio::test(flavor = "current_thread")]
async fn without_reload_the_original_set_does_not_match() {
    // No reload: the original OTHER_IP set never matches the BAD_IP flow.
    let n = replay_count_matches(|_h| {}).await;
    assert_eq!(n, 0, "original set must not match a different IP");
}

#[tokio::test(flavor = "current_thread")]
async fn handle_without_ioc_is_a_noop() {
    let monitor = Monitor::builder()
        .interfaces(["lo"])
        .build()
        .expect("build");
    let h = monitor.reload_handle();
    assert!(!h.has_ioc());
    assert!(
        !h.set_ioc(IocSet::new().ip(BAD_IP.into())),
        "no-op without ioc()"
    );
}
