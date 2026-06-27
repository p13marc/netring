//! Issue #53: hot-reload of a packet-tier `.expr()` filter without dropping
//! packets.
//!
//! Builds a Monitor with one packet subscription whose filter does **not**
//! match the replayed frame, swaps the filter through a [`ReloadHandle`]
//! *before* replay, and asserts the handler now fires — proving the per-frame
//! `ArcSwap::load()` in the zero-copy drain sees the reload. Cap-free (pcap
//! replay; no kernel prefilter is involved offline, so the swap takes full
//! effect).

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use netring::ctx::Ctx;
use netring::monitor::Monitor;
use netring::monitor::subscription::packet;
use tempfile::NamedTempFile;

/// UDP frame `10.0.0.1:40000 → 10.0.0.2:4444` (payload "beacon").
fn udp_frame() -> Vec<u8> {
    let payload = b"beacon";
    let mut f = Vec::new();
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // dst mac
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // src mac
    f.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.push(64);
    f.push(17); // UDP
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&[10, 0, 0, 1]); // src ip
    f.extend_from_slice(&[10, 0, 0, 2]); // dst ip
    f.extend_from_slice(&40000u16.to_be_bytes()); // src port
    f.extend_from_slice(&4444u16.to_be_bytes()); // dst port
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
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
    let frame = udp_frame();
    w.write_packet(&PcapPacket::new_owned(
        Duration::new(100, 0),
        frame.len() as u32,
        frame,
    ))
    .expect("write");
    drop(w);
    file
}

/// Build a monitor with one packet sub filtered to `dst port 9999` (which the
/// replayed `:4444` frame does NOT match), run `set_up` against the reload
/// handle, replay, and return how many times the handler fired.
async fn replay_hits(set_up: impl FnOnce(&netring::monitor::ReloadHandle)) -> usize {
    let pcap = write_pcap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .subscribe(
            packet()
                .expr("udp and dst port 9999")
                .expect("valid expr")
                .to(move |_view, _ctx: &mut Ctx<'_>| {
                    counter.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }),
        )
        .build()
        .expect("build");

    set_up(&monitor.reload_handle());
    monitor.replay().await.expect("replay completes");

    hits.load(Ordering::Relaxed)
}

#[tokio::test(flavor = "current_thread")]
async fn reload_swaps_in_a_matching_filter() {
    // Swap `dst port 9999` for `dst port 4444` → the :4444 frame now matches,
    // proving the drain reads the live (reloaded) predicate.
    let n = replay_hits(|h| {
        assert_eq!(h.packet_filter_count(), 1);
        assert!(h.set_packet_filter(0, "udp and dst port 4444").unwrap());
    })
    .await;
    assert_eq!(n, 1, "reloaded filter should match the :4444 frame");
}

#[tokio::test(flavor = "current_thread")]
async fn without_reload_the_original_filter_does_not_match() {
    let n = replay_hits(|_h| {}).await;
    assert_eq!(n, 0, "original `dst port 9999` filter must not match :4444");
}

#[tokio::test(flavor = "current_thread")]
async fn a_bad_expr_leaves_the_live_filter_untouched() {
    // A reload with an unparseable expr returns Err and must NOT disturb the
    // running filter (validate-before-swap) — the frame still doesn't match.
    let n = replay_hits(|h| {
        assert!(h.set_packet_filter(0, "this is not a filter").is_err());
    })
    .await;
    assert_eq!(
        n, 0,
        "a failed reload must leave the original filter in place"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn out_of_range_index_is_a_noop() {
    let n = replay_hits(|h| {
        // Index 1 doesn't exist (only one packet sub) → Ok(false), no swap.
        assert!(!h.set_packet_filter(1, "udp and dst port 4444").unwrap());
    })
    .await;
    assert_eq!(n, 0, "an out-of-range reload must not affect index 0");
}

#[tokio::test(flavor = "current_thread")]
async fn handle_without_packet_subs_reports_zero() {
    let monitor = Monitor::builder()
        .interfaces(["lo"])
        .build()
        .expect("build");
    let h = monitor.reload_handle();
    assert_eq!(h.packet_filter_count(), 0);
    assert!(
        !h.set_packet_filter(0, "udp and dst port 4444").unwrap(),
        "no-op when no packet subscription is armed"
    );
}
