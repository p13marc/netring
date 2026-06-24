//! Issue #72: end-to-end nPrint per-flow matrix export over pcap replay.
//!
//! Replays a small bidirectional TCP flow through a Monitor armed with
//! `.nprint(..)` + `.on_nprint(..)` and asserts the handler fires once at flow
//! end with a matrix holding **one row per packet of the whole flow** — proving
//! (a) the per-packet feed reaches the accumulator and (b) both directions fold
//! into a single matrix under the canonical key the tracker uses for
//! `FlowEnded`. Cap-free; the flow ends via the EOF `finish` drain.

#![cfg(all(
    feature = "nprint",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowscope::nprint::{NPrintConfig, NPrintMatrix};
use netring::monitor::Monitor;
use netring::protocol::FlowKey;
use netring::protocol::builtin::Tcp;
use tempfile::NamedTempFile;

/// Eth/IPv4/TCP frame `a:sp → b:dp` with `payload`. `a`/`b` are 10.0.0.x hosts.
fn tcp_frame(a: u8, sp: u16, b: u8, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, b]); // dst MAC
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, a]); // src MAC
    f.extend_from_slice(&[0x08, 0x00]); // IPv4
    f.push(0x45);
    f.push(0x00);
    let total_len = (20 + 20 + payload.len()) as u16;
    f.extend_from_slice(&total_len.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.push(64);
    f.push(6); // TCP
    f.extend_from_slice(&[0, 0]); // checksum (ignored)
    f.extend_from_slice(&Ipv4Addr::new(10, 0, 0, a).octets());
    f.extend_from_slice(&Ipv4Addr::new(10, 0, 0, b).octets());
    f.extend_from_slice(&sp.to_be_bytes());
    f.extend_from_slice(&dp.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes()); // seq
    f.extend_from_slice(&0u32.to_be_bytes()); // ack
    f.push(0x50); // data offset 5 words
    f.push(0x18); // PSH+ACK
    f.extend_from_slice(&64240u16.to_be_bytes()); // window
    f.extend_from_slice(&[0, 0]); // checksum
    f.extend_from_slice(&[0, 0]); // urg
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
    // One flow 10.0.0.1:40000 <-> 10.0.0.2:80 — three client→server segments
    // and ONE server→client reply. All four must land in a single matrix.
    let frames = [
        tcp_frame(1, 40000, 2, 80, b"GET / HTTP/1.1\r\n"),
        tcp_frame(1, 40000, 2, 80, b"Host: x\r\n"),
        tcp_frame(2, 80, 1, 40000, b"HTTP/1.1 200 OK\r\n"), // reverse direction
        tcp_frame(1, 40000, 2, 80, b"\r\n"),
    ];
    for (i, frame) in frames.into_iter().enumerate() {
        let pkt =
            PcapPacket::new_owned(Duration::new(100 + i as u64, 0), frame.len() as u32, frame);
        w.write_packet(&pkt).expect("write");
    }
    drop(w);
    file
}

#[tokio::test(flavor = "current_thread")]
async fn replay_accumulates_one_matrix_per_flow_both_directions() {
    let pcap = write_pcap();

    // (key, row count, row width) captured at flow end.
    let captured: Arc<Mutex<Vec<(FlowKey, usize, usize)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);

    let cfg = NPrintConfig::default();
    let expected_width = cfg.row_width();

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Tcp>()
        .nprint(cfg)
        .on_nprint(move |key: &FlowKey, m: &NPrintMatrix| {
            let width = m.rows().first().map(|r| r.bits.len()).unwrap_or(0);
            sink.lock().unwrap().push((*key, m.rows().len(), width));
        })
        .build()
        .expect("build with pcap_source + nprint");

    monitor.replay().await.expect("replay completes");

    let rows = captured.lock().unwrap();
    assert_eq!(rows.len(), 1, "exactly one flow ended, got {}", rows.len());
    let (key, n_rows, width) = rows[0];
    // All four packets (both directions) folded into one matrix.
    assert_eq!(n_rows, 4, "one row per packet of the whole flow");
    assert_eq!(width, expected_width, "every row has the configured width");
    // Canonical (bidirectional) key: endpoints sorted, so `a < b`.
    assert!(key.a <= key.b, "flow key is canonical: {key:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn matrix_is_capped_at_max_packets() {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

    // A config that caps each matrix at 2 packets.
    let mut cfg = NPrintConfig::default();
    cfg.max_packets = 2;

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
    for i in 0..5u64 {
        let frame = tcp_frame(1, 40000, 2, 80, b"x");
        let pkt = PcapPacket::new_owned(Duration::new(100 + i, 0), frame.len() as u32, frame);
        w.write_packet(&pkt).expect("write");
    }
    drop(w);

    let rows: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let sink = Arc::clone(&rows);
    let monitor = Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Tcp>()
        .nprint(cfg)
        .on_nprint(move |_k, m: &NPrintMatrix| *sink.lock().unwrap() = m.rows().len())
        .build()
        .expect("build");
    monitor.replay().await.expect("replay completes");

    assert_eq!(*rows.lock().unwrap(), 2, "matrix stops at max_packets=2");
}
