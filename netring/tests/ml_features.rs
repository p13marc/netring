//! Issue #32: end-to-end CICFlowMeter ML-feature export over pcap replay.
//!
//! Replays a small TCP flow through a Monitor armed with `.on_ml_features(..)`
//! and asserts the handler fires at flow end with a `CicFlowFeatures` vector
//! whose packet totals match what was sent — proving the live `FlowStats` →
//! `CicFlowFeatures` bridge (the IAT/active-idle data the summary FlowRecord
//! drops). Cap-free; the flow ends via the EOF `finish` drain.

#![cfg(all(
    feature = "ml-features",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;
use tempfile::NamedTempFile;

/// Eth/IPv4/TCP frame from 10.0.0.1:`sp` → 10.0.0.2:`dp` with `payload`.
fn tcp_frame(sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // dst MAC
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // src MAC
    f.extend_from_slice(&[0x08, 0x00]); // IPv4
    f.push(0x45);
    f.push(0x00);
    let total_len = (20 + 20 + payload.len()) as u16;
    f.extend_from_slice(&total_len.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.push(64);
    f.push(6); // TCP
    f.extend_from_slice(&[0, 0]); // checksum (ignored)
    f.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
    f.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
    // TCP header
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
    // Three client→server segments of one flow (40000 → 80).
    for (i, frame) in [
        tcp_frame(40000, 80, b"GET / HTTP/1.1\r\n"),
        tcp_frame(40000, 80, b"Host: x\r\n"),
        tcp_frame(40000, 80, b"\r\n"),
    ]
    .into_iter()
    .enumerate()
    {
        let pkt =
            PcapPacket::new_owned(Duration::new(100 + i as u64, 0), frame.len() as u32, frame);
        w.write_packet(&pkt).expect("write");
    }
    drop(w);
    file
}

#[tokio::test(flavor = "current_thread")]
async fn replay_delivers_cicflow_features_at_flow_end() {
    let pcap = write_pcap();

    // (count, total packets seen by the last features vector)
    let captured: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Tcp>()
        .on_ml_features(move |f: &flowscope::CicFlowFeatures| {
            sink.lock().unwrap().push((
                f.flow_duration_us,
                f.total_fwd_packets + f.total_bwd_packets,
            ));
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");

    let rows = captured.lock().unwrap();
    assert_eq!(rows.len(), 1, "exactly one flow ended, got {}", rows.len());
    let (_duration_us, total_packets) = rows[0];
    assert_eq!(total_packets, 3, "all three segments counted");
}
