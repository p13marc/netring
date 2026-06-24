//! Issue #45: end-to-end YARA payload scanning over pcap replay.
//!
//! Replays a TCP flow whose payload carries the EICAR test string **split
//! across two segments**, with a Monitor armed `.yara(rules)`, and asserts the
//! match fires once at flow end — proving the scan runs over the flow's
//! *accumulated* payload (so a signature can span segment boundaries), not
//! per packet. Cap-free; the flow ends via the EOF `finish` drain.

#![cfg(all(
    feature = "yara",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netring::monitor::Monitor;
use netring::monitor::yara::{ScanDirection, YaraRules};
use netring::protocol::FlowKey;
use netring::protocol::builtin::Tcp;
use tempfile::NamedTempFile;

/// Eth/IPv4/TCP frame `10.0.0.1:sp → 10.0.0.2:dp` carrying `payload`.
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
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
    f.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
    f.extend_from_slice(&sp.to_be_bytes());
    f.extend_from_slice(&dp.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes()); // seq
    f.extend_from_slice(&0u32.to_be_bytes()); // ack
    f.push(0x50); // data offset 5
    f.push(0x18); // PSH+ACK
    f.extend_from_slice(&64240u16.to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    f
}

fn write_pcap(segments: &[&[u8]]) -> NamedTempFile {
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
    for (i, seg) in segments.iter().enumerate() {
        let frame = tcp_frame(40000, 80, seg);
        let pkt =
            PcapPacket::new_owned(Duration::new(100 + i as u64, 0), frame.len() as u32, frame);
        w.write_packet(&pkt).expect("write");
    }
    drop(w);
    file
}

const EICAR: &str = r#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

#[tokio::test(flavor = "current_thread")]
async fn replay_matches_signature_split_across_segments() {
    // Split EICAR across two TCP segments — a per-packet scan would miss it.
    let (a, b) = EICAR.as_bytes().split_at(20);
    let pcap = write_pcap(&[a, b]);

    let rules = YaraRules::compile(
        r#"rule eicar { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }"#,
    )
    .expect("compile");

    let hits: Arc<Mutex<Vec<(String, ScanDirection)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&hits);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Tcp>()
        .yara(rules)
        .on_yara_match(move |_key: &FlowKey, m| {
            sink.lock().unwrap().push((m.rule.clone(), m.direction));
        })
        .build()
        .expect("build with pcap_source + yara");

    monitor.replay().await.expect("replay completes");

    let hits = hits.lock().unwrap();
    assert_eq!(hits.len(), 1, "exactly one match, got {hits:?}");
    assert_eq!(hits[0].0, "eicar");
    assert_eq!(hits[0].1, ScanDirection::Initiator);
}

#[tokio::test(flavor = "current_thread")]
async fn replay_clean_traffic_does_not_match() {
    let pcap = write_pcap(&[b"GET / HTTP/1.1\r\n", b"Host: example\r\n\r\n"]);
    let rules =
        YaraRules::compile(r#"rule eicar { strings: $a = "EICAR-STANDARD" condition: $a }"#)
            .expect("compile");

    let hits: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let sink = Arc::clone(&hits);
    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Tcp>()
        .yara(rules)
        .on_yara_match(move |_k, _m| *sink.lock().unwrap() += 1)
        .build()
        .expect("build");
    monitor.replay().await.expect("replay completes");
    assert_eq!(*hits.lock().unwrap(), 0, "clean traffic must not match");
}
