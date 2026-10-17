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
    tcp_frame_between([10, 0, 0, 1], [10, 0, 0, 2], sp, dp, payload)
}

/// Eth/IPv4/TCP frame `src:sp → dst:dp` carrying `payload`.
fn tcp_frame_between(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
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
    f.extend_from_slice(&Ipv4Addr::from(src).octets());
    f.extend_from_slice(&Ipv4Addr::from(dst).octets());
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

#[tokio::test(flavor = "current_thread")]
async fn set_yara_hot_swaps_the_live_rule_set() {
    // Issue #53: arm with a rule that DOESN'T match, hot-swap in one that does
    // BEFORE replay, and assert the swapped rule fires. Proves the scanner reads
    // the live (reloaded) cell rather than the build-time snapshot.
    let (a, b) = EICAR.as_bytes().split_at(20);
    let pcap = write_pcap(&[a, b]);

    let inert =
        YaraRules::compile(r#"rule never { strings: $a = "ZZZ-NO-SUCH-BYTES" condition: $a }"#)
            .expect("compile inert");

    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&hits);
    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Tcp>()
        .yara(inert)
        .on_yara_match(move |_k, m| sink.lock().unwrap().push(m.rule.clone()))
        .build()
        .expect("build with yara");

    let handle = monitor.reload_handle();
    assert!(handle.has_yara(), "handle should report yara armed");

    // Swap in the matching rule before replay drives the scan.
    let live = YaraRules::compile(
        r#"rule eicar { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }"#,
    )
    .expect("compile live");
    assert!(handle.set_yara(live), "set_yara should swap the live set");

    monitor.replay().await.expect("replay completes");

    let hits = hits.lock().unwrap();
    assert_eq!(hits.len(), 1, "swapped-in rule should fire, got {hits:?}");
    assert_eq!(hits[0], "eicar");
}

#[tokio::test(flavor = "current_thread")]
async fn set_yara_is_a_noop_without_yara_armed() {
    let pcap = write_pcap(&[b"hello"]);
    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .protocol::<Tcp>()
        .build()
        .expect("build");
    let handle = monitor.reload_handle();
    assert!(!handle.has_yara());
    let rules = YaraRules::compile(r#"rule r { strings: $a = "x" condition: $a }"#).expect("c");
    assert!(!handle.set_yara(rules), "unarmed set_yara must be a no-op");
}

/// A pcap of the given frames, one second apart.
fn write_frames(frames: Vec<Vec<u8>>) -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let file = NamedTempFile::new().expect("tempfile");
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).expect("writer");
    for (i, frame) in frames.into_iter().enumerate() {
        let pkt =
            PcapPacket::new_owned(Duration::new(100 + i as u64, 0), frame.len() as u32, frame);
        w.write_packet(&pkt).expect("write");
    }
    file
}

/// One IPv4 fragment `10.0.0.1 → 10.0.0.2` (UDP) carrying `payload` at
/// byte offset `offset` (a multiple of 8), More-Fragments `mf`.
fn udp_fragment(payload: &[u8], offset: u16, mf: bool) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&0x4242u16.to_be_bytes());
    ip[6..8].copy_from_slice(&((if mf { 0x2000u16 } else { 0 }) | (offset / 8)).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
    let mut sum: u32 = ip
        .chunks(2)
        .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    f.extend_from_slice(&ip);
    f.extend_from_slice(payload);
    f
}

fn eicar_rules() -> YaraRules {
    YaraRules::compile(
        r#"rule eicar { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }"#,
    )
    .expect("compile")
}

/// Replay `pcap` through `.yara(eicar)`, configured by `extra`; the hits.
async fn yara_hits(
    pcap: &NamedTempFile,
    extra: impl FnOnce(netring::monitor::MonitorBuilder) -> netring::monitor::MonitorBuilder,
) -> Vec<(String, ScanDirection)> {
    let hits: Arc<Mutex<Vec<(String, ScanDirection)>>> = Arc::default();
    let sink = Arc::clone(&hits);
    let builder = Monitor::builder()
        .pcap_source(pcap.path())
        .yara(eicar_rules())
        .on_yara_match(move |_key: &FlowKey, m| {
            sink.lock().unwrap().push((m.rule.clone(), m.direction));
        });
    extra(builder)
        .build()
        .expect("build")
        .replay()
        .await
        .expect("replay");
    hits.lock().unwrap().clone()
}

/// #214: a UDP datagram split into IPv4 fragments, the signature across
/// the fragment boundary, is scanned as the reassembled datagram. The
/// accumulators used to be fed the raw fragments: the first fragment's
/// half of the signature only.
#[tokio::test(flavor = "current_thread")]
async fn fragmented_payload_is_scanned_with_reassembly() {
    use netring::protocol::builtin::Udp;
    let mut datagram = Vec::new();
    let payload = format!("padding-{EICAR}-padding");
    datagram.extend_from_slice(&40_000u16.to_be_bytes());
    datagram.extend_from_slice(&9_999u16.to_be_bytes());
    datagram.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(payload.as_bytes());
    // Split inside the signature, at a multiple of 8.
    let (a, b) = datagram.split_at(40);
    let pcap = write_frames(vec![udp_fragment(a, 0, true), udp_fragment(b, 40, false)]);
    let hits = yara_hits(&pcap, |b| b.protocol::<Udp>().reassemble_ip_fragments()).await;
    assert_eq!(
        hits,
        vec![("eicar".to_string(), ScanDirection::Initiator)],
        "the reassembled datagram is scanned"
    );
}

/// #214 / #215: the initiator's buffer holds the client's bytes, whatever
/// the address order. With the client on the higher address its packets
/// are `Reverse` in the canonical key, and they used to land in the
/// responder's buffer.
#[tokio::test(flavor = "current_thread")]
async fn initiator_buffer_is_the_clients() {
    let (client, server) = ([10, 0, 0, 9], [10, 0, 0, 1]);
    let (a, b) = EICAR.as_bytes().split_at(20);
    let pcap = write_frames(vec![
        tcp_frame_between(client, server, 40_000, 80, a),
        tcp_frame_between(client, server, 40_000, 80, b),
        tcp_frame_between(server, client, 80, 40_000, b"HTTP/1.1 200 OK\r\n\r\n"),
    ]);
    let hits = yara_hits(&pcap, |b| b.protocol::<Tcp>()).await;
    assert_eq!(
        hits,
        vec![("eicar".to_string(), ScanDirection::Initiator)],
        "the client sent it"
    );
}
