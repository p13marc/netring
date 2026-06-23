//! Issue #46: end-to-end Sigma rule evaluation over pcap replay.
//!
//! Replays a DNS query for a subdomain of a flagged domain through a Monitor
//! armed with `.sigma(rules)` and asserts a `sigma_match` anomaly reaches the
//! sink — exercising the real DNS event-build + rule-eval arm. Also confirms a
//! benign query does NOT match. Cap-free.

#![cfg(all(
    feature = "sigma",
    feature = "dns",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::net::Ipv4Addr;
use std::time::Duration;

use netring::anomaly::shipped_sinks::ChannelSink;
use netring::monitor::Monitor;
use netring::monitor::sigma::SigmaRuleSet;
use tempfile::NamedTempFile;

/// UDP frame to `dst_ip:dst_port` with a tiny payload.
fn udp_frame(dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // dst MAC
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src MAC
    f.extend_from_slice(&[0x08, 0x00]); // IPv4
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.push(64);
    f.push(17); // UDP
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&[10, 0, 0, 1]); // src ip
    f.extend_from_slice(&dst_ip.octets()); // dst ip
    f.extend_from_slice(&40000u16.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    f
}

/// UDP/53 DNS standard query for `qname`.
fn dns_query_frame(qname: &str) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&0x1234u16.to_be_bytes());
    dns.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    dns.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    dns.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in qname.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&1u16.to_be_bytes()); // A
    dns.extend_from_slice(&1u16.to_be_bytes()); // IN
    udp_frame(Ipv4Addr::new(10, 0, 0, 2), 53, &dns)
}

const RULE: &str = r#"
title: DNS lookup of a flagged domain
id: netring-test-dns
level: high
logsource:
  category: dns
detection:
  selection:
    query|contains: 'evil'
  condition: selection
"#;

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
    for (i, frame) in [
        dns_query_frame("good.example"),
        dns_query_frame("login.evil.example"),
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
async fn replay_emits_sigma_match_for_flagged_dns_query_only() {
    let pcap = write_pcap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    let rules = SigmaRuleSet::from_yaml_str(RULE).expect("parse rule");

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .sigma(rules)
        .sink(ChannelSink::new(tx))
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");

    let matches: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok())
        .filter(|a| a.kind == "sigma_match")
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "exactly the evil.example query should match, got {}",
        matches.len()
    );
    // The alert carries the rule identity.
    let m = &matches[0];
    assert!(
        m.observations
            .iter()
            .any(|(k, v)| *k == "rule" && v == "netring-test-dns"),
        "sigma_match should carry the rule id observation"
    );
}
