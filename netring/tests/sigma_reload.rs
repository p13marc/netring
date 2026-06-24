//! Issue #53: hot-reload of Sigma rules without dropping packets.
//!
//! Arms a Monitor with a DNS-category Sigma rule that does **not** match the
//! traffic, swaps in a matching rule through the [`ReloadHandle`] before replay,
//! and asserts a `sigma_match` fires — proving the eval closure reads the live
//! (reloaded) rule set. Both rules are the same category so the DNS handler arm
//! installed at build stays valid across the swap. Cap-free.

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

/// A DNS-category rule that flags queries containing `needle`.
fn dns_rule(id: &str, needle: &str) -> String {
    format!(
        "title: t\nid: {id}\nlevel: high\nlogsource:\n  category: dns\ndetection:\n  selection:\n    query|contains: '{needle}'\n  condition: selection\n"
    )
}

fn udp_frame(dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    f.extend_from_slice(&[0x08, 0x00]);
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.push(64);
    f.push(17);
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&dst_ip.octets());
    f.extend_from_slice(&40000u16.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    f
}

fn dns_query_frame(qname: &str) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&0x1234u16.to_be_bytes());
    dns.extend_from_slice(&0x0100u16.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in qname.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());
    udp_frame(Ipv4Addr::new(10, 0, 0, 2), 53, &dns)
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
    let frame = dns_query_frame("login.evil.example");
    w.write_packet(&PcapPacket::new_owned(
        Duration::new(100, 0),
        frame.len() as u32,
        frame,
    ))
    .expect("write");
    drop(w);
    file
}

async fn replay_count(reload: bool) -> usize {
    let pcap = write_pcap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // Arm with a DNS rule that does NOT match 'evil' (installs the DNS arm).
    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .sigma(SigmaRuleSet::from_yaml_str(&dns_rule("orig", "benign")).expect("parse"))
        .sink(ChannelSink::new(tx))
        .build()
        .expect("build");

    let handle = monitor.reload_handle();
    assert!(handle.has_sigma());
    if reload {
        // Swap in a rule that DOES match the flagged query.
        assert!(
            handle.set_sigma(SigmaRuleSet::from_yaml_str(&dns_rule("hot", "evil")).expect("parse"))
        );
    }
    monitor.replay().await.expect("replay completes");

    let mut n = 0;
    while let Ok(a) = rx.try_recv() {
        if a.kind == "sigma_match" {
            n += 1;
        }
    }
    n
}

#[tokio::test(flavor = "current_thread")]
async fn reloaded_rule_matches() {
    assert_eq!(
        replay_count(true).await,
        1,
        "the reloaded rule should match"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn original_non_matching_rule_does_not() {
    assert_eq!(
        replay_count(false).await,
        0,
        "the original rule must not match"
    );
}
