//! Traffic aggregation wiring (issue #121).
//!
//! Cap-free build coverage — the rate tables are exercised by flowscope's
//! BandwidthByKey / RollingRate tests.

#![cfg(all(feature = "tokio", feature = "flow"))]

use netring::monitor::Monitor;
use netring::monitor::aggregate::AggregateConfig;
use netring::prelude::StdoutSink;
use std::time::Duration;

#[tokio::test(flavor = "current_thread")]
async fn aggregate_builds_default() {
    let m = Monitor::builder()
        .interface("lo")
        .aggregate()
        .aggregate() // idempotent
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "aggregate build failed: {:?}", m.err());
}

/// DNS names are case-insensitive: resolvers' 0x20 case randomisation
/// must not split one domain into several top-domain keys.
#[cfg(all(feature = "pcap", feature = "parse", feature = "dns"))]
#[tokio::test(flavor = "current_thread")]
async fn top_domains_fold_case() {
    use std::sync::{Arc, Mutex};

    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

    fn query(qname: &str) -> Vec<u8> {
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in qname.trim_end_matches('.').split('.') {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.extend_from_slice(&[0, 0, 1, 0, 1]);
        flowscope::extract::parse::test_frames::ipv4_udp(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            40000,
            53,
            &dns,
        )
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dns.pcap");
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(std::fs::File::create(&path).unwrap(), header).unwrap();
    for (ms, name) in [
        (100_000, "Evil.Example"),
        (100_300, "eVIL.exAMPLE"),
        (100_600, "evil.example"),
        (102_000, "evil.example"),
    ] {
        let f = query(name);
        w.write_packet(&PcapPacket::new(
            Duration::from_millis(ms),
            f.len() as u32,
            &f,
        ))
        .unwrap();
    }
    drop(w);

    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = Arc::clone(&seen);
    let mut cfg = AggregateConfig::default();
    cfg.top_talkers = false;
    cfg.traffic_matrix = false;
    Monitor::builder()
        .pcap_source(&path)
        .aggregate_with(cfg)
        .on_aggregate(Duration::from_secs(1), move |r| {
            s.lock().unwrap().push(r.top_domains(10));
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "the report ticked");
    for top in seen.iter().filter(|t| !t.is_empty()) {
        let names: Vec<&str> = top.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["evil.example"], "{seen:?}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn on_aggregate_reports() {
    let mut cfg = AggregateConfig::default();
    cfg.top_domains = false;
    cfg.top_sni = false;
    let m = Monitor::builder()
        .interface("lo")
        .on_aggregate(Duration::from_secs(10), |r| {
            let _ = (r.top_talkers(5), r.top_pairs(5), r.to_snapshot(5));
            Ok(())
        })
        .aggregate_with(cfg) // already armed by on_aggregate → idempotent
        .build();
    assert!(m.is_ok(), "on_aggregate build failed: {:?}", m.err());
}
