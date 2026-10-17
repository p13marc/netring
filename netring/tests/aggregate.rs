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

/// Top talkers attribute bytes to the host that sent them, also when the
/// flow's initiator has the higher address (the bidirectional key is
/// address-sorted, so `key.a` is then the responder).
#[cfg(all(feature = "pcap", feature = "parse"))]
#[tokio::test(flavor = "current_thread")]
async fn top_talkers_credit_the_sender() {
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

    // 10.0.0.9 → 10.0.0.1 only: the initiator is `key.b`.
    let f = flowscope::extract::parse::test_frames::ipv4_udp(
        [10, 0, 0, 9],
        [10, 0, 0, 1],
        40000,
        53,
        b"query",
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("udp.pcap");
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(std::fs::File::create(&path).unwrap(), header).unwrap();
    for ms in [100_000, 100_100, 102_000] {
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
    Monitor::builder()
        .pcap_source(&path)
        .on_aggregate(Duration::from_secs(1), move |r| {
            s.lock().unwrap().extend(r.top_talkers(10));
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "the report ticked");
    for (ip, _) in seen.iter() {
        assert_eq!(*ip, Ipv4Addr::new(10, 0, 0, 9), "{seen:?}");
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

/// A pcap of one UDP datagram from each of `n` distinct senders
/// (10.1.x.y:40000 → 10.0.0.1:53) inside one 100 ms burst, plus a repeat
/// of the first 2 s later so a 1 s report ticks after the burst.
#[cfg(all(feature = "pcap", feature = "parse"))]
fn many_senders_pcap(dir: &std::path::Path, n: u32) -> std::path::PathBuf {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

    let path = dir.join("senders.pcap");
    let header = PcapHeader {
        datalink: pcap_file::DataLink::ETHERNET,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(std::fs::File::create(&path).unwrap(), header).unwrap();
    let frame = |i: u32| {
        let [_, _, x, y] = (0x0a01_0000 + i).to_be_bytes();
        flowscope::extract::parse::test_frames::ipv4_udp(
            [10, 1, x, y],
            [10, 0, 0, 1],
            40000,
            53,
            b"q",
        )
    };
    for i in 0..n {
        let f = frame(i);
        let ts = Duration::from_millis(100_000) + Duration::from_micros(u64::from(i) * 10);
        w.write_packet(&PcapPacket::new(ts, f.len() as u32, &f))
            .unwrap();
    }
    let f = frame(0);
    w.write_packet(&PcapPacket::new(
        Duration::from_millis(102_000),
        f.len() as u32,
        &f,
    ))
    .unwrap();
    path
}

/// #214: the default aggregation is bounded — 5000 distinct senders in one
/// bucket keep at most 4096 talkers / pairs (0.31 kept all 5000, and kept
/// growing with the key space).
#[cfg(all(feature = "pcap", feature = "parse"))]
#[tokio::test(flavor = "current_thread")]
async fn default_aggregation_is_bounded() {
    use std::sync::{Arc, Mutex};

    let dir = tempfile::tempdir().unwrap();
    let path = many_senders_pcap(dir.path(), 5000);
    let sizes: Arc<Mutex<Vec<(usize, usize)>>> = Arc::default();
    let s = Arc::clone(&sizes);
    Monitor::builder()
        .pcap_source(&path)
        .on_aggregate(Duration::from_secs(1), move |r| {
            s.lock()
                .unwrap()
                .push((r.top_talkers(100_000).len(), r.top_pairs(100_000).len()));
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    let sizes = sizes.lock().unwrap();
    let (talkers, pairs) = sizes.iter().copied().max().expect("the report ticked");
    assert!(talkers > 0 && pairs > 0, "{sizes:?}");
    assert!(talkers <= 4096 && pairs <= 4096, "{sizes:?}");
}

/// #214: `max_keys` caps every dimension, and the report counts what the
/// cap refused.
#[cfg(all(feature = "pcap", feature = "parse"))]
#[tokio::test(flavor = "current_thread")]
async fn max_keys_caps_the_tables_and_counts_the_overflow() {
    use std::sync::{Arc, Mutex};

    use netring::monitor::aggregate::AggregateOverflow;

    let dir = tempfile::tempdir().unwrap();
    let path = many_senders_pcap(dir.path(), 100);
    let mut cfg = AggregateConfig::default();
    cfg.max_keys = 8;
    let seen: Arc<Mutex<Vec<(usize, AggregateOverflow)>>> = Arc::default();
    let s = Arc::clone(&seen);
    Monitor::builder()
        .pcap_source(&path)
        .aggregate_with(cfg)
        .on_aggregate(Duration::from_secs(1), move |r| {
            let snap = r.to_snapshot(1000);
            assert_eq!(snap.overflow, r.overflow());
            s.lock()
                .unwrap()
                .push((r.top_talkers(1000).len(), r.overflow()));
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    let (talkers, overflow) = *seen.last().expect("the report ticked");
    assert_eq!(talkers, 8, "{seen:?}");
    // 100 senders, 8 keyed: the other 92 folded into the overflow total.
    assert_eq!(overflow.talkers, 92, "{seen:?}");
    assert_eq!(overflow.pairs, 92, "{seen:?}");
}
