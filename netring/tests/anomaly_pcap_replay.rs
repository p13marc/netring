#![allow(deprecated)]
// 0.21 H.3: this file uses the legacy ProtocolMonitor / AnomalyMonitor / AnomalyRule API; remove with the legacy types in 0.22.

//! Integration test: synthesize a pcap with N DNS queries from
//! one source IP, replay through `AsyncPcapSource::datagrams` +
//! `AnomalyMonitor` + a `DnsBurstRule`, assert the rule fires.
//!
//! This exercises the same pipeline `examples/anomaly/pcap_replay.rs`
//! ships, end-to-end, with no privileges.
//!
//! Run with:
//!   cargo test --features tokio,flow,parse,pcap,dns \
//!       --test anomaly_pcap_replay

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap",
    feature = "dns"
))]

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use flowscope::dns::{DnsMessage, DnsUdpParser};
use flowscope::{SessionEvent, Timestamp};
use futures::StreamExt;
use netring::AsyncPcapSource;
use netring::anomaly::{Anomaly, AnomalyMonitor, AnomalyRule, Severity};
use netring::correlate::TimeBucketedCounter;
use netring::flow::extract::{FiveTuple, FiveTupleKey};
use netring::protocol::{ProtocolEvent, ProtocolMessage};
use tempfile::NamedTempFile;

/// Build an Ethernet+IPv4+UDP frame to `10.0.0.1:5353 →
/// 10.0.0.2:53` carrying `payload` (a DNS query). Mirrors the
/// helper in `tests/async_pcap_source.rs` but with the canonical
/// DNS port pair.
fn dns_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + 20 + 8 + payload.len());
    // Ethernet
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4
    // IPv4 header (no options)
    frame.push(0x45);
    frame.push(0x00);
    let ip_total = (20 + 8 + payload.len()) as u16;
    frame.extend_from_slice(&ip_total.to_be_bytes());
    frame.extend_from_slice(&[0, 0]); // ID
    frame.extend_from_slice(&[0, 0]); // flags + frag
    frame.push(64); // TTL
    frame.push(17); // UDP
    frame.extend_from_slice(&[0, 0]); // header checksum (skipped)
    frame.extend_from_slice(&[10, 0, 0, 1]); // src
    frame.extend_from_slice(&[10, 0, 0, 2]); // dst
    // UDP
    frame.extend_from_slice(&5353u16.to_be_bytes());
    frame.extend_from_slice(&53u16.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0, 0]); // UDP checksum (skipped)
    frame.extend_from_slice(payload);
    frame
}

/// Minimal DNS query body — same shape `synthetic_traffic` builds.
fn dns_query_body(txid: u16, qname: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(48);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // flags
    pkt.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    for label in qname.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // qtype = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // qclass = IN
    pkt
}

fn write_pcap(frames: &[(Timestamp, Vec<u8>)]) -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let file = NamedTempFile::new().unwrap();
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
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).unwrap();
    for (ts, data) in frames {
        let pkt = PcapPacket::new_owned(
            Duration::new(ts.sec as u64, ts.nsec),
            data.len() as u32,
            data.clone(),
        );
        w.write_packet(&pkt).unwrap();
    }
    drop(w);
    file
}

struct DnsBurstRule {
    counts: TimeBucketedCounter<IpAddr>,
    threshold: u64,
    alerted: HashSet<IpAddr>,
}

impl AnomalyRule<FiveTupleKey> for DnsBurstRule {
    fn name(&self) -> &'static str {
        "DnsQueryBurst"
    }
    fn observe(
        &mut self,
        evt: &ProtocolEvent<FiveTupleKey>,
        emit: &mut Vec<Anomaly<FiveTupleKey>>,
    ) {
        let ProtocolEvent::Message {
            parser_kind: flowscope::parser_kinds::DNS_UDP,
            message: ProtocolMessage::Dns(DnsMessage::Query(_)),
            key,
            ts,
            ..
        } = evt
        else {
            return;
        };
        let src = key.a.ip();
        self.counts.bump(src, *ts);
        let n = self.counts.count(&src, *ts);
        if n > self.threshold && self.alerted.insert(src) {
            emit.push(
                Anomaly::new(self.name(), Severity::Warning, *ts)
                    .with_key(*key)
                    .with_metric("count", n as f64),
            );
        }
    }
}

#[tokio::test]
async fn pcap_replay_fires_dns_burst() {
    // 60 DNS queries from 10.0.0.1:5353 within 5 seconds — well
    // above any reasonable per-source-IP threshold.
    let frames: Vec<(Timestamp, Vec<u8>)> = (0..60u32)
        .map(|i| {
            let payload = dns_query_body(0x1000 + i as u16, &format!("h{i}.test"));
            (Timestamp::new(100 + i / 12, 0), dns_frame(&payload))
        })
        .collect();
    let pcap = write_pcap(&frames);

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new().with_rule(DnsBurstRule {
        counts: TimeBucketedCounter::new_unbounded(Duration::from_secs(10), Duration::from_secs(1)),
        threshold: 10,
        alerted: HashSet::new(),
    });

    let source = AsyncPcapSource::open(pcap.path()).await.unwrap();
    let mut stream = source.datagrams(FiveTuple::bidirectional(), DnsUdpParser::with_correlation());

    let mut alerts = 0u64;
    let mut dns_messages = 0u64;

    while let Some(evt) = stream.next().await {
        if let SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind,
        } = evt.unwrap()
        {
            dns_messages += 1;
            let pe = ProtocolEvent::Message {
                key,
                side,
                parser_kind,
                message: ProtocolMessage::Dns(message),
                ts,
            };
            alerts += rules.observe(&pe).len() as u64;
        }
    }

    assert!(
        dns_messages >= 50,
        "expected ≥50 DNS messages, got {dns_messages}"
    );
    assert_eq!(
        alerts, 1,
        "expected exactly one burst alert (first crossing of threshold)"
    );
}

#[tokio::test]
async fn pcap_replay_quiet_traffic_no_alerts() {
    // Just 5 queries — well below threshold=10.
    let frames: Vec<(Timestamp, Vec<u8>)> = (0..5u32)
        .map(|i| {
            let payload = dns_query_body(0x2000 + i as u16, &format!("low{i}.test"));
            (Timestamp::new(200 + i, 0), dns_frame(&payload))
        })
        .collect();
    let pcap = write_pcap(&frames);

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new().with_rule(DnsBurstRule {
        counts: TimeBucketedCounter::new_unbounded(Duration::from_secs(10), Duration::from_secs(1)),
        threshold: 10,
        alerted: HashSet::new(),
    });

    let source = AsyncPcapSource::open(pcap.path()).await.unwrap();
    let mut stream = source.datagrams(FiveTuple::bidirectional(), DnsUdpParser::with_correlation());

    let mut alerts = 0u64;
    while let Some(evt) = stream.next().await {
        if let SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind,
        } = evt.unwrap()
        {
            let pe = ProtocolEvent::Message {
                key,
                side,
                parser_kind,
                message: ProtocolMessage::Dns(message),
                ts,
            };
            alerts += rules.observe(&pe).len() as u64;
        }
    }
    assert_eq!(alerts, 0, "below-threshold traffic must not fire");
}
