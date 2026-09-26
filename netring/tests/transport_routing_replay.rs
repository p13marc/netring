//! Datagram parsers only see their own transport (flowscope 0.25
//! `DatagramParser::transports`): the `Icmp` marker no longer parses
//! UDP payloads (#157) and UDP datagram streams no longer get ICMP
//! messages (#158).

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap",
    feature = "icmp"
))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_udp;
use flowscope::{DatagramParser, FlowSide, SessionEvent, Timestamp};
use futures::StreamExt;
use netring::AsyncPcapSource;
use netring::monitor::Monitor;
use netring::protocol::builtin::{Icmp, Udp};
use tempfile::NamedTempFile;

/// DNS-looking UDP payload whose first byte (3) is also an ICMP
/// "destination unreachable" type.
fn dns_frame() -> Vec<u8> {
    ipv4_udp(
        [10, 0, 0, 1],
        [10, 0, 0, 53],
        40000,
        53,
        &[3, 3, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 0, 0, 1, 0, 1],
    )
}

/// Ethernet / IPv4 / ICMP echo request.
fn icmp_echo() -> Vec<u8> {
    let icmp = [8u8, 0, 0, 0, 0, 1, 0, 1, b'p', b'i', b'n', b'g'];
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&[0x08, 0x00]);
    let total = (20 + icmp.len()) as u16;
    f.extend_from_slice(&[0x45, 0]);
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
    f.extend_from_slice(&icmp);
    f
}

fn pcap(frames: &[Vec<u8>]) -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let file = NamedTempFile::new().unwrap();
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), PcapHeader::default()).unwrap();
    for (i, f) in frames.iter().enumerate() {
        w.write_packet(&PcapPacket::new_owned(
            Duration::from_millis(1_000 + i as u64),
            f.len() as u32,
            f.clone(),
        ))
        .unwrap();
    }
    file
}

#[tokio::test(flavor = "current_thread")]
async fn icmp_marker_ignores_udp_payloads() {
    let file = pcap(&[dns_frame(), icmp_echo()]);
    let seen = Arc::new(Mutex::new(0usize));
    let s = Arc::clone(&seen);
    Monitor::builder()
        .pcap_source(file.path())
        .protocol::<Udp>()
        .protocol::<Icmp>()
        .on::<Icmp>(move |_m: &flowscope::icmp::IcmpMessage| {
            *s.lock().unwrap() += 1;
            Ok(())
        })
        .build()
        .unwrap()
        .replay()
        .await
        .unwrap();
    assert_eq!(*seen.lock().unwrap(), 1, "the echo only — not the DNS datagram");
}

#[derive(Default, Clone)]
struct AnyBytes;

impl DatagramParser for AnyBytes {
    type Message = usize;
    fn parse(&mut self, p: &[u8], _: FlowSide, _: Timestamp, out: &mut Vec<usize>) {
        out.push(p.len());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn udp_datagram_stream_ignores_icmp() {
    let file = pcap(&[icmp_echo(), dns_frame()]);
    let events: Vec<_> = AsyncPcapSource::open(file.path())
        .await
        .unwrap()
        .flow_events(FiveTuple::bidirectional())
        .datagram_stream(AnyBytes)
        .map(|r| r.unwrap())
        .collect()
        .await;
    let sizes: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Application { message, .. } => Some(*message),
            _ => None,
        })
        .collect();
    assert_eq!(sizes, vec![21], "the UDP payload only");
}
