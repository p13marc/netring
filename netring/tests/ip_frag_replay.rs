//! IP-fragment reassembly end-to-end (issue #134).
//!
//! A DNS response is split across two IPv4 fragments. Replayed through a Monitor
//! with `.reassemble_ip_fragments()` armed, the DNS parser sees the reassembled
//! datagram and fires `on_dns` with the right qname; without arming, the
//! fragments never parse and no such event is seen. This is the strongest
//! statement of the feature: the payload is *only* visible when reassembled.
//!
//! Cap-free — driven entirely by `Monitor::replay()` over a synthesized pcap, so
//! it needs no capture privileges.

#![cfg(all(feature = "tokio", feature = "flow", feature = "dns"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::monitor::Monitor;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use tempfile::NamedTempFile;

const SRC_IP: [u8; 4] = [10, 0, 0, 53];
const DST_IP: [u8; 4] = [10, 0, 0, 9];
const IP_ID: u16 = 0xABCD;

/// A well-formed DNS response for `example.com` A → 93.184.216.34 (45 bytes).
fn dns_response() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&[0x12, 0x34]); // id
    d.extend_from_slice(&[0x81, 0x80]); // flags: response, RA
    d.extend_from_slice(&[0x00, 0x01]); // qdcount
    d.extend_from_slice(&[0x00, 0x01]); // ancount
    d.extend_from_slice(&[0x00, 0x00]); // nscount
    d.extend_from_slice(&[0x00, 0x00]); // arcount
    // Question: example.com A IN
    d.push(7);
    d.extend_from_slice(b"example");
    d.push(3);
    d.extend_from_slice(b"com");
    d.push(0);
    d.extend_from_slice(&[0x00, 0x01]); // A
    d.extend_from_slice(&[0x00, 0x01]); // IN
    // Answer: ptr to name, A IN, TTL 300, 4-byte RDATA
    d.extend_from_slice(&[0xc0, 0x0c]);
    d.extend_from_slice(&[0x00, 0x01]);
    d.extend_from_slice(&[0x00, 0x01]);
    d.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL 300
    d.extend_from_slice(&[0x00, 0x04]);
    d.extend_from_slice(&[93, 184, 216, 34]);
    d
}

/// The full UDP datagram (server port 53 → client 40000) carrying the response.
fn udp_datagram() -> Vec<u8> {
    let dns = dns_response();
    let mut u = Vec::new();
    u.extend_from_slice(&53u16.to_be_bytes()); // src port (DNS server)
    u.extend_from_slice(&40000u16.to_be_bytes()); // dst port (client)
    u.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes()); // length
    u.extend_from_slice(&[0, 0]); // checksum (0 = not computed, valid for IPv4/UDP)
    u.extend_from_slice(&dns);
    u
}

/// Build one IPv4 fragment frame carrying `payload` at `frag_offset` (bytes,
/// must be a multiple of 8) with the More-Fragments flag `mf`.
fn fragment_frame(payload: &[u8], frag_offset_bytes: u16, mf: bool) -> Vec<u8> {
    let mut f = Vec::new();
    // Ethernet: arbitrary unicast dst/src, IPv4 ethertype.
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    f.extend_from_slice(&[0x08, 0x00]);
    // IPv4 header (20 bytes, no options).
    f.push(0x45); // version 4, IHL 5
    f.push(0x00); // DSCP/ECN
    let total_len = (20 + payload.len()) as u16;
    f.extend_from_slice(&total_len.to_be_bytes());
    f.extend_from_slice(&IP_ID.to_be_bytes());
    // Flags (3 bits) + fragment offset (13 bits, in 8-byte units).
    let flags_frag = (if mf { 0x2000u16 } else { 0 }) | (frag_offset_bytes / 8);
    f.extend_from_slice(&flags_frag.to_be_bytes());
    f.push(64); // TTL
    f.push(17); // protocol UDP
    f.extend_from_slice(&[0, 0]); // header checksum placeholder
    f.extend_from_slice(&SRC_IP);
    f.extend_from_slice(&DST_IP);
    // Fix the IPv4 header checksum over bytes 14..34.
    let ck = ipv4_checksum(&f[14..34]);
    f[24] = (ck >> 8) as u8;
    f[25] = ck as u8;
    f.extend_from_slice(payload);
    f
}

fn ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// A pcap of the DNS response split into two IPv4 fragments (24 + rest bytes).
fn write_fragmented_pcap() -> NamedTempFile {
    let datagram = udp_datagram();
    // Fragment 1: first 24 bytes of the L4 payload (UDP header + part of DNS),
    // a multiple of 8, MF=1. Fragment 2: the remainder at offset 24, MF=0.
    let (a, b) = datagram.split_at(24);
    let frag1 = fragment_frame(a, 0, true);
    let frag2 = fragment_frame(b, 24, false);

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
    for (i, frame) in [frag1, frag2].into_iter().enumerate() {
        let pkt =
            PcapPacket::new_owned(Duration::new(100 + i as u64, 0), frame.len() as u32, frame);
        w.write_packet(&pkt).expect("write");
    }
    drop(w);
    file
}

/// Count `on_dns` events whose qname is `example.com`, replaying the fragmented
/// pcap with reassembly `armed` or not.
async fn count_example_com(armed: bool) -> u32 {
    let pcap = write_fragmented_pcap();
    let hits = Arc::new(AtomicU32::new(0));
    let h = Arc::clone(&hits);

    let mut builder = Monitor::builder()
        .pcap_source(pcap.path())
        .on_dns(move |v, _ctx| {
            if v.qname() == Some("example.com") {
                h.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        });
    if armed {
        builder = builder.reassemble_ip_fragments();
    }
    let monitor = builder.build().expect("build with pcap_source");
    monitor.replay().await.expect("replay completes");
    hits.load(Ordering::Relaxed)
}

#[tokio::test(flavor = "current_thread")]
async fn fragmented_dns_parses_only_when_reassembly_armed() {
    let armed = count_example_com(true).await;
    let unarmed = count_example_com(false).await;

    assert_eq!(
        armed, 1,
        "armed: the reassembled DNS response should parse once"
    );
    assert_eq!(
        unarmed, 0,
        "unarmed: the split fragments must not yield the qname"
    );
}
