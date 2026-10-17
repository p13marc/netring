//! #210 / #222: the snap length is enforced by the socket filter, and the
//! typed filters accept whole packets.
//!
//! TPACKET_V3 cuts a packet only to the socket filter's return value
//! (`tpacket_rcv`: `if (snaplen > res) snaplen = res;`); the ring's frame
//! size does not limit it. 0.31's `snap_len` set the frame size, so it cut
//! nothing, and the builder's accept verdict `ret #65535` cut every frame
//! longer than 65535 bytes — `lo`'s 65536-byte MTU makes 65549-byte ones.
//!
//! Needs `CAP_NET_RAW`; skips without it.

#![cfg(feature = "integration-tests")]

mod helpers;

use std::net::UdpSocket;
use std::time::Duration;

use netring::{BpfFilter, Capture, CaptureBuilder, Error, Packet};

const MARKER: &[u8; 8] = b"NRSNAPLN";
/// Ethernet + IPv4 + UDP headers in front of the payload.
const PAYLOAD_OFF: usize = 14 + 20 + 8;

fn private_port(slot: u16) -> u16 {
    50_000 + (std::process::id() % 3_000) as u16 * 4 + slot
}

fn open(builder: CaptureBuilder) -> Option<Capture> {
    match builder.build() {
        Ok(cap) => Some(cap),
        Err(Error::PermissionDenied) => {
            eprintln!("skipping: needs CAP_NET_RAW");
            None
        }
        Err(e) => panic!("build capture: {e}"),
    }
}

fn base() -> CaptureBuilder {
    Capture::builder()
        .interface(helpers::LOOPBACK)
        .ignore_outgoing(true)
        .block_timeout_ms(10)
        .poll_timeout(Duration::from_millis(50))
}

fn port_filter(port: u16) -> BpfFilter {
    BpfFilter::builder()
        .udp()
        .dst_port(port)
        .build()
        .expect("filter")
}

/// Send `count` datagrams of `size` payload bytes (marker first) to `port`.
fn send(port: u16, size: usize, count: usize) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let mut payload = vec![0x5a; size];
    payload[..MARKER.len()].copy_from_slice(MARKER);
    for _ in 0..count {
        sock.send_to(&payload, ("127.0.0.1", port))
            .expect("send_to");
    }
}

/// One of our datagrams to `port` (the captured bytes must reach the
/// marker; a cut packet still has its headers).
fn is_ours(pkt: &Packet<'_>, port: u16) -> bool {
    let d = pkt.data();
    d.len() >= PAYLOAD_OFF + MARKER.len()
        && d[12..14] == [0x08, 0x00]
        && d[23] == 17
        && d[36..38] == port.to_be_bytes()
        && d[PAYLOAD_OFF..PAYLOAD_OFF + MARKER.len()] == MARKER[..]
}

/// `(len, original_len, truncated)` of the first `n` of our datagrams seen
/// within 3 s.
fn ours(cap: &mut Capture, port: u16, n: usize) -> Vec<(usize, usize, bool)> {
    let mut out = Vec::new();
    let mut pkts = cap.packets_for(Duration::from_secs(3));
    while out.len() < n {
        let Some(pkt) = pkts.next_packet() else { break };
        if is_ours(&pkt, port) {
            out.push((pkt.len(), pkt.original_len(), pkt.status().truncated));
        }
    }
    out
}

fn assert_cut_to(seen: &[(usize, usize, bool)], snap: usize, n: usize) {
    assert_eq!(seen.len(), n, "{seen:?}");
    for &(len, orig, truncated) in seen {
        assert!(len <= snap, "captured {len} > snap {snap}: {seen:?}");
        assert_eq!(orig, PAYLOAD_OFF + 1000, "{seen:?}");
        assert!(truncated, "{seen:?}");
    }
}

#[test]
fn snap_len_without_filter_truncates() {
    let port = private_port(0);
    let Some(mut cap) = open(base().snap_len(64)) else {
        return;
    };
    assert_eq!(cap.snap_len(), Some(64));
    send(port, 1000, 5);
    let seen = ours(&mut cap, port, 5);
    // 0.31: whole 1042-byte frames (the frame size does not cut on V3).
    assert_cut_to(&seen, 64, 5);
}

#[test]
fn snap_len_with_filter() {
    let port = private_port(1);
    let Some(mut cap) = open(base().snap_len(64).bpf_filter(port_filter(port))) else {
        return;
    };
    send(port, 1000, 5);
    assert_cut_to(&ours(&mut cap, port, 5), 64, 5);
}

#[test]
fn snap_len_survives_set_filter_and_detach() {
    let port = private_port(2);
    let Some(mut cap) = open(base().snap_len(64)) else {
        return;
    };
    cap.set_filter(&port_filter(port)).expect("set_filter");
    send(port, 1000, 3);
    assert_cut_to(&ours(&mut cap, port, 3), 64, 3);

    // Detaching keeps the snap length: a bare `ret #64` stays installed.
    cap.detach_filter().expect("detach_filter");
    send(port, 1000, 3);
    assert_cut_to(&ours(&mut cap, port, 3), 64, 3);
}

#[test]
fn filter_accepts_whole_lo_jumbo() {
    let port = private_port(3);
    let Some(mut cap) = open(
        base()
            .block_size(1 << 18)
            .block_count(8)
            .bpf_filter(port_filter(port)),
    ) else {
        return;
    };
    // The largest UDP payload an IPv4 datagram carries: 65507 + 8 + 20 =
    // 65535-byte datagram, a 65549-byte frame on lo (MTU 65536).
    send(port, 65_507, 2);
    let seen = ours(&mut cap, port, 2);
    assert_eq!(seen.len(), 2, "{seen:?}");
    for (len, orig, truncated) in seen {
        // 0.31.3: 65535 (the filter's `ret #65535`).
        assert_eq!(len, 65_549);
        assert_eq!(orig, 65_549);
        assert!(!truncated);
    }
}
