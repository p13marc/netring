//! Issue #12: end-to-end ARP detection over pcap replay.
//!
//! Writes a small pcap containing a **gratuitous ARP reply** whose target
//! MAC ≠ sender MAC (the classic spoof pattern), replays it through a
//! Monitor with `.on_arp` + `.on_arp_anomaly`, and asserts both the raw
//! message hook and the `SpoofSuspected` anomaly fire. Exercises the real
//! `replay → dispatch_arp → arp::parse_frame → detector` path.
//!
//! Cap-free (no live socket), so it runs in the ordinary cap-free CI job —
//! the live AF_PACKET path is covered by the rest of the lo suite.

#![cfg(all(
    feature = "arp",
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "pcap"
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::monitor::Monitor;
use netring::monitor::arp::ArpAnomalyKind;
use tempfile::NamedTempFile;

const SENDER_MAC: [u8; 6] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa];
const TARGET_MAC: [u8; 6] = [0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb];
const SENDER_IP: [u8; 4] = [192, 0, 2, 50];

/// A gratuitous ARP-reply Ethernet frame that trips
/// `ArpMessage::is_likely_spoof` (padded to the 60-byte Ethernet minimum).
fn spoof_arp_frame() -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[0..6].copy_from_slice(&[0xff; 6]); // dst: broadcast
    f[6..12].copy_from_slice(&SENDER_MAC); // src
    f[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ethertype: ARP
    f[14..16].copy_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
    f[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
    f[18] = 6; // hlen
    f[19] = 4; // plen
    f[20..22].copy_from_slice(&2u16.to_be_bytes()); // oper: reply
    f[22..28].copy_from_slice(&SENDER_MAC); // sha
    f[28..32].copy_from_slice(&SENDER_IP); // spa
    f[32..38].copy_from_slice(&TARGET_MAC); // tha (≠ sha → spoof)
    f[38..42].copy_from_slice(&SENDER_IP); // tpa (== spa → gratuitous)
    f
}

/// A UDP/IPv4 frame sourced from `SENDER_IP` (so a flow handler can resolve its
/// MAC against the ARP table the ARP frame taught).
fn udp_from_sender(dst_port: u16) -> Vec<u8> {
    let payload = [0u8; 4];
    let mut f = Vec::new();
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // dst mac
    f.extend_from_slice(&SENDER_MAC); // src mac
    f.extend_from_slice(&[0x08, 0x00]); // ipv4
    f.push(0x45);
    f.push(0);
    let ip_total = (20 + 8 + payload.len()) as u16;
    f.extend_from_slice(&ip_total.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.push(64);
    f.push(17); // udp
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&SENDER_IP); // src ip = the ARP sender
    f.extend_from_slice(&[10, 0, 0, 9]); // dst ip
    f.extend_from_slice(&54321u16.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&payload);
    f
}

fn write_pcap(frames: &[Vec<u8>]) -> NamedTempFile {
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    let file = NamedTempFile::new().expect("tempfile");
    let header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: u32::MAX,
        datalink: pcap_file::DataLink::from(1), // Ethernet
        ts_resolution: pcap_file::TsResolution::NanoSecond,
        endianness: pcap_file::Endianness::native(),
    };
    let mut w = PcapWriter::with_header(file.reopen().unwrap(), header).expect("writer");
    for (i, frame) in frames.iter().enumerate() {
        let pkt = PcapPacket::new_owned(
            Duration::new(100 + i as u64, 0),
            frame.len() as u32,
            frame.clone(),
        );
        w.write_packet(&pkt).expect("write");
    }
    drop(w);
    file
}

fn write_arp_pcap() -> NamedTempFile {
    write_pcap(&[spoof_arp_frame()])
}

#[tokio::test(flavor = "current_thread")]
async fn replay_detects_arp_spoof() {
    let pcap = write_arp_pcap();

    let msgs = Arc::new(AtomicU32::new(0));
    let spoofs = Arc::new(AtomicU32::new(0));
    let m = Arc::clone(&msgs);
    let s = Arc::clone(&spoofs);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        // Warm-up doesn't gate SpoofSuspected, but keep it 0 for clarity.
        .arp_warmup(Duration::from_millis(0))
        .on_arp(move |_msg, _ctx| {
            m.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .on_arp_anomaly(move |a, _ctx| {
            if a.kind == ArpAnomalyKind::SpoofSuspected {
                s.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");

    let got_msgs = msgs.load(Ordering::Relaxed);
    let got_spoofs = spoofs.load(Ordering::Relaxed);
    assert_eq!(got_msgs, 1, "expected exactly one parsed ARP message");
    assert_eq!(got_spoofs, 1, "expected exactly one SpoofSuspected anomaly");
}

// Issue #19: `Ctx::arp_table()` is populated in the ARP drain and reflects the
// binding the current frame just taught — so an `on_arp` detector can read the
// broader table (here: peek the sender's learned MAC).
#[tokio::test(flavor = "current_thread")]
async fn ctx_arp_table_exposes_the_learned_binding() {
    use std::net::Ipv4Addr;

    use netring::prelude::MacAddr;

    let pcap = write_arp_pcap();
    let hits = Arc::new(AtomicU32::new(0));
    let h = Arc::clone(&hits);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .on_arp(move |_m, ctx| {
            let ts = ctx.ts;
            let table = ctx
                .arp_table()
                .expect("arp_table() is Some inside the ARP drain");
            let binding = table
                .peek(&Ipv4Addr::from(SENDER_IP), ts)
                .expect("the sender's binding was just learned");
            assert_eq!(binding.addr, MacAddr(SENDER_MAC), "learned MAC matches");
            h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");
    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "on_arp ran and read the table"
    );
}

// Issue #23: cross-protocol — an ARP frame teaches the binding, then a UDP flow
// from that IP fires `FlowStarted<Udp>`, whose handler resolves the peer's MAC
// via `ctx.arp_table()`. Proves the table reaches the flow/lifecycle paths, not
// just ARP handlers.
#[tokio::test(flavor = "current_thread")]
async fn flow_handler_resolves_peer_mac_via_arp_table() {
    use std::net::Ipv4Addr;

    use netring::ctx::Ctx;
    use netring::prelude::MacAddr;
    use netring::protocol::builtin::Udp;
    use netring::protocol::event_typed::FlowStarted;

    // ARP first (teach 192.0.2.50 → SENDER_MAC), then a UDP flow from that IP.
    let pcap = write_pcap(&[spoof_arp_frame(), udp_from_sender(53)]);
    let resolved = Arc::new(AtomicU32::new(0));
    let r = Arc::clone(&resolved);

    let monitor = Monitor::builder()
        .pcap_source(pcap.path())
        .arp_table() // arm ARP learning WITHOUT an ARP handler
        .protocol::<Udp>()
        .on_ctx::<FlowStarted<Udp>>(move |_e: &FlowStarted<Udp>, ctx: &mut Ctx<'_>| {
            let ts = ctx.ts;
            // A flow handler resolves the peer IP → MAC the ARP frame taught.
            if let Some(t) = ctx.arp_table()
                && let Some(b) = t.peek(&Ipv4Addr::from(SENDER_IP), ts)
                && b.addr == MacAddr(SENDER_MAC)
            {
                r.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        })
        .build()
        .expect("build with pcap_source");

    monitor.replay().await.expect("replay completes");
    assert_eq!(
        resolved.load(Ordering::Relaxed),
        1,
        "the UDP flow handler resolved the peer MAC from the ARP table"
    );
}
