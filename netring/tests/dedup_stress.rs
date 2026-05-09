//! Stress test for `Dedup::loopback()` at sub-millisecond, same-direction
//! cadence with structurally-similar TCP-shaped payloads. Asserts zero
//! false-positive drops.
//!
//! Closes feedback item F4 from des-rs (`plans/feedback-from-des-rs-2026-05-09.md`):
//! des-rs traffic can spike to 500 Hz on a single TCP connection (two
//! packets within < 2 ms), and structurally-similar payloads were a
//! theoretical xxh3-64 collision concern. This test drives 10 k packets
//! at both 1 kHz and 2 kHz cadence and asserts `dropped() == 0`.

use netring::{Dedup, PacketDirection, Timestamp};

/// Build a 1500-byte payload with deterministic-but-distinct content
/// per `seq`. The first ~54 bytes mimic Ethernet+IPv4+TCP headers
/// (heavily-similar across packets); the rest is unique per `seq`.
fn synth_packet(seq: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 1500];
    // Ethernet header (14 B): same MACs and EtherType for every packet.
    buf[0..6].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    buf[6..12].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x02]);
    buf[12..14].copy_from_slice(&[0x08, 0x00]);
    // IPv4 header (20 B): same src/dst, varying IP id.
    buf[14] = 0x45;
    buf[18..20].copy_from_slice(&(seq as u16).to_be_bytes());
    buf[26..30].copy_from_slice(&[10, 0, 0, 1]);
    buf[30..34].copy_from_slice(&[10, 0, 0, 2]);
    // TCP header (20 B): same ports, varying seq.
    buf[34..36].copy_from_slice(&12345u16.to_be_bytes());
    buf[36..38].copy_from_slice(&80u16.to_be_bytes());
    buf[38..42].copy_from_slice(&seq.to_be_bytes());
    // Payload: deterministic-but-unique. Vary every byte so the body
    // has structure without being identical between packets.
    for (i, slot) in buf.iter_mut().enumerate().skip(54) {
        *slot = ((i as u32).wrapping_add(seq) & 0xff) as u8;
    }
    buf
}

fn ts_from_ns(ts_ns: u64) -> Timestamp {
    Timestamp::new(
        (ts_ns / 1_000_000_000) as u32,
        (ts_ns % 1_000_000_000) as u32,
    )
}

#[test]
fn loopback_dedup_no_false_positives_at_1khz_same_direction() {
    let mut d = Dedup::loopback();
    let mut kept = 0u64;
    let mut ts_ns: u64 = 0;
    for seq in 0u32..10_000 {
        let pkt = synth_packet(seq);
        if d.keep_raw(&pkt, PacketDirection::Outgoing, ts_from_ns(ts_ns)) {
            kept += 1;
        }
        ts_ns += 1_000_000; // 1 ms tick → 1 kHz
    }
    assert_eq!(d.dropped(), 0, "false positives at 1 kHz cadence");
    assert_eq!(kept, 10_000);
}

#[test]
fn loopback_dedup_no_false_positives_at_2khz_subms() {
    // 500 µs cadence → distinct packets fall well *inside* the 1 ms
    // dedup window, where a hash collision would surface fastest.
    let mut d = Dedup::loopback();
    let mut ts_ns: u64 = 0;
    for seq in 0u32..10_000 {
        let pkt = synth_packet(seq);
        assert!(
            d.keep_raw(&pkt, PacketDirection::Outgoing, ts_from_ns(ts_ns)),
            "dedup dropped distinct packet seq={seq}"
        );
        ts_ns += 500_000;
    }
    assert_eq!(d.dropped(), 0);
}
