//! Integration tests for capture statistics.

#![cfg(feature = "integration-tests")]

mod helpers;

use netring::Capture;
use std::time::Duration;

#[test]
fn capture_stats_basic() {
    let port = helpers::unique_port();

    let mut cap = Capture::builder()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build capture");

    // Reset counters
    let _ = cap.stats();

    // Send packets
    helpers::send_udp_to_loopback(port, b"stats_test_payload", 50);

    // Give time for packets to arrive
    std::thread::sleep(Duration::from_millis(100));

    // Drain some packets to ensure the ring processes them
    for _ in 0..10 {
        if cap
            .next_batch_blocking(Duration::from_millis(50))
            .unwrap()
            .is_some()
        {
            break;
        }
    }

    let stats = cap.stats().expect("get stats");
    // We should have received at least some packets (loopback has other traffic too)
    // The exact count depends on timing, so just verify the field is populated.
    assert_eq!(
        stats.drops, 0,
        "no drops expected on loopback with default ring"
    );
}

/// The kernel contract the Monitor's drop rate relies on (#183):
/// `PACKET_STATISTICS` reports `tp_packets` with the drops already added,
/// so on an overflowed ring that is never read, `packets - drops` is only
/// what fit in the ring.
#[test]
fn overflowed_ring_reports_drops_inside_packets() {
    use netring::BpfFilter;

    let port = helpers::unique_port();
    let cap = Capture::builder()
        .interface(helpers::LOOPBACK)
        .block_size(4096)
        .block_count(2)
        .frame_size(2048)
        .block_timeout_ms(10)
        .bpf_filter(
            BpfFilter::builder()
                .udp()
                .dst_port(port)
                .build()
                .expect("filter"),
        )
        .build()
        .expect("build capture");

    // Never read: two 4 KiB blocks hold a few dozen of these frames.
    helpers::send_udp_to_loopback(port, &[0x42; 200], 2000);
    std::thread::sleep(Duration::from_millis(100));

    let s = cap.cumulative_stats().expect("stats");
    eprintln!("overflowed ring: {s}");
    assert!(s.drops > 0, "the ring should have overflowed: {s}");
    assert!(s.packets >= s.drops, "packets must include drops: {s}");
    assert!(
        s.packets - s.drops <= 128,
        "only what fits in two 4 KiB blocks was delivered: {s}"
    );
    assert!(s.packets >= 2000, "every datagram reached the socket: {s}");
}
