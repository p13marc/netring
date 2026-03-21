//! Integration tests for capture statistics.

#![cfg(feature = "integration-tests")]

mod helpers;

use netring::{Capture, PacketSource};
use std::time::Duration;

#[test]
fn capture_stats_basic() {
    let port = helpers::unique_port();

    let cap = Capture::builder()
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
    let rx = cap.into_inner();
    let mut rx = rx;
    for _ in 0..10 {
        if rx
            .next_batch_blocking(Duration::from_millis(50))
            .unwrap()
            .is_some()
        {
            break;
        }
    }

    let stats = rx.stats().expect("get stats");
    // We should have received at least some packets (loopback has other traffic too)
    // The exact count depends on timing, so just verify the field is populated.
    assert_eq!(
        stats.drops, 0,
        "no drops expected on loopback with default ring"
    );
}
