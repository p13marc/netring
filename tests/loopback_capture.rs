//! Integration tests for loopback capture.
//!
//! Requires CAP_NET_RAW. Run with: cargo test --features integration-tests

#![cfg(feature = "integration-tests")]

mod helpers;

use netring::{AfPacketRxBuilder, Capture, PacketSource};
use std::time::{Duration, Instant};

#[test]
fn capture_loopback_basic() {
    let port = helpers::unique_port();
    let marker = format!("netring_test_{port}");

    let mut rx = AfPacketRxBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build rx");

    // Send packets in a background thread
    let marker_clone = marker.clone();
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        helpers::send_udp_to_loopback(port, marker_clone.as_bytes(), 10);
    });

    // Capture until we see our marker or deadline
    let mut found = 0;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Some(batch) = rx.next_batch_blocking(Duration::from_millis(200)).unwrap() {
            for pkt in &batch {
                if pkt.data().windows(marker.len()).any(|w| w == marker.as_bytes()) {
                    found += 1;
                }
            }
            if found >= 5 {
                break;
            }
        }
    }

    sender.join().unwrap();
    assert!(found > 0, "should have captured at least 1 marked packet");
}

#[test]
fn low_level_rx_next_batch() {
    let port = helpers::unique_port();
    let marker = format!("netring_batch_{port}");

    let mut rx = AfPacketRxBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build rx");

    let marker_clone = marker.clone();
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        helpers::send_udp_to_loopback(port, marker_clone.as_bytes(), 5);
    });

    let mut found = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Some(batch) = rx.next_batch_blocking(Duration::from_millis(100)).unwrap() {
            assert!(!batch.is_empty());
            for pkt in &batch {
                if pkt.data().windows(marker.len()).any(|w| w == marker.as_bytes()) {
                    found = true;
                }
            }
            if found {
                break;
            }
        }
    }

    sender.join().unwrap();
    assert!(found, "should have found marker in batch");
}

#[test]
fn capture_promiscuous_no_crash() {
    let _cap = Capture::builder()
        .interface(helpers::LOOPBACK)
        .promiscuous(true)
        .build()
        .expect("promiscuous on loopback should work");
}
