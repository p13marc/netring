//! Integration test for async capture.

#![cfg(all(feature = "integration-tests", feature = "tokio"))]

mod helpers;

use netring::async_adapters::tokio_adapter::AsyncCapture;
use netring::{AfPacketRxBuilder, PacketSource};
use std::time::Duration;

#[tokio::test]
async fn async_capture_recv() {
    let port = helpers::unique_port();
    let marker = format!("async_test_{port}");

    let rx = AfPacketRxBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build rx");

    let mut async_cap = AsyncCapture::new(rx).expect("wrap in AsyncFd");

    // Send packets from a blocking thread
    let marker_clone = marker.clone();
    tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(50));
        helpers::send_udp_to_loopback(port, marker_clone.as_bytes(), 10);
    });

    // Wait and capture with a deadline
    let mut found = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        tokio::select! {
            result = async_cap.wait_readable() => {
                result.expect("wait_readable");
                if let Some(batch) = async_cap.get_mut().next_batch() {
                    for pkt in &batch {
                        if pkt.data().windows(marker.len()).any(|w| w == marker.as_bytes()) {
                            found = true;
                        }
                    }
                    if found { break; }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                break;
            }
        }
    }

    assert!(found, "should have found async marker packet");
}
