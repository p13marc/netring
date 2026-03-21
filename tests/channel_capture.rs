//! Integration tests for channel capture adapter.

#![cfg(all(feature = "integration-tests", feature = "channel"))]

mod helpers;

use netring::async_adapters::channel::ChannelCapture;
use std::time::Duration;

#[test]
fn channel_capture_recv() {
    let port = helpers::unique_port();
    let marker = format!("channel_test_{port}");

    let rx = ChannelCapture::spawn(helpers::LOOPBACK, 1024).expect("spawn channel capture");

    // Send packets
    std::thread::sleep(Duration::from_millis(100));
    helpers::send_udp_to_loopback(port, marker.as_bytes(), 10);

    // Receive via channel
    let mut found = false;
    for _ in 0..500 {
        match rx.try_recv() {
            Ok(pkt) => {
                if pkt
                    .data
                    .windows(marker.len())
                    .any(|w| w == marker.as_bytes())
                {
                    found = true;
                    break;
                }
            }
            Err(crossbeam_channel::TryRecvError::Empty) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(crossbeam_channel::TryRecvError::Disconnected) => break,
        }
    }

    assert!(found, "should have received marker via channel");
}

#[test]
fn channel_capture_drop_stops_thread() {
    let rx = ChannelCapture::spawn(helpers::LOOPBACK, 64).expect("spawn");
    // Drop should signal the thread and join it without hanging
    drop(rx);
    // If we get here, the thread stopped successfully.
}
