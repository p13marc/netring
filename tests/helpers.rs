//! Shared test helpers for integration tests.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicU16, Ordering};

/// Loopback interface name.
pub const LOOPBACK: &str = "lo";

/// Unique port counter to avoid collisions between parallel tests.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(30_000);

/// Get a unique UDP port for testing.
pub fn unique_port() -> u16 {
    PORT_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Send `count` UDP packets to localhost on the given port.
pub fn send_udp_to_loopback(port: u16, payload: &[u8], count: usize) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let dst = format!("127.0.0.1:{port}");
    for _ in 0..count {
        sock.send_to(payload, &dst).expect("send_to");
    }
}
