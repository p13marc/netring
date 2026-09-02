//! Shared test helpers for integration tests.

#![allow(dead_code)]

use std::net::UdpSocket;
use std::process::Command;
use std::sync::atomic::{AtomicU16, Ordering};

/// Loopback interface name.
pub const LOOPBACK: &str = "lo";

/// Unique port counter to avoid collisions between parallel tests.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(30_000);

/// Get a unique UDP port for testing.
pub fn unique_port() -> u16 {
    PORT_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Fanout group counter, so one process never reuses a group id either.
static FANOUT_GROUP_COUNTER: AtomicU16 = AtomicU16::new(0);

/// Get a fanout group id no other test run is using.
///
/// `PACKET_FANOUT` group ids are a **system-wide** namespace, not a per-process
/// one: joining an id another process still holds does not fail — the kernel
/// adds our socket to *that* group and then hashes traffic across every member,
/// including theirs. A test with a hardcoded id therefore goes quiet (not red at
/// the join, but red at the "did we capture anything" assertion) whenever a
/// previous or concurrent run still has sockets in the same group. The CI
/// integration lane runs `cancel-in-progress: true`, which leaves exactly those
/// stragglers behind.
///
/// Seeded from the pid so concurrent runs, and back-to-back runs racing kernel
/// cleanup, both get distinct ids. Never returns 0.
pub fn unique_fanout_group() -> u16 {
    let seq = FANOUT_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as u16;
    pid.wrapping_mul(31).wrapping_add(seq) | 1
}

/// Send `count` UDP packets to localhost on the given port.
pub fn send_udp_to_loopback(port: u16, payload: &[u8], count: usize) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let dst = format!("127.0.0.1:{port}");
    for _ in 0..count {
        sock.send_to(payload, &dst).expect("send_to");
    }
}

/// RAII drop guard for a paired-veth test fixture.
///
/// Creates two `veth` interfaces wired together. Both ends are brought
/// up at construction. On drop, the pair is removed (deleting one end
/// removes its peer too).
///
/// Requires `CAP_NET_ADMIN`. Returns `None` if `ip link add` fails
/// (typically permission denied) so the caller can skip the test.
pub struct VethPair {
    pub a: String,
    pub b: String,
}

impl VethPair {
    /// Create a new veth pair. Both ends are brought up. On any failure
    /// (typically permission denied), returns `None` so the caller can skip.
    pub fn create(a: &str, b: &str) -> Option<Self> {
        // Idempotent: delete any leftover from a previous failed run.
        let _ = Command::new("ip").args(["link", "delete", a]).output();
        let status = Command::new("ip")
            .args(["link", "add", a, "type", "veth", "peer", "name", b])
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
        let up_a = Command::new("ip")
            .args(["link", "set", a, "up"])
            .status()
            .ok()?;
        if !up_a.success() {
            let _ = Command::new("ip").args(["link", "delete", a]).status();
            return None;
        }
        let up_b = Command::new("ip")
            .args(["link", "set", b, "up"])
            .status()
            .ok()?;
        if !up_b.success() {
            let _ = Command::new("ip").args(["link", "delete", a]).status();
            return None;
        }
        Some(Self {
            a: a.to_string(),
            b: b.to_string(),
        })
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        // Deleting one end of a veth pair removes both.
        let _ = Command::new("ip")
            .args(["link", "delete", &self.a])
            .output();
    }
}
