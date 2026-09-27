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

/// Synthetic captures for the replay (no-privilege) tests.
#[cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "pcap",
    feature = "parse"
))]
pub mod pcap {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    use pcap_file::{DataLink, Endianness, TsResolution};

    pub const SYN: u8 = 0x02;
    pub const ACK: u8 = 0x10;
    pub const PSH: u8 = 0x08;
    pub const FIN: u8 = 0x01;

    /// Client 10.0.0.1:40000 → server 10.0.0.2:9000: handshake, the given
    /// (offset, payload) client segments, FIN exchange. 1 ms apart from
    /// t = 1 s.
    pub fn flow(segments: &[(u32, Vec<u8>)]) -> Vec<(Duration, Vec<u8>)> {
        flow_from(40_000, segments)
    }

    /// [`flow`] with the client port `cp` (distinct flows in one capture).
    pub fn flow_from(cp: u16, segments: &[(u32, Vec<u8>)]) -> Vec<(Duration, Vec<u8>)> {
        flow_to(cp, 9_000, segments)
    }

    /// [`flow`] with explicit client and server ports (`sp = 80` puts the
    /// flow on the HTTP parser).
    pub fn flow_to(cp: u16, sp: u16, segments: &[(u32, Vec<u8>)]) -> Vec<(Duration, Vec<u8>)> {
        let (c, s) = ([10, 0, 0, 1], [10, 0, 0, 2]);
        let (cisn, sisn) = (1000u32, 5000u32);
        let m = [0u8; 6];
        let mut v = vec![
            ipv4_tcp(m, m, c, s, cp, sp, cisn, 0, SYN, &[]),
            ipv4_tcp(m, m, s, c, sp, cp, sisn, cisn + 1, SYN | ACK, &[]),
            ipv4_tcp(m, m, c, s, cp, sp, cisn + 1, sisn + 1, ACK, &[]),
        ];
        let mut end = cisn + 1;
        for (off, payload) in segments {
            let seq = cisn + 1 + off;
            v.push(ipv4_tcp(
                m,
                m,
                c,
                s,
                cp,
                sp,
                seq,
                sisn + 1,
                PSH | ACK,
                payload,
            ));
            end = end.max(seq + payload.len() as u32);
        }
        v.push(ipv4_tcp(m, m, c, s, cp, sp, end, sisn + 1, FIN | ACK, &[]));
        v.push(ipv4_tcp(
            m,
            m,
            s,
            c,
            sp,
            cp,
            sisn + 1,
            end + 1,
            FIN | ACK,
            &[],
        ));
        v.push(ipv4_tcp(m, m, c, s, cp, sp, end + 1, sisn + 2, ACK, &[]));
        v.into_iter()
            .enumerate()
            .map(|(i, f)| (Duration::from_millis(1_000 + i as u64), f))
            .collect()
    }

    /// `n` UDP datagrams 10.0.0.1:`sport` → 10.0.0.2:53, 1 ms apart.
    pub fn udp_flow(sport: u16, n: usize) -> Vec<(Duration, Vec<u8>)> {
        (0..n)
            .map(|i| {
                (
                    Duration::from_millis(1_000 + i as u64),
                    ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], sport, 53, b"query"),
                )
            })
            .collect()
    }

    /// Every frame twice, the twin `gap` later (a `tcpdump -i lo` shape).
    pub fn doubled(frames: &[(Duration, Vec<u8>)], gap: Duration) -> Vec<(Duration, Vec<u8>)> {
        frames
            .iter()
            .flat_map(|(t, f)| [(*t, f.clone()), (*t + gap, f.clone())])
            .collect()
    }

    /// Write `frames` as a classic nanosecond-resolution Ethernet pcap.
    pub fn write_pcap(dir: &Path, name: &str, frames: &[(Duration, Vec<u8>)]) -> PathBuf {
        let path = dir.join(format!("{name}.pcap"));
        let header = PcapHeader {
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: u32::MAX,
            datalink: DataLink::ETHERNET,
            ts_resolution: TsResolution::NanoSecond,
            endianness: Endianness::native(),
        };
        let mut w = PcapWriter::with_header(std::fs::File::create(&path).unwrap(), header).unwrap();
        for (ts, f) in frames {
            w.write_packet(&PcapPacket::new_owned(*ts, f.len() as u32, f.clone()))
                .unwrap();
        }
        path
    }
}
