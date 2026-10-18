//! Shared test helpers for integration tests.

#![allow(dead_code)]

use std::net::UdpSocket;
use std::process::Command;
use std::sync::atomic::{AtomicU16, Ordering};

/// Loopback interface name.
pub const LOOPBACK: &str = "lo";

/// First port of the test port space — below the kernel's default
/// ephemeral range (32768–60999), so a test port never collides with a
/// sender's ephemeral one.
const PORT_BASE: u16 = 10_000;
/// Ports each test process owns: [`private_port`] slots `0..16`, then
/// [`unique_port`]'s counter.
const PORT_BLOCK: u16 = 128;
/// Ports handed out by [`unique_port`] start after the private slots.
const PRIVATE_SLOTS: u16 = 16;

/// This process's block of [`PORT_BLOCK`] ports, derived from the pid, so
/// concurrent test binaries on the shared `lo` (each one restarts its
/// counter) use different ports — they all started at 30000 before.
fn port_block_base() -> u16 {
    let blocks = (32_768 - u32::from(PORT_BASE)) / u32::from(PORT_BLOCK);
    PORT_BASE + (std::process::id() % blocks) as u16 * PORT_BLOCK
}

/// Unique port counter within this process's block.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(0);

/// Get a unique UDP port for testing: distinct within the process, and
/// from other test processes (see [`port_block_base`]).
pub fn unique_port() -> u16 {
    let seq = PORT_COUNTER.fetch_add(1, Ordering::Relaxed) % (PORT_BLOCK - PRIVATE_SLOTS);
    port_block_base() + PRIVATE_SLOTS + seq
}

/// A fixed port of this process (`slot < 16`), for tests that name their
/// ports as constants.
pub fn private_port(slot: u16) -> u16 {
    port_block_base() + slot % PRIVATE_SLOTS
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

/// A dummy interface (`ip link add <name> type dummy`), deleted on drop.
/// Requires `CAP_NET_ADMIN`; the constructors return `None` without it.
pub struct Dummy(pub String);

impl Dummy {
    /// `name` (≤ 15 bytes), up, with `mtu` when given.
    pub fn create(name: &str, mtu: Option<u32>) -> Option<Self> {
        let _ = Command::new("ip").args(["link", "delete", name]).output();
        let ok = |args: &[&str]| {
            Command::new("ip")
                .args(args)
                .status()
                .is_ok_and(|s| s.success())
        };
        if !ok(&["link", "add", name, "type", "dummy"]) {
            return None;
        }
        let d = Self(name.to_string());
        if let Some(mtu) = mtu
            && !ok(&["link", "set", name, "mtu", &mtu.to_string()])
        {
            return None;
        }
        ok(&["link", "set", name, "up"]).then_some(d)
    }

    /// `ip link set <name> <args…>` (e.g. `["mtu", "3000"]`, `["down"]`).
    pub fn set(&self, args: &[&str]) -> bool {
        Command::new("ip")
            .args(["link", "set", &self.0])
            .args(args)
            .status()
            .is_ok_and(|s| s.success())
    }
}

impl Drop for Dummy {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "delete", &self.0])
            .output();
    }
}

/// A dummy interface, up, whose root qdisc is `plug` — it holds every frame
/// until released, so the frames an injector sends stay in flight. Deleted
/// on drop.
pub struct PluggedDummy(pub String);

impl PluggedDummy {
    /// `nrplug<pid>`; `None` without CAP_NET_ADMIN or `sch_plug`.
    pub fn create() -> Option<Self> {
        Self::create_named(&format!("nrplug{}", std::process::id() % 100_000))
    }

    /// The interface `name` (≤ 15 bytes).
    pub fn create_named(name: &str) -> Option<Self> {
        Self::create_with_limit(name, 1 << 20)
    }

    /// The interface `name`, whose plug holds at most `limit` bytes: it
    /// drops what comes on top (`NET_XMIT_DROP`).
    pub fn create_with_limit(name: &str, limit: u32) -> Option<Self> {
        use std::process::Command;
        let name = name.to_string();
        let _ = Command::new("ip").args(["link", "delete", &name]).output();
        let ok = |args: &[&str]| {
            Command::new("ip")
                .args(args)
                .status()
                .is_ok_and(|s| s.success())
        };
        if !ok(&["link", "add", &name, "type", "dummy"]) {
            return None;
        }
        let d = Self(name);
        if !ok(&["link", "set", &d.0, "up"]) {
            return None;
        }
        let ifindex = nix::net::if_::if_nametoindex(d.0.as_str()).ok()?;
        plug_qdisc_request(
            ifindex,
            0, // TCQ_PLUG_BUFFER
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16,
            limit,
        )
        .ok()?;
        Some(d)
    }
}

impl PluggedDummy {
    /// Let the held frames (and every later one) through.
    pub fn release(&self) -> std::io::Result<()> {
        let ifindex =
            nix::net::if_::if_nametoindex(self.0.as_str()).map_err(std::io::Error::from)?;
        release_plug_qdisc(ifindex)
    }

    /// Hold every frame again after a [`release`](Self::release)
    /// (`tc qdisc change … plug block`).
    pub fn block(&self) -> std::io::Result<()> {
        let ifindex =
            nix::net::if_::if_nametoindex(self.0.as_str()).map_err(std::io::Error::from)?;
        plug_qdisc_request(
            ifindex,
            0,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            1 << 20,
        )
    }
}

impl Drop for PluggedDummy {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", &self.0])
            .output();
    }
}

/// `tc qdisc add dev <ifindex> root plug limit 1MiB`, over rtnetlink (no
/// `tc` binary needed). `plug` starts out holding (sch_plug: plug_init
/// throttles): every frame is queued until a release that never comes.
pub fn add_plug_qdisc(ifindex: u32) -> std::io::Result<()> {
    plug_qdisc_request(
        ifindex,
        0, // TCQ_PLUG_BUFFER
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16,
        1 << 20,
    )
}

/// `tc qdisc change dev <ifindex> root plug release_indefinite`: the plug
/// lets every held frame (and all later ones) through.
pub fn release_plug_qdisc(ifindex: u32) -> std::io::Result<()> {
    plug_qdisc_request(
        ifindex,
        2, // TCQ_PLUG_RELEASE_INDEFINITE
        (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
        1 << 20,
    )
}

/// One RTM_NEWQDISC for the root `plug` qdisc of `ifindex`, with
/// `tc_plug_qopt { action, limit }`.
fn plug_qdisc_request(ifindex: u32, action: i32, flags: u16, limit: u32) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn attr(buf: &mut Vec<u8>, kind: u16, data: &[u8]) {
        let len = 4 + data.len();
        buf.extend_from_slice(&(len as u16).to_ne_bytes());
        buf.extend_from_slice(&kind.to_ne_bytes());
        buf.extend_from_slice(data);
        buf.resize(buf.len().next_multiple_of(4), 0);
    }

    const RTM_NEWQDISC: u16 = 36;
    const TCA_KIND: u16 = 1;
    const TCA_OPTIONS: u16 = 2;
    let mut body = Vec::new();
    // struct tcmsg { family: u8, pad: [u8; 3], ifindex: i32, handle: u32,
    // parent: u32, info: u32 }
    body.extend_from_slice(&[libc::AF_UNSPEC as u8, 0, 0, 0]);
    body.extend_from_slice(&(ifindex as i32).to_ne_bytes());
    body.extend_from_slice(&0x0001_0000u32.to_ne_bytes()); // handle 1:
    body.extend_from_slice(&0xffff_ffffu32.to_ne_bytes()); // TC_H_ROOT
    body.extend_from_slice(&0u32.to_ne_bytes());
    attr(&mut body, TCA_KIND, b"plug\0");
    // struct tc_plug_qopt { action: i32, limit: u32 }
    let mut qopt = Vec::new();
    qopt.extend_from_slice(&action.to_ne_bytes());
    qopt.extend_from_slice(&limit.to_ne_bytes());
    attr(&mut body, TCA_OPTIONS, &qopt);

    let mut msg = Vec::new();
    msg.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    msg.extend_from_slice(&RTM_NEWQDISC.to_ne_bytes());
    msg.extend_from_slice(&flags.to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.extend_from_slice(&body);

    // SAFETY: plain syscalls on a fresh fd we own; buffers sized as passed.
    unsafe {
        let raw = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(raw);
        if libc::send(fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut ack = [0u8; 256];
        let n = libc::recv(fd.as_raw_fd(), ack.as_mut_ptr().cast(), ack.len(), 0);
        if n < 20 {
            return Err(std::io::Error::other("short netlink ack"));
        }
        // nlmsgerr: the error code follows the 16-byte header.
        let errno = i32::from_ne_bytes([ack[16], ack[17], ack[18], ack[19]]);
        if errno != 0 {
            return Err(std::io::Error::from_raw_os_error(-errno));
        }
    }
    Ok(())
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
        flow_between([10, 0, 0, 1], [10, 0, 0, 2], cp, sp, segments)
    }

    /// [`flow_to`] between explicit addresses: client `c`:`cp` opens the
    /// connection to server `s`:`sp`. With `c > s` the initiator is the
    /// flow key's `b` endpoint (the key is address-sorted).
    pub fn flow_between(
        c: [u8; 4],
        s: [u8; 4],
        cp: u16,
        sp: u16,
        segments: &[(u32, Vec<u8>)],
    ) -> Vec<(Duration, Vec<u8>)> {
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
