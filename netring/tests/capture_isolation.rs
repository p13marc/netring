//! A capture sees only its interface's packets that pass its filter — from
//! the first packet on. The socket used to start receiving on *every*
//! interface at `socket(ETH_P_ALL)`, so whatever arrived while the ring was
//! being set up (the slow `MAP_POPULATE` mmap) landed in the first blocks,
//! before `bind()` narrowed the interface and before the BPF filter was
//! attached.
//!
//! Requires root (CAP_NET_RAW + CAP_NET_ADMIN). Run with:
//! cargo test --features integration-tests --test capture_isolation

#![cfg(feature = "integration-tests")]

mod helpers;

use std::net::UdpSocket;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use netring::{BpfFilter, Capture, CaptureBuilder};

/// Send UDP datagrams carrying `marker` to `127.0.0.1:port` until `stop`.
fn flood_loopback(port: u16, marker: Vec<u8>, stop: Arc<AtomicBool>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let dst = format!("127.0.0.1:{port}");
        while !stop.load(Ordering::Relaxed) {
            let _ = sock.send_to(&marker, &dst);
        }
    })
}

/// Every packet `cap` yields within `window`.
fn collect(cap: &mut Capture, window: Duration) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        if let Some(batch) = cap
            .next_batch_blocking(Duration::from_millis(20))
            .expect("next_batch_blocking")
        {
            out.extend(batch.iter().map(|p| p.data().to_vec()));
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A dummy interface, down-sized to silence: no IPv6 (no DAD / MLD).
struct Dummy(String);

impl Dummy {
    fn create() -> Option<Self> {
        let name = format!("nrpi{}", std::process::id() % 100_000);
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
        let dummy = Self(name);
        let _ = std::fs::write(
            format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", dummy.0),
            "1",
        );
        ok(&["link", "set", &dummy.0, "up"]).then_some(dummy)
    }
}

impl Drop for Dummy {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "delete", &self.0])
            .output();
    }
}

/// Loopback traffic sent while a capture on another interface is being
/// built never shows up in that capture.
#[test]
fn capture_sees_only_its_interface() {
    let Some(dummy) = Dummy::create() else {
        eprintln!("skip: cannot create a dummy interface (need CAP_NET_ADMIN)");
        return;
    };
    let port = helpers::unique_port();
    let marker = format!("netring_isolation_{port}").into_bytes();
    let stop = Arc::new(AtomicBool::new(false));
    let flood = flood_loopback(port, marker.clone(), Arc::clone(&stop));
    std::thread::sleep(Duration::from_millis(20));

    let built = CaptureBuilder::default()
        .interface(&dummy.0)
        .block_timeout_ms(10)
        .build();
    let packets = built.map(|mut cap| collect(&mut cap, Duration::from_millis(300)));
    stop.store(true, Ordering::Relaxed);
    flood.join().unwrap();
    let packets = packets.expect("build capture on the dummy interface");

    let leaked = packets.iter().filter(|p| contains(p, &marker)).count();
    assert_eq!(
        leaked,
        0,
        "{leaked} of {} packets captured on {} were loopback traffic",
        packets.len(),
        dummy.0
    );
}

/// A capture built with a BPF filter never yields a packet the filter
/// rejects, even while other traffic floods the interface during the build.
#[test]
fn filter_applies_from_the_first_packet() {
    let wanted = helpers::unique_port();
    let other = helpers::unique_port();
    let filter = BpfFilter::builder()
        .udp()
        .dst_port(wanted)
        .build()
        .expect("filter");

    let stop = Arc::new(AtomicBool::new(false));
    let noise = flood_loopback(other, b"netring_noise".to_vec(), Arc::clone(&stop));
    let signal = flood_loopback(wanted, b"netring_signal".to_vec(), Arc::clone(&stop));
    std::thread::sleep(Duration::from_millis(20));

    let built = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .bpf_filter(filter.clone())
        .build();
    let packets = built.map(|mut cap| collect(&mut cap, Duration::from_millis(300)));
    stop.store(true, Ordering::Relaxed);
    noise.join().unwrap();
    signal.join().unwrap();
    let packets = packets.expect("build filtered capture on lo");

    assert!(!packets.is_empty(), "the filter's own traffic was captured");
    let unfiltered = packets.iter().filter(|p| !filter.matches(p)).count();
    assert_eq!(
        unfiltered,
        0,
        "{unfiltered} of {} captured packets fail the capture's own filter",
        packets.len()
    );
}
