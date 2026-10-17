//! A packet socket whose interface is down has `sk_err = ENETDOWN` set
//! (packet_do_bind() on an admin-down device, packet_notifier() on
//! NETDEV_DOWN), so poll(2) reports POLLERR — at once, every time, until
//! the error is read. Reads must not return "no batch yet" in a tight
//! loop: a down interface is waited out (it may come back), a removed one
//! is an error.
//!
//! Requires root (CAP_NET_RAW + CAP_NET_ADMIN). Run with:
//! cargo test --features integration-tests --test interface_down

#![cfg(feature = "integration-tests")]

mod helpers;

use std::process::Command;
use std::time::{Duration, Instant};

use helpers::VethPair;
use netring::bridge::{Bridge, BridgeAction};
use netring::{CaptureBuilder, Error};

fn ip(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

/// A dummy interface left administratively down.
struct DownDummy(String);

impl DownDummy {
    fn create() -> Option<Self> {
        let name = format!("nrpdn{}", std::process::id() % 100_000);
        let _ = Command::new("ip").args(["link", "delete", &name]).output();
        ip(&["link", "add", &name, "type", "dummy"]).then(|| Self(name))
    }
}

impl Drop for DownDummy {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "delete", &self.0])
            .output();
    }
}

fn is_enetdown(e: &Error) -> bool {
    matches!(e, Error::Io(io) if io.raw_os_error() == Some(libc::ENETDOWN))
}

/// Capturing on a down interface: the reads wait out their timeout (no
/// tight loop on the kernel's ENETDOWN), report no error — the interface
/// may come back — and see packets once it is up.
#[test]
fn next_batch_blocking_on_a_down_interface_waits_and_recovers() {
    let Some(dummy) = DownDummy::create() else {
        eprintln!("skip: cannot create a dummy interface (need CAP_NET_ADMIN)");
        return;
    };
    let mut cap = CaptureBuilder::default()
        .interface(&dummy.0)
        .block_count(2)
        .block_size(1 << 16)
        .block_timeout_ms(10)
        .build()
        .expect("build capture on a down interface");

    let start = Instant::now();
    let mut returns = 0u32;
    while start.elapsed() < Duration::from_secs(1) && returns < 10_000 {
        let batch = cap
            .next_batch_blocking(Duration::from_millis(500))
            .expect("a down interface is not an error");
        assert!(batch.is_none(), "no traffic on a down interface");
        returns += 1;
    }
    assert!(
        returns <= 4,
        "next_batch_blocking(500 ms) returned {returns} times in 1 s"
    );

    // Back up: the kernel re-arms the socket, and frames sent on the
    // interface reach the capture.
    assert!(ip(&["link", "set", &dummy.0, "up"]), "set {} up", dummy.0);
    let marker = b"netring-interface-back-up";
    let mut tx = netring::Injector::open(&dummy.0).expect("injector");
    let mut seen = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while !seen && Instant::now() < deadline {
        let mut frame = vec![0xffu8; 12];
        frame.extend_from_slice(&0x88b5u16.to_be_bytes());
        frame.extend_from_slice(marker);
        frame.resize(60, 0);
        if let Some(mut slot) = tx.allocate(frame.len()) {
            slot.data_mut()[..frame.len()].copy_from_slice(&frame);
            slot.set_len(frame.len());
            slot.send();
        }
        let _ = tx.flush();
        if let Some(batch) = cap
            .next_batch_blocking(Duration::from_millis(100))
            .expect("interface is up")
        {
            seen = batch
                .iter()
                .any(|p| p.data().windows(marker.len()).any(|w| w == marker));
        }
    }
    assert!(seen, "capture did not resume after the interface came up");
}

/// A capture whose interface is deleted reports ENETDOWN instead of
/// waiting forever or spinning.
#[test]
fn next_batch_blocking_reports_a_removed_interface() {
    let Some(dummy) = DownDummy::create() else {
        eprintln!("skip: cannot create a dummy interface (need CAP_NET_ADMIN)");
        return;
    };
    assert!(ip(&["link", "set", &dummy.0, "up"]));
    let mut cap = CaptureBuilder::default()
        .interface(&dummy.0)
        .block_count(2)
        .block_size(1 << 16)
        .build()
        .expect("build capture");
    assert!(ip(&["link", "delete", &dummy.0]), "delete {}", dummy.0);

    let start = Instant::now();
    let err = loop {
        match cap.next_batch_blocking(Duration::from_millis(200)) {
            Err(e) => break e,
            Ok(_) if start.elapsed() < Duration::from_secs(2) => continue,
            Ok(_) => panic!("no error 2 s after the interface was removed"),
        }
    };
    assert!(is_enetdown(&err), "{err:?}");
}

/// A bridge side going down is waited out, not a tight loop or an error;
/// removing it ends `run_iterations` with ENETDOWN. (The filter drops
/// everything, so the error can only come from the RX side.)
#[test]
fn bridge_waits_out_a_side_going_down_and_reports_its_removal() {
    let pid = std::process::id() % 10_000;
    let Some(x) = VethPair::create(&format!("nrpbx{pid}a"), &format!("nrpbx{pid}b")) else {
        eprintln!("skip: needs CAP_NET_ADMIN to create veth");
        return;
    };
    let Some(y) = VethPair::create(&format!("nrpby{pid}a"), &format!("nrpby{pid}b")) else {
        eprintln!("skip: needs CAP_NET_ADMIN to create veth");
        return;
    };
    let mut bridge = Bridge::builder()
        .interface_a(&x.b)
        .interface_b(&y.b)
        .profile(netring::RingProfile::LowMemory)
        .poll_timeout(Duration::from_millis(100))
        .build()
        .expect("build bridge");
    assert!(ip(&["link", "set", &y.b, "down"]), "set {} down", y.b);

    // Ten 100 ms iterations: waited out, not spun through.
    let start = Instant::now();
    bridge
        .run_iterations(10, |_pkt, _dir| BridgeAction::Drop)
        .expect("a down side is not an error");
    assert!(
        start.elapsed() >= Duration::from_millis(500),
        "run_iterations(10) took only {:?} with side B down",
        start.elapsed()
    );

    // Deleting a veth end removes its peer: side B is gone for good.
    drop(y);
    let err = bridge
        .run_iterations(10, |_pkt, _dir| BridgeAction::Drop)
        .expect_err("side B was removed");
    assert!(is_enetdown(&err), "{err:?}");
}
