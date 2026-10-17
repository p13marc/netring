//! A packet socket whose interface is down has `sk_err = ENETDOWN` set
//! (packet_do_bind() on an admin-down device, packet_notifier() on
//! NETDEV_DOWN), so poll(2) reports POLLERR — at once, every time, until
//! the error is read. Reads must surface it instead of returning
//! "no batch yet" in a tight loop.
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

/// Capturing on a down interface: the first read reports ENETDOWN, and
/// the reads after it wait out their timeout instead of returning at once.
#[test]
fn next_batch_blocking_on_a_down_interface_reports_enetdown() {
    let Some(dummy) = DownDummy::create() else {
        eprintln!("skip: cannot create a dummy interface (need CAP_NET_ADMIN)");
        return;
    };
    let mut cap = CaptureBuilder::default()
        .interface(&dummy.0)
        .block_count(2)
        .block_size(1 << 16)
        .build()
        .expect("build capture on a down interface");

    let start = Instant::now();
    let (mut returns, mut errors) = (0u32, Vec::new());
    while start.elapsed() < Duration::from_secs(1) && returns < 10_000 {
        match cap.next_batch_blocking(Duration::from_millis(500)) {
            Ok(batch) => assert!(batch.is_none(), "no traffic on a down interface"),
            Err(e) => errors.push(e),
        }
        returns += 1;
    }

    assert!(
        returns <= 4,
        "next_batch_blocking(500 ms) returned {returns} times in 1 s"
    );
    assert_eq!(errors.len(), 1, "one ENETDOWN, then waiting: {errors:?}");
    assert!(is_enetdown(&errors[0]), "{:?}", errors[0]);
}

/// A bridge side going down ends `run_iterations` with ENETDOWN instead of
/// spinning through its iterations. (The filter drops everything, so the
/// error can only come from the RX side, not a send on the down device.)
#[test]
fn bridge_reports_a_side_going_down() {
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

    let start = Instant::now();
    let result = bridge.run_iterations(10, |_pkt, _dir| BridgeAction::Drop);
    let err = result.expect_err(&format!(
        "run_iterations(10) returned Ok after {:?} with side B down",
        start.elapsed()
    ));
    assert!(is_enetdown(&err), "{err:?}");
}
