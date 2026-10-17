//! #212: `BackendErrorPolicy` against a capture interface that goes away.
//!
//! A two-source Monitor — a dummy interface `D` plus `lo` — runs while
//! `D` is deleted, set down, or deleted and re-created:
//!
//! - `FailFast` ends the run with `ENETDOWN` (it used to keep waiting on
//!   the dead socket until its deadline);
//! - `SkipSource` retires `D` and keeps dispatching `lo`;
//! - `Reopen` re-opens `D` once it exists again;
//! - a down interface is not a backend error at all.
//!
//! Requires root (CAP_NET_RAW + CAP_NET_ADMIN). Run with:
//! cargo test --features integration-tests,tokio,flow --test monitor_backend_policy

#![cfg(all(feature = "integration-tests", feature = "tokio", feature = "flow"))]

use std::net::UdpSocket;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use netring::ctx::Ctx;
use netring::monitor::{BackendErrorPolicy, Monitor, MonitorHealth};
use netring::prelude::*;

fn ip(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

/// A dummy interface, brought up; deleted on drop.
struct Dummy(String);

impl Dummy {
    fn up(tag: &str) -> Option<Self> {
        let name = format!("nrbp{tag}{}", std::process::id() % 100_000);
        let _ = Command::new("ip").args(["link", "delete", &name]).output();
        let d = Self(name);
        (d.add() && ip(&["link", "set", &d.0, "up"])).then_some(d)
    }

    fn add(&self) -> bool {
        ip(&["link", "add", &self.0, "type", "dummy"])
    }
}

impl Drop for Dummy {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "delete", &self.0])
            .output();
    }
}

fn is_enetdown(e: &netring::Error) -> bool {
    matches!(e, netring::Error::Io(io) if io.raw_os_error() == Some(libc::ENETDOWN))
}

/// Per-source `FlowPacket` counts (source 0 = the dummy, 1 = `lo`).
#[derive(Default)]
struct Seen([AtomicU64; 2]);

impl Seen {
    fn get(&self, i: usize) -> u64 {
        self.0[i].load(Ordering::SeqCst)
    }
}

fn monitor(dummy: &str, policy: BackendErrorPolicy, seen: &Arc<Seen>) -> Monitor {
    let seen = Arc::clone(seen);
    Monitor::builder()
        .interfaces([dummy, "lo"])
        .protocol::<Udp>()
        .drain_timeout(Duration::ZERO)
        .backend_error_policy(policy)
        .on_ctx::<FlowPacket>(move |_e: &FlowPacket, ctx: &mut Ctx<'_>| {
            if let Some(c) = ctx.source.and_then(|s| seen.0.get(s.0 as usize)) {
                c.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        })
        .build()
        .expect("build monitor")
}

/// Wait until the run loop has opened its sockets.
async fn wait_ready(health: &MonitorHealth) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if health.is_ready() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// An Ethernet/IPv4/UDP frame 10.99.0.1:`sport` → 10.99.0.2:5000.
fn udp_frame(sport: u16) -> Vec<u8> {
    let payload = b"netring-backend-policy";
    let mut f = vec![0xffu8; 6];
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    let total = (20 + 8 + payload.len()) as u16;
    let mut ipv4 = [0u8; 20];
    ipv4[0] = 0x45;
    ipv4[2..4].copy_from_slice(&total.to_be_bytes());
    ipv4[8] = 64;
    ipv4[9] = 17;
    ipv4[12..16].copy_from_slice(&[10, 99, 0, 1]);
    ipv4[16..20].copy_from_slice(&[10, 99, 0, 2]);
    let mut sum: u32 = ipv4
        .chunks(2)
        .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    ipv4[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    f.extend_from_slice(&ipv4);
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&5000u16.to_be_bytes());
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    f.resize(f.len().max(60), 0);
    f
}

/// Inject UDP frames on `iface` until `seen` counts some for source 0,
/// or `limit` passes.
async fn inject_until_seen(iface: &str, seen: &Seen, limit: Duration) -> bool {
    let mut tx = netring::Injector::open(iface).expect("injector");
    let frame = udp_frame(40_000);
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(mut slot) = tx.allocate(frame.len()) {
            slot.data_mut()[..frame.len()].copy_from_slice(&frame);
            slot.set_len(frame.len());
            slot.send();
        }
        let _ = tx.flush();
        if seen.get(0) > 0 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    seen.get(0) > 0
}

/// UDP to a closed port on `lo`, every 5 ms until `stop`.
fn lo_traffic(stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    let closed = {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    std::thread::spawn(move || {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        while !stop.load(Ordering::Relaxed) {
            let _ = sock.send_to(b"netring-lo", ("127.0.0.1", closed));
            std::thread::sleep(Duration::from_millis(5));
        }
    })
}

/// `FailFast`: removing a capture interface ends the run with ENETDOWN,
/// promptly — not at the deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fail_fast_ends_the_run_when_an_interface_is_removed() {
    let Some(dummy) = Dummy::up("ff") else {
        eprintln!("skip: cannot create a dummy interface (need CAP_NET_ADMIN)");
        return;
    };
    let seen = Arc::new(Seen::default());
    let m = monitor(&dummy.0, BackendErrorPolicy::FailFast, &seen);
    let health = m.health();
    let run = tokio::spawn(m.run_for(Duration::from_secs(10)));
    assert!(wait_ready(&health).await, "monitor did not start");

    let start = Instant::now();
    assert!(ip(&["link", "delete", &dummy.0]));
    let res = tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("run still going 5 s after the interface was removed")
        .expect("run task");
    let err = res.expect_err("FailFast ends the run");
    assert!(is_enetdown(&err), "{err:?}");
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "took {:?}",
        start.elapsed()
    );
}

/// `SkipSource`: the removed interface is retired, the other source
/// keeps dispatching, and the run ends normally at its deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn skip_source_retires_the_removed_interface_and_keeps_the_rest() {
    let Some(dummy) = Dummy::up("ss") else {
        eprintln!("skip: cannot create a dummy interface (need CAP_NET_ADMIN)");
        return;
    };
    let seen = Arc::new(Seen::default());
    let m = monitor(&dummy.0, BackendErrorPolicy::SkipSource, &seen);
    let health = m.health();
    let run = tokio::spawn(m.run_for(Duration::from_secs(4)));
    assert!(wait_ready(&health).await, "monitor did not start");
    let stop = Arc::new(AtomicBool::new(false));
    let traffic = lo_traffic(Arc::clone(&stop));

    assert!(ip(&["link", "delete", &dummy.0]));
    // Past the removal (and the liveness probe), `lo` still dispatches.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let lo_before = seen.get(1);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let lo_after = seen.get(1);

    let res = tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("run ends at its deadline")
        .expect("run task");
    stop.store(true, Ordering::Relaxed);
    let _ = traffic.join();
    res.expect("SkipSource keeps the run going");
    assert!(
        lo_after > lo_before,
        "lo stopped dispatching after the dummy was removed ({lo_before} → {lo_after})"
    );
    assert_eq!(
        health.backend_errors(),
        1,
        "the removal is one backend error"
    );
}

/// `Reopen`: a removed interface that comes back (same name) is
/// re-opened, and its frames reach the handlers again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reopen_recovers_a_recreated_interface() {
    let Some(dummy) = Dummy::up("ro") else {
        eprintln!("skip: cannot create a dummy interface (need CAP_NET_ADMIN)");
        return;
    };
    let seen = Arc::new(Seen::default());
    let m = monitor(&dummy.0, BackendErrorPolicy::Reopen, &seen);
    let health = m.health();
    let run = tokio::spawn(m.run_for(Duration::from_secs(15)));
    assert!(wait_ready(&health).await, "monitor did not start");

    assert!(ip(&["link", "delete", &dummy.0]));
    // Long enough for the removal to be noticed and a re-open to fail.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!run.is_finished(), "Reopen ended the run");
    assert!(dummy.add() && ip(&["link", "set", &dummy.0, "up"]));

    let recovered = inject_until_seen(&dummy.0, &seen, Duration::from_secs(5)).await;
    let finished = run.is_finished();
    run.abort();
    assert!(!finished, "Reopen ended the run");
    assert!(
        recovered,
        "frames on the re-created interface never arrived"
    );
    assert!(health.backend_errors() >= 1);
}

/// A down interface is not a backend error: even under `FailFast` the
/// run keeps going, and the source delivers again once it is back up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn down_then_up_is_not_a_backend_error() {
    let Some(dummy) = Dummy::up("du") else {
        eprintln!("skip: cannot create a dummy interface (need CAP_NET_ADMIN)");
        return;
    };
    let seen = Arc::new(Seen::default());
    let m = monitor(&dummy.0, BackendErrorPolicy::FailFast, &seen);
    let health = m.health();
    let run = tokio::spawn(m.run_for(Duration::from_secs(15)));
    assert!(wait_ready(&health).await, "monitor did not start");

    assert!(ip(&["link", "set", &dummy.0, "down"]));
    // Past the liveness probe period.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!run.is_finished(), "a down interface ended the run");
    assert!(ip(&["link", "set", &dummy.0, "up"]));

    let recovered = inject_until_seen(&dummy.0, &seen, Duration::from_secs(5)).await;
    let finished = run.is_finished();
    run.abort();
    assert!(!finished, "the run ended");
    assert!(
        recovered,
        "frames after the interface came back up never arrived"
    );
    assert_eq!(health.backend_errors(), 0);
}
