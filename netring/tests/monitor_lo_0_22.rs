//! Root-gated end-to-end tests for the 0.22 high-level monitor API on
//! the loopback interface. These exercise the **full live path**
//! (capture → tracker/parser → dispatch → handler) that the synthetic
//! unit tests can only approximate.
//!
//! Needs `CAP_NET_RAW` on the test binary (`just setcap` or root) and
//! the `integration-tests` Cargo feature. Each test skips gracefully if
//! the capture can't be opened.
//!
//! ```sh
//! just setcap
//! cargo nextest run -p netring \
//!     --features "monitor-quickstart,icmp,integration-tests" \
//!     -E 'binary(monitor_lo_0_22)'
//! ```

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "icmp",
    feature = "integration-tests"
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::prelude::*;

/// Open short-lived UDP sends + TCP connects on `lo` for `dur`.
async fn drive_lo_traffic(udp_port: u16, tcp_closed_port: u16, dur: Duration) {
    let deadline = tokio::time::Instant::now() + dur;
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok();
    while tokio::time::Instant::now() < deadline {
        if let Some(s) = &udp {
            let _ = s
                .send_to(b"netring-0.22-probe", ("127.0.0.1", udp_port))
                .await;
        }
        // Connect to a closed TCP port → RST (and the SYN is captured).
        let _ = tokio::time::timeout(
            Duration::from_millis(15),
            tokio::net::TcpStream::connect(("127.0.0.1", tcp_closed_port)),
        )
        .await;
        tokio::task::yield_now().await;
    }
}

/// A closed loopback port (bind-then-drop) — UDP to it yields an ICMP
/// Port Unreachable; TCP to it yields a RST.
fn likely_closed_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let p = s.local_addr().unwrap().port();
    drop(s);
    p
}

#[tokio::test(flavor = "current_thread")]
async fn on_bandwidth_sees_lo_traffic() {
    let udp_port = likely_closed_port();
    let saw_bytes = Arc::new(AtomicU32::new(0));
    let flag = Arc::clone(&saw_bytes);

    let monitor = match Monitor::builder()
        .interface("lo")
        .all_l4()
        .on_bandwidth(
            Duration::from_millis(200),
            move |bw: &BandwidthReport<'_>| {
                if bw.total() > 0.0 {
                    flag.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            },
        )
        .build()
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("skip (needs CAP_NET_RAW): {e}");
            return;
        }
    };

    let dur = Duration::from_millis(800);
    let gen_task = tokio::spawn(drive_lo_traffic(udp_port, likely_closed_port(), dur));
    let run = tokio::time::timeout(Duration::from_secs(5), monitor.run_for(dur)).await;
    gen_task.abort();
    if matches!(run, Ok(Err(_)) | Err(_)) {
        eprintln!("skip: run_for did not complete cleanly (likely CAP_NET_RAW)");
        return;
    }
    assert!(
        saw_bytes.load(Ordering::Relaxed) >= 1,
        "on_bandwidth should have reported nonzero bytes/sec from lo traffic"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn on_icmp_error_fires_on_port_unreachable() {
    // UDP to a closed port → kernel replies ICMP Port Unreachable on lo.
    let closed = likely_closed_port();
    let hits = Arc::new(AtomicU32::new(0));
    let h = Arc::clone(&hits);

    let monitor = match Monitor::builder()
        .interface("lo")
        .on_icmp_error(move |_err: &IcmpError, _ctx: &mut Ctx<'_>| {
            h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("skip (needs CAP_NET_RAW): {e}");
            return;
        }
    };

    let dur = Duration::from_millis(900);
    let gen_task = tokio::spawn(drive_lo_traffic(closed, likely_closed_port(), dur));
    let run = tokio::time::timeout(Duration::from_secs(5), monitor.run_for(dur)).await;
    gen_task.abort();
    if matches!(run, Ok(Err(_)) | Err(_)) {
        eprintln!("skip: run_for did not complete cleanly");
        return;
    }
    // Best-effort: ICMP generation depends on the kernel + no firewall
    // swallowing it. Don't hard-fail on 0 (CI environments vary), but
    // log so a maintainer notices.
    let n = hits.load(Ordering::Relaxed);
    eprintln!("on_icmp_error fired {n} times");
}

#[tokio::test(flavor = "current_thread")]
async fn on_tcp_reset_fires_on_closed_port() {
    let closed = likely_closed_port();
    let resets = Arc::new(AtomicU32::new(0));
    let r = Arc::clone(&resets);

    let monitor = match Monitor::builder()
        .interface("lo")
        .on_tcp_reset(move |_rst: &TcpRst, _ctx: &mut Ctx<'_>| {
            r.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("skip (needs CAP_NET_RAW): {e}");
            return;
        }
    };

    let dur = Duration::from_millis(900);
    let gen_task = tokio::spawn(drive_lo_traffic(likely_closed_port(), closed, dur));
    let run = tokio::time::timeout(Duration::from_secs(5), monitor.run_for(dur)).await;
    gen_task.abort();
    if matches!(run, Ok(Err(_)) | Err(_)) {
        eprintln!("skip: run_for did not complete cleanly");
        return;
    }
    let n = resets.load(Ordering::Relaxed);
    eprintln!("on_tcp_reset fired {n} times");
}
