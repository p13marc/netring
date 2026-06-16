//! Root-gated AF_XDP-on-`lo` live test (0.25; the first live AF_XDP
//! validation, and the A3c de-risk).
//!
//! Loads the built-in redirect-all program (plan 12) in **SKB / generic mode**
//! on `lo` — the realistic CI configuration (no NIC, no native driver) —
//! opens an AF_XDP socket registered in its `XSKMAP`, and asserts the socket
//! captures redirected loopback frames. Loopback ingress traverses `lo`'s rx
//! path, where generic XDP redirects each frame into the socket. The A3c
//! `{proto,port}`-map filter program builds on exactly this plumbing.
//!
//! **Proven green on GitHub-hosted runners** (ubuntu-24.04, kernel 6.17). Two
//! real `xdp-loader` bugs were found + fixed getting here:
//! 1. the vendored `redirect_all.bpf.o` had **no BTF** → aya ≥ 0.13 can't load
//!    the BTF-style `.maps` def (regenerated with `clang -g | llvm-strip -g`);
//! 2. **`XDP_FLAGS_REPLACE` is rejected by the link API** (`bpf_link_create`),
//!    so `force_replace(true)` breaks the attach — see the note below.
//!
//! Gated behind `integration-tests` + `af-xdp` + `xdp-loader` so it only
//! compiles in the privileged CI job (never in a normal/sandbox build). Needs
//! **root** (or `CAP_BPF`+`CAP_NET_ADMIN`+`CAP_NET_RAW`) — the CI job runs the
//! test binary under `sudo`.

#![cfg(all(
    feature = "integration-tests",
    feature = "af-xdp",
    feature = "xdp-loader"
))]

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use netring::XdpSocket;
use netring::xdp::XdpFlags;

/// Build an AF_XDP socket, retrying on transient failure for ~8s. These tests
/// share `lo`'s queue 0; the kernel releases a dropped socket's bind + XDP
/// attachment asynchronously, so a back-to-back test can hit
/// `ResourceBusy` before the previous one's teardown completes. On a clean `lo`
/// the first attempt succeeds.
fn build_with_retry(
    label: &str,
    mut f: impl FnMut() -> Result<XdpSocket, netring::Error>,
) -> XdpSocket {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match f() {
            Ok(s) => return s,
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!("{label}: {e:?}");
                }
                std::thread::sleep(Duration::from_millis(150));
            }
        }
    }
}

/// Wait until `lo`'s queue 0 is bindable (the prior test fully released it),
/// then leave a short settle margin. Used before a test whose bind happens
/// inside a run loop (and so can't itself be retried).
fn wait_lo_free() {
    let probe = build_with_retry("wait_lo_free", || {
        XdpSocket::builder()
            .interface("lo")
            .queue_id(0)
            .frame_size(2048)
            .frame_count(64)
            .build()
    });
    drop(probe);
    std::thread::sleep(Duration::from_millis(300));
}

#[test]
fn afxdp_lo_redirect_all_captures_loopback_traffic() {
    // Attach the built-in redirect-all XDP program to `lo` in SKB/generic mode
    // and open an AF_XDP socket registered in its XSKMAP.
    //
    // NOTE: no `force_replace` — `XDP_FLAGS_REPLACE` is a netlink-only flag and
    // is rejected by the link API (`bpf_link_create`) the loader uses. A fresh
    // CI runner has a clean `lo`, so REPLACE isn't needed.
    let mut sock = build_with_retry("redirect-all socket on lo", || {
        XdpSocket::builder()
            .interface("lo")
            .queue_id(0)
            .frame_size(2048)
            .frame_count(4096)
            .with_default_program()
            .xdp_attach_flags(XdpFlags::SKB_MODE)
            .build()
    });

    // Generate loopback ingress: UDP to 127.0.0.1 is transmitted on `lo` and
    // received back on `lo`, where generic XDP redirects it to our socket
    // *before* the kernel stack — so there's no need for a listener on the
    // destination port (the frame never reaches the UDP stack).
    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind udp tx");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut captured: u64 = 0;
    while Instant::now() < deadline && captured == 0 {
        for _ in 0..8 {
            let _ = tx.send_to(b"netring-afxdp-smoke", "127.0.0.1:65111");
        }
        captured += sock.recv().expect("AF_XDP recv").len() as u64;
        if captured == 0 {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    assert!(
        captured > 0,
        "AF_XDP socket should capture at least one redirected loopback frame \
         within 10s (XDP redirect on lo not delivering to the XSKMAP)",
    );

    // Dropping the socket detaches the XDP program from `lo`. Settle so the
    // next test in this binary finds queue 0 free.
    drop(sock);
    std::thread::sleep(Duration::from_millis(300));
}

/// Issue #4: AF_XDP **promiscuous mode**. Building with `.promiscuous(true)`
/// must install the AF_PACKET `PACKET_MR_PROMISC` guard on `lo` *and* leave
/// capture working — enabling promisc must not interfere with the redirect
/// path, and the guard must drop cleanly when the socket is dropped.
///
/// `lo` supports promiscuous mode (`ip link set lo promisc on`), so the guard's
/// setsockopt succeeds under root here. On a real NIC this is what makes AF_XDP
/// see traffic not addressed to the local MAC.
#[test]
fn afxdp_lo_promiscuous_guard_does_not_break_capture() {
    wait_lo_free();

    let mut sock = build_with_retry("promiscuous redirect-all socket on lo", || {
        XdpSocket::builder()
            .interface("lo")
            .queue_id(0)
            .frame_size(2048)
            .frame_count(4096)
            .promiscuous(true) // installs the PACKET_MR_PROMISC guard
            .with_default_program()
            .xdp_attach_flags(XdpFlags::SKB_MODE)
            .build()
    });

    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind udp tx");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut captured: u64 = 0;
    while Instant::now() < deadline && captured == 0 {
        for _ in 0..8 {
            let _ = tx.send_to(b"netring-afxdp-promisc", "127.0.0.1:65124");
        }
        captured += sock.recv().expect("AF_XDP recv").len() as u64;
        if captured == 0 {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    assert!(
        captured > 0,
        "AF_XDP socket built with promiscuous(true) should still capture \
         redirected loopback frames (promisc guard must not disturb the \
         redirect path)",
    );

    // Dropping the socket drops the promisc guard (its fd closes → kernel
    // decrements lo's promiscuity) and detaches the program. Settle for the
    // next test.
    drop(sock);
    std::thread::sleep(Duration::from_millis(300));
}

/// Issue #6: the high-level multi-queue [`XdpCapture`]. On `lo` (single queue)
/// this degenerates to one socket on queue 0, but it exercises the whole
/// `XdpCapture` path end-to-end: queue resolution, one-program-load, per-queue
/// socket open + XSKMAP register, single attach, the interface-global
/// promiscuous guard, and the unified round-robin `next_batch`. Asserts it
/// captures redirected loopback frames and reports COPY mode (SKB on lo).
#[test]
fn xdp_capture_lo_captures_via_unified_recv() {
    use netring::xdp::{Queues, XdpCapture};

    wait_lo_free();

    let mut cap = XdpCapture::builder()
        .interface("lo")
        .queues(Queues::Auto) // → [0] on lo (no ethtool channels)
        .promiscuous(true)
        .frame_size(2048)
        .frame_count(4096)
        .build()
        .expect("build XdpCapture on lo (needs root / CAP_BPF+CAP_NET_ADMIN)");

    assert_eq!(cap.socket_count(), 1, "lo has a single queue");
    assert_eq!(cap.queue_ids(), &[0]);
    assert!(
        !cap.is_zerocopy(),
        "SKB/generic XDP on lo binds in COPY mode, not zero-copy"
    );

    let tx = UdpSocket::bind("127.0.0.1:0").expect("bind udp tx");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut captured: u64 = 0;
    let mut last_qid = u32::MAX;
    while Instant::now() < deadline && captured == 0 {
        for _ in 0..8 {
            let _ = tx.send_to(b"netring-xdpcapture", "127.0.0.1:65125");
        }
        if let Some((qid, batch)) = cap.next_batch() {
            last_qid = qid;
            captured += (&batch).into_iter().count() as u64;
        }
        if captured == 0 {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    assert!(
        captured > 0,
        "XdpCapture should capture at least one redirected loopback frame via \
         the unified round-robin within 10s",
    );
    assert_eq!(last_qid, 0, "the only queue is 0");

    drop(cap);
    std::thread::sleep(Duration::from_millis(300));
}

/// 0.25 W1a: the **in-Monitor** AF_XDP loader path. `xdp_interface_loaded("lo")`
/// must make a high-level [`Monitor`] attach the redirect-all program itself,
/// register its socket on the XSKMAP, and deliver redirected loopback frames
/// through the normal flow-tracking dispatch — with **no external loader**.
///
/// Before W1a, `xdp_interface` opened a bare socket with no program attached,
/// so a Monitor-on-AF_XDP captured nothing. This is the regression guard for
/// that gap.
#[cfg(all(feature = "flow", feature = "tokio"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn monitor_xdp_interface_loaded_captures_loopback_flows() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use netring::monitor::Monitor;
    use netring::protocol::builtin::Udp;
    use netring::protocol::event_typed::FlowStarted;

    // The Monitor binds (lo, queue 0) inside `run_for`, which can't be retried —
    // make sure the previous test fully released the queue first.
    wait_lo_free();

    let seen = Arc::new(AtomicU64::new(0));
    let seen_h = Arc::clone(&seen);

    let monitor = Monitor::builder()
        .xdp_interface_loaded("lo")
        .protocol::<Udp>()
        .on::<FlowStarted<Udp>>(move |_evt: &FlowStarted<Udp>| {
            seen_h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect(
            "build Monitor with xdp_interface_loaded on lo \
             (needs root / CAP_BPF+CAP_NET_ADMIN; generic XDP on lo)",
        );

    // Generate loopback UDP ingress on a blocking thread for the run window.
    let stop = Arc::new(AtomicU64::new(0));
    let stop_h = Arc::clone(&stop);
    let generator = std::thread::spawn(move || {
        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind udp tx");
        while stop_h.load(Ordering::Relaxed) == 0 {
            for _ in 0..16 {
                let _ = tx.send_to(b"netring-monitor-xdp", "127.0.0.1:65112");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });

    // Run the Monitor for a bounded window; the redirected frames must produce
    // at least one UDP flow.
    let _ = monitor.run_for(Duration::from_secs(4)).await;
    stop.store(1, Ordering::Relaxed);
    let _ = generator.join();

    assert!(
        seen.load(Ordering::Relaxed) > 0,
        "Monitor with xdp_interface_loaded should observe >=1 UDP flow from \
         redirected loopback traffic (in-Monitor XDP loader not delivering)",
    );
}

/// Issue #6 (M4 Tier 1): the **multi-queue** Monitor path. `.xdp_queues(Auto)`
/// routes through `AnyBackend::XdpMq` (an `AsyncXdpCapture` of one socket per
/// queue, unified round-robin) instead of the single-socket arm. On `lo` (one
/// queue) this is N=1 through `XdpMq`, exercising `AsyncXdpCapture::new`,
/// `poll_read_ready` (with stale-readiness clearing), and the round-robin
/// `drain_batch` end-to-end through the real run loop. Regression guard for the
/// G2 silent-single-queue footgun fix.
#[cfg(all(feature = "flow", feature = "tokio"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn monitor_xdp_queues_auto_captures_via_xdpmq() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use netring::monitor::Monitor;
    use netring::protocol::builtin::Udp;
    use netring::protocol::event_typed::FlowStarted;
    use netring::xdp::Queues;

    wait_lo_free();

    let seen = Arc::new(AtomicU64::new(0));
    let seen_h = Arc::clone(&seen);

    let monitor = Monitor::builder()
        .xdp_interface_loaded("lo")
        .xdp_queues(Queues::Auto) // → [0] on lo, routed through AnyBackend::XdpMq
        .protocol::<Udp>()
        .on::<FlowStarted<Udp>>(move |_evt: &FlowStarted<Udp>| {
            seen_h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
        .expect("build Monitor with xdp_queues(Auto) on lo (needs root)");

    let stop = Arc::new(AtomicU64::new(0));
    let stop_h = Arc::clone(&stop);
    let generator = std::thread::spawn(move || {
        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind udp tx");
        while stop_h.load(Ordering::Relaxed) == 0 {
            for _ in 0..16 {
                let _ = tx.send_to(b"netring-monitor-xdpmq", "127.0.0.1:65126");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });

    let _ = monitor.run_for(Duration::from_secs(4)).await;
    stop.store(1, Ordering::Relaxed);
    let _ = generator.join();

    assert!(
        seen.load(Ordering::Relaxed) > 0,
        "Monitor with xdp_queues(Auto) should observe >=1 UDP flow through the \
         multi-queue AnyBackend::XdpMq round-robin",
    );
}

/// 0.25 W1a: the **table-driven** `filter_program` + `XdpProgram::set_filter`
/// end-to-end. Loads the filter program on `lo`, registers the socket, populates
/// the `{udp, PORT}` filter, and asserts that matching loopback frames are
/// redirected into the socket — validating both the BPF program's map lookup
/// and the userspace map-population path.
///
/// Root-gated (XDP load + BPF maps + XSKMAP). Same plumbing as the redirect-all
/// smoke test above.
#[test]
fn afxdp_lo_filter_program_redirects_configured_tuple() {
    use netring::xdp::{XdpFlags, filter_program};

    const PORT: u16 = 65123;

    // A bare AF_XDP socket (no auto-attached program) — we attach the
    // table-driven filter program to it manually.
    let mut sock = build_with_retry("bare AF_XDP socket on lo", || {
        XdpSocket::builder()
            .interface("lo")
            .queue_id(0)
            .frame_size(2048)
            .frame_count(4096)
            .build()
    });

    let mut prog = filter_program().expect("load filter_program");
    prog.register(0, &sock)
        .expect("register socket on the program's XSKMAP");
    let mut attach = prog
        .attach("lo", XdpFlags::SKB_MODE)
        .expect("attach filter program to lo");

    // Mark {UDP, PORT} as interesting → the program redirects those frames.
    attach
        .set_filter(17 /* IPPROTO_UDP */, PORT, true)
        .expect("set_filter udp/PORT");

    let tx = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp tx");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut captured: u64 = 0;
    while Instant::now() < deadline && captured == 0 {
        for _ in 0..8 {
            let _ = tx.send_to(b"filter-map-test", ("127.0.0.1", PORT));
        }
        captured += sock.recv().expect("AF_XDP recv").len() as u64;
        if captured == 0 {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    assert!(
        captured > 0,
        "filter_program with a {{udp,{PORT}}} entry should redirect matching \
         loopback frames into the AF_XDP socket",
    );

    drop(attach);
    drop(sock);
    // Settle so the next test in this binary finds queue 0 free.
    std::thread::sleep(Duration::from_millis(300));
}
