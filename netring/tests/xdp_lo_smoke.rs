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

#[test]
fn afxdp_lo_redirect_all_captures_loopback_traffic() {
    // Attach the built-in redirect-all XDP program to `lo` in SKB/generic mode
    // and open an AF_XDP socket registered in its XSKMAP.
    //
    // NOTE: no `force_replace` — `XDP_FLAGS_REPLACE` is a netlink-only flag and
    // is rejected by the link API (`bpf_link_create`) the loader uses. A fresh
    // CI runner has a clean `lo`, so REPLACE isn't needed.
    let mut sock = XdpSocket::builder()
        .interface("lo")
        .queue_id(0)
        .frame_size(2048)
        .frame_count(4096)
        .with_default_program()
        .xdp_attach_flags(XdpFlags::SKB_MODE)
        .build()
        .expect(
            "build AF_XDP socket on lo with the redirect-all program \
             (needs root / CAP_BPF+CAP_NET_ADMIN; generic XDP on lo)",
        );

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

    // Dropping the socket detaches the XDP program from `lo`.
    drop(sock);
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
