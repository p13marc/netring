//! Root-gated AF_XDP-on-`lo` smoke test (0.25 A3c spike).
//!
//! De-risks the AF_XDP STAGE-0 pushdown (A3c) by answering the one real
//! unknown before investing in a map-driven filter program: **does AF_XDP plus
//! an attached XDP redirect program work on a GitHub Actions runner at all?**
//!
//! It uses the *existing* built-in redirect-all program (plan 12) in
//! **SKB / generic mode** on `lo` — the only realistic CI configuration (no
//! NIC, no native driver). Loopback ingress traverses `lo`'s rx path, where
//! generic XDP redirects each frame into the AF_XDP socket's `XSKMAP`. If this
//! is green on the runner, A3c's `{proto,port}`-map filter program builds on
//! exactly this plumbing; if it flakes, the project goes the qemu/`vmtest`
//! route instead.
//!
//! Gated behind `integration-tests` + `af-xdp` + `xdp-loader` so it only
//! compiles in the privileged CI job (never in a normal/sandbox build). Needs
//! **root** (or `CAP_BPF`+`CAP_NET_ADMIN`+`CAP_NET_RAW`) — the CI `xdp-smoke`
//! job runs the test binary under `sudo`.

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
         in 10s — if 0, AF_XDP/XDP-redirect on lo is unsupported on this \
         kernel/runner and A3c CI needs a qemu/vmtest VM instead",
    );

    // Dropping the socket detaches the XDP program from `lo`.
    drop(sock);
}
