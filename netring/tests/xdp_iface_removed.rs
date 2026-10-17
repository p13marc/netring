//! #212: an AF_XDP socket whose interface is removed reports an error.
//!
//! On NETDEV_UNREGISTER the kernel sets `sk_err = ENETDOWN` on the socket
//! and unbinds it (xsk_notifier()), after which `xsk_poll()` reports no
//! event at all — so an epoll-driven wait never wakes on its own. The
//! async adapter's idle liveness probe has to notice.
//!
//! Needs root (CAP_BPF + CAP_NET_ADMIN + CAP_NET_RAW) and the `veth`
//! module. Run with:
//! cargo test --features integration-tests,tokio,af-xdp,xdp-loader --test xdp_iface_removed

#![cfg(all(
    feature = "integration-tests",
    feature = "tokio",
    feature = "af-xdp",
    feature = "xdp-loader"
))]

mod helpers;

use std::time::{Duration, Instant};

use helpers::VethPair;
use netring::{AsyncXdpSocket, XdpMode, XdpSocket};

#[tokio::test(flavor = "current_thread")]
async fn async_xdp_socket_reports_a_removed_interface() {
    let pid = std::process::id() % 10_000;
    let Some(veth) = VethPair::create(&format!("nrxr{pid}a"), &format!("nrxr{pid}b")) else {
        eprintln!("skip: needs CAP_NET_ADMIN to create veth");
        return;
    };
    // The built-in redirect-all program, attached in SKB (generic) mode.
    let socket = match XdpSocket::builder()
        .interface(&veth.b)
        .queue_id(0)
        .mode(XdpMode::Rx)
        .frame_size(2048)
        .frame_count(64)
        .with_default_program()
        .build()
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skip: cannot open an AF_XDP socket on {}: {e}", veth.b);
            return;
        }
    };
    let mut xdp = AsyncXdpSocket::new(socket).expect("register with tokio");

    let start = Instant::now();
    // Deleting either end of the pair removes both.
    drop(veth);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let err = loop {
        match tokio::time::timeout_at(deadline, xdp.readable()).await {
            Err(_) => panic!("readable() still waiting 3 s after the interface was removed"),
            Ok(Err(e)) => break e,
            Ok(Ok(mut guard)) => {
                let _ = guard.next_batch();
            }
        }
    };
    eprintln!("removal reported after {:?}: {err}", start.elapsed());
    assert!(
        matches!(&err, netring::Error::Io(io) if io.raw_os_error() == Some(libc::ENETDOWN)),
        "{err:?}"
    );
}
