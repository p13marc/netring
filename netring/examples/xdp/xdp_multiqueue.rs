//! **Full-NIC AF_XDP capture: one socket per queue** (the answer to "is it
//! expected to have N XdpSocket?" — yes).
//!
//! An AF_XDP socket binds to a **single** RX queue. A modern NIC spreads
//! inbound traffic across many queues via RSS, so one socket only ever sees the
//! share of traffic hashed to its queue — even in promiscuous mode. To capture
//! *everything*, you open **one `XdpSocket` per queue** and poll them together.
//!
//! The shape:
//! 1. Load the redirect program **once** (`default_program`), sized for the
//!    queue count. Its XSKMAP maps `rx_queue_index → socket`.
//! 2. Open one socket per queue (`queue_id(q)`), registering each at its queue
//!    index in the program's map.
//! 3. Attach the program **once** and poll all sockets round-robin.
//!
//! Promiscuity is an interface-global, reference-counted property, so a single
//! guard on the first socket holds the whole NIC promiscuous for the lifetime of
//! the capture — no need to enable it on every socket.
//!
//! To find your queue count: `ethtool -l <iface>` (the "Combined" row). To force
//! a single queue instead (simpler, lower throughput): `ethtool -L <iface>
//! combined 1` and use a single socket (see `async_xdp_self_loaded`).
//!
//! Memory note: each socket here owns its own UMEM (simplest + correct). For
//! large rings, `XdpSocketBuilder::shared_umem` lets the per-queue sockets share
//! one UMEM region — at the cost of partitioning the frame space by hand.
//!
//! Requires CAP_NET_RAW + CAP_BPF + CAP_NET_ADMIN. Use `just setcap`.
//!
//! Usage (defaults to `lo`, which has a single queue, so N=1 there):
//!     cargo run --example xdp_multiqueue \
//!         --features af-xdp,xdp-loader -- [iface] [queues] [seconds]

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
fn main() -> Result<(), netring::Error> {
    use netring::xdp::{XdpFlags, default_program};
    use netring::{XdpMode, XdpSocket};
    use std::time::{Duration, Instant};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let queues: u32 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .filter(|&q| q > 0)
        .unwrap_or(1);
    let seconds: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!("AF_XDP multi-queue capture on {iface}: {queues} queue(s) for {seconds}s");

    // 1. Load the redirect-all program once; its XSKMAP holds one slot per queue.
    let mut prog = default_program(queues)?;

    // 2. One socket per queue, each registered at its queue index in the map.
    //    Promiscuous mode is enabled on the first socket only — it's an
    //    interface-global refcounted property, so one guard covers every queue.
    let mut sockets: Vec<XdpSocket> = Vec::with_capacity(queues as usize);
    for q in 0..queues {
        let sock = XdpSocket::builder()
            .interface(&iface)
            .queue_id(q)
            .mode(XdpMode::Rx)
            .frame_size(2048)
            .frame_count(4096)
            .promiscuous(q == 0)
            .build()?;
        prog.register(q, &sock)?;
        sockets.push(sock);
    }

    // 3. Attach the program once (keep the guard alive for the capture window).
    let _attachment = prog.attach(&iface, XdpFlags::SKB_MODE)?;

    // 4. Round-robin poll every queue's socket.
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut per_queue = vec![0u64; sockets.len()];
    let mut total: u64 = 0;
    while Instant::now() < deadline {
        let mut idle = true;
        for (q, sock) in sockets.iter_mut().enumerate() {
            let batch = sock.recv()?;
            let n = batch.len() as u64;
            if n > 0 {
                idle = false;
                per_queue[q] += n;
                total += n;
            }
        }
        if idle {
            std::thread::sleep(Duration::from_micros(200));
        }
    }

    eprintln!("captured {total} frames total");
    for (q, n) in per_queue.iter().enumerate() {
        eprintln!("  queue {q}: {n} frames");
    }
    // Dropping the sockets releases the promisc guard and the program detaches.
    Ok(())
}

#[cfg(not(all(feature = "af-xdp", feature = "xdp-loader")))]
fn main() {
    eprintln!("Build with --features af-xdp,xdp-loader");
}
