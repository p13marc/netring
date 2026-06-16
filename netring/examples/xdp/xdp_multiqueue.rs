//! **Full-NIC AF_XDP capture: one socket per queue**, via the high-level
//! [`XdpCapture`](netring::xdp::XdpCapture) (issue #6).
//!
//! An AF_XDP socket binds to a single RX queue, and RSS spreads traffic across
//! queues — so one socket under-captures even in promiscuous mode. `XdpCapture`
//! opens one socket per queue, loads + attaches a single redirect program,
//! registers each socket in its XSKMAP, and drains them through a unified
//! round-robin. What used to be ~60 lines of manual orchestration is now a
//! builder call.
//!
//! Queue selection:
//! - `Queues::Auto` — every RSS queue, auto-detected via `ethtool` (default here).
//! - `Queues::range(0..N)` — an explicit span (pass a count as the 2nd arg).
//! - `Queues::single(q)` — one queue.
//!
//! `lo` has a single queue, so there N collapses to 1 (`Auto` falls back to 0).
//! Find a real NIC's queue count with `ethtool -l <iface>`.
//!
//! Requires CAP_NET_RAW + CAP_BPF + CAP_NET_ADMIN. Use `just setcap`.
//!
//! Usage:
//!     cargo run --example xdp_multiqueue \
//!         --features af-xdp,xdp-loader -- [iface] [queues] [seconds]

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
fn main() -> Result<(), netring::Error> {
    use netring::xdp::{Queues, XdpCapture};
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let queues = match std::env::args().nth(2).and_then(|s| s.parse::<u32>().ok()) {
        Some(n) if n > 0 => Queues::range(0..n),
        _ => Queues::Auto,
    };
    let seconds: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    // One call: resolve queues → load program → open one socket per queue
    // (own UMEM each) → register → attach → raise promiscuous mode once.
    let mut cap = XdpCapture::builder()
        .interface(&iface)
        .queues(queues)
        .promiscuous(true)
        .build()?;

    eprintln!(
        "AF_XDP capture on {iface}: {} queue(s) {:?}, zero-copy={}, for {seconds}s",
        cap.socket_count(),
        cap.queue_ids(),
        cap.is_zerocopy(),
    );

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut per_queue: BTreeMap<u32, u64> = BTreeMap::new();
    let mut total: u64 = 0;
    while Instant::now() < deadline {
        // `None` = timed out with no traffic; loop and re-check the deadline.
        if let Some((qid, batch)) = cap.next_batch_blocking(Duration::from_millis(200))? {
            let n = (&batch).into_iter().count() as u64;
            *per_queue.entry(qid).or_default() += n;
            total += n;
        }
    }

    eprintln!("captured {total} frames total");
    for (qid, n) in &per_queue {
        eprintln!("  queue {qid}: {n} frames");
    }
    // Dropping `cap` detaches the program and releases promiscuous mode.
    Ok(())
}

#[cfg(not(all(feature = "af-xdp", feature = "xdp-loader")))]
fn main() {
    eprintln!("Build with --features af-xdp,xdp-loader");
}
