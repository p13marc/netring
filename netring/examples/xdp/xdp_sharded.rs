//! **Tier 2 AF_XDP capture: one Monitor per RX queue** via
//! [`XdpShardedRunner`](netring::monitor::XdpShardedRunner) (issue #6 M5).
//!
//! The line-rate multi-queue model: one socket per RX queue, each drained by an
//! independent single-shard `Monitor` on its own core, busy-polled. The runner
//! attaches one shared XDP program, opens one socket per queue, and hands each
//! shard its socket — so every queue gets full flow tracking in parallel
//! (Suricata's `threads: auto`).
//!
//! Contrast with `MonitorBuilder::xdp_queues(Auto)` (the single-reactor tier,
//! one core for all queues): use this when one core can't keep up.
//!
//! On `lo` (one queue) this runs a single shard. Find a real NIC's queue count
//! with `ethtool -l <iface>`; pair `--pin-cpus` with NIC IRQ affinity.
//!
//! Requires CAP_NET_RAW + CAP_BPF + CAP_NET_ADMIN. Use `just setcap`.
//!
//! Usage:
//!     cargo run --example xdp_sharded \
//!         --features "monitor,af-xdp,xdp-loader" -- [iface] [seconds]

#[cfg(all(feature = "monitor", feature = "af-xdp", feature = "xdp-loader"))]
fn main() -> Result<(), netring::Error> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use netring::monitor::XdpShardedRunner;
    use netring::prelude::*;
    use netring::xdp::Queues;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    // One global counter, shared across shards (each shard clones the Arc).
    let flows = Arc::new(AtomicU64::new(0));

    eprintln!("AF_XDP sharded capture on {iface}: one Monitor per RX queue for {seconds}s");

    let flows_for_shards = Arc::clone(&flows);
    XdpShardedRunner::new(&iface, Queues::Auto, move |queue, builder| {
        let flows = Arc::clone(&flows_for_shards);
        builder
            .name(format!("xdp-shard-q{queue}"))
            .protocol::<Tcp>()
            .protocol::<Udp>()
            .on::<FlowStarted<Tcp>>(move |_e: &FlowStarted<Tcp>| {
                flows.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .sink(StdoutJsonSink::default())
    })
    .promiscuous(true)
    .busy_poll(50) // µs — one busy-polled socket per core
    .pin_cpus(true)
    .run_for(Duration::from_secs(seconds))?;

    eprintln!(
        "captured {} TCP flows across all queues",
        flows.load(Ordering::Relaxed)
    );
    Ok(())
}

#[cfg(not(all(feature = "monitor", feature = "af-xdp", feature = "xdp-loader")))]
fn main() {
    eprintln!("Build with --features monitor,af-xdp,xdp-loader");
}
