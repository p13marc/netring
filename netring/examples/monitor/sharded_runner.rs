//! 0.21 Phase C — per-CPU sharded monitor execution.
//!
//! Fans one capture across N AF_PACKET sockets via
//! `PACKET_FANOUT_CPU`. Each shard owns its own dispatcher,
//! state, and sink — no cross-shard locking on the hot path. The
//! kernel hashes inbound packets across shards per `FanoutMode`.
//!
//! Each shard increments a shared atomic counter on `FlowStarted<Tcp>`
//! so you can see all shards contributing. For production you would
//! shard a real metrics counter / sink per shard and aggregate via
//! the metrics backend (the 0.22 roadmap's `merge_state::<T>` lifts
//! aggregation back into `ShardedRunner` directly).
//!
//! ```sh
//! cargo run --example monitor_sharded_runner \
//!     --features "monitor-quickstart" -- eth0 4 30
//! ```
//!
//! Arguments: `<iface>` (default `lo`) `<n_shards>` (default 2)
//! `<seconds>` (default 30).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use netring::config::FanoutMode;
use netring::monitor::shard::ShardedRunner;
use netring::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let num_shards: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let dur_secs: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    eprintln!(
        "monitor_sharded_runner: capturing on {iface} across {num_shards} shards for {dur_secs}s"
    );

    let started = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&started);

    // The build closure runs once per shard on the spawned shard
    // thread. Each shard binds to the same fanout group; the
    // kernel does the work-stealing.
    let iface_owned = iface.clone();
    let runner = ShardedRunner::new(
        iface,
        FanoutMode::Cpu,
        0xC0DE,
        num_shards,
        move |cpu_idx: usize| -> netring::error::Result<Monitor> {
            let c = Arc::clone(&counter);
            Monitor::builder()
                .interface(iface_owned.clone())
                .fanout(FanoutMode::Cpu, 0xC0DE)
                .name(format!("shard-{cpu_idx}"))
                .protocol::<Tcp>()
                .on::<FlowStarted<Tcp>>(move |_e: &FlowStarted<Tcp>| {
                    c.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })
                .sink(StdoutSink::default())
                .build()
        },
    );

    // `run_for` is sync — it spawns OS threads + joins them.
    runner.run_for(Duration::from_secs(dur_secs))?;

    eprintln!(
        "monitor_sharded_runner: done; total FlowStarted<Tcp> across shards: {}",
        started.load(Ordering::Relaxed)
    );
    Ok(())
}
