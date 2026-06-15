//! Per-CPU sharded monitor execution + cross-shard state merging.
//!
//! Fans one capture across N AF_PACKET sockets via `PACKET_FANOUT_CPU`.
//! Each shard owns its own dispatcher, state, and sink — **no
//! cross-shard locking on the hot path**. The kernel hashes inbound
//! packets across shards per `FanoutMode`.
//!
//! 0.22 §5.1: instead of a shared atomic (the old workaround), each
//! shard keeps a **local** `ConnCount` in its own state slot. The
//! `ShardedRunner::state_auto_merge` worker folds the per-shard counts
//! into a global total once a second (take-and-reset on each shard, so
//! the primary is the running grand total), printed via `on_merge`.
//!
//! ```sh
//! cargo run --example monitor_sharded_runner \
//!     --features "monitor-quickstart" -- eth0 4 30
//! ```
//!
//! Arguments: `<iface>` (default `lo`) `<n_shards>` (default 2)
//! `<seconds>` (default 30).

use std::ops::AddAssign;
use std::time::Duration;

use netring::config::FanoutMode;
use netring::monitor::shard::ShardedRunner;
use netring::prelude::*;

/// Per-shard TCP-connection counter. `AddAssign` lets the runner fold
/// shards together with `state_auto_merge` (no explicit merge closure).
#[derive(Default)]
struct ConnCount(u64);

impl AddAssign for ConnCount {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

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

    // The build closure runs once per shard on the spawned shard thread.
    // Each shard binds the same fanout group; the kernel work-steals.
    let iface_owned = iface.clone();
    let runner = ShardedRunner::new(
        iface,
        FanoutMode::Cpu,
        0xC0DE,
        num_shards,
        move |cpu_idx: usize| -> netring::error::Result<Monitor> {
            Monitor::builder()
                .interface(iface_owned.clone())
                .fanout(FanoutMode::Cpu, 0xC0DE)
                .name(format!("shard-{cpu_idx}"))
                .protocol::<Tcp>()
                .state::<ConnCount>()
                .on_ctx::<FlowStarted<Tcp>>(|_e: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
                    // Per-shard LOCAL increment — no shared atomic, no lock.
                    ctx.state_mut::<ConnCount>().0 += 1;
                    Ok(())
                })
                .sink(StdoutSink::default())
                .build()
        },
    )
    // 0.25 C1: pin each shard's OS thread to its core (shard i → core i) so
    // flow state + RX ring + worker stay core-local. Pairs with FanoutMode::Cpu
    // + matching NIC IRQ affinity. See docs/PERFORMANCE.md.
    .pin_cpus(true)
    // 0.22 §5.1: fold every shard's ConnCount into a global running total
    // each second, and print it.
    .state_auto_merge::<ConnCount>(Duration::from_secs(1))
    .on_merge::<ConnCount, _>(|total: &ConnCount| {
        println!("── global TCP connections so far: {}", total.0);
    });

    // `run_for` is sync — it spawns the shard + merge-worker OS threads
    // and joins them.
    runner.run_for(Duration::from_secs(dur_secs))?;

    eprintln!("monitor_sharded_runner: done");
    Ok(())
}
