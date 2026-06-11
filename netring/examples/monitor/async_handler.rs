//! Demonstrates `on_async` — async-handler I/O escape hatch.
//!
//! Two handlers cooperate via a shared `Arc<AtomicU64>`:
//!
//! - **sync `on::<FlowStarted<Tcp>>`** — bumps an in-memory
//!   counter. Cost: zero allocations per dispatch.
//! - **async `on_async::<FlowStarted<Tcp>>`** — captures an
//!   `Arc<SimulatedPool>` and pretends to do remote I/O. Each
//!   event yields once and then increments the pool's counter.
//!   Cost: one boxed future allocation per dispatch.
//!
//! Both handlers fire on every flow start. The sync one finishes
//! first; the async one's future is then awaited to completion
//! before the next event is processed.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_async_handler \
//!     --features "tokio,flow" -- eth0
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use netring::prelude::*;

/// Stand-in for a real I/O resource (Redis pool, HTTP client, …).
/// In a real monitor you'd hold an `Arc<bb8::Pool<…>>` or similar.
struct SimulatedPool {
    publishes: AtomicU64,
}

impl SimulatedPool {
    async fn publish(&self) -> Result<(), netring::Error> {
        tokio::task::yield_now().await;
        self.publishes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let dur_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!("monitor_async_handler: capturing on {iface} for {dur_secs}s");

    let sync_count = Arc::new(AtomicU64::new(0));
    let pool = Arc::new(SimulatedPool {
        publishes: AtomicU64::new(0),
    });

    let sync_count_h = Arc::clone(&sync_count);
    let pool_h = Arc::clone(&pool);

    let monitor = Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        .on::<FlowStarted<Tcp>>(move |_evt: &FlowStarted<Tcp>| {
            sync_count_h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .on_async::<FlowStarted<Tcp>, _>(move |_evt: &FlowStarted<Tcp>| {
            let pool = Arc::clone(&pool_h);
            async move { pool.publish().await }
        })
        .build()?;

    monitor.run_for(Duration::from_secs(dur_secs)).await?;

    eprintln!(
        "sync handler fires:  {}",
        sync_count.load(Ordering::Relaxed)
    );
    eprintln!(
        "async pool publishes: {}",
        pool.publishes.load(Ordering::Relaxed)
    );
    Ok(())
}
