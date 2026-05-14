//! Scale flow capture across N CPUs using `FanoutMode::Cpu`.
//!
//! See `docs/scaling.md` for the full recipe, anti-patterns, and
//! troubleshooting.
//!
//! Usage:
//!     cargo run -p netring --example async_fanout_workers \
//!         --features tokio,flow,parse -- eth0 4

use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::StreamExt;
use netring::AsyncMultiCapture;
use netring::flow::extract::FiveTuple;

const GROUP_ID: u16 = 0xDE57;

#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let iface = args.next().unwrap_or_else(|| "lo".to_string());
    let n: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(4);

    println!("scaling {iface} across {n} workers (group_id 0x{GROUP_ID:04x})");

    let multi = AsyncMultiCapture::open_workers(&iface, n, GROUP_ID)?;
    let stream = multi.flow_stream(FiveTuple::bidirectional());

    let total = Arc::new(AtomicU64::new(0));

    // Periodic operator dashboard.
    let total_tick = total.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let t = total_tick.load(Ordering::Relaxed);
            eprintln!("[total events = {t}]");
        }
    });

    // Drain the merged stream. Each event already carries the
    // originating worker index.
    let mut stream = stream;
    while let Some(evt) = stream.next().await {
        match evt {
            Ok(tagged) => {
                total.fetch_add(1, Ordering::Relaxed);
                let _ = tagged; // demo: nothing else to do
            }
            Err(e) => {
                eprintln!("stream error: {e}");
                break;
            }
        }
    }

    // Final stats dump (per-source breakdown).
    eprintln!("\n[per-source capture stats]");
    for (label, stats) in stream.per_source_capture_stats() {
        match stats {
            Some(Ok(s)) => eprintln!("  [{label}] packets={} drops={}", s.packets, s.drops),
            Some(Err(e)) => eprintln!("  [{label}] error: {e}"),
            None => eprintln!("  [{label}] exhausted"),
        }
    }
    eprintln!("[aggregate] {:?}", stream.capture_stats());

    Ok(())
}
