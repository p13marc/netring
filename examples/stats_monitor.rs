//! Real-time capture statistics monitoring.
//!
//! Usage: cargo run --example stats_monitor -- [interface]
//! Shows packets/sec, drops, and freeze count every second.

use netring::Capture;
use std::time::{Duration, Instant};

fn main() -> Result<(), netring::Error> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("Monitoring {iface}... (Ctrl-C to stop)");

    let mut rx = Capture::builder()
        .interface(&iface)
        .ignore_outgoing(true)
        .block_timeout_ms(100)
        .build()?;

    // Reset counters
    let _ = rx.stats();

    let mut last_report = Instant::now();
    let mut pkt_count = 0u64;

    loop {
        if let Some(batch) = rx.next_batch_blocking(Duration::from_millis(200))? {
            pkt_count += batch.len() as u64;
            for pkt in &batch {
                let _ = pkt.data();
            }
        }

        if last_report.elapsed() >= Duration::from_secs(1) {
            let stats = rx.stats().unwrap_or_default();
            let elapsed = last_report.elapsed().as_secs_f64();
            let pps = pkt_count as f64 / elapsed;

            println!(
                "{pps:.0} pkt/s | kernel: {} received, {} dropped, {} frozen",
                stats.packets, stats.drops, stats.freeze_count,
            );

            pkt_count = 0;
            last_report = Instant::now();
        }
    }
}
