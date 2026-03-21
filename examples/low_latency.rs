//! Low-latency capture tuning example.
//!
//! Usage: cargo run --example low_latency -- [interface]
//! Demonstrates configuration for minimal capture latency.

use netring::Capture;

fn main() -> Result<(), netring::Error> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("Low-latency capture on {iface}...");

    let mut cap = Capture::builder()
        .interface(&iface)
        // Small blocks retire faster → lower latency
        .block_size(256 * 1024) // 256 KiB (vs default 4 MiB)
        .block_count(64)
        // Very short block timeout — retire partial blocks quickly
        .block_timeout_ms(1) // 1 ms (vs default 60 ms)
        // Kernel-side NIC polling — avoids interrupt latency
        .busy_poll_us(50)
        .ignore_outgoing(true)
        .build()?;

    // Measure inter-packet latency via timestamps
    let mut prev_nsec: Option<u64> = None;
    for pkt in cap.packets().take(100) {
        let ts = pkt.timestamp();
        let now_nsec = ts.sec as u64 * 1_000_000_000 + ts.nsec as u64;

        if let Some(prev) = prev_nsec {
            let delta_us = (now_nsec.saturating_sub(prev)) as f64 / 1000.0;
            println!(
                "[{}.{:09}] {} bytes  Δ={:.1}µs",
                ts.sec, ts.nsec, pkt.len(), delta_us,
            );
        } else {
            println!("[{}.{:09}] {} bytes  (first)", ts.sec, ts.nsec, pkt.len());
        }
        prev_nsec = Some(now_nsec);
    }

    Ok(())
}
