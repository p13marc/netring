//! Low-level batch processing with sequence gap detection.
//!
//! Usage: cargo run --example batch_processing -- [interface]

use netring::Capture;
use std::time::Duration;

fn main() -> Result<(), netring::Error> {
    env_logger::init();

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("Batch capture on {iface}...");

    let mut rx = Capture::builder()
        .interface(&iface)
        .block_size(1 << 20) // 1 MiB
        .block_count(16)
        .block_timeout_ms(100)
        .build()?;

    let mut last_seq = 0u64;
    let mut total_packets = 0u64;
    let mut total_batches = 0u64;

    for _ in 0..100 {
        let Some(batch) = rx.next_batch_blocking(Duration::from_millis(500))? else {
            continue;
        };

        if batch.seq_num() != last_seq + 1 && last_seq != 0 {
            eprintln!(
                "! sequence gap: expected {}, got {} (dropped {} blocks)",
                last_seq + 1,
                batch.seq_num(),
                batch.seq_num() - last_seq - 1
            );
        }
        last_seq = batch.seq_num();

        let pkt_count = batch.len();
        total_packets += pkt_count as u64;
        total_batches += 1;

        println!(
            "batch seq={} pkts={} timed_out={} ts=[{} → {}]",
            batch.seq_num(),
            pkt_count,
            batch.timed_out(),
            batch.ts_first(),
            batch.ts_last(),
        );

        for pkt in &batch {
            // Process packet...
            let _ = pkt.data();
        }
    }

    eprintln!("{total_batches} batches, {total_packets} packets");
    eprintln!("{}", rx.stats()?);
    Ok(())
}
