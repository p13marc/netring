//! Async capture with Ctrl-C graceful shutdown.
//!
//! Combines an [`AsyncCapture`] with [`tokio::signal::ctrl_c`] via
//! `tokio::select!` — capture runs forever until SIGINT, at which point
//! we print final stats and exit cleanly.
//!
//! This is the canonical "how do I run a tokio capture process" pattern.
//!
//! Usage: cargo run --example async_signal --features tokio -- [interface]

#[cfg(feature = "tokio")]
#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    use netring::AfPacketRxBuilder;
    use netring::async_adapters::tokio_adapter::AsyncCapture;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("Capturing on {iface} (Ctrl-C to stop)...");

    let rx = AfPacketRxBuilder::default()
        .interface(&iface)
        .block_timeout_ms(50)
        .build()?;
    let mut cap = AsyncCapture::new(rx)?;

    let mut packets = 0u64;
    let mut bytes = 0u64;

    loop {
        // tokio::select! polls both arms. ctrl_c is cancel-safe (drops
        // cleanly), and our readable()/next_batch path is cancel-safe
        // too — so whichever arm wins, the other is dropped without
        // losing data.
        tokio::select! {
            res = cap.readable() => {
                let mut guard = res?;
                if let Some(batch) = guard.next_batch() {
                    for pkt in &batch {
                        packets += 1;
                        bytes += pkt.len() as u64;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nSIGINT received, shutting down");
                break;
            }
        }
    }

    // Final stats — read after we've stopped capturing so the totals
    // include everything we observed. AsyncCapture exposes a direct
    // passthrough so we don't need `use netring::PacketSource;`.
    let stats = cap.cumulative_stats()?;
    eprintln!("packets seen: {packets}, bytes: {bytes}");
    eprintln!(
        "kernel stats:  packets: {}, drops: {}, freezes: {}",
        stats.packets, stats.drops, stats.freeze_count
    );
    Ok(())
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!(
        "This example requires the 'tokio' feature: cargo run --example async_signal --features tokio"
    );
}
