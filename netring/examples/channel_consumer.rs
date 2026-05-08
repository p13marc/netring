//! Channel adapter example — runtime-agnostic packet consumption.
//!
//! Usage: cargo run --example channel_consumer --features channel -- [interface]
//! Spawns a capture thread and consumes packets via a bounded channel.

#[cfg(feature = "channel")]
fn main() -> Result<(), netring::Error> {
    use netring::async_adapters::channel::ChannelCapture;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("Channel capture on {iface} (capacity=4096)...");

    let rx = ChannelCapture::spawn(&iface, 4096)?;

    // Iterate via the channel — each packet is an OwnedPacket (copied from ring)
    let mut count = 0u64;
    for pkt in &rx {
        println!(
            "[{}.{:09}] {} bytes (wire: {})",
            pkt.timestamp.sec,
            pkt.timestamp.nsec,
            pkt.data.len(),
            pkt.original_len,
        );
        count += 1;
        if count >= 50 {
            break;
        }
    }

    // rx dropped here → background thread stops, joins
    eprintln!("{count} packets received via channel");
    Ok(())
}

#[cfg(not(feature = "channel"))]
fn main() {
    eprintln!(
        "This example requires the 'channel' feature: cargo run --example channel_consumer --features channel"
    );
}
