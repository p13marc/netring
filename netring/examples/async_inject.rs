//! Async packet injection with backpressure.
//!
//! Demonstrates [`AsyncInjector`]: `send` awaits `POLLOUT` when the TX
//! ring is full, instead of forcing the caller to poll/retry. After all
//! frames are queued, `wait_drained` blocks until the kernel has
//! actually transmitted them.
//!
//! Usage: cargo run --example async_inject --features tokio -- [interface] [count]

#[cfg(feature = "tokio")]
#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    use netring::Injector;
    use netring::async_adapters::tokio_injector::AsyncInjector;
    use std::time::Duration;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let count: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    eprintln!("Injecting {count} broadcast frames on {iface} via AsyncInjector...");

    // Build a small TX ring on purpose to exercise the backpressure path.
    // With 64 frames, sending 1000 will cycle the ring ~16 times — every
    // few hundred sends will await POLLOUT.
    let tx = Injector::builder()
        .interface(&iface)
        .frame_size(2048)
        .frame_count(64)
        .qdisc_bypass(true)
        .build()?;

    let mut atx = AsyncInjector::new(tx)?;
    let mut sent = 0u64;
    let started = std::time::Instant::now();

    for i in 0..count {
        // 64-byte broadcast Ethernet frame with the index in the payload.
        let mut frame = [0u8; 64];
        frame[0..6].copy_from_slice(&[0xff; 6]); // dst broadcast
        frame[6..12].copy_from_slice(&[0; 6]); // src
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // EtherType IPv4
        frame[14..22].copy_from_slice(&(i as u64).to_be_bytes());

        // send() awaits POLLOUT internally if the ring is saturated.
        atx.send(&frame).await?;
        sent += 1;

        // Flush every 32 frames so the kernel actually drains the ring;
        // otherwise it would fill up and stall on backpressure.
        if i % 32 == 0 {
            atx.flush().await?;
        }
    }
    atx.flush().await?;
    atx.wait_drained(Duration::from_secs(1)).await?;

    let elapsed = started.elapsed();
    eprintln!(
        "Sent {sent} frames in {elapsed:?} ({:.0} pkt/s)",
        sent as f64 / elapsed.as_secs_f64()
    );
    Ok(())
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!(
        "This example requires the 'tokio' feature: cargo run --example async_inject --features tokio"
    );
}
