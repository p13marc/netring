//! Async AF_XDP — TX with backpressure via [`AsyncXdpSocket`].
//!
//! AF_XDP is the high-perf path (10M+ pps). The async wrapper makes it
//! ergonomic to use from tokio: `send().await` waits on `POLLOUT` when
//! the ring or UMEM is exhausted instead of returning `Ok(false)`.
//!
//! This example sends N broadcast frames; pair with the BPF program of
//! your choice (via aya, libbpf-rs, ...) for the RX side.
//!
//! Usage: cargo run --example async_xdp --features tokio,af-xdp -- [interface] [count]

#[cfg(all(feature = "tokio", feature = "af-xdp"))]
#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    use netring::{AsyncXdpSocket, XdpMode, XdpSocket};
    use std::time::Duration;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let count: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    eprintln!("Async AF_XDP TX on {iface}: sending {count} frames");

    // Build a small UMEM on purpose to exercise the backpressure path.
    // 64 frames means we'll cycle through ~16 times for 1000 sends.
    let socket = XdpSocket::builder()
        .interface(&iface)
        .queue_id(0)
        .frame_size(2048)
        .frame_count(64)
        .mode(XdpMode::Tx)
        .build()?;
    let mut xdp = AsyncXdpSocket::new(socket)?;

    let started = std::time::Instant::now();
    for i in 0u32..(count as u32) {
        let mut frame = [0u8; 64];
        // Broadcast destination MAC.
        frame[0..6].copy_from_slice(&[0xff; 6]);
        // Index in the payload so we can verify on RX.
        frame[14..18].copy_from_slice(&i.to_be_bytes());

        // send() awaits POLLOUT internally if UMEM/ring is exhausted.
        xdp.send(&frame).await?;

        if i.is_multiple_of(32) {
            xdp.flush().await?;
        }
    }
    xdp.flush().await?;
    let _ = xdp.wait_drained(Duration::from_secs(1)).await;

    let elapsed = started.elapsed();
    let stats = xdp.statistics()?;
    eprintln!(
        "sent {count} frames in {elapsed:?} ({:.0} pkt/s) · stats: {stats}",
        count as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "af-xdp")))]
fn main() {
    eprintln!(
        "This example requires both 'tokio' and 'af-xdp' features: \
         cargo run --example async_xdp --features tokio,af-xdp"
    );
}
