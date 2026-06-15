//! TX symmetry (0.25 Phase D): stream-inject frames with **rate pacing** and
//! read back **egress timestamps**.
//!
//! Feeds a `Stream` of frames to [`AsyncInjector::send_stream`], paced by a
//! [`TxPacer`] token bucket, then reads a few hardware/software egress
//! timestamps off the socket error queue (`tx_timestamps(true)`).
//!
//! ```sh
//! # send 10k 64-byte frames at 1000 pps on lo (needs CAP_NET_RAW):
//! cargo run --example tx_replay --features tokio -- lo 1000
//! ```

use std::time::Duration;

use netring::{AsyncInjector, Injector, TxPacer};

#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".to_string());
    let pps: f64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000.0);

    // Request egress timestamps on the TX socket.
    let injector = Injector::builder()
        .interface(&iface)
        .tx_timestamps(true)
        .build()?;
    let mut tx = AsyncInjector::new(injector)?;

    // Any `Stream<Item = impl AsRef<[u8]>>` works — an mpsc of frames, a
    // replayed pcap, or (here) a synthetic generator of 64-byte frames.
    let frames = futures::stream::iter((0..10_000u32).map(|_| vec![0u8; 64]));

    // Send, paced to `pps` packets/sec.
    let sent = tx
        .send_stream(frames, Some(TxPacer::packets_per_second(pps)))
        .await?;
    let _ = tx.wait_drained(Duration::from_secs(2)).await;

    // Pull a handful of egress timestamps from the error queue.
    let mut stamped = 0;
    for _ in 0..sent.min(5) {
        if let Some(ts) = tx.read_tx_timestamp() {
            println!("egress timestamp: {ts:?}");
            stamped += 1;
        }
    }

    println!("sent {sent} frames at ~{pps} pps on {iface}; read {stamped} egress timestamps");
    Ok(())
}
