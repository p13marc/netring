//! Async capture-to-workers pipeline via `tokio::sync::mpsc`.
//!
//! Production pattern: one task captures (the only one that touches the
//! ring), N worker tasks consume `OwnedPacket`s from a bounded channel
//! and do CPU-heavy work. Backpressure flows back automatically — when
//! workers fall behind, `tx.send().await` blocks the capture task; when
//! the OS ring fills up, you'll see drops surface in `cumulative_stats`.
//!
//! Usage: cargo run --example async_pipeline --features tokio -- [iface] [workers] [duration_secs]

#[cfg(feature = "tokio")]
#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    use netring::CaptureBuilder;
    use netring::async_adapters::tokio_adapter::AsyncCapture;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::sync::mpsc;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let workers: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let secs: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!("Capturing on {iface} into {workers} worker tasks for {secs}s...");

    let (tx, rx) = mpsc::channel::<netring::OwnedPacket>(4096);
    let processed = Arc::new(AtomicU64::new(0));

    // Workers: each pops from the same channel. tokio::sync::mpsc is MPSC,
    // so we wrap rx in Arc<Mutex<...>> to share — or, idiomatic for fan-out:
    // use async_channel (MPMC). For simplicity here we use a single worker
    // pulling from rx and dispatching to per-worker channels. But the
    // simplest production pattern is one mpsc per worker with a dispatcher,
    // OR async-channel for true MPMC.
    //
    // To keep this example minimal, we spawn `workers` tasks that share a
    // Mutex-guarded receiver. NOT recommended for high throughput — see
    // `async-channel` or `flume` for lock-free MPMC.

    use tokio::sync::Mutex;
    let rx = Arc::new(Mutex::new(rx));
    let mut handles = Vec::with_capacity(workers);
    for w in 0..workers {
        let rx = Arc::clone(&rx);
        let processed = Arc::clone(&processed);
        handles.push(tokio::spawn(async move {
            loop {
                let pkt = {
                    let mut guard = rx.lock().await;
                    match guard.recv().await {
                        Some(p) => p,
                        None => break, // channel closed
                    }
                };
                // Pretend-do something CPU-bound with the packet.
                // In real code: parse, deep-inspect, classify, log, etc.
                let _checksum = pkt.data.iter().fold(0u32, |a, b| a.wrapping_add(*b as u32));
                processed.fetch_add(1, Ordering::Relaxed);
                let _ = (w, pkt); // silence unused warnings
            }
        }));
    }

    // Capture task: runs in this scope, owned by main. Stops when the
    // duration elapses. Drops the channel on exit, which causes workers
    // to see None and exit cleanly.
    //
    // We use cap.recv() (returns Vec<OwnedPacket>) rather than
    // readable()/next_batch() because PacketBatch is !Send (it borrows
    // from the mmap ring) and the spawned task crosses await points.
    // recv() copies the batch out as owned packets before returning, so
    // the future is Send.
    let cap_handle = {
        let tx = tx.clone();
        let iface = iface.clone();
        tokio::spawn(async move {
            let rx = CaptureBuilder::default()
                .interface(&iface)
                .block_timeout_ms(50)
                .build()
                .expect("build rx");
            let mut cap = AsyncCapture::new(rx).expect("wrap async");
            let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);

            loop {
                tokio::select! {
                    res = cap.recv() => {
                        let packets = match res {
                            Ok(p) => p,
                            Err(e) => { eprintln!("recv error: {e}"); break; }
                        };
                        for pkt in packets {
                            // tx.send().await applies backpressure if the
                            // channel is full — slowing the capture loop,
                            // which surfaces as kernel-side drops in
                            // cumulative_stats.
                            if tx.send(pkt).await.is_err() {
                                return; // workers all exited
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => break,
                }
            }
        })
    };

    // Drop our writer half so once the capture task exits, all senders
    // are dropped and the channel closes.
    drop(tx);

    let _ = cap_handle.await;
    for h in handles {
        let _ = h.await;
    }

    eprintln!(
        "Pipeline finished. {} packets processed across {workers} workers",
        processed.load(Ordering::Relaxed)
    );
    Ok(())
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!(
        "This example requires the 'tokio' feature: cargo run --example async_pipeline --features tokio"
    );
}
