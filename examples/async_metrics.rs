//! Async capture with periodic stats reporting via the `metrics` crate.
//!
//! Demonstrates the "capture in the foreground, emit metrics on a timer"
//! pattern using `tokio::select!`. With `metrics-exporter-prometheus` (or
//! any other recorder) installed in the host process, the counters
//! surface as:
//!
//!   netring_capture_packets_total{iface="eth0"}
//!   netring_capture_drops_total{iface="eth0"}
//!   netring_capture_freezes_total{iface="eth0"}
//!
//! Usage: cargo run --example async_metrics --features tokio,metrics -- [interface] [duration_secs]

#[cfg(all(feature = "tokio", feature = "metrics"))]
#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    use netring::AsyncCapture;
    use netring::metrics::record_capture_delta;
    use std::time::Duration;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!("Capturing on {iface} for {secs}s with 1Hz metrics emission");

    let mut cap = AsyncCapture::open(&iface)?;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);

    let mut local_packets = 0u64;
    let mut local_bytes = 0u64;

    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }

        tokio::select! {
            res = cap.readable() => {
                let mut guard = res?;
                if let Some(batch) = guard.next_batch() {
                    for pkt in &batch {
                        local_packets += 1;
                        local_bytes += pkt.len() as u64;
                    }
                }
            }
            _ = tick.tick() => {
                // Delta since last tick — feeds Prometheus / OTel /
                // statsd via whatever recorder is installed.
                let delta = cap.stats()?;
                record_capture_delta(&iface, &delta);
                eprintln!(
                    "[1Hz] kernel: pkts={} drops={} freezes={} | local: {local_packets}/{local_bytes}B",
                    delta.packets, delta.drops, delta.freeze_count
                );
            }
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }

    eprintln!("done");
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "metrics")))]
fn main() {
    eprintln!(
        "This example requires both 'tokio' and 'metrics' features: \
         cargo run --example async_metrics --features tokio,metrics"
    );
}
