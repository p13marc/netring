//! Per-flow exponential-moving-average byte rate using
//! flowscope's [`Ewma`](flowscope::correlate::Ewma).
//!
//! Each flow's per-side byte rate gets smoothed across packets;
//! at end-of-stream we print the highest-rate flows. Useful as
//! a baseline for detecting bulk-transfer / exfil patterns.
//!
//! Usage:
//!     cargo run -p netring --example ewma_rate \
//!         --features tokio,flow,parse -- [interface] [seconds]
//!
//! Defaults: lo, 60s.
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    use flowscope::FlowEvent;
    use flowscope::correlate::Ewma;
    use futures::StreamExt;
    use netring::AsyncCapture;
    use netring::flow::extract::{FiveTuple, FiveTupleKey};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    eprintln!("[ewma] watching {iface} for {seconds}s; smoothing per-flow packet sizes");

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap.flow_stream(FiveTuple::bidirectional());

    // alpha=0.1 → recent samples count for ~10% of the average.
    let mut rate: Ewma<FiveTupleKey> = Ewma::new(0.1);
    let deadline = Instant::now() + Duration::from_secs(seconds);

    while Instant::now() < deadline
        && let Some(evt) = stream.next().await
    {
        match evt? {
            FlowEvent::Packet { key, len, .. } => {
                rate.record(key, len as f64);
            }
            FlowEvent::Ended { key, .. } => {
                // Settle: read the smoothed value, then evict.
                if let Some(_v) = rate.get(&key) {
                    // (kept for symmetry — the snapshot below shows it)
                }
            }
            _ => {}
        }
    }

    let mut snap: Vec<_> = rate.iter().map(|(k, v)| (*k, v)).collect();
    snap.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    eprintln!("\n[done] top 10 flows by EWMA-smoothed packet size:");
    for (key, ewma_bytes) in snap.into_iter().take(10) {
        println!(
            "  {a} <-> {b}  ewma_len={ewma_bytes:.1}B",
            a = key.a,
            b = key.b
        );
    }
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "flow", feature = "parse")))]
fn main() {
    eprintln!("Build with --features tokio,flow,parse");
}
