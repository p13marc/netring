//! Periodic snapshot of the currently-live flows in the tracker
//! — `FlowTracker::iter_active` exposed via
//! `FlowStream::snapshot_flow_stats`.
//!
//! Every 5 seconds, print the top-10 live flows sorted by bytes
//! and the live-flow population size. Useful for ops dashboards
//! and for catching slow-burn exfil patterns.
//!
//! Usage:
//!     cargo run -p netring --example active_flows_snapshot \
//!         --features tokio,flow,parse -- [interface] [seconds]
//!
//! Defaults: lo, 60s.
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    use futures::StreamExt;
    use netring::AsyncCapture;
    use netring::flow::extract::FiveTuple;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    eprintln!("[snapshot] watching {iface} for {seconds}s; snapshot every 5s");

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap.flow_stream(FiveTuple::bidirectional());

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut snapshot = tokio::time::interval(Duration::from_secs(5));

    while Instant::now() < deadline {
        tokio::select! {
            biased;
            evt = stream.next() => {
                if evt.is_none() { break }
            }
            _ = snapshot.tick() => {
                let mut by_bytes: Vec<_> = stream
                    .snapshot_flow_stats()
                    .map(|(k, s)| (k, s.total_bytes()))
                    .collect();
                by_bytes.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
                eprintln!("\n[snapshot] {} live flows", by_bytes.len());
                for (key, bytes) in by_bytes.into_iter().take(10) {
                    println!("  {a} <-> {b}  total={bytes}B",
                        a = key.a, b = key.b);
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "flow", feature = "parse")))]
fn main() {
    eprintln!("Build with --features tokio,flow,parse");
}
