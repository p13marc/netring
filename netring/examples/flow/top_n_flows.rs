//! Streaming top-K flows by total bytes, using flowscope's
//! [`TopK`](flowscope::correlate::TopK) (Misra–Gries
//! frequent-items sketch).
//!
//! Why a sketch and not a `HashMap`? On a busy backbone the
//! number of distinct flows in a 5-minute window is millions;
//! a sketch holds O(K) entries with bounded error. For
//! K=10 a HashMap is fine; the value of the example is showing
//! the *pattern* — switch K to 1000 and the sketch costs the
//! same as K=10.
//!
//! Usage:
//!     cargo run -p netring --example top_n_flows \
//!         --features tokio,flow,parse -- [interface] [seconds] [k]
//!
//! Defaults: lo, 60s, K=10.
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "flow", feature = "parse"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    use flowscope::FlowEvent;
    use flowscope::correlate::TopK;
    use futures::StreamExt;
    use netring::AsyncCapture;
    use netring::flow::extract::{FiveTuple, FiveTupleKey};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let k: usize = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!("[top-n] watching {iface} for {seconds}s; reporting top {k} flows by total bytes");

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap.flow_stream(FiveTuple::bidirectional());

    let mut topk: TopK<FiveTupleKey> = TopK::new(k);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut total_flows = 0u64;

    while Instant::now() < deadline
        && let Some(evt) = stream.next().await
    {
        if let FlowEvent::Ended { key, stats, .. } = evt? {
            total_flows += 1;
            topk.observe_n(key, stats.total_bytes());
        }
    }

    eprintln!("\n[done] saw {total_flows} flow-end events; top {k}:");
    for (key, est) in topk.top() {
        println!("  {a} <-> {b}  ~{est} bytes", a = key.a, b = key.b);
    }
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "flow", feature = "parse")))]
fn main() {
    eprintln!("Build with --features tokio,flow,parse");
}
