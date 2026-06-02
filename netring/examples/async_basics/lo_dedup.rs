//! Loopback dedup demo.
//!
//! Capture on `lo`, drop the kernel's re-injected duplicates, print
//! drop ratio every second.
//!
//! Without dedup, every `ping 127.0.0.1` packet appears twice (once
//! Outgoing, once Host). With `Dedup::loopback()` you see each
//! logical packet exactly once.
//!
//! Usage:
//!     cargo run -p netring --example async_lo_dedup --features tokio
//!
//! Optionally pass an interface name (defaults to `lo`):
//!     cargo run -p netring --example async_lo_dedup --features tokio -- eth0

use std::env;
use std::time::Duration;

use futures::StreamExt;
use netring::{AsyncCapture, Dedup};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = env::args().nth(1).unwrap_or_else(|| "lo".to_string());
    eprintln!("listening on {iface} with Dedup::loopback() (Ctrl+C to stop)...");

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap.dedup_stream(Dedup::loopback());

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.tick().await; // skip the immediate first tick

    let mut last_seen = 0u64;
    let mut last_dropped = 0u64;

    loop {
        tokio::select! {
            biased;
            _ = tick.tick() => {
                let s = stream.dedup().seen();
                let d = stream.dedup().dropped();
                let kept = s - d;
                let s_delta = s - last_seen;
                let d_delta = d - last_dropped;
                let pct = if s_delta > 0 { 100.0 * d_delta as f64 / s_delta as f64 } else { 0.0 };
                eprintln!(
                    "[1s] seen={s_delta:>5} kept={k:>5} dropped={d_delta:>5} ({pct:.1}%)  \
                     totals: seen={s} kept={kept} dropped={d}",
                    k = s_delta - d_delta
                );
                last_seen = s;
                last_dropped = d;
            }
            evt = stream.next() => {
                match evt {
                    Some(Ok(_pkt)) => { /* keep going */ }
                    Some(Err(e)) => {
                        eprintln!("error: {e}");
                        break;
                    }
                    None => break,
                }
            }
        }
    }
    Ok(())
}
