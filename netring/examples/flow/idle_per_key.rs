//! Per-key idle timeouts on `FlowStream` (plan 19 / flowscope 0.3).
//!
//! Demonstrates `.with_idle_timeout_fn(|key, l4| ...)`. DNS gets a
//! 5-second timeout (short, since queries are usually instantaneous);
//! all other flows use the protocol defaults. Pair with
//! `.with_monotonic_timestamps(true)` so the printed timeline is
//! strictly non-decreasing even across step-back NIC timestamps.
//!
//! Usage:
//!     cargo run --example async_flow_idle_per_key \
//!         --features tokio,flow -- [iface] [seconds]
//!
//! Requires CAP_NET_RAW. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "flow"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use futures::StreamExt;
    use netring::AsyncCapture;
    use netring::flow::extract::FiveTuple;
    use netring::flow::{EndReason, FlowEvent};
    use std::time::{Duration, Instant};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!(
        "Flow tracking on {iface} for {seconds}s. DNS idle=5s, default protocol idle for everything else."
    );

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap
        .flow_stream(FiveTuple::bidirectional())
        .with_idle_timeout_fn(|key, _l4| {
            if key.either_port(53) {
                Some(Duration::from_secs(5))
            } else {
                None
            }
        })
        .with_monotonic_timestamps(true);

    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline
        && let Some(evt) = stream.next().await
    {
        match evt? {
            FlowEvent::Started { key, ts, .. } => {
                eprintln!("[{}.{:09}] + {key:?}", ts.sec, ts.nsec);
            }
            FlowEvent::Ended {
                key, reason, stats, ..
            } => {
                let tag = match reason {
                    EndReason::IdleTimeout => "idle",
                    EndReason::Fin => "fin ",
                    EndReason::Rst => "rst ",
                    EndReason::Evicted => "evt ",
                    EndReason::BufferOverflow => "ovf ",
                    EndReason::ParseError => "perr",
                    _ => "????",
                };
                eprintln!(
                    "[{}.{:09}] - {tag} {key:?} pkt_i={} pkt_r={}",
                    stats.last_seen.sec,
                    stats.last_seen.nsec,
                    stats.packets_initiator,
                    stats.packets_responder,
                );
            }
            FlowEvent::Anomaly { key, kind, ts } => {
                eprintln!("[{}.{:09}] ! anomaly {key:?} {kind:?}", ts.sec, ts.nsec);
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "flow")))]
fn main() {
    eprintln!("Build with --features tokio,flow");
}
