//! Live kernel-ring stats on a running async flow stream.
//!
//! Demonstrates the [`StreamCapture`] trait (plan 20): the
//! underlying capture moves into the stream when you call
//! `cap.flow_stream(...)`, but `stream.capture_stats()` and
//! `stream.capture_cumulative_stats()` keep working — out-of-band
//! access to the same `PACKET_STATISTICS` socket option you'd
//! poll on a sync `Capture` via [`stats_monitor`](./stats_monitor.rs).
//!
//! Usage:
//!     cargo run --example async_stats_monitor \
//!         --features tokio,flow,parse -- [interface] [seconds]
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "flow"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use futures::StreamExt;
    use netring::flow::extract::FiveTuple;
    use netring::flow::{EndReason, FlowEvent};
    use netring::{AsyncCapture, StreamCapture};
    use std::time::{Duration, Instant};

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!("Async flow tracking on {iface} for {seconds}s with live stats");

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap.flow_stream(FiveTuple::bidirectional());

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut next_report = Instant::now() + Duration::from_secs(1);
    let mut flow_started = 0u64;
    let mut flow_ended = 0u64;

    while Instant::now() < deadline {
        // Periodic stats line. The `capture_stats()` call is
        // independent of stream polling — it reaches through the
        // `StreamCapture` trait to the underlying `AsyncCapture`.
        if Instant::now() >= next_report {
            let stats = stream.capture_cumulative_stats()?;
            println!(
                "[+{:>2}s] kernel: {} pkt, {} drops, {} freeze | flows: +{flow_started} / -{flow_ended}",
                seconds - deadline.saturating_duration_since(Instant::now()).as_secs(),
                stats.packets,
                stats.drops,
                stats.freeze_count,
            );
            next_report += Duration::from_secs(1);
        }

        // Drive the flow stream with a timeout so the report loop
        // wakes regularly even on a quiet interface.
        let timeout = tokio::time::sleep_until(next_report.into());
        tokio::select! {
            _ = timeout => continue,
            evt = stream.next() => match evt {
                Some(Ok(FlowEvent::Started { .. })) => flow_started += 1,
                Some(Ok(FlowEvent::Ended { reason, .. })) => {
                    flow_ended += 1;
                    if matches!(reason, EndReason::Rst | EndReason::BufferOverflow | EndReason::ParseError) {
                        // Aborted flows are interesting — surface them in the
                        // periodic line above by leaving a tracing hint.
                        tracing::debug!(?reason, "flow aborted");
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.into()),
                None => break,
            }
        }
    }

    let final_stats = stream.capture_cumulative_stats()?;
    eprintln!(
        "final: {} pkt, {} drops, {} freeze, {flow_started} starts / {flow_ended} ends",
        final_stats.packets, final_stats.drops, final_stats.freeze_count
    );
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "flow")))]
fn main() {
    eprintln!("Build with --features tokio,flow");
}
