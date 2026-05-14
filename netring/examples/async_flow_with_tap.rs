//! Live flow tracking + raw pcap recording in one invocation.
//!
//! Demonstrates plan 20's `with_pcap_tap`: every captured packet is
//! recorded to `<output>.pcap` **before** the flow tracker sees it,
//! so you get decoded events AND a wire-faithful capture file with
//! a single tool. Pair with `StreamCapture::capture_stats()` for
//! periodic operator readouts.
//!
//! Usage:
//!     cargo run -p netring --example async_flow_with_tap \
//!         --features tokio,flow,parse,pcap -- eth0 capture.pcap

use std::env;
use std::fs::File;
use std::io::BufWriter;
use std::time::Duration;

use futures::StreamExt;
use netring::flow::FlowEvent;
use netring::flow::extract::FiveTuple;
use netring::pcap::CaptureWriter;
use netring::{AsyncCapture, Dedup, StreamCapture};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let iface = args.next().unwrap_or_else(|| "lo".to_string());
    let out_path = args.next().unwrap_or_else(|| "capture.pcap".to_string());

    println!("listening on {iface}, recording to {out_path} (Ctrl+C to stop)...");

    // BufWriter is strongly recommended — `CaptureWriter::write_packet`
    // does a syscall per record otherwise.
    let writer = CaptureWriter::create(BufWriter::new(File::create(&out_path)?))?;

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap
        .flow_stream(FiveTuple::bidirectional())
        .with_dedup(Dedup::loopback())
        .with_pcap_tap(writer);

    // Print kernel ring stats every second from a parallel task. The
    // `StreamCapture` trait makes the underlying capture reachable
    // even though the stream owns it.
    //
    // (Demo shape only — in production you'd hold the stream behind
    // an Arc/Mutex or have one task call `capture_stats` between
    // its own poll iterations.)
    let mut stats_tick = tokio::time::interval(Duration::from_secs(1));
    stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // First tick fires immediately; skip it.
    stats_tick.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = stats_tick.tick() => {
                if let Ok(stats) = stream.capture_stats() {
                    eprintln!(
                        "[stats] packets={} drops={} freeze_count={}",
                        stats.packets, stats.drops, stats.freeze_count,
                    );
                }
            }
            evt = stream.next() => match evt {
                Some(Ok(FlowEvent::Started { key, l4, .. })) => {
                    println!("+ {l4:?} {a} <-> {b}", a = key.a, b = key.b);
                }
                Some(Ok(FlowEvent::Ended { key, reason, stats, .. })) => {
                    println!(
                        "- {a} <-> {b}  reason={reason:?}  pkts={p}",
                        a = key.a, b = key.b,
                        p = stats.packets_initiator + stats.packets_responder,
                    );
                }
                Some(Ok(_)) => { /* Packet/StateChange/Anomaly: skip in this demo */ }
                Some(Err(e)) => {
                    eprintln!("stream error: {e}");
                    break;
                }
                None => break,
            }
        }
    }
    Ok(())
}
