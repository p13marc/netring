//! Zeek-style `conn.log` output: one line per ended flow with the
//! TCP history string.
//!
//! Demonstrates the `HistoryString` field on the `Ended` event.
//!
//! Usage:
//!     cargo run -p netring --example async_flow_history --features tokio,flow -- eth0

use std::env;

use futures::StreamExt;
use netring::AsyncCapture;
use netring::flow::FlowEvent;
use netring::flow::extract::FiveTuple;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = env::args().nth(1).unwrap_or_else(|| "lo".to_string());
    eprintln!("listening on {iface} (Ctrl+C to stop)...");

    // Header (TSV, similar to Zeek's conn.log columns).
    println!("ts\tproto\torig\tresp\tduration\torig_pkts\tresp_pkts\thistory\treason");

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap.flow_stream(FiveTuple::bidirectional());

    while let Some(evt) = stream.next().await {
        if let FlowEvent::Ended {
            key,
            reason,
            stats,
            history,
        } = evt?
        {
            let dur = stats
                .last_seen
                .to_duration()
                .saturating_sub(stats.started.to_duration());
            println!(
                "{ts}\t{proto:?}\t{orig}\t{resp}\t{dur}.{frac:06}\t{op}\t{rp}\t{history}\t{reason:?}",
                ts = stats.last_seen,
                proto = key.proto,
                orig = key.a,
                resp = key.b,
                dur = dur.as_secs(),
                frac = dur.subsec_micros(),
                op = stats.packets_initiator,
                rp = stats.packets_responder,
            );
        }
    }
    Ok(())
}
