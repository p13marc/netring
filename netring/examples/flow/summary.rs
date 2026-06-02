//! Async flow tracking over a live capture.
//!
//! Open `AsyncCapture`, run a 5-tuple flow stream, print one line
//! per Started/Ended event. Demonstrates the headline tokio API.
//!
//! Usage:
//!     cargo run -p netring --example async_flow_summary --features tokio,flow -- eth0

use std::env;

use futures::StreamExt;
use netring::AsyncCapture;
use netring::flow::FlowEvent;
use netring::flow::extract::FiveTuple;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = env::args().nth(1).unwrap_or_else(|| "lo".to_string());
    println!("listening on {iface} (Ctrl+C to stop)...");

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap.flow_stream(FiveTuple::bidirectional());

    while let Some(evt) = stream.next().await {
        match evt? {
            FlowEvent::Started { key, l4, ts, .. } => {
                println!("[{ts}] + {l4:?} {a} <-> {b}", l4 = l4, a = key.a, b = key.b);
            }
            FlowEvent::Established { key, .. } => {
                println!("       3WHS {a} <-> {b}", a = key.a, b = key.b);
            }
            FlowEvent::Ended {
                key,
                reason,
                stats,
                history,
            } => {
                let pkts = stats.packets_initiator + stats.packets_responder;
                let bytes = stats.bytes_initiator + stats.bytes_responder;
                println!(
                    "      - {a} <-> {b}  reason={reason:?}  pkts={pkts}  bytes={bytes}  history={history}",
                    a = key.a,
                    b = key.b,
                );
            }
            _ => {}
        }
    }
    Ok(())
}
