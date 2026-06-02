//! Async TCP reassembly with `channel_factory`: spawn a task per
//! (flow, side), feed it bytes via mpsc with backpressure.
//!
//! Demonstrates the headline tokio + reassembler pattern. Open
//! `AsyncCapture`, use `with_async_reassembler` + `channel_factory`,
//! and let each flow's bytes flow into a per-flow processor task.
//!
//! Usage:
//!     cargo run -p netring --example async_flow_channel --features tokio,flow -- eth0

use std::env;

use bytes::Bytes;
use futures::StreamExt;
use tokio::sync::mpsc;

use netring::AsyncCapture;
use netring::flow::extract::{FiveTuple, FiveTupleKey};
use netring::flow::{FlowEvent, channel_factory};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = env::args().nth(1).unwrap_or_else(|| "lo".to_string());
    eprintln!("listening on {iface} (Ctrl+C to stop)...");

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap
        .flow_stream(FiveTuple::bidirectional())
        .with_async_reassembler(channel_factory(|key: &FiveTupleKey, side| {
            let (tx, mut rx) = mpsc::channel::<Bytes>(64);
            let key_str = format!("{} <-> {}", key.a, key.b);
            tokio::spawn(async move {
                let mut total: u64 = 0;
                let mut chunks: u64 = 0;
                while let Some(bytes) = rx.recv().await {
                    total += bytes.len() as u64;
                    chunks += 1;
                }
                eprintln!("[done {key_str} side={side:?}] chunks={chunks} bytes={total}");
            });
            tx
        }));

    while let Some(evt) = stream.next().await {
        match evt? {
            FlowEvent::Started { key, l4, ts, .. } => {
                println!("[{ts}] + {l4:?} {a} <-> {b}", l4 = l4, a = key.a, b = key.b);
            }
            FlowEvent::Ended {
                key, reason, stats, ..
            } => {
                let pkts = stats.packets_initiator + stats.packets_responder;
                println!(
                    "      - {a} <-> {b}  reason={reason:?}  pkts={pkts}",
                    a = key.a,
                    b = key.b,
                );
            }
            _ => {}
        }
    }
    Ok(())
}
