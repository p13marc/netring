//! Multi-interface gateway capture — one stream tagged by source.
//!
//! Usage:
//!     cargo run -p netring --example async_multi_interface \
//!         --features tokio,flow,parse -- lo eth0

use std::env;

use futures::StreamExt;
use netring::AsyncMultiCapture;
use netring::flow::FlowEvent;
use netring::flow::extract::FiveTuple;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interfaces: Vec<String> = env::args().skip(1).collect();
    let interfaces: Vec<&str> = if interfaces.is_empty() {
        vec!["lo"]
    } else {
        interfaces.iter().map(|s| s.as_str()).collect()
    };

    println!("watching {interfaces:?}");

    let multi = AsyncMultiCapture::open(&interfaces)?;
    let mut stream = multi.flow_stream(FiveTuple::bidirectional());

    while let Some(evt) = stream.next().await {
        match evt {
            Ok(tagged) => {
                let iface = stream.label(tagged.source_idx).unwrap_or("?");
                match tagged.event {
                    FlowEvent::Started { key, .. } => {
                        println!("[{iface}] + {a} <-> {b}", a = key.a, b = key.b);
                    }
                    FlowEvent::Ended { key, reason, .. } => {
                        println!(
                            "[{iface}] - {a} <-> {b} reason={reason:?}",
                            a = key.a,
                            b = key.b,
                        );
                    }
                    _ => {}
                }
            }
            Err(e) => {
                eprintln!("stream error: {e}");
                break;
            }
        }
    }

    Ok(())
}
