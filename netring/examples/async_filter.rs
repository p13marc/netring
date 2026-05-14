//! Live flow capture with a kernel-side BPF filter — and an optional
//! runtime filter swap halfway through.
//!
//! Demonstrates plan 21:
//! - `AsyncCapture::open_with_filter` for one-call setup.
//! - `set_filter` for atomic in-kernel swap on a running capture.
//!
//! Usage:
//!     cargo run -p netring --example async_filter \
//!         --features tokio,flow,parse -- eth0 80

use std::env;
use std::time::Duration;

use futures::StreamExt;
use netring::flow::FlowEvent;
use netring::flow::extract::FiveTuple;
use netring::{AsyncCapture, BpfFilter, StreamCapture};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let iface = args.next().unwrap_or_else(|| "lo".to_string());
    let port: u16 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);

    let initial = BpfFilter::builder().tcp().dst_port(port).build()?;
    println!("listening on {iface}, initial filter: tcp dst port {port}");

    let cap = AsyncCapture::open_with_filter(&iface, initial)?;

    // Demonstrate runtime swap: after 5 s, narrow to dst_port=443.
    let swap_after = tokio::time::sleep(Duration::from_secs(5));

    let mut stream = cap.flow_stream(FiveTuple::bidirectional());
    let mut swapped = false;
    tokio::pin!(swap_after);

    loop {
        tokio::select! {
            biased;
            _ = &mut swap_after, if !swapped => {
                let new_filter = BpfFilter::builder().tcp().dst_port(443).build()?;
                println!("[swap] narrowing filter to tcp dst port 443");
                stream.capture().set_filter(&new_filter)?;
                swapped = true;
            }
            evt = stream.next() => match evt {
                Some(Ok(FlowEvent::Started { key, .. })) => {
                    println!("+ {a} <-> {b}", a = key.a, b = key.b);
                }
                Some(Ok(FlowEvent::Ended { key, reason, .. })) => {
                    println!("- {a} <-> {b}  reason={reason:?}", a = key.a, b = key.b);
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => { eprintln!("stream error: {e}"); break; }
                None => break,
            }
        }
    }
    Ok(())
}
