//! Async flow filtering — print only events for flows matching a
//! given protocol or destination port.
//!
//! Demonstrates `Stream` combinator usage on top of `flow_stream`.
//!
//! Usage:
//!     cargo run -p netring --example async_flow_filter --features tokio,flow -- eth0 tcp 443

use std::env;

use futures::StreamExt;
use netring::AsyncCapture;
use netring::flow::extract::FiveTuple;
use netring::flow::{FlowEvent, L4Proto};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let iface = args.next().unwrap_or_else(|| "lo".to_string());
    let proto_arg = args.next().unwrap_or_else(|| "tcp".to_string());
    let port_arg: Option<u16> = args.next().and_then(|s| s.parse().ok());

    let want_proto = match proto_arg.to_lowercase().as_str() {
        "tcp" => L4Proto::Tcp,
        "udp" => L4Proto::Udp,
        other => return Err(format!("unsupported proto: {other}").into()),
    };

    println!(
        "listening on {iface}, filtering {proto_arg}{port}...",
        port = port_arg.map(|p| format!(":{p}")).unwrap_or_default()
    );

    let cap = AsyncCapture::open(&iface)?;
    let mut stream = cap.flow_stream(FiveTuple::bidirectional());

    while let Some(evt) = stream.next().await {
        let evt = evt?;
        // Inline filter: protocol + (optional) port match.
        let key = evt.key();
        if key.proto != want_proto {
            continue;
        }
        if let Some(port) = port_arg
            && key.a.port() != port
            && key.b.port() != port
        {
            continue;
        }
        match evt {
            FlowEvent::Started { key, ts, .. } => {
                println!("[{ts}] + {a} <-> {b}", a = key.a, b = key.b);
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
