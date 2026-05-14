//! Offline pcap replay through the same flow-tracking pipeline as a
//! live capture.
//!
//! Demonstrates plan 23: `AsyncPcapSource` + `flow_events()`. Both
//! legacy PCAP and PCAPNG are auto-detected at open.
//!
//! Usage:
//!     cargo run -p netring --example async_pcap_replay \
//!         --features tokio,flow,parse,pcap -- trace.pcap [speed]
//!
//! `speed` is the optional replay multiplier:
//!     0.0 (default) — as fast as possible
//!     1.0           — wire rate
//!     0.5           — half speed
//!     2.0           — double speed

use std::env;

use futures::StreamExt;
use netring::flow::FlowEvent;
use netring::flow::extract::FiveTuple;
use netring::{AsyncPcapConfig, AsyncPcapSource};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: async_pcap_replay <pcap> [speed]")?;
    let replay_speed: f32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);

    let cfg = AsyncPcapConfig {
        replay_speed,
        ..AsyncPcapConfig::default()
    };
    let source = AsyncPcapSource::open_with_config(&path, cfg).await?;
    eprintln!(
        "[replay] {} format={:?} speed={replay_speed}",
        path,
        source.format()
    );

    let mut events = source.flow_events(FiveTuple::bidirectional());
    let mut started = 0usize;
    let mut ended = 0usize;
    while let Some(evt) = events.next().await {
        match evt? {
            FlowEvent::Started { key, l4, .. } => {
                started += 1;
                println!("+ {l4:?} {a} <-> {b}", a = key.a, b = key.b);
            }
            FlowEvent::Ended {
                key, reason, stats, ..
            } => {
                ended += 1;
                println!(
                    "- {a} <-> {b}  reason={reason:?}  pkts={p}",
                    a = key.a,
                    b = key.b,
                    p = stats.packets_initiator + stats.packets_responder,
                );
            }
            _ => {}
        }
    }
    eprintln!(
        "[done] flows started={started} ended={ended} packets_read={}",
        events.packets_read()
    );
    Ok(())
}
