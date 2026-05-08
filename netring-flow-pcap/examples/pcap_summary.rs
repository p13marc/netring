//! One-liner pcap flow summary using `netring-flow-pcap`.
//!
//! Compare with `netring-flow/examples/pcap_flow_summary.rs` —
//! that one shows the manual integration; this one uses the
//! companion crate to skip the boilerplate.
//!
//! Usage:
//!     cargo run -p netring-flow-pcap --example pcap_summary -- trace.pcap

use std::env;

use netring_flow::FlowEvent;
use netring_flow::extract::FiveTuple;
use netring_flow_pcap::PcapFlowSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: pcap_summary <trace.pcap>")?;

    let mut started = 0u64;
    let mut ended = 0u64;

    for evt in PcapFlowSource::open(&path)?.with_extractor(FiveTuple::bidirectional()) {
        match evt? {
            FlowEvent::Started { key, l4, .. } => {
                started += 1;
                println!("+ {l4:?} {a} <-> {b}", l4 = l4, a = key.a, b = key.b);
            }
            FlowEvent::Ended {
                key,
                reason,
                stats,
                history,
            } => {
                ended += 1;
                let pkts = stats.packets_initiator + stats.packets_responder;
                let bytes = stats.bytes_initiator + stats.bytes_responder;
                println!(
                    "- {a} <-> {b}  reason={reason:?}  pkts={pkts}  bytes={bytes}  history={history}",
                    a = key.a,
                    b = key.b,
                );
            }
            _ => {}
        }
    }

    eprintln!("\n--- summary: {started} flows started, {ended} flows ended");
    Ok(())
}
