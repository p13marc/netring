//! Sync flow tracking over a pcap input.
//!
//! Reads a pcap file, runs every frame through a `FlowTracker` with
//! a `FiveTuple::bidirectional()` extractor, and prints a one-line
//! summary for each ended flow. Demonstrates that `netring-flow`
//! works without `netring` and without tokio.
//!
//! Usage:
//!     cargo run -p netring-flow --example pcap_flow_summary -- trace.pcap

use std::env;
use std::fs::File;
use std::io::BufReader;

use netring_flow::extract::FiveTuple;
use netring_flow::{FlowEvent, FlowTracker, PacketView, Timestamp};

use pcap_file::pcap::PcapReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: pcap_flow_summary <trace.pcap>")?;
    let file = File::open(&path)?;
    let mut reader = PcapReader::new(BufReader::new(file))?;
    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());

    let mut packets = 0usize;
    let mut started = 0usize;
    let mut ended = 0usize;
    let mut last_seen_ts = Timestamp::default();

    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt?;
        packets += 1;
        let ts = Timestamp::new(pkt.timestamp.as_secs() as u32, pkt.timestamp.subsec_nanos());
        last_seen_ts = ts;
        let view = PacketView::new(&pkt.data, ts);
        for evt in tracker.track(view) {
            match evt {
                FlowEvent::Started { key, l4, ts, .. } => {
                    started += 1;
                    println!("[{ts}] + {l4:?} {a} <-> {b}", l4 = l4, a = key.a, b = key.b);
                }
                FlowEvent::Ended {
                    key,
                    reason,
                    stats,
                    history,
                } => {
                    ended += 1;
                    let total_pkts = stats.packets_initiator + stats.packets_responder;
                    let total_bytes = stats.bytes_initiator + stats.bytes_responder;
                    println!(
                        "      - {a} <-> {b}  reason={reason:?}  pkts={total_pkts}  bytes={total_bytes}  history={history}",
                        a = key.a,
                        b = key.b,
                    );
                }
                _ => {}
            }
        }
    }

    // Force the remaining flows to end via a sweep at far-future ts.
    let far = Timestamp::new(last_seen_ts.sec.saturating_add(86_400), 0);
    for evt in tracker.sweep(far) {
        if let FlowEvent::Ended {
            key,
            stats,
            history,
            ..
        } = evt
        {
            ended += 1;
            let total_pkts = stats.packets_initiator + stats.packets_responder;
            let total_bytes = stats.bytes_initiator + stats.bytes_responder;
            println!(
                "      - {a} <-> {b}  reason=IdleTimeout  pkts={total_pkts}  bytes={total_bytes}  history={history}",
                a = key.a,
                b = key.b,
            );
        }
    }

    eprintln!("\n--- summary: {packets} packets, {started} flows started, {ended} flows ended");
    Ok(())
}
