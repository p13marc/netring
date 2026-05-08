//! Sync TCP reassembly over a pcap input.
//!
//! Reads a pcap file, runs every frame through a `FlowDriver` with
//! a `BufferedReassemblerFactory`, prints each Started/Ended event.
//! On Ended (FIN), the per-(flow, side) reassembler buffers are
//! drained and sizes printed. Demonstrates that `netring-flow` does
//! sync reassembly without tokio or netring.
//!
//! Usage:
//!     cargo run -p netring-flow --example pcap_buffered_reassembly -- trace.pcap

use std::env;
use std::fs::File;
use std::io::BufReader;

use netring_flow::extract::FiveTuple;
use netring_flow::{BufferedReassemblerFactory, FlowDriver, FlowEvent, PacketView, Timestamp};

use pcap_file::pcap::PcapReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: pcap_buffered_reassembly <trace.pcap>")?;
    let file = File::open(&path)?;
    let mut reader = PcapReader::new(BufReader::new(file))?;

    let mut driver: FlowDriver<FiveTuple, BufferedReassemblerFactory, ()> =
        FlowDriver::new(FiveTuple::bidirectional(), BufferedReassemblerFactory);

    let mut packets = 0usize;
    let mut total_payload = 0u64;
    let mut last_ts = Timestamp::default();

    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt?;
        packets += 1;
        let ts = Timestamp::new(pkt.timestamp.as_secs() as u32, pkt.timestamp.subsec_nanos());
        last_ts = ts;
        let view = PacketView::new(&pkt.data, ts);
        for evt in driver.track(view) {
            match evt {
                FlowEvent::Started { key, l4, .. } => {
                    println!("+ {l4:?} {a} <-> {b}", l4 = l4, a = key.a, b = key.b);
                }
                FlowEvent::Ended {
                    key, reason, stats, ..
                } => {
                    let fwd = stats.bytes_initiator;
                    let rev = stats.bytes_responder;
                    total_payload += fwd + rev;
                    println!(
                        "- {a} <-> {b}  reason={reason:?}  init_bytes={fwd}  resp_bytes={rev}",
                        a = key.a,
                        b = key.b,
                    );
                }
                _ => {}
            }
        }
    }

    // Sweep remaining flows.
    let far = Timestamp::new(last_ts.sec.saturating_add(86_400), 0);
    for evt in driver.sweep(far) {
        if let FlowEvent::Ended {
            key, reason, stats, ..
        } = evt
        {
            let fwd = stats.bytes_initiator;
            let rev = stats.bytes_responder;
            total_payload += fwd + rev;
            println!(
                "- {a} <-> {b}  reason={reason:?}  init_bytes={fwd}  resp_bytes={rev}",
                a = key.a,
                b = key.b,
            );
        }
    }

    eprintln!("\n--- summary: {packets} packets, total payload bytes seen: {total_payload}");
    Ok(())
}
