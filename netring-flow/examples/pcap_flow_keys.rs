//! Source-agnostic flow extraction example: read a pcap, run a
//! `FiveTuple::bidirectional()` extractor over each frame, print
//! the canonical flow keys.
//!
//! Demonstrates that `netring-flow` works without `netring` —
//! pcap input only, no Linux capture, no tokio.
//!
//! Usage:
//!     cargo run -p netring-flow --example pcap_flow_keys -- path/to/trace.pcap

use std::env;
use std::fs::File;
use std::io::BufReader;

use netring_flow::extract::FiveTuple;
use netring_flow::{FlowExtractor, PacketView, Timestamp};

use pcap_file::pcap::PcapReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: pcap_flow_keys <trace.pcap>")?;
    let file = File::open(&path)?;
    let mut reader = PcapReader::new(BufReader::new(file))?;
    let extractor = FiveTuple::bidirectional();

    let mut total = 0usize;
    let mut extracted = 0usize;

    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt?;
        total += 1;
        let ts = Timestamp::new(pkt.timestamp.as_secs() as u32, pkt.timestamp.subsec_nanos());
        let view = PacketView::new(&pkt.data, ts);

        if let Some(e) = extractor.extract(view) {
            extracted += 1;
            println!(
                "{ts:>20}  {proto:?}  {a} <-> {b}  orientation={ori:?}",
                ts = ts,
                proto = e.key.proto,
                a = e.key.a,
                b = e.key.b,
                ori = e.orientation,
            );
        }
    }

    eprintln!(
        "\n--- summary: {extracted}/{total} packets extracted",
        extracted = extracted,
        total = total,
    );
    Ok(())
}
