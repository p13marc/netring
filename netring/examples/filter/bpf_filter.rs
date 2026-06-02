//! Typed BPF filter builder demo.
//!
//! Builds a filter that accepts:
//!   `(tcp dst port 443) or (udp dst port 53)`
//! and prints how many packets it would accept on each interface tick.
//!
//! Usage:
//!   cargo run --example bpf_filter -- [interface]
//!
//! Requires CAP_NET_RAW. Run on a host with traffic for visible output.

use netring::{BpfFilter, Capture};

fn main() -> Result<(), netring::Error> {
    env_logger::init();

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    let filter = BpfFilter::builder()
        .tcp()
        .dst_port(443)
        .or(|b| b.udp().dst_port(53))
        .build()?;

    eprintln!(
        "Attaching filter on {iface} ({} cBPF instructions)",
        filter.len()
    );

    let mut cap = Capture::builder()
        .interface(&iface)
        .promiscuous(false)
        .ignore_outgoing(true)
        .bpf_filter(filter)
        .build()?;

    eprintln!("Capturing 50 matching packets... (Ctrl-C to stop early)");

    for pkt in cap.packets().take(50) {
        println!(
            "[{}.{:09}] {} bytes (wire: {})",
            pkt.timestamp().sec,
            pkt.timestamp().nsec,
            pkt.len(),
            pkt.original_len(),
        );
    }

    let stats = cap.stats()?;
    eprintln!("{stats}");
    Ok(())
}
