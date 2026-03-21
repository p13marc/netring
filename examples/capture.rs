//! Basic packet capture example.
//!
//! Usage: cargo run --example capture -- [interface]
//! Requires CAP_NET_RAW.

use netring::Capture;

fn main() -> Result<(), netring::Error> {
    env_logger::init();

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("Capturing on {iface}... (Ctrl-C to stop)");

    let mut cap = Capture::builder()
        .interface(&iface)
        .promiscuous(true)
        .ignore_outgoing(true)
        .build()?;

    for pkt in cap.packets().take(100) {
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
