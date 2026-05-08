//! Capture packets to a PCAP file (feature: `pcap`).
//!
//! Usage: cargo run --example pcap_write --features pcap -- [interface] [count] [out.pcap]
//!
//! Defaults: lo / 100 packets / out.pcap

#[cfg(feature = "pcap")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use netring::Capture;
    use netring::pcap::CaptureWriter;
    use std::fs::File;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let count: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let out = std::env::args().nth(3).unwrap_or_else(|| "out.pcap".into());

    eprintln!("Capturing {count} packets from {iface} into {out}");

    let mut cap = Capture::open(&iface)?;
    let mut writer = CaptureWriter::create(File::create(&out)?)?;

    for pkt in cap.packets().take(count) {
        writer.write_packet(&pkt)?;
    }

    eprintln!("Done. Inspect with `tcpdump -r {out}` or `wireshark {out}`.");
    Ok(())
}

#[cfg(not(feature = "pcap"))]
fn main() {
    eprintln!(
        "This example requires the 'pcap' feature: cargo run --example pcap_write --features pcap"
    );
}
