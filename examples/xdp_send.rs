//! AF_XDP TX-only example — send packets without a BPF program.
//!
//! Usage: cargo run --example xdp_send --features af-xdp -- <interface>
//! Requires CAP_NET_RAW + CAP_BPF (or root).

use netring::afxdp::XdpSocketBuilder;

fn main() -> Result<(), netring::Error> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("Opening AF_XDP socket on {iface} (TX only, no BPF program needed)");

    let mut xdp = XdpSocketBuilder::default()
        .interface(&iface)
        .queue_id(0)
        .build()?;

    // Send 10 raw Ethernet frames
    for i in 0u16..10 {
        let mut frame = vec![0u8; 64];
        // Broadcast destination MAC
        frame[0..6].copy_from_slice(&[0xff; 6]);
        // Zero source MAC
        frame[6..12].copy_from_slice(&[0x00; 6]);
        // EtherType: IPv4
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        // Sequence number in payload
        frame[14..16].copy_from_slice(&i.to_be_bytes());

        match xdp.send(&frame)? {
            true => eprintln!("  queued frame {i}"),
            false => eprintln!("  TX ring full, dropped frame {i}"),
        }
    }

    xdp.flush()?;
    eprintln!("Flushed — sent 10 frames via AF_XDP on {iface}");
    Ok(())
}
