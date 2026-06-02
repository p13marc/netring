//! Packet injection example.
//!
//! Usage: cargo run --example inject -- [interface]
//! Sends dummy Ethernet frames on the specified interface.

use netring::Injector;

fn main() -> Result<(), netring::Error> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("Injecting 10 frames on {iface}...");

    let mut tx = Injector::builder().interface(&iface).build()?;

    for i in 0u16..10 {
        if let Some(mut slot) = tx.allocate(64) {
            let buf = slot.data_mut();
            // Broadcast destination MAC
            buf[0..6].copy_from_slice(&[0xff; 6]);
            // Source MAC (dummy)
            buf[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
            // EtherType: IPv4
            buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            // Sequence number in payload
            buf[14..16].copy_from_slice(&i.to_be_bytes());
            slot.set_len(64);
            slot.send();
        } else {
            eprintln!("TX ring full at frame {i}");
        }
    }

    let flushed = tx.flush()?;
    eprintln!("Flushed {flushed} frames");
    Ok(())
}
