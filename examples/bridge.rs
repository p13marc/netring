//! Transparent packet bridge between two interfaces.
//!
//! Usage: cargo run --example bridge -- <interface_a> <interface_b>
//! Requires CAP_NET_RAW on both interfaces.
//!
//! Forwards all packets bidirectionally. Press Ctrl-C to stop.

use netring::bridge::{Bridge, BridgeAction, BridgeDirection};

fn main() -> Result<(), netring::Error> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <interface_a> <interface_b>", args[0]);
        eprintln!("Example: {} eth0 eth1", args[0]);
        std::process::exit(1);
    }
    let iface_a = &args[1];
    let iface_b = &args[2];

    eprintln!("Bridging {iface_a} ↔ {iface_b} (Ctrl-C to stop)");

    let mut bridge = Bridge::builder()
        .interface_a(iface_a)
        .interface_b(iface_b)
        .build()?;

    let mut count_a_to_b = 0u64;
    let mut count_b_to_a = 0u64;

    // Forward all packets, counting each direction
    bridge.run(|_pkt, direction| {
        match direction {
            BridgeDirection::AtoB => count_a_to_b += 1,
            BridgeDirection::BtoA => count_b_to_a += 1,
        }
        if (count_a_to_b + count_b_to_a) % 1000 == 0 {
            eprintln!("A→B: {count_a_to_b}  B→A: {count_b_to_a}");
        }
        BridgeAction::Forward
    })?;

    Ok(())
}
