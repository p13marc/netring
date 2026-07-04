//! Network-namespace capture (issue #126): capture on an interface that lives
//! inside another network namespace (e.g. a container's `veth`).
//!
//! `NetNs::from_name("blue")` opens `/run/netns/blue` (the `ip netns add`
//! convention); `CaptureBuilder::netns(&ns)` creates the AF_PACKET socket inside
//! that namespace so it binds to *its* interfaces. The socket is
//! namespace-independent once created, so the returned `Capture` is used
//! normally from this thread. Requires `CAP_SYS_ADMIN` (+ `CAP_NET_RAW`).
//!
//! ```sh
//! sudo ip netns add blue
//! sudo ip -n blue link add veth0 type veth
//! cargo run --example monitor_netns_capture --features "tokio" -- blue veth0
//! ```

use netring::Capture;
use netring::netns::NetNs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ns_name = std::env::args().nth(1).unwrap_or_else(|| "blue".into());
    let iface = std::env::args().nth(2).unwrap_or_else(|| "veth0".into());

    let ns = NetNs::from_name(&ns_name)?;
    eprintln!(
        "capturing on {iface} inside netns {} (inode {}) — Ctrl-C to stop",
        ns.label(),
        ns.inode()?,
    );

    let mut cap = Capture::builder().interface(&iface).netns(&ns)?;

    let mut pkts = cap.packets();
    let mut seen = 0;
    while seen < 20 {
        let Some(pkt) = pkts.next_packet() else { break };
        println!(
            "[{}.{:09}] {} bytes",
            pkt.timestamp().sec,
            pkt.timestamp().nsec,
            pkt.len()
        );
        seen += 1;
    }
    Ok(())
}
