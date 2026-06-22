//! Issue #28: passive MAC-keyed asset inventory.
//!
//! Enables the asset [`Inventory`](netring::prelude::Inventory) and prints each
//! device as it's discovered or its record changes. The inventory is fed by
//! whichever discovery protocols are compiled in — ARP & NDP (host presence +
//! IP↔MAC bindings), LLDP & CDP (switches / routers / APs), and the UDP
//! broadcast/discovery datagrams DHCP, SSDP, NetBIOS-NS & mDNS (hostnames,
//! firmware banners, fingerprints). No active probing; every fact is leaked by
//! the device itself.
//!
//! `on_asset` is an inventory-event stream: it fires when an observation
//! creates a new [`Asset`](netring::prelude::Asset) or changes an existing one
//! (a freshly-learned IP, hostname, platform, …) — not on every frame.
//!
//! **Live-capture note:** LLDP/CDP are link-local multicast; the interface must
//! receive them (promiscuous / multicast membership). ARP/NDP are seen on any
//! broadcast domain.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_asset_inventory \
//!     --features "tokio,asset,arp,ndp,lldp,cdp" -- eth0
//! ```

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_asset_inventory: building a passive inventory on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .name("asset-inventory")
        .asset_inventory(8192)
        .on_asset(|asset: &Asset, _ctx| {
            println!(
                "[asset] mac={} ipv4={:?} host={:?} platform={:?} via={:?}",
                asset.mac,
                asset.ipv4,
                asset.hostname.as_deref().unwrap_or("-"),
                asset.platform.as_deref().unwrap_or("-"),
                asset.seen_via,
            );
            Ok(())
        })
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
