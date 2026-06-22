//! Issue #28 (part 1): passive asset discovery over DHCP / SSDP / NetBIOS-NS.
//!
//! Surfaces the three flowscope 0.18 broadcast/discovery datagram protocols
//! and prints the device facts each one leaks onto the LAN — no active
//! probing, no payload decryption:
//!
//!   * **DHCP** (67/68) — `client_mac` → `hostname` (opt 12), requested IP,
//!     `vendor_class` (opt 60), and the Fingerbank-style `fingerprint()`
//!     (opt 55 + opt 60) for OS/device classification.
//!   * **SSDP** (1900) — UPnP `server` firmware banner, `location` URL, and
//!     `usn` / `st` service type for IoT and consumer devices.
//!   * **NetBIOS-NS** (137) — queried/registered NetBIOS `queried_name` and
//!     `answer_addresses` (legacy Windows hostnames).
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_asset_discovery \
//!     --features "tokio,asset-protocols,emit" -- eth0
//! ```

use std::time::Duration;

use flowscope::dhcp::DhcpMessage;
use flowscope::netbios_ns::NbnsMessage;
use flowscope::ssdp::SsdpMessage;
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    Monitor::builder()
        .interface(&iface)
        .name("asset-discovery")
        // ── DHCP ───────────────────────────────────────────────────────────
        .protocol::<Dhcp>()
        .on_ctx::<Dhcp>(|m: &DhcpMessage, ctx: &mut Ctx<'_>| {
            if let Some(mac) = m.client_mac {
                let mut report = ctx
                    .emit("DhcpAsset", Severity::Info)
                    .with("mac", format!("{mac}"));
                if let Some(host) = &m.hostname {
                    report = report.with("hostname", host.clone());
                }
                if let Some(fp) = m.fingerprint() {
                    report = report.with("fingerprint", fp);
                }
                report.emit();
            }
            Ok(())
        })
        // ── SSDP ───────────────────────────────────────────────────────────
        .protocol::<Ssdp>()
        .on_ctx::<Ssdp>(|m: &SsdpMessage, ctx: &mut Ctx<'_>| {
            if let Some(server) = &m.server {
                ctx.emit("SsdpAsset", Severity::Info)
                    .with("server", server.clone())
                    .with("usn", m.usn.clone().unwrap_or_default())
                    .emit();
            }
            Ok(())
        })
        // ── NetBIOS-NS ─────────────────────────────────────────────────────
        .protocol::<Nbns>()
        .on_ctx::<Nbns>(|m: &NbnsMessage, ctx: &mut Ctx<'_>| {
            if let Some(name) = &m.queried_name {
                ctx.emit("NbnsAsset", Severity::Info)
                    .with("name", name.clone())
                    .emit();
            }
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
