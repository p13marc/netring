//! Issue #28: passive L2 neighbor discovery via LLDP + CDP.
//!
//! Watches for LLDP (IEEE 802.1AB) and CDP (Cisco) announcements — the frames
//! switches, routers, APs, and IP phones broadcast about themselves — and
//! emits the device facts they leak: chassis/device id, port, system name,
//! platform, and capabilities. The network-infrastructure half of an asset
//! inventory; no active probing.
//!
//! **Note:** LLDP/CDP are link-local multicast. The interface must actually
//! receive them — run on a switch-port-facing NIC in promiscuous mode (many
//! host stacks filter these frames by default).
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_l2_discovery --features "tokio,lldp,cdp,emit" -- eth0
//! ```

use std::time::Duration;

use flowscope::{CdpMessage, LldpMessage};
use netring::prelude::*;

fn bytes_str<B: AsRef<[u8]>>(b: Option<&B>) -> String {
    b.map(|v| String::from_utf8_lossy(v.as_ref()).into_owned())
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    Monitor::builder()
        .interface(&iface)
        .name("l2-discovery")
        .on_lldp(|m: &LldpMessage, ctx: &mut Ctx<'_>| {
            ctx.emit("LldpNeighbor", Severity::Info)
                .with("chassis", format!("{:?}", m.chassis_id))
                .with("port", format!("{:?}", m.port_id))
                .with("system_name", bytes_str(m.system_name.as_ref()))
                .with_metric("ttl_s", m.ttl_seconds as f64)
                .emit();
            Ok(())
        })
        .on_cdp(|m: &CdpMessage, ctx: &mut Ctx<'_>| {
            ctx.emit("CdpNeighbor", Severity::Info)
                .with("device_id", bytes_str(m.device_id.as_ref()))
                .with("platform", bytes_str(m.platform.as_ref()))
                .with("software", bytes_str(m.software_version.as_ref()))
                .emit();
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
