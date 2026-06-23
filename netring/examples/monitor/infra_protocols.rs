//! Issue #30: passive visibility into UDP infrastructure protocols —
//! NTP, SNMP, TFTP, RADIUS.
//!
//! Arms the four `Protocol` markers and prints each parsed message. These are
//! the unglamorous-but-security-relevant services an NSM wants to see: rogue
//! time sources (NTP), cleartext community strings (SNMP v1/v2c), unauthenticated
//! file transfers (TFTP), and the auth fabric (RADIUS).
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_infra_protocols --features "infra-protocols,tokio,emit" -- eth0
//! ```

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_infra_protocols: NTP/SNMP/TFTP/RADIUS on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .name("infra")
        .protocol::<Ntp>()
        .on::<Ntp>(|m: &flowscope::ntp::NtpMessage| {
            println!("ntp    {m:?}");
            Ok(())
        })
        .protocol::<Snmp>()
        .on::<Snmp>(|m: &flowscope::snmp::SnmpMessage| {
            println!("snmp   {m:?}");
            Ok(())
        })
        .protocol::<Tftp>()
        .on::<Tftp>(|m: &flowscope::tftp::TftpMessage| {
            println!("tftp   {m:?}");
            Ok(())
        })
        .protocol::<Radius>()
        .on::<Radius>(|m: &flowscope::radius::RadiusMessage| {
            println!("radius {m:?}");
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
