//! Issue #30: passive visibility into the application / OT / VPN Tier-2
//! protocols — FTP, SMTP, Modbus, DNP3, STUN, WireGuard.
//!
//! Arms the six `Protocol` markers and prints each parsed message. Covers mail
//! and file transfer (SMTP/FTP — cleartext creds, exfil), industrial control
//! (Modbus/DNP3 — unauthorized PLC/RTU writes), and NAT-traversal / VPN
//! (STUN/WireGuard — tunnel endpoints, covert channels).
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_app_protocols \
//!   --features "ftp,smtp,modbus,dnp3,stun,wireguard,tokio,emit" -- eth0
//! ```

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_app_protocols: FTP/SMTP/Modbus/DNP3/STUN/WireGuard on {iface} (Ctrl-C)");

    Monitor::builder()
        .interface(&iface)
        .name("app")
        .protocol::<Ftp>()
        .on::<Ftp>(|m: &flowscope::ftp::FtpMessage| {
            println!("ftp       {m:?}");
            Ok(())
        })
        .protocol::<Smtp>()
        .on::<Smtp>(|m: &flowscope::smtp::SmtpMessage| {
            println!("smtp      {m:?}");
            Ok(())
        })
        .protocol::<Modbus>()
        .on::<Modbus>(|m: &flowscope::modbus::ModbusMessage| {
            println!("modbus    {m:?}");
            Ok(())
        })
        .protocol::<Dnp3>()
        .on::<Dnp3>(|m: &flowscope::dnp3::DnpMessage| {
            println!("dnp3      {m:?}");
            Ok(())
        })
        .protocol::<Stun>()
        .on::<Stun>(|m: &flowscope::stun::StunMessage| {
            println!("stun      {m:?}");
            Ok(())
        })
        .protocol::<WireGuard>()
        .on::<WireGuard>(|m: &flowscope::wireguard::WireGuardMessage| {
            println!("wireguard {m:?}");
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
