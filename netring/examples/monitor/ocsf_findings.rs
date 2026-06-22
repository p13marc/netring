//! Issue #50: emit detections as OCSF Detection Findings.
//!
//! Pairs the threat-intel IOC matcher with the [`OcsfSink`], so every match —
//! and any other anomaly the Monitor raises — is written as an OCSF 2004
//! Detection Finding NDJSON line. Point the output at AWS Security Lake, Splunk
//! (OCSF add-on), or any OCSF 1.x consumer:
//!
//! ```sh
//! cargo run --example monitor_ocsf --features "tokio,ocsf-sink,dns,tls" -- eth0 \
//!     | aws s3 cp - s3://my-security-lake/netring/findings.ndjson
//! ```
//!
//! [`OcsfSink`]: netring::prelude::OcsfSink

use std::net::Ipv4Addr;
use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    let iocs = IocSet::new()
        .ip(Ipv4Addr::new(203, 0, 113, 7).into())
        .domains(["evil.example", "c2.example.net"]);

    eprintln!("monitor_ocsf: writing OCSF Detection Findings for {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .name("ocsf")
        .ioc(iocs)
        .sink(OcsfSink::stdout())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
