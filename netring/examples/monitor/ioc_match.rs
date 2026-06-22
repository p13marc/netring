//! Issue #48: passive threat-intel (IOC) matching.
//!
//! Loads a small blocklist of indicators of compromise — bad IPs, bad domains
//! (subdomain-aware), and bad JA4 TLS fingerprints — and passively matches them
//! against every flow IP, DNS query, TLS SNI/JA4, and HTTP `Host` on the wire,
//! emitting an `ioc_match` anomaly per hit. No active lookups; the equivalent of
//! a Zeek Intel framework / Suricata dataset tap.
//!
//! In production the [`IocSet`] is populated from a feed (MISP, a threat-intel
//! provider, an internal blocklist); here a couple of illustrative entries.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_ioc --features "tokio,dns,tls,http" -- eth0
//! ```

use std::net::Ipv4Addr;
use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    let iocs = IocSet::new()
        .ip(Ipv4Addr::new(203, 0, 113, 7).into()) // a known C2 IP
        .domains(["evil.example", "c2.example.net"]) // subdomain-aware
        .ja4("t13d1516h2_8daaf6152771_b186095e22b6"); // a malware client JA4

    eprintln!("monitor_ioc: matching traffic on {iface} against the blocklist (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .name("ioc")
        .ioc(iocs)
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
