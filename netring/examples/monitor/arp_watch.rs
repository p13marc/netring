//! ARP watch — L2 visibility + ARP-spoof / binding-change detection.
//!
//! Two surfaces on one Monitor, both from the `arp` feature:
//!
//! 1. **Raw ARP feed** — `.on_arp(...)` prints every parsed `ArpMessage`:
//!    who-has requests, is-at replies, gratuitous announcements, RARP.
//! 2. **Anomalies** — `.on_arp_anomaly(...)` raises the security signal:
//!    `SpoofSuspected` (a gratuitous reply whose target MAC ≠ sender MAC —
//!    classic cache poisoning) and `BindingChanged` (a known IP now claims
//!    a different MAC — failover or MITM). Each is also pushed to the
//!    anomaly sink so it lands in your normal alert pipeline.
//!
//! ARP is L2 (no 5-tuple), so arming any ARP hook makes the Monitor
//! capture every frame (the kernel prefilter can't narrow to ARP) — fine
//! for an L2 watch, but don't combine it with a narrow L4 workload
//! expecting the kernel to shed the rest.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_arp_watch \
//!     --features "monitor" -- eth0 300
//! ```
//!
//! Arguments: `<iface>` (default `lo`) `<seconds>` (default 300).
//!
//! Smoke test on a real segment: `arping -U <your-ip>` sends a gratuitous
//! ARP; a tool like `arpspoof` (dsniff) triggers `SpoofSuspected`.

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let dur_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    eprintln!("monitor_arp_watch: watching ARP on {iface} for {dur_secs}s");
    eprintln!("                  press Ctrl-C to stop early");

    Monitor::builder()
        .interface(&iface)
        // The gateway's virtual MAC is trusted — a VRRP failover that moves
        // it to the backup router must not page anyone. (Example value.)
        // .arp_allow("10.0.0.1".parse()?, MacAddr([0x00, 0x00, 0x5e, 0x00, 0x01, 0x01]))
        .arp_warmup(Duration::from_secs(3))
        .on_arp(|m, _ctx| {
            // Raw feed: one line per ARP message.
            let kind = if m.is_likely_spoof() {
                " [SPOOF?]"
            } else if m.is_gratuitous() {
                " [gratuitous]"
            } else {
                ""
            };
            println!(
                "arp {:<12} {} is-at {:?} → {}{}",
                m.oper.as_str(),
                m.sender_ip,
                m.sender,
                m.target_ip,
                kind,
            );
            Ok(())
        })
        .on_arp_anomaly(|a, ctx| {
            // Security signal: log + push to the anomaly sink.
            eprintln!(
                "!! {} — {} claims {:?}{}",
                a.kind.as_str(),
                a.ip(),
                a.mac(),
                a.prior_mac
                    .map(|p| format!(" (was {p:?})"))
                    .unwrap_or_default(),
            );
            ctx.emit(a.kind.as_str(), a.kind.severity())
                .with("ip", a.ip().to_string())
                .with("mac", format!("{:?}", a.mac()))
                .emit();
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(dur_secs))
        .await?;

    eprintln!("monitor_arp_watch: done");
    Ok(())
}
