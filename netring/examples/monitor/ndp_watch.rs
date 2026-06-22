//! NDP watch — IPv6 Neighbor Discovery visibility + NDP-spoof detection.
//!
//! The IPv6 sibling of `monitor_arp_watch`. Two surfaces from the `ndp`
//! feature:
//!
//! 1. **Raw NDP feed** — `.on_ndp(...)` prints every parsed `NdpMessage`
//!    (Neighbor Solicitation / Advertisement) with its target + MAC + flags.
//! 2. **Anomalies** — `.on_ndp_anomaly(...)` raises the security signal:
//!    `SpoofSuspected` (an unsolicited override NA carrying a MAC — the
//!    SLAAC cache-poisoning vector) and `BindingChanged` (a known IPv6 now
//!    claims a different MAC). Each also lands on the anomaly sink.
//!
//! NDP rides ICMPv6, so arming an NDP hook narrows the kernel prefilter to
//! ICMPv6 (proto 58) — cheaper than ARP's capture-all-EtherType term.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_ndp_watch --features "monitor" -- eth0 300
//! ```
//!
//! Arguments: `<iface>` (default `lo`) `<seconds>` (default 300).

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let dur_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    eprintln!("monitor_ndp_watch: watching NDP on {iface} for {dur_secs}s");
    eprintln!("                  press Ctrl-C to stop early");

    Monitor::builder()
        .interface(&iface)
        // .ndp_allow("fe80::1".parse()?, MacAddr([0x00, 0x00, 0x5e, 0x00, 0x02, 0x01]))
        .ndp_warmup(Duration::from_secs(3))
        .on_ndp(|m, _ctx| {
            let flag = if m.is_likely_spoof() {
                " [SPOOF?]"
            } else if m.is_unsolicited_override() {
                " [unsolicited]"
            } else {
                ""
            };
            println!(
                "ndp {:<13} {} is-at {:?}{}",
                m.kind.as_str(),
                m.target,
                m.lladdr,
                flag,
            );
            Ok(())
        })
        .on_ndp_anomaly(|a, ctx| {
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
                .emit();
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(dur_secs))
        .await?;

    eprintln!("monitor_ndp_watch: done");
    Ok(())
}
