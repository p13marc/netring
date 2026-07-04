//! Owner-attributed bandwidth (issue #130): track throughput by a caller-defined
//! *owner* — a tenant / container / cgroup / subscriber — instead of by app
//! label.
//!
//! `.with_flow_attribution(hook)` maps each flow's 5-tuple to an opaque
//! [`Attribution`]; `.on_owner_bandwidth(period, |report| …)` then reports the
//! top owners plus an unattributed bucket. Arming `owner_bandwidth` without a
//! hook is a build error (`BuildError::AttributionHookRequired`).
//!
//! Here we attribute by /24 subnet as a stand-in for a real tenant map.
//!
//! ```sh
//! cargo run --example monitor_owner_bandwidth --features "tokio,flow" -- eth0
//! ```

use std::net::IpAddr;
use std::time::Duration;

use flowscope::correlate::Attribution;
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_owner_bandwidth: per-/24 bandwidth on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        // Attribute each flow to its source /24 (a stand-in for a tenant map).
        .with_flow_attribution(|key| match key.a.ip() {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Some(Attribution(
                    u64::from(o[0]) << 16 | u64::from(o[1]) << 8 | u64::from(o[2]),
                ))
            }
            IpAddr::V6(_) => None,
        })
        .on_owner_bandwidth(Duration::from_secs(10), |r| {
            println!("── owner bandwidth ({:?}) ──", r.semantics());
            for (owner, bps) in r.top(5) {
                println!("  owner {:#08x}  {bps:>12.0} B/s", owner.0);
            }
            println!(
                "  unattributed {:.0} B/s ({:.0}%)",
                r.unknown_rate(),
                r.unknown_share() * 100.0
            );
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_until_signal()
        .await?;

    Ok(())
}
