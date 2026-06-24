//! Issue #53: hot-reload the IOC blocklist while the monitor runs.
//!
//! Arms a Monitor with an initial threat-intel set, grabs a `ReloadHandle`, and
//! spawns a background task that periodically swaps in a fresh set — simulating
//! a feed refresh (MISP, an internal blocklist, a file watcher). The swap is
//! lock-free: in-flight flows never see a torn set, and the capture loop is
//! never blocked.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_ioc_reload --features "tokio,dns,tls,http" -- eth0
//! ```

use std::net::Ipv4Addr;
use std::time::Duration;

use netring::monitor::Monitor;
use netring::monitor::ioc::IocSet;
use netring::prelude::*;

/// Stand-in for "pull the latest indicators from your feed".
fn load_iocs(round: u32) -> IocSet {
    IocSet::new()
        .ip(Ipv4Addr::new(203, 0, 113, 7).into())
        .domains(["evil.example", "c2.example.net"])
        // A new indicator appears on each refresh.
        .domain(format!("rotating-{round}.bad.example"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    let monitor = Monitor::builder()
        .interface(&iface)
        .name("ioc-reload")
        .ioc(load_iocs(0))
        .sink(StdoutSink::default())
        .build()?;

    // Grab the handle BEFORE running, then drive reloads from a control task.
    let handle = monitor.reload_handle();
    tokio::spawn(async move {
        let mut round = 1;
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            handle.set_ioc(load_iocs(round));
            eprintln!("[ioc-reload] swapped in blocklist round {round}");
            round += 1;
        }
    });

    eprintln!("monitor_ioc_reload: matching {iface}; blocklist refreshes every 60s");
    monitor.run_until_signal().await?;
    Ok(())
}
