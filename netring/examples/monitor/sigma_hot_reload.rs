//! Issue #53: hot-reload the Sigma rule set while the monitor runs.
//!
//! The Sigma sibling of `monitor_ioc_reload`. Arms a Monitor with an initial
//! rule pack, grabs a `ReloadHandle`, and spawns a background task that swaps in
//! a fresh `SigmaRuleSet` — simulating a rule-feed refresh (a SIEM content push,
//! a file watcher over `/etc/netring/sigma`, a SIGHUP). The swap is lock-free:
//! in-flight records never see a torn rule set, and the capture loop never
//! blocks.
//!
//! Caveat (see `ReloadHandle::set_sigma`): the *set of L7 categories* whose
//! handlers run is fixed at build from the initial rule set, so a reload that
//! adds a rule in a brand-new category (e.g. the first `tls` rule when you
//! started with only `dns`) isn't evaluated until rebuild. Same-category content
//! refreshes hot-swap fully.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_sigma_reload --features "sigma,dns,tls,http,tokio" -- eth0
//! ```

use std::time::Duration;

use netring::monitor::Monitor;
use netring::monitor::sigma::SigmaRuleSet;
use netring::prelude::*;

/// Stand-in for "pull the latest Sigma content from your feed". A new DNS rule
/// appears on each refresh; staying in the `dns` category keeps the reload fully
/// effective (see the module caveat).
fn load_rules(round: u32) -> SigmaRuleSet {
    let yaml = format!(
        r#"
title: DNS lookup containing 'evil'
id: demo-dns-evil
level: high
logsource:
  category: dns
detection:
  selection:
    query|contains: 'evil'
  condition: selection
---
title: Rotating C2 domain (feed round {round})
id: demo-dns-rotating-{round}
level: high
logsource:
  category: dns
detection:
  selection:
    query|contains: 'rotating-{round}.bad'
  condition: selection
"#
    );
    SigmaRuleSet::from_yaml_str(&yaml).expect("inline rules parse")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    let monitor = Monitor::builder()
        .interface(&iface)
        .name("sigma-reload")
        .sigma(load_rules(0))
        .sink(StdoutSink::default())
        .build()?;

    // Grab the handle BEFORE running, then drive reloads from a control task.
    let handle = monitor.reload_handle();
    tokio::spawn(async move {
        let mut round = 1;
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            if handle.set_sigma(load_rules(round)) {
                eprintln!("[sigma-reload] swapped in rule set round {round}");
            }
            round += 1;
        }
    });

    eprintln!("monitor_sigma_reload: evaluating {iface}; rule set refreshes every 60s");
    monitor.run_until_signal().await?;
    Ok(())
}
