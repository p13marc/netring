//! Issue #46: evaluate Sigma rules over live DNS/HTTP/TLS records.
//!
//! Loads an inline Sigma rule pack (in practice you'd
//! `SigmaRuleSet::from_dir("/etc/netring/sigma")`) and arms it with
//! `MonitorBuilder::sigma`. Every parsed DNS query / HTTP request / TLS
//! handshake is matched against the rules whose `logsource.category` maps to
//! that surface; a `sigma_match` anomaly is printed per hit.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_sigma_rules --features "sigma,dns,tls,http,tokio,emit" -- eth0
//! ```

use std::time::Duration;

use netring::prelude::*;

/// A tiny inline rule pack. Each `---`-separated document is one Sigma rule.
const RULES: &str = r#"
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
title: Outdated curl user agent
id: demo-http-curl7
level: low
logsource:
  category: proxy
detection:
  selection:
    user_agent|startswith: 'curl/7.'
  condition: selection
"#;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let rules = SigmaRuleSet::from_yaml_str(RULES)?;
    eprintln!(
        "monitor_sigma_rules: evaluating {} Sigma rule(s) on {iface} (Ctrl-C to stop)",
        rules.len()
    );

    Monitor::builder()
        .interface(&iface)
        .name("sigma")
        .sigma(rules)
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
