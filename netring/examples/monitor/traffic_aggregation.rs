//! Traffic aggregation (issue #121): rolling top-talkers, a host-pair traffic
//! matrix, and top DNS names / TLS SNI — the "who's busy, talking to whom, and
//! resolving what" dashboard.
//!
//! `.on_aggregate(period, |report| …)` fires an [`AggregateReport`] every period;
//! each dimension is toggleable via `aggregate_with(AggregateConfig)`.
//!
//! ```sh
//! cargo run --example monitor_traffic_aggregation \
//!     --features "tokio,flow,dns,tls" -- eth0
//! ```

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_traffic_aggregation: 10s rolling top-N on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .on_aggregate(Duration::from_secs(10), |r| {
            println!("── aggregate ──────────────────────────────");
            for (ip, bps) in r.top_talkers(5) {
                println!("  talker {ip:<39} {bps:>12.0} B/s");
            }
            for ((a, b), bps) in r.top_pairs(5) {
                println!("  pair   {a} → {b:<28} {bps:>12.0} B/s");
            }
            for (name, qps) in r.top_domains(5) {
                println!("  domain {name:<39} {qps:>10.2} q/s");
            }
            for (sni, hps) in r.top_sni(5) {
                println!("  sni    {sni:<39} {hps:>10.2} hs/s");
            }
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_until_signal()
        .await?;

    Ok(())
}
