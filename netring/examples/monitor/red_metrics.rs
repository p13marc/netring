//! RED metrics (issue #122): request **Rate**, **Error** rate and **Duration**
//! quantiles per protocol — the SRE "RED method" over passively-observed L7.
//!
//! DNS is graded per-response (rcode + timeouts, latency from the query→response
//! RTT); flows per-connection (end reason, duration = lifetime).
//! `.on_red(period, |report| …)` delivers a [`RedReport`] every period.
//!
//! ```sh
//! cargo run --example monitor_red_metrics --features "tokio,flow,dns" -- eth0
//! ```

use std::time::Duration;

use netring::monitor::red::RedProto;
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_red_metrics: 10s RED per protocol on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .on_red(Duration::from_secs(10), |r| {
            for proto in [RedProto::Dns, RedProto::Flow] {
                let p50 = r.duration_ms(proto, 0.50).unwrap_or(0.0);
                let p99 = r.duration_ms(proto, 0.99).unwrap_or(0.0);
                println!(
                    "{proto:?}: {:.1} req/s  errors {:.1}%  p50 {p50:.1}ms  p99 {p99:.1}ms",
                    r.rate(proto),
                    r.error_ratio(proto) * 100.0,
                );
            }
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_until_signal()
        .await?;

    Ok(())
}
