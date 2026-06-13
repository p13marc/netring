//! Report stream (0.22 §3): ship a periodic, typed snapshot of derived
//! state to a sink — the third output shape beside per-event anomalies
//! and broadcast event streams (the Suricata `stats.log` / Zeek
//! `conn.log` shape).
//!
//! This demo registers a per-app bandwidth primitive and emits a
//! [`BandwidthSnapshot`] every 5s as **newline-delimited JSON** via
//! `report_to(period, build, JsonReportSink)` — pipe it to `jq`, Vector,
//! or Filebeat. The `report(period, |snap| …)` closure form (for ad-hoc
//! / println reporting) is shown commented out.
//!
//! ```sh
//! cargo run --example monitor_report_stream \
//!     --features "monitor-quickstart" -- eth0 | jq .
//! ```

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_report_stream: bandwidth snapshots as JSON on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .bandwidth_by_app()
        // Typed report → JSON sink. `build` turns the cadence snapshot
        // into an owned `BandwidthSnapshot` (a `Report`); `JsonReportSink`
        // writes one JSON line per period.
        .report_to(
            Duration::from_secs(5),
            |snap: ReportSnapshot<'_, '_>| {
                snap.bandwidth()
                    .map(|bw| bw.to_snapshot(10))
                    .unwrap_or(BandwidthSnapshot { apps: vec![] })
            },
            JsonReportSink,
        )
        // Ad-hoc closure form (no typed Report / sink):
        // .report(Duration::from_secs(5), |snap| {
        //     if let Some(bw) = snap.bandwidth() {
        //         eprintln!("total: {:.0} B/s across {} apps", bw.total(), bw.app_count());
        //     }
        //     Ok(())
        // })
        .sink(StdoutSink::default())
        .build()?
        .run_until_signal()
        .await?;

    Ok(())
}
