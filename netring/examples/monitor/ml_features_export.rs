//! Issue #32: export CICFlowMeter ML features per flow.
//!
//! Arms `MonitorBuilder::on_ml_features` and prints the CICFlowMeter feature
//! vector (totals + throughput + the IAT / active-idle block that the summary
//! flow record drops) for every flow at flow end — the shape you'd feed to an
//! offline ML pipeline (serialize `CicFlowFeatures` via `serde` for CSV/JSON).
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_ml_features --features "ml-features,tokio" -- eth0
//! ```

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_ml_features: CICFlowMeter features per flow on {iface} (Ctrl-C to stop)");

    // CSV-ish header for the few columns we print here.
    println!("duration_us,fwd_pkts,bwd_pkts,fwd_bytes,bwd_bytes,pkts_per_sec");

    Monitor::builder()
        .interface(&iface)
        .name("ml-features")
        .protocol::<Tcp>()
        .on_ml_features(|f: &flowscope::CicFlowFeatures| {
            println!(
                "{},{},{},{},{},{:.1}",
                f.flow_duration_us,
                f.total_fwd_packets,
                f.total_bwd_packets,
                f.total_fwd_bytes,
                f.total_bwd_bytes,
                f.flow_packets_per_sec,
            );
        })
        .build()?
        .run_for(Duration::from_secs(300))
        .await?;

    Ok(())
}
