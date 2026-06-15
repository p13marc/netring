//! Flow-record export — the NetFlow/IPFIX/`conn.log` output shape.
//!
//! Emits one [`FlowRecord`](netring::export::FlowRecord) per completed flow to
//! an exporter, plus **interim records for long-lived flows** on an active
//! timeout (0.25 W1c) — the standard NetFlow behaviour where a flow alive
//! longer than the timeout gets periodic snapshots, not just one record at the
//! end.
//!
//! ```sh
//! cargo run --example monitor_flow_export --features monitor -- eth0
//! # NDJSON flow records on stdout; pipe into Vector / Loki / jq:
//! #   cargo run ... | jq 'select(.proto=="Tcp")'
//! ```
//!
//! For IPFIX/NetFlow v10 wire output to a collector, swap `JsonFlowExporter`
//! for `IpfixExporter::new(socket, observation_domain_id)` (feature `ipfix`).

use std::time::Duration;

use netring::export::JsonFlowExporter;
use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;

#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".to_string());

    let monitor = Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        // One newline-delimited JSON record per completed flow.
        .export_flows(JsonFlowExporter::stdout())
        // 0.25 W1c: also emit an interim record (reason == null / is_ongoing)
        // every 30s for flows still alive — so a long download/stream shows up
        // before it finishes.
        .export_active_timeout(Duration::from_secs(30))
        // A second exporter: a closure is a FlowExporter too. Tag the ongoing
        // ones so the difference is visible on stdout.
        .export_flows(|rec: &netring::export::FlowRecord| {
            if rec.is_ongoing() {
                eprintln!(
                    "# ongoing  {:?} {} ↔ {} : {} bytes so far",
                    rec.proto,
                    rec.a,
                    rec.b,
                    rec.total_bytes()
                );
            }
        })
        .build()?;

    println!("# exporting TCP flow records on {iface} (Ctrl-C to stop)");
    monitor.run_until_signal().await
}
