//! Export netring capture telemetry to an OTLP collector as metrics (issue #52).
//!
//! Wires [`OtlpMetricsExporter`] into an
//! [`on_capture_stats`](netring::monitor::MonitorBuilder::on_capture_stats)
//! handler — every sample period the per-source capture counters
//! (`netring.capture.packets` / `.drops` / `.freezes` cumulative Sums, plus the
//! windowed `.drop_rate` Gauge) are POSTed to the collector's `/v1/metrics`
//! endpoint as OTLP/HTTP JSON.
//!
//! ```sh
//! # point at your OTLP/HTTP collector (default: local):
//! cargo run -p netring-exporters --example otlp_metrics -- http://localhost:4318/v1/metrics eth0
//! ```

use std::time::Duration;

use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;
use netring_exporters::OtlpMetricsExporter;

#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:4318/v1/metrics".to_string());
    let iface = std::env::args().nth(2).unwrap_or_else(|| "lo".to_string());

    let exporter = OtlpMetricsExporter::new(endpoint.clone(), "netring-demo");

    let monitor = Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        // Sample + push capture metrics every 10s. The exporter blocks on the
        // HTTP round-trip with a short timeout; on failure it warns and returns
        // an error we deliberately ignore so an unreachable collector never
        // tears down the capture.
        .on_capture_stats(Duration::from_secs(10), move |t, _ctx| {
            let _ = exporter.export(t);
            Ok(())
        })
        .build()?;

    eprintln!("# exporting capture metrics to {endpoint} on {iface} (Ctrl-C to stop)");
    monitor.run_until_signal().await
}
