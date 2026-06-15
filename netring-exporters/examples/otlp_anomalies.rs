//! Export netring anomalies to an OTLP collector (0.25 W5).
//!
//! Wires [`OtlpAnomalySink`] as the monitor's anomaly sink — every anomaly your
//! detectors emit is shipped as an OpenTelemetry LogRecord to the collector's
//! `/v1/logs` endpoint. A 5-second heartbeat anomaly is emitted so you can see
//! records arrive even on a quiet link.
//!
//! ```sh
//! # point at your OTLP/HTTP collector (default: local):
//! cargo run -p netring-exporters --example otlp_anomalies -- http://localhost:4318/v1/logs eth0
//! ```

use std::time::Duration;

use netring::anomaly::Severity;
use netring::ctx::Ctx;
use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;
use netring_exporters::OtlpAnomalySink;

#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:4318/v1/logs".to_string());
    let iface = std::env::args().nth(2).unwrap_or_else(|| "lo".to_string());

    let monitor = Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        .sink(OtlpAnomalySink::new(endpoint.clone(), "netring-demo"))
        // Heartbeat anomaly every 5s — real anomalies come from your detectors;
        // this just proves the export path end to end.
        .tick_ctx(Duration::from_secs(5), |ctx: &mut Ctx<'_>| {
            // `ctx.emit(kind, severity)` is the one-line anomaly builder.
            ctx.emit("heartbeat", Severity::Info)
                .with("note", "demo OTLP export")
                .emit();
            Ok(())
        })
        .build()?;

    eprintln!("# exporting anomalies to {endpoint} on {iface} (Ctrl-C to stop)");
    monitor.run_until_signal().await
}
