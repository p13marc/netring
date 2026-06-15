//! 0.25 W1f (C5): structured **JSON logging** of a Monitor's anomalies and
//! capture telemetry via `tracing-subscriber`'s JSON formatter — the
//! newline-delimited JSON shape Vector / Loki / Elasticsearch ingest directly,
//! with no custom netring sink.
//!
//! Two sources of structured events:
//! - **Anomalies** flow through [`TracingSink`], which re-emits each one as a
//!   `tracing` event at the matching level — so the JSON subscriber renders it.
//! - **Per-flow** + **capture-telemetry** events are emitted by hand with
//!   `tracing::info!` and structured fields, so they share the same JSON
//!   pipeline as the anomalies.
//!
//! Run (Ctrl-C to stop; `RUST_LOG` tunes the level):
//!
//! ```sh
//! cargo run --example monitor_tracing_json --features monitor -- eth0
//! # each line is a JSON object: {"timestamp":..,"level":"INFO","fields":{..},..}
//! # pipe into a collector:  ... | vector --config vector.toml
//! ```

use std::time::Duration;

use netring::monitor::Monitor;
use netring::prelude::TracingSink;
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowEnded;

#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    // One JSON object per log line on stdout. `RUST_LOG` (env-filter) controls
    // the level; default to `info` so the demo prints without configuration.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .init();

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".to_string());

    let monitor = Monitor::builder()
        .interface(&iface)
        .name("tracing-json-demo")
        .protocol::<Tcp>()
        // Anomalies → `tracing` events at their severity level (JSON-rendered).
        .sink(TracingSink::default())
        // One structured JSON event per completed TCP flow.
        .on::<FlowEnded<Tcp>>(|f: &FlowEnded<Tcp>| {
            tracing::info!(
                target: "netring.flow",
                src = %f.key.a,
                dst = %f.key.b,
                packets = f.stats.packets_initiator + f.stats.packets_responder,
                bytes = f.stats.bytes_initiator + f.stats.bytes_responder,
                reason = ?f.reason,
                "tcp flow ended"
            );
            Ok(())
        })
        // Capture telemetry every 2s → one structured JSON event per source.
        .on_capture_stats(Duration::from_secs(2), |t, _ctx| {
            tracing::info!(
                target: "netring.telemetry",
                source = t.source.0,
                packets = t.packets,
                drops = t.drops,
                freezes = t.freezes,
                "capture telemetry"
            );
            Ok(())
        })
        .build()?;

    println!("# logging TCP flows + telemetry as JSON on {iface} (Ctrl-C to stop)");
    monitor.run_until_signal().await
}
