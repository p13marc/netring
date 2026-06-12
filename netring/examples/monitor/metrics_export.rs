//! 0.21 B.3 — `MetricsSink` Prometheus counter facade.
//!
//! Bridges `Monitor` anomalies to the `metrics` crate facade,
//! emitting one `netring_anomaly_total{kind, severity}` counter
//! per anomaly and one histogram observation per numeric metric
//! carried on the `AnomalyWriter`.
//!
//! `MetricsSink` is agnostic about the exporter — wire any
//! `metrics-exporter-*` crate downstream. This example uses
//! `metrics::with_local_recorder` + a snapshot recorder so the
//! demo is self-contained; production code would mount a
//! Prometheus or OTLP exporter at program start.
//!
//! ```sh
//! cargo run --example monitor_metrics_export \
//!     --features "monitor-quickstart" -- eth0 30
//! ```
//!
//! Arguments: `<iface>` (default `lo`) `<seconds>` (default 30).

use std::time::Duration;

use netring::anomaly::MetricsSink;
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let dur_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    eprintln!("monitor_metrics_export: counting anomalies on {iface} for {dur_secs}s");
    eprintln!(
        "                       counter=netring_anomaly_total{{kind, severity}}\n\
         monitor_metrics_export: histogram=netring_anomaly_metric{{metric}}"
    );
    eprintln!(
        "                       wire a metrics-exporter-prometheus / -otlp / -statsd\n\
         monitor_metrics_export: at process start to scrape these (see metrics-rs docs)"
    );

    Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        .on_ctx::<FlowStarted<Tcp>>(|evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
            let ts = ctx.ts;
            ctx.sink_mut()
                .begin("FlowStartedTcp", Severity::Info, ts)
                .with("src", format!("{}", evt.key.a))
                .with("dst", format!("{}", evt.key.b))
                .with_metric("dst_port", evt.key.b.port() as f64)
                .emit();
            Ok(())
        })
        .sink(MetricsSink::default().with_counter_name("netring_anomaly_total"))
        .build()?
        .run_for(Duration::from_secs(dur_secs))
        .await?;

    eprintln!("monitor_metrics_export: done");
    Ok(())
}
