//! Declarative backend selection (issue #106) — one line picks the capture
//! backend instead of hand-wiring `interface` / `xdp_interface` / `xdp_queues`.
//!
//! [`Backend::Auto`] runs a cap-free capability probe and resolves to a
//! concrete backend (self-loading AF_XDP when the `xdp-loader` feature is
//! compiled in, else AF_PACKET), **logging the chosen plan** so it is never a
//! black box. The resolved plan is also queryable via
//! `MonitorBuilder::resolved_capture_plan()` before `build()`.
//!
//! ```sh
//! cargo run --example monitor_auto_backend --features "tokio,flow" -- eth0
//! # AF_XDP rung lights up only when built with the loader:
//! cargo run --example monitor_auto_backend \
//!     --features "tokio,flow,af-xdp,xdp-loader" -- eth0
//! ```
//!
//! `lo` works for smoke-testing. The example prints the resolved plan, then
//! counts TCP flow starts for a few seconds.

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `tracing` shows the `netring::monitor::auto` plan line `capture()` logs.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("netring::monitor::auto=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .ok();

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let dur_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    // One declarative line: probe the host + interface, pick + log the backend.
    let builder = Monitor::builder()
        .capture(&iface, Backend::Auto)
        .protocol::<Tcp>();

    // Observe what Auto chose without scraping logs.
    for (iface, plan) in builder.resolved_capture_plan() {
        eprintln!("monitor_auto_backend: {iface} -> {plan}");
    }

    eprintln!("monitor_auto_backend: capturing on {iface} for {dur_secs}s");

    builder
        .on::<FlowStarted<Tcp>>(|_evt: &FlowStarted<Tcp>| {
            eprintln!("flow started");
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(dur_secs))
        .await?;

    eprintln!("monitor_auto_backend: done");
    Ok(())
}
