//! Custom port labels (0.22 §2.2): teach a monitor the names of your
//! site's internal services on non-standard ports, so bandwidth-by-app
//! (and any `app_label` lookup) labels them instead of falling back to
//! the L4-canonical name.
//!
//! `LabelTable::new()` inherits flowscope's built-in well-known table
//! (so `80 → "http"`, `53 → "dns"`, … still work); `.set(proto, port,
//! label)` adds your overlays. `LabelTable::standalone()` starts empty
//! (whitelist-only) if you don't want the built-ins.
//!
//! ```sh
//! cargo run --example monitor_label_table \
//!     --features "monitor-quickstart" -- eth0
//! ```

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    // Inherit the built-in well-known ports, then add site overlays.
    let mut table = LabelTable::new();
    table.set(L4Proto::Tcp, 8765, "grpc-internal");
    table.set(L4Proto::Tcp, 9101, "telemetry");
    table.set(L4Proto::Udp, 6831, "jaeger");

    eprintln!("monitor_label_table: per-app bandwidth on {iface} with custom labels (Ctrl-C)");

    Monitor::builder()
        .interface(&iface)
        .label_table(table) // threaded into app_label lookups
        .on_bandwidth(Duration::from_secs(5), |bw: &BandwidthReport<'_>| {
            println!("─── bandwidth by app ───");
            for (app, bps) in bw.top(15) {
                // "grpc-internal" / "telemetry" / "jaeger" appear here
                // instead of "tcp"/"udp" for those ports.
                println!("{app:<16} {bps:>12.0} B/s");
            }
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_until_signal()
        .await?;

    Ok(())
}
