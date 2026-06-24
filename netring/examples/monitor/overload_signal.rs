//! Issue #54: overload detection with hysteresis.
//!
//! Wires an [`OverloadDetector`] off `on_capture_stats` to print a debounced
//! Normal↔Emergency signal as the kernel ring's drop rate crosses the
//! thresholds. The capture pipeline has no upstream backpressure (the NIC keeps
//! sending), so the value is *knowing* when you're shedding — react however you
//! like (alert, autoscale, drop at your sink, bypass elephant flows).
//!
//! Run (generate load on the interface to see Emergency fire):
//!
//! ```sh
//! cargo run --example monitor_overload --features "tokio,flow" -- eth0
//! ```

use std::time::Duration;

use netring::monitor::Monitor;
use netring::monitor::overload::{OverloadConfig, OverloadDetector, OverloadState};
use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    // Enter Emergency at 5% drops; recover after 3 windows under 1%.
    let mut overload =
        OverloadDetector::new(OverloadConfig::default().enter_at(0.05).recover_at(0.01, 3));

    eprintln!("monitor_overload: watching {iface} for drop-rate overload (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .name("overload")
        .protocol::<Tcp>()
        .on_capture_stats(Duration::from_secs(1), move |t, _ctx| {
            if let Some(state) = overload.observe(t.drop_rate) {
                match state {
                    OverloadState::Emergency => {
                        eprintln!(
                            "⚠ OVERLOAD — dropping {:.1}% ({} pkts/s)",
                            t.drop_rate * 100.0,
                            t.packets
                        );
                    }
                    OverloadState::Normal => eprintln!("✓ recovered"),
                    _ => {}
                }
            }
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_until_signal()
        .await?;

    Ok(())
}
