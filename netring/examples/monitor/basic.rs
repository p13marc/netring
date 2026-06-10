//! Basic 0.20 Monitor example — single-protocol flow lifecycle.
//!
//! Counts TCP flows started + ended on the given interface. Emits
//! one anomaly per flow start to stdout via `StdoutSink`.
//!
//! Run (single-thread tokio runtime is required; the Monitor is
//! `!Send`):
//!
//! ```sh
//! cargo run --example monitor_basic --features "tokio,flow" -- eth0
//! ```
//!
//! `lo` works for smoke-testing — start `ping -c 1 127.0.0.1`
//! while the example is running and you should see one
//! `FlowStarted<Tcp>` per outbound TCP attempt (none for ICMP echo).
//! Use `monitor_async_handler` if you also want ICMP lifecycle.

use std::time::Duration;

use netring::prelude::*;

#[derive(Default)]
struct FlowCounters {
    started: u64,
    ended: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let dur_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    eprintln!("monitor_basic: capturing on {iface} for {dur_secs}s");

    Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>() // FlowStarted/Ended<Tcp> lifecycle events
        .state::<FlowCounters>()
        .on::<FlowStarted<Tcp>, _, _>(|_evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
            // Scope the state borrow tightly so the subsequent
            // `ctx.ts` read and `ctx.sink_mut()` call don't
            // conflict with the previous mutable borrow.
            let started_total = {
                let counters = ctx.state_mut::<FlowCounters>();
                counters.started += 1;
                counters.started
            };
            let now = ctx.ts;
            ctx.sink_mut()
                .begin("FlowStartedTcp", Severity::Info, now)
                .with_metric("started_total", started_total as f64)
                .emit();
            Ok(())
        })
        .on::<FlowEnded<Tcp>, _, _>(|_evt: &FlowEnded<Tcp>, ctx: &mut Ctx<'_>| {
            ctx.state_mut::<FlowCounters>().ended += 1;
            Ok(())
        })
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(dur_secs))
        .await?;

    eprintln!("monitor_basic: done");
    Ok(())
}
