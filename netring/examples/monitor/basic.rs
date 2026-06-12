//! Basic Monitor example — single-protocol flow lifecycle.
//!
//! Counts TCP flows started + ended on the given interface. Emits
//! one anomaly per flow start to stdout via `StdoutSink`.
//!
//! Runs on the default multi-thread tokio runtime — `Monitor` is
//! `Send` as of 0.21 (flowscope 0.13's `Driver<E>: Send + Sync`):
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

#[tokio::main]
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
        .on_ctx::<FlowStarted<Tcp>>(|_evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
            // 0.21 A.3: `split_state_sink::<T>()` projects two
            // disjoint borrows in one step — no manual borrow-
            // shortening scope needed. 0.21 A.2: `ctx.emit(kind,
            // sev)` is the one-line shortcut for the begin chain;
            // it captures `ctx.ts` automatically.
            let ts = ctx.ts;
            let (counters, sink) = ctx.split_state_sink::<FlowCounters>();
            counters.started += 1;
            sink.begin("FlowStartedTcp", Severity::Info, ts)
                .with_metric("started_total", counters.started as f64)
                .emit();
            Ok(())
        })
        .on_ctx::<FlowEnded<Tcp>>(|_evt: &FlowEnded<Tcp>, ctx: &mut Ctx<'_>| {
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
