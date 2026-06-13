//! The Send story, demonstrated (0.22 §7).
//!
//! Two facts that look contradictory but aren't:
//!
//! 1. **`Monitor` is `Send`.** Plain `#[tokio::main]` (multi-thread)
//!    works — no `flavor = "current_thread"` ceremony needed.
//! 2. **The *future* `Monitor::run_for(..).await` is `!Send`.** It
//!    borrows the `!Sync` capture ring (and the async-dispatch path
//!    holds a raw pointer) across awaits, so it can't be
//!    `tokio::spawn`'d — it must stay on the task that owns it.
//!
//! The working pattern for "do other async work alongside the
//! monitor" is `tokio::select!` on the main task (the run loop never
//! leaves it), with anomalies fanned out to spawned tasks via a
//! `ChannelSink` (which *is* `Send`).
//!
//! Run: `cargo run --example monitor_multi_thread_default --features monitor`

use std::time::Duration;

use netring::prelude::*;

#[tokio::main] // ← multi-thread runtime; no `flavor = "current_thread"`.
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    // A ChannelSink is Send: anomalies cross the spawn boundary here.
    let (sink, mut rx) = ChannelSink::channel();

    // Consumer task — runs on a *different* worker thread. This is how
    // you get work off the capture task without spawning the run loop.
    let consumer = tokio::spawn(async move {
        while let Some(anomaly) = rx.recv().await {
            println!("[consumer thread] {anomaly:?}");
        }
    });

    let monitor = Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        .on_ctx::<FlowStarted<Tcp>>(|evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
            ctx.emit("FlowStarted", Severity::Info)
                .with_key(&evt.key)
                .emit();
            Ok(())
        })
        .sink(sink)
        .build()?;

    // ✅ Works: the run-loop future stays on *this* task. Drive it with
    // `tokio::select!` if you need to interleave other async work.
    tokio::select! {
        r = monitor.run_for(Duration::from_secs(10)) => { r?; }
        // … other branches (timers, control channels, …) go here.
    }

    // ❌ Does NOT compile — the run-loop future is `!Send`:
    //
    //     tokio::spawn(monitor.run_for(Duration::from_secs(10)));
    //
    // (see docs/MIGRATING_0.21_TO_0.22.md §8 +
    //  plans/netring-0.22-send-future-decision.md)

    drop(consumer); // detach; it ends when the sink is dropped.
    Ok(())
}
