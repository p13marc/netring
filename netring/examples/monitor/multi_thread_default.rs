//! The Send story, demonstrated (0.23).
//!
//! Two facts, both true since 0.23:
//!
//! 1. **`Monitor` is `Send`** (since 0.21). Plain `#[tokio::main]`
//!    (multi-thread) works — no `flavor = "current_thread"` ceremony.
//! 2. **The *future* `Monitor::run_for(..)` is also `Send + 'static`**
//!    (since 0.23). It can be `tokio::spawn`'d onto its own worker
//!    task instead of being pinned to the task that owns it. The
//!    capture mmap ring is `Send`, and the async-dispatch path no
//!    longer holds a raw pointer across `.await`.
//!
//! The one constraint that comes with #2: `on_async` handlers must
//! now return `Send` futures (the same rule `tokio::spawn` imposes).
//! Handlers that capture `Arc<…>` and do I/O already satisfy it.
//!
//! Run: `cargo run --example monitor_multi_thread_default --features monitor`

use std::time::Duration;

use netring::prelude::*;

#[tokio::main] // ← multi-thread runtime; no `flavor = "current_thread"`.
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());

    // A ChannelSink is Send: anomalies cross the spawn boundary here.
    let (sink, mut rx) = ChannelSink::channel();

    // Consumer task — runs on a worker thread, draining anomalies.
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

    // ✅ 0.23: the run-loop future is `Send + 'static`, so it can run
    // on its own spawned task. `tokio::spawn` returns a `JoinHandle`
    // you can await, abort, or just detach.
    let run = tokio::spawn(monitor.run_for(Duration::from_secs(10)));

    // … your main task is now free to do other async work here while
    // the capture loop runs on a different worker thread …

    run.await??; // outer `?`: JoinError; inner `?`: the run loop's Result

    // (Still valid: if you'd rather keep the loop on *this* task and
    // interleave with other branches, `tokio::select!` on
    // `monitor.run_for(..)` works exactly as before — spawning is now
    // an option, not a requirement.)

    drop(consumer); // detach; it ends when the sink is dropped.
    Ok(())
}
