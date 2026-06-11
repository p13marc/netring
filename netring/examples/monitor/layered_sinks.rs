//! Demonstrates the layered anomaly sink chain.
//!
//! Three layers wrap the base `StdoutSink`:
//!
//! - `MinSeverity::warning()` (outermost) — drops `Info` events.
//! - `DedupeAnomalies::within(60s)` — drops repeats of the same
//!   `(kind, key)` within a sliding 60s window.
//! - `RateLimitAnomalies::new(5, 1s)` — drops anomalies past 5
//!   per second per kind.
//! - `StdoutSink` (innermost) — final destination.
//!
//! Runtime order: emit → MinSeverity → Dedupe → RateLimit → Stdout.
//!
//! The handler fires `Info` (gets dropped) and `Warning` (passes)
//! for every TCP flow start, so you can observe the layers at work.
//!
//! Run:
//!
//! ```sh
//! cargo run --example monitor_layered_sinks \
//!     --features "tokio,flow" -- eth0
//! ```

use std::time::Duration;

use netring::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let dur_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    eprintln!("monitor_layered_sinks: capturing on {iface} for {dur_secs}s");
    eprintln!("Layers (outermost-first):");
    eprintln!("  MinSeverity::warning()");
    eprintln!("  DedupeAnomalies::within(60s)");
    eprintln!("  RateLimitAnomalies::new(5/sec)");
    eprintln!("  StdoutSink (base)");

    Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        .on_ctx::<FlowStarted<Tcp>>(|evt: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
            let key = evt.key;
            // 0.21 A.2: `ctx.emit(kind, severity)` captures
            // `ctx.ts` automatically — replaces the
            // `let now = ctx.ts; ctx.sink_mut().begin(...)` dance.
            //
            // Fire one Info per flow start — will be dropped by
            // MinSeverity::warning().
            ctx.emit("FlowInfo", Severity::Info).with_key(&key).emit();
            // Fire one Warning per flow start — passes MinSeverity
            // but gets deduped by (kind="FlowWarn", key=evt.key)
            // within 60s. Different flows still fire.
            ctx.emit("FlowWarn", Severity::Warning)
                .with_key(&key)
                .emit();
            Ok(())
        })
        .layer(MinSeverity::warning())
        .layer(DedupeAnomalies::within(Duration::from_secs(60)))
        .layer(RateLimitAnomalies::new(5, Duration::from_secs(1)))
        .sink(StdoutSink::default())
        .build()?
        .run_for(Duration::from_secs(dur_secs))
        .await?;

    Ok(())
}
