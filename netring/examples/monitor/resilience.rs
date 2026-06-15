//! Resilience (0.25 W1e): survive a flapping capture source **and** a panicking
//! handler without tearing down the monitor.
//!
//! - [`BackendErrorPolicy::Reopen`] rebuilds a failed capture source in place
//!   (interface flap, driver reset) so it self-heals.
//! - [`catch_handler_panics(true)`](netring::monitor::MonitorBuilder::catch_handler_panics)
//!   converts a panic in a sync handler into an error, which
//!   [`HandlerErrorPolicy::Isolate`] then logs + counts + continues past —
//!   instead of unwinding the capture loop.
//!
//! ```sh
//! cargo run --example monitor_resilience --features monitor -- eth0
//! ```

use netring::monitor::{BackendErrorPolicy, HandlerErrorPolicy, Monitor};
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowStarted;

#[tokio::main]
async fn main() -> Result<(), netring::Error> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".to_string());

    let monitor = Monitor::builder()
        .interface(&iface)
        .protocol::<Tcp>()
        // A transient backend error reopens the source rather than stopping.
        .backend_error_policy(BackendErrorPolicy::Reopen)
        // Catch sync-handler panics …
        .catch_handler_panics(true)
        // … and isolate them (log + count + keep capturing).
        .handler_error_policy(HandlerErrorPolicy::Isolate)
        .on::<FlowStarted<Tcp>>(|f: &FlowStarted<Tcp>| {
            // A deliberately buggy handler: panics on the discard port. With
            // catch + Isolate the monitor logs it and keeps running.
            assert_ne!(f.key.b.port(), 9, "simulated handler bug on port 9");
            Ok(())
        })
        .build()?;

    println!("# resilient monitor on {iface} (Reopen + panic isolation); Ctrl-C to stop");
    monitor.run_until_signal().await
}
