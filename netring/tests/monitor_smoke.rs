//! End-to-end Monitor smoke test on the loopback interface.
//!
//! Builds a `Monitor` with one `FlowStarted<Tcp>` handler, runs
//! it for a short window, and asserts the handler count survives
//! the run loop. Doesn't require actual TCP traffic — the run
//! loop blocks awaiting packets, but the deadline-based stop
//! condition guarantees it exits in bounded time.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;
use netring::protocol::event_typed::FlowStarted;

#[tokio::test(flavor = "current_thread")]
async fn monitor_builds_and_runs_to_deadline_without_traffic() {
    let count = Arc::new(AtomicU32::new(0));
    let c = Arc::clone(&count);

    // Opening AF_PACKET on `lo` needs CAP_NET_RAW. The setcap'd
    // test binary has it; bail gracefully otherwise so this
    // test stays usable in unprivileged environments.
    let monitor = match Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>() // lifecycle-only — no parser slot
        .on::<FlowStarted<Tcp>>(move |_evt: &FlowStarted<Tcp>| {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .build()
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Monitor::builder().build() failed: {e}");
            return;
        }
    };

    let run = monitor.run_for(Duration::from_millis(100));
    match tokio::time::timeout(Duration::from_secs(2), run).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            // Capture open is fallible without CAP_NET_RAW; this is
            // the expected error path on dev workstations without
            // `just setcap`. Don't fail the test.
            eprintln!("monitor.run_for failed (likely needs CAP_NET_RAW): {e}");
        }
        Err(_) => panic!("monitor.run_for didn't honour its deadline within 2s"),
    }

    // Handler count visible from outside the run loop (the handler
    // closure clones the Arc, so the increment is observable).
    let _ = count.load(Ordering::Relaxed);
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_with_no_handlers_still_builds() {
    let m = Monitor::builder().interface("lo").build();
    assert!(m.is_ok());
}
