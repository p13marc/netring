//! Live run-loop regressions on `lo` (0.31.2 audit): the handler error
//! policy on capture-stats handlers.
//!
//! Need `CAP_NET_RAW` (run as root); without it the monitor can't open
//! `lo` and each test returns early, like the other `monitor_lo_*`
//! tests.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use netring::monitor::{HandlerErrorPolicy, Monitor};
use netring::protocol::builtin::Udp;

/// `HandlerErrorPolicy::Isolate` covers `on_capture_stats` handlers: an
/// `Err` is counted and the monitor keeps running (it used to stop).
#[tokio::test(flavor = "current_thread")]
async fn isolate_policy_covers_capture_stats_handlers() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    let monitor = Monitor::builder()
        .interface("lo")
        .protocol::<Udp>()
        .drain_timeout(Duration::ZERO)
        .handler_error_policy(HandlerErrorPolicy::Isolate)
        .on_capture_stats(Duration::from_millis(50), move |_t, _ctx| {
            c.fetch_add(1, Ordering::SeqCst);
            Err(netring::Error::Config("stats handler failed".into()))
        })
        .build()
        .unwrap();
    let health = monitor.health();
    if let Err(e) = monitor.run_for(Duration::from_millis(400)).await {
        if calls.load(Ordering::SeqCst) == 0 {
            eprintln!("run_for errored before any sample (likely no CAP_NET_RAW): {e}");
            return;
        }
        panic!("Isolate must keep the monitor running: {e}");
    }
    let n = calls.load(Ordering::SeqCst);
    assert!(n >= 3, "sampled every 50 ms for 400 ms: {n}");
    assert_eq!(health.handler_errors(), n as u64);
}
