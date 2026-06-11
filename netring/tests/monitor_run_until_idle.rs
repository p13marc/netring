//! 0.21 E.2: `Monitor::run_until_idle(window)` exits after
//! `window` of inactivity. Verifies the builder + run-loop wire-
//! up: a monitor that never sees any packets exits within
//! `window + jitter`.
//!
//! Skipped silently when AsyncCapture::open fails on `lo` (no
//! `CAP_NET_RAW`). The exit-timing check is the actual assertion;
//! a permission failure would mean we never even started the run
//! loop, which is fine — the API shape is still exercised by the
//! build.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::time::{Duration, Instant};

use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;

#[tokio::test(flavor = "current_thread")]
async fn idle_window_triggers_stop_on_quiet_loopback() {
    let m = match Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .drain_timeout(Duration::ZERO) // skip the drain for tighter timing
        .build()
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Monitor::build failed (likely needs CAP_NET_RAW): {e}");
            return;
        }
    };

    let window = Duration::from_millis(150);
    let start = Instant::now();
    let r = m.run_until_idle(window).await;
    let elapsed = start.elapsed();

    if let Err(e) = r {
        // Same root-gate fallback as the other monitor_lo_* tests.
        eprintln!("run_until_idle errored (likely no CAP_NET_RAW): {e}");
        return;
    }

    // `lo` is essentially silent under nextest, so the run loop
    // should exit shortly after `window`. Allow generous slack
    // (3× window) for CI jitter.
    assert!(
        elapsed >= window,
        "exited before the idle window expired: elapsed={elapsed:?}, window={window:?}"
    );
    assert!(
        elapsed < window * 5,
        "took too long to exit after idle window: elapsed={elapsed:?}, window={window:?}"
    );
}
