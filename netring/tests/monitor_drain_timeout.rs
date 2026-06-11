//! 0.21 D.2: smoke-test the `drain_timeout` setter shape.
//!
//! Pure builder-side tests — they construct `Monitor`s but never
//! call `run_for` / `run_until_*` so the AsyncCapture::open path
//! is never reached (no `CAP_NET_RAW` required to run). The
//! actual drain phase is exercised by the run loop in production
//! and indirectly by the `monitor_lo_dispatch.rs` root-gated
//! tests that hit the live capture path.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::time::Duration;

use netring::monitor::Monitor;
use netring::protocol::builtin::Tcp;

#[test]
fn drain_timeout_setter_accepts_zero() {
    // Zero = skip the drain phase entirely. Useful for fail-fast
    // smoke tests that don't care about residual events.
    let _m = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .drain_timeout(Duration::ZERO)
        .build()
        .expect("build with zero drain timeout");
}

#[test]
fn drain_timeout_setter_accepts_one_second() {
    let _m = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .drain_timeout(Duration::from_secs(1))
        .build()
        .expect("build with 1s drain timeout");
}

#[test]
fn drain_timeout_setter_accepts_large_durations() {
    let _m = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .drain_timeout(Duration::from_secs(60))
        .build()
        .expect("build with 60s drain timeout");
}

#[test]
fn drain_timeout_default_is_implicit_when_unset() {
    // Build without `.drain_timeout(_)`. The `MonitorBuilder::build`
    // path picks the 1s default — this just confirms the build
    // path compiles + runs without the setter.
    let _m = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .build()
        .expect("build without drain_timeout setter");
}
