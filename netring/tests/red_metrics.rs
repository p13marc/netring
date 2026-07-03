//! RED metrics wiring (issue #122).
//!
//! Cap-free build coverage — the rate/quantile tables are exercised by
//! flowscope's RollingRate / WindowedQuantiles tests.

#![cfg(all(feature = "tokio", feature = "flow"))]

use netring::monitor::Monitor;
use netring::monitor::red::{RedConfig, RedProto};
use netring::prelude::StdoutSink;
use std::time::Duration;

#[tokio::test(flavor = "current_thread")]
async fn red_builds_default() {
    let m = Monitor::builder()
        .interface("lo")
        .red()
        .red() // idempotent
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "red build failed: {:?}", m.err());
}

#[tokio::test(flavor = "current_thread")]
async fn on_red_reports() {
    let mut cfg = RedConfig::default();
    cfg.dns = false; // flow-only
    let m = Monitor::builder()
        .interface("lo")
        .on_red(Duration::from_secs(10), |r| {
            let _ = (
                r.rate(RedProto::Flow),
                r.error_ratio(RedProto::Flow),
                r.duration_ms(RedProto::Flow, 0.95),
                r.to_snapshot(RedProto::Flow),
            );
            Ok(())
        })
        .red_with(cfg) // idempotent (already armed by on_red)
        .build();
    assert!(m.is_ok(), "on_red build failed: {:?}", m.err());
}
