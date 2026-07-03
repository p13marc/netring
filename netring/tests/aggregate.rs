//! Traffic aggregation wiring (issue #121).
//!
//! Cap-free build coverage — the rate tables are exercised by flowscope's
//! BandwidthByKey / RollingRate tests.

#![cfg(all(feature = "tokio", feature = "flow"))]

use netring::monitor::Monitor;
use netring::monitor::aggregate::AggregateConfig;
use netring::prelude::StdoutSink;
use std::time::Duration;

#[tokio::test(flavor = "current_thread")]
async fn aggregate_builds_default() {
    let m = Monitor::builder()
        .interface("lo")
        .aggregate()
        .aggregate() // idempotent
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "aggregate build failed: {:?}", m.err());
}

#[tokio::test(flavor = "current_thread")]
async fn on_aggregate_reports() {
    let mut cfg = AggregateConfig::default();
    cfg.top_domains = false;
    cfg.top_sni = false;
    let m = Monitor::builder()
        .interface("lo")
        .on_aggregate(Duration::from_secs(10), |r| {
            let _ = (r.top_talkers(5), r.top_pairs(5), r.to_snapshot(5));
            Ok(())
        })
        .aggregate_with(cfg) // already armed by on_aggregate → idempotent
        .build();
    assert!(m.is_ok(), "on_aggregate build failed: {:?}", m.err());
}
