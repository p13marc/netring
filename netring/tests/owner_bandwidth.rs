//! Owner-attributed bandwidth (issue #130).
//!
//! Cap-free build coverage + the AttributionHookRequired guard. The rate
//! computation itself is exercised by flowscope's BandwidthByKey tests.

#![cfg(all(feature = "tokio", feature = "flow"))]

use flowscope::correlate::Attribution;
use netring::monitor::Monitor;
use netring::prelude::StdoutSink;
use std::time::Duration;

#[tokio::test(flavor = "current_thread")]
async fn owner_bandwidth_builds_with_hook() {
    let m = Monitor::builder()
        .interface("lo")
        .with_flow_attribution(|key| Some(Attribution(u64::from(key.b.port()))))
        .owner_bandwidth()
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "owner_bandwidth build failed: {:?}", m.err());
}

#[tokio::test(flavor = "current_thread")]
async fn on_owner_bandwidth_reports() {
    let m = Monitor::builder()
        .interface("lo")
        .with_flow_attribution(|_k| Some(Attribution(1)))
        .on_owner_bandwidth(Duration::from_secs(5), |r| {
            let _ = (r.top(10), r.unknown_share(), r.semantics());
            Ok(())
        })
        .build();
    assert!(m.is_ok(), "on_owner_bandwidth build failed: {:?}", m.err());
}

#[tokio::test(flavor = "current_thread")]
async fn owner_bandwidth_without_hook_errors() {
    // owner_bandwidth() before with_flow_attribution() → build error.
    let m = Monitor::builder().interface("lo").owner_bandwidth().build();
    let err = match m {
        Ok(_) => panic!("expected a build error"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("attribution"),
        "expected AttributionHookRequired, got: {err}"
    );
}
