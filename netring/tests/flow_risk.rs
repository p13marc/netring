//! Flow-risk analysis wiring (issue #124, formerly #49).
//!
//! Cap-free: `.flow_analysis()` auto-registers the L7 protocols and the TCP/UDP
//! `FlowEnded` finalize handlers, and asserts the resulting Monitor builds. The
//! detection logic itself is unit-tested in `monitor::analysis` and upstream in
//! flowscope's `detect::risk`. `.build()` opens no capture.

#![cfg(all(feature = "tokio", feature = "flow", feature = "tls", feature = "http"))]

use netring::monitor::Monitor;
use netring::monitor::analysis::FlowAnalysisConfig;
use netring::prelude::StdoutSink;

#[tokio::test(flavor = "current_thread")]
async fn flow_analysis_builds_and_coexists_with_explicit_protocols() {
    // Bare arm.
    let m = Monitor::builder()
        .interface("lo")
        .flow_analysis()
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "flow_analysis build failed: {:?}", m.err());

    // Explicit `.protocol::<Http>()` first → flow_analysis must not double-register.
    let m = Monitor::builder()
        .interface("lo")
        .protocol::<netring::protocol::builtin::Http>()
        .flow_analysis()
        .build();
    assert!(
        m.is_ok(),
        "flow_analysis + explicit Http build failed: {:?}",
        m.err()
    );

    // Arming twice is idempotent (must not double-wire feeds/finalize).
    let m = Monitor::builder()
        .interface("lo")
        .flow_analysis()
        .flow_analysis()
        .build();
    assert!(
        m.is_ok(),
        "double flow_analysis build failed: {:?}",
        m.err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn flow_analysis_with_config_and_on_analyzed_flow_builds() {
    let mut cfg = FlowAnalysisConfig::default();
    cfg.emit_risk_anomalies = false;
    // `on_analyzed_flow` registered BEFORE arming — order must not matter.
    let m = Monitor::builder()
        .interface("lo")
        .on_analyzed_flow(|af, _ctx| {
            let _ = af.score();
        })
        .flow_analysis_with(cfg)
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "flow_analysis_with build failed: {:?}", m.err());
}

#[tokio::test(flavor = "current_thread")]
#[allow(deprecated)]
async fn deprecated_flow_risk_alias_still_builds() {
    let m = Monitor::builder()
        .interface("lo")
        .flow_risk()
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "flow_risk alias build failed: {:?}", m.err());
}
