//! Flow-risk wiring (issue #49).
//!
//! Cap-free: `.flow_risk()` auto-registers the TLS handshake + HTTP protocols
//! and wires the internal risk-check handlers. Assert the resulting Monitor
//! builds (the detection logic itself is unit-tested in `monitor::risk`).
//! `.build()` opens no capture.

#![cfg(all(feature = "tokio", feature = "flow", feature = "tls", feature = "http"))]

use netring::monitor::Monitor;
use netring::prelude::StdoutSink;

#[tokio::test(flavor = "current_thread")]
async fn flow_risk_builds_and_coexists_with_explicit_protocols() {
    // Bare arm.
    let m = Monitor::builder()
        .interface("lo")
        .flow_risk()
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "flow_risk build failed: {:?}", m.err());

    // Explicit `.protocol::<Http>()` first → flow_risk must not double-register.
    let m = Monitor::builder()
        .interface("lo")
        .protocol::<netring::protocol::builtin::Http>()
        .flow_risk()
        .build();
    assert!(
        m.is_ok(),
        "flow_risk + explicit Http build failed: {:?}",
        m.err()
    );
}
