//! DNS handler + name-map wiring (issue #120).
//!
//! Cap-free: `.on_dns` / `.name_map` / `.on_name` auto-register the Dns protocol
//! (and, for the name map, a state cell) and the Monitor builds without a
//! capture. The NameMap folding logic is unit-tested upstream in flowscope and
//! in `netring::monitor::dns`; end-to-end name learning rides the replay suites.

#![cfg(all(feature = "tokio", feature = "flow", feature = "dns"))]

use netring::monitor::Monitor;
use netring::prelude::StdoutSink;

#[tokio::test(flavor = "current_thread")]
async fn on_dns_builds() {
    let m = Monitor::builder()
        .interface("lo")
        .on_dns(|v, _ctx| {
            let _ = (v.qname(), v.client, v.is_answerless());
            Ok(())
        })
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "on_dns build failed: {:?}", m.err());
}

#[tokio::test(flavor = "current_thread")]
async fn name_map_and_on_name_build_order_independent() {
    // on_name registered BEFORE name_map — order must not matter.
    let m = Monitor::builder()
        .interface("lo")
        .on_name(|ip, claim, _ctx| {
            let _ = (ip, &claim.name);
        })
        .name_map()
        .name_map() // idempotent
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "name_map build failed: {:?}", m.err());
}
