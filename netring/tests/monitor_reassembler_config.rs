//! Issue #34: the reassembler-hardening config (flowscope 0.18) is reachable
//! through `MonitorBuilder` and round-trips into the flow-tracker config.
//!
//! Cap-free — inspects the builder's `tracker_config()` without opening a
//! socket.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::time::Duration;

use netring::monitor::Monitor;
use netring::prelude::{MemcapPolicy, TcpOverlapPolicy};

#[test]
fn reassembler_hardening_knobs_round_trip() {
    let builder = Monitor::builder()
        .interface("lo")
        .tcp_overlap_policy(TcpOverlapPolicy::Last)
        .reassembly_memcap(64 * 1024 * 1024, MemcapPolicy::DropFlow)
        .active_idle_threshold(Some(Duration::from_secs(5)));

    let cfg = builder.tracker_config();
    assert_eq!(cfg.tcp_overlap_policy, TcpOverlapPolicy::Last);
    assert_eq!(cfg.reassembly_memcap, Some(64 * 1024 * 1024));
    assert_eq!(cfg.reassembly_memcap_policy, MemcapPolicy::DropFlow);
    assert_eq!(cfg.active_idle_threshold, Some(Duration::from_secs(5)));
}

#[test]
fn defaults_mirror_flowscope() {
    // No knobs set → flowscope defaults (BSD `First`, no memcap, 1s idle).
    let builder = Monitor::builder().interface("lo");
    let cfg = builder.tracker_config();
    assert_eq!(cfg.tcp_overlap_policy, TcpOverlapPolicy::First);
    assert_eq!(cfg.reassembly_memcap, None);
    assert_eq!(cfg.reassembly_memcap_policy, MemcapPolicy::Ignore);
    assert_eq!(cfg.active_idle_threshold, Some(Duration::from_secs(1)));

    // And it builds.
    assert!(builder.build().is_ok());
}
