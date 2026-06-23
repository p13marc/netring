//! Issue #30: build-wiring test for the UDP infrastructure protocol markers
//! (NTP / SNMP / TFTP / RADIUS).
//!
//! Builds a `Monitor` with each `Protocol` marker + a typed `.on::<P>()`
//! message handler and asserts the whole registration chain — parser install,
//! datagram slot-handle creation, dispatcher wiring — succeeds. `.build()`
//! opens no capture, so no CAP_NET_RAW is needed; payload parsing is covered by
//! flowscope's own pcap suite.

#![cfg(all(
    feature = "ntp",
    feature = "snmp",
    feature = "tftp",
    feature = "radius",
    feature = "tokio",
    feature = "flow"
))]

use netring::monitor::Monitor;
use netring::prelude::{Ntp, Radius, Snmp, Tftp};
use netring::protocol::{Dispatch, Protocol};

#[test]
fn dispatch_ports_match_iana_assignments() {
    assert!(matches!(Ntp::dispatch(), Dispatch::Udp(ref p) if p == &[123]));
    assert!(matches!(Snmp::dispatch(), Dispatch::Udp(ref p) if p == &[161, 162]));
    assert!(matches!(Tftp::dispatch(), Dispatch::Udp(ref p) if p == &[69]));
    assert!(matches!(Radius::dispatch(), Dispatch::Udp(ref p) if p == &[1812, 1813]));
}

#[test]
fn names_are_stable_lowercase_slugs() {
    assert_eq!(Ntp::NAME, "ntp");
    assert_eq!(Snmp::NAME, "snmp");
    assert_eq!(Tftp::NAME, "tftp");
    assert_eq!(Radius::NAME, "radius");
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_registers_all_four_infra_protocols() {
    let built = Monitor::builder()
        .interface("lo")
        .protocol::<Ntp>()
        .on::<Ntp>(|m: &flowscope::ntp::NtpMessage| {
            let _ = m;
            Ok(())
        })
        .protocol::<Snmp>()
        .on::<Snmp>(|m: &flowscope::snmp::SnmpMessage| {
            let _ = m;
            Ok(())
        })
        .protocol::<Tftp>()
        .on::<Tftp>(|m: &flowscope::tftp::TftpMessage| {
            let _ = m;
            Ok(())
        })
        .protocol::<Radius>()
        .on::<Radius>(|m: &flowscope::radius::RadiusMessage| {
            let _ = m;
            Ok(())
        })
        .build();

    assert!(
        built.is_ok(),
        "infra-protocol registration should build cleanly: {:?}",
        built.err()
    );
}
