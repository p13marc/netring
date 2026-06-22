//! Asset-discovery protocol surfacing (issue #28, part 1).
//!
//! Cap-free wiring tests: build a `Monitor` with the DHCP / SSDP / NetBIOS-NS
//! `Protocol` markers and typed `.on::<P>()` message handlers, and assert the
//! whole registration path — flowscope datagram-parser install via
//! `datagram_on_ports`, slot-handle creation, and dispatcher slot wiring —
//! succeeds. `.build()` does not open a capture, so no CAP_NET_RAW is needed.
//!
//! Actual on-wire parsing is covered by flowscope's own pcap test suite; here
//! we prove that netring surfaces them correctly and that the typed handler
//! signatures bind to the right `Protocol::Message`.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "dhcp",
    feature = "ssdp",
    feature = "netbios-ns"
))]

use flowscope::dhcp::DhcpMessage;
use flowscope::netbios_ns::NbnsMessage;
use flowscope::ssdp::SsdpMessage;
use netring::monitor::Monitor;
use netring::prelude::{Dhcp, Nbns, Ssdp};
use netring::protocol::{Dispatch, Protocol};

#[test]
fn dispatch_ports_match_iana_assignments() {
    assert!(matches!(Dhcp::dispatch(), Dispatch::Udp(ref p) if p == &[67, 68]));
    assert!(matches!(Ssdp::dispatch(), Dispatch::Udp(ref p) if p == &[1900]));
    assert!(matches!(Nbns::dispatch(), Dispatch::Udp(ref p) if p == &[137]));
}

#[test]
fn names_match_flowscope_kinds() {
    assert_eq!(Dhcp::NAME, "dhcp");
    assert_eq!(Ssdp::NAME, "ssdp");
    assert_eq!(Nbns::NAME, "netbios-ns");
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_registers_all_asset_protocols() {
    let built = Monitor::builder()
        .interface("lo")
        .protocol::<Dhcp>()
        .on::<Dhcp>(|m: &DhcpMessage| {
            // Pin the payload type to flowscope's `DhcpMessage`.
            let _ = &m.client_mac;
            Ok(())
        })
        .protocol::<Ssdp>()
        .on::<Ssdp>(|m: &SsdpMessage| {
            let _ = &m.server;
            Ok(())
        })
        .protocol::<Nbns>()
        .on::<Nbns>(|m: &NbnsMessage| {
            let _ = &m.queried_name;
            Ok(())
        })
        .build();

    assert!(
        built.is_ok(),
        "asset-protocol registration should build cleanly: {:?}",
        built.err()
    );
}
