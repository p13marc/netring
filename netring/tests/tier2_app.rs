//! Issue #30: build-wiring test for the application / OT / VPN Tier-2 protocol
//! markers — FTP, SMTP, Modbus, DNP3 (TCP session) + STUN, WireGuard (UDP
//! datagram).
//!
//! Builds a `Monitor` with each `Protocol` marker + a typed `.on::<P>()`
//! message handler and asserts the whole registration chain succeeds.
//! `.build()` opens no capture (no CAP_NET_RAW); payload parsing is covered by
//! flowscope's own pcap suite.

#![cfg(all(
    feature = "ftp",
    feature = "smtp",
    feature = "modbus",
    feature = "dnp3",
    feature = "stun",
    feature = "wireguard",
    feature = "tokio",
    feature = "flow"
))]

use netring::monitor::Monitor;
use netring::prelude::{Dnp3, Ftp, Modbus, Smtp, Stun, WireGuard};
use netring::protocol::{Dispatch, Protocol};

#[test]
fn dispatch_ports_match_iana_assignments() {
    assert!(matches!(Ftp::dispatch(), Dispatch::Tcp(ref p) if p == &[21]));
    assert!(matches!(Smtp::dispatch(), Dispatch::Tcp(ref p) if p == &[25, 587]));
    assert!(matches!(Modbus::dispatch(), Dispatch::Tcp(ref p) if p == &[502]));
    assert!(matches!(Dnp3::dispatch(), Dispatch::Tcp(ref p) if p == &[20000]));
    assert!(matches!(Stun::dispatch(), Dispatch::Udp(ref p) if p == &[3478]));
    assert!(matches!(WireGuard::dispatch(), Dispatch::Udp(ref p) if p == &[51820]));
}

#[test]
fn names_are_stable_lowercase_slugs() {
    assert_eq!(Ftp::NAME, "ftp");
    assert_eq!(Smtp::NAME, "smtp");
    assert_eq!(Modbus::NAME, "modbus");
    assert_eq!(Dnp3::NAME, "dnp3");
    assert_eq!(Stun::NAME, "stun");
    assert_eq!(WireGuard::NAME, "wireguard");
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_registers_all_six_app_protocols() {
    let built = Monitor::builder()
        .interface("lo")
        .protocol::<Ftp>()
        .on::<Ftp>(|m: &flowscope::ftp::FtpMessage| {
            let _ = m;
            Ok(())
        })
        .protocol::<Smtp>()
        .on::<Smtp>(|m: &flowscope::smtp::SmtpMessage| {
            let _ = m;
            Ok(())
        })
        .protocol::<Modbus>()
        .on::<Modbus>(|m: &flowscope::modbus::ModbusMessage| {
            let _ = m;
            Ok(())
        })
        .protocol::<Dnp3>()
        .on::<Dnp3>(|m: &flowscope::dnp3::DnpMessage| {
            let _ = m;
            Ok(())
        })
        .protocol::<Stun>()
        .on::<Stun>(|m: &flowscope::stun::StunMessage| {
            let _ = m;
            Ok(())
        })
        .protocol::<WireGuard>()
        .on::<WireGuard>(|m: &flowscope::wireguard::WireGuardMessage| {
            let _ = m;
            Ok(())
        })
        .build();

    assert!(
        built.is_ok(),
        "app-protocol registration should build cleanly: {:?}",
        built.err()
    );
}
