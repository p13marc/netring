//! Lateral-movement / Active Directory protocol surfacing (issue #29).
//!
//! Cap-free wiring tests: build a `Monitor` with the SMB / Kerberos / LDAP /
//! RDP `Protocol` markers and typed `.on::<P>()` message handlers, and assert
//! the whole registration path — flowscope parser install via
//! `session_on_ports`, slot-handle creation, and dispatcher slot wiring —
//! succeeds. `.build()` does not open a capture, so no CAP_NET_RAW is needed.
//!
//! Actual on-wire parsing of these protocols is covered by flowscope's own
//! pcap test suite; here we prove that netring surfaces them correctly and
//! that the typed handler signatures bind to the right `Protocol::Message`.

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "smb",
    feature = "kerberos",
    feature = "ldap",
    feature = "rdp"
))]

use flowscope::kerberos::KerberosMessage;
use flowscope::ldap::LdapMessage;
use flowscope::rdp::RdpMessage;
use flowscope::smb::SmbMessage;
use netring::monitor::Monitor;
use netring::prelude::{Ctx, Kerberos, Ldap, Rdp, Smb};
use netring::protocol::{Dispatch, Protocol};

#[test]
fn dispatch_ports_match_iana_assignments() {
    // The kernel prefilter narrows to these ports; a regression here would
    // silently capture the wrong traffic.
    assert!(matches!(Smb::dispatch(), Dispatch::Tcp(ref p) if p == &[445]));
    assert!(matches!(Kerberos::dispatch(), Dispatch::Tcp(ref p) if p == &[88]));
    assert!(matches!(Ldap::dispatch(), Dispatch::Tcp(ref p) if p == &[389]));
    assert!(matches!(Rdp::dispatch(), Dispatch::Tcp(ref p) if p == &[3389]));
}

#[test]
fn names_are_stable_lowercase_slugs() {
    assert_eq!(Smb::NAME, "smb");
    assert_eq!(Kerberos::NAME, "kerberos");
    assert_eq!(Ldap::NAME, "ldap");
    assert_eq!(Rdp::NAME, "rdp");
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_registers_all_four_ad_protocols() {
    // Each `.protocol::<P>()` installs the flowscope session parser; each
    // `.on::<P>()` binds a typed message handler to the dispatcher. A failure
    // anywhere in that chain surfaces as a `BuildError`.
    let built = Monitor::builder()
        .interface("lo")
        .protocol::<Smb>()
        .on::<Smb>(|m: &SmbMessage| {
            // Exercise a lateral-movement field so the closure's payload type
            // is pinned to flowscope's `SmbMessage` at compile time.
            let _ = m.tree_connect_is_admin_share;
            Ok(())
        })
        .protocol::<Kerberos>()
        .on::<Kerberos>(|m: &KerberosMessage| {
            let _ = m.kerberoast_suspect;
            Ok(())
        })
        .protocol::<Ldap>()
        .on::<Ldap>(|m: &LdapMessage| {
            let _ = m.search_attributes_spn_query;
            Ok(())
        })
        .protocol::<Rdp>()
        .on_ctx::<Rdp>(|m: &RdpMessage, _ctx: &mut Ctx<'_>| {
            // RDP's message is an enum; match one variant to pin the type.
            if let RdpMessage::ConnectionRequest {
                cookie_username, ..
            } = m
            {
                let _ = cookie_username;
            }
            Ok(())
        })
        .build();

    assert!(
        built.is_ok(),
        "AD-protocol registration should build cleanly: {:?}",
        built.err()
    );
}
