//! SSH protocol surfacing (issue #30, first Tier-2 protocol).
//!
//! Cap-free wiring test: build a `Monitor` with the SSH `Protocol` marker and
//! a typed `.on::<Ssh>()` handler that extracts HASSH, and assert the
//! registration path — flowscope session-parser install via `session_on_ports`,
//! slot-handle creation, dispatcher wiring — succeeds. `.build()` opens no
//! capture, so no CAP_NET_RAW is needed. On-wire parsing is covered by
//! flowscope's own pcap suite.

#![cfg(all(feature = "tokio", feature = "flow", feature = "ssh"))]

use flowscope::ssh::SshMessage;
use netring::monitor::Monitor;
use netring::prelude::Ssh;
use netring::protocol::{Dispatch, Protocol};

#[test]
fn dispatch_targets_tcp_22() {
    assert!(matches!(Ssh::dispatch(), Dispatch::Tcp(ref p) if p == &[22]));
    assert_eq!(Ssh::NAME, "ssh");
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_registers_ssh_and_extracts_hassh() {
    let built = Monitor::builder()
        .interface("lo")
        .protocol::<Ssh>()
        .on::<Ssh>(|m: &SshMessage| {
            // Pin the payload type and exercise the HASSH accessor.
            if let SshMessage::KexInit(k) = m {
                let _ = (&k.hassh, k.from_client);
            }
            Ok(())
        })
        .build();

    assert!(
        built.is_ok(),
        "SSH registration should build cleanly: {:?}",
        built.err()
    );
}
