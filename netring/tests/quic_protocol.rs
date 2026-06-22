//! QUIC Initial-packet surfacing (issue #14).
//!
//! Cap-free wiring test: build a Monitor with the `Quic` `Protocol` marker and a
//! typed `.on::<Quic>()` handler reading SNI/ALPN, and assert the registration
//! path (flowscope datagram-parser install + dispatcher wiring) succeeds.
//! `.build()` opens no capture. On-wire QUIC Initial decryption + parsing is
//! covered by flowscope's own pcap suite.

#![cfg(all(feature = "tokio", feature = "flow", feature = "quic"))]

use flowscope::QuicInitial;
use netring::monitor::Monitor;
use netring::prelude::Quic;
use netring::protocol::{Dispatch, Protocol};

#[test]
fn dispatch_targets_udp_443() {
    assert!(matches!(Quic::dispatch(), Dispatch::Udp(ref p) if p == &[443]));
    assert_eq!(Quic::NAME, "quic");
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_registers_quic_and_reads_sni() {
    let built = Monitor::builder()
        .interface("lo")
        .protocol::<Quic>()
        .on::<Quic>(|m: &QuicInitial| {
            // Pin the payload type and exercise the SNI/ALPN accessors.
            let _ = (&m.sni, &m.alpn, &m.version);
            Ok(())
        })
        .build();

    assert!(
        built.is_ok(),
        "QUIC registration should build cleanly: {:?}",
        built.err()
    );
}
