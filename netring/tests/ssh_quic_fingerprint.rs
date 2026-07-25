//! SSH + QUIC fingerprint wiring (issue #128).
//!
//! Cap-free: `.on_ssh_fingerprint(..)` / `.on_quic_fingerprint(..)` auto-register
//! their protocol (and, for SSH, a per-flow accumulator slot) and the Monitor
//! builds without a capture. The fingerprint composition is unit-tested in
//! `netring::monitor::fingerprint`; the SSH state machine needs real (non
//! synthesizable — flowscope's SshMessage is #[non_exhaustive]) wire data, so it
//! is exercised by the live/replay suites rather than here.

#![cfg(all(feature = "tokio", feature = "flow"))]

// Only referenced by the feature-gated tests below.
#[cfg(any(feature = "ssh", feature = "tls", feature = "quic"))]
use netring::monitor::Monitor;
#[cfg(any(feature = "ssh", feature = "tls", feature = "quic"))]
use netring::prelude::StdoutSink;

#[cfg(feature = "ssh")]
#[tokio::test(flavor = "current_thread")]
async fn on_ssh_fingerprint_builds() {
    let m = Monitor::builder()
        .interface("lo")
        .on_ssh_fingerprint(|fp, _ctx| {
            let _ = (&fp.hassh, &fp.hassh_server, &fp.banners);
            Ok(())
        })
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "on_ssh_fingerprint build failed: {:?}", m.err());

    // Explicit `.protocol::<Ssh>()` first → hook must not double-register.
    let m = Monitor::builder()
        .interface("lo")
        .protocol::<netring::protocol::builtin::Ssh>()
        .on_ssh_fingerprint(|_fp, _ctx| Ok(()))
        .build();
    assert!(m.is_ok(), "ssh + explicit build failed: {:?}", m.err());
}

#[cfg(feature = "tls")]
#[tokio::test(flavor = "current_thread")]
async fn on_encrypted_dns_builds() {
    let m = Monitor::builder()
        .interface("lo")
        .on_encrypted_dns(|e, _ctx| {
            let _ = (e.app_protocol.as_str(), &e.sni, e.via_known_resolver);
            Ok(())
        })
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "on_encrypted_dns build failed: {:?}", m.err());
}

#[cfg(feature = "quic")]
#[tokio::test(flavor = "current_thread")]
async fn on_quic_fingerprint_builds() {
    let m = Monitor::builder()
        .interface("lo")
        .on_quic_fingerprint(|fp, _ctx| {
            let _ = (&fp.sni, &fp.alpn, &fp.version, fp.pq_key_share);
            Ok(())
        })
        .sink(StdoutSink::default())
        .build();
    assert!(m.is_ok(), "on_quic_fingerprint build failed: {:?}", m.err());
}
