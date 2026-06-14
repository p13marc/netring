//! JA4 / JA4S fingerprint IOC matching (0.24 Phase E).
//!
//! Watches TLS handshakes and matches each one's JA4 (client) / JA4S
//! (server) fingerprint against a small blocklist of indicators of
//! compromise — the canonical "is this a known-bad client/server stack"
//! check. A hit emits an anomaly; everything else is logged at info.
//!
//! `on_fingerprint(|fp, ctx|)` hands you a [`TlsFingerprint`] bundling
//! SNI + ALPN + JA3 / JA4 / JA4S + the flow key, so the detector is a few
//! lines. JA4S (the ServerHello fingerprint) is new in this release — it
//! identifies the *server* software, complementing JA4's client view.
//!
//! ```sh
//! cargo run --example monitor_ja4_fingerprint \
//!     --features "monitor-quickstart" -- eth0
//! ```
//!
//! [`TlsFingerprint`]: netring::monitor::TlsFingerprint

use std::time::Duration;

use netring::prelude::*;

/// A tiny JA4/JA4S blocklist. In production this is loaded from a feed
/// (e.g. the FoxIO JA4+ database); here two illustrative entries.
const JA4_BLOCKLIST: &[&str] = &[
    // Example: a JA4 known to be used by a specific malware family.
    "t13d1516h2_8daaf6152771_b186095e22b6",
];
const JA4S_BLOCKLIST: &[&str] = &[
    // Example: a JA4S of a known C2 server stack.
    "t130200_1301_a56c5b993250",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    eprintln!("monitor_ja4_fingerprint: watching TLS handshakes on {iface} (Ctrl-C to stop)");

    Monitor::builder()
        .interface(&iface)
        .sink(StdoutSink::default())
        .on_fingerprint(|fp, ctx| {
            // Match the client + server fingerprints against the blocklist.
            let ja4_hit = fp
                .ja4
                .as_deref()
                .is_some_and(|j| JA4_BLOCKLIST.contains(&j));
            let ja4s_hit = fp
                .ja4s
                .as_deref()
                .is_some_and(|j| JA4S_BLOCKLIST.contains(&j));

            if ja4_hit || ja4s_hit {
                let which = if ja4_hit { "ja4" } else { "ja4s" };
                ctx.emit("tls_fingerprint_ioc", Severity::Critical)
                    .with("match", which)
                    .with("sni", fp.sni.clone().unwrap_or_default())
                    .with("ja4", fp.ja4.clone().unwrap_or_default())
                    .with("ja4s", fp.ja4s.clone().unwrap_or_default())
                    .emit();
            } else if fp.has_fingerprint() {
                eprintln!(
                    "tls {} ja4={:?} ja4s={:?} sni={:?}",
                    fp.alpn.as_deref().unwrap_or("-"),
                    fp.ja4,
                    fp.ja4s,
                    fp.sni,
                );
            }
            Ok(())
        })
        .build()?
        .run_for(Duration::from_secs(120))
        .await?;

    Ok(())
}
