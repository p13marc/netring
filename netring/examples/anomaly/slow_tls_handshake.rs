//! Anomaly: TLS handshake aborted before ServerHello — a
//! "truncated" handshake.
//!
//! Hints at: server-side timeout / TCP RST before ServerHello,
//! middlebox inspection that drops the connection, or a slow /
//! unreachable peer.
//!
//! Built on flowscope 0.9's
//! [`TlsHandshakeParser`](flowscope::tls::TlsHandshakeParser) —
//! one synthesised event per observed handshake. The
//! `HandshakeOutcome::Truncated` variant fires when the flow
//! ends (FIN / RST / idle) before a ServerHello arrives. The
//! aggregator carries SNI, ALPN, optional JA3/JA4, negotiated
//! version, and cipher suite alongside the outcome.
//!
//! Architecture:
//!
//! ```text
//! ProtocolMonitor (.flow().tls_handshake())
//!       │
//!       ▼  Message{kind:"tls-handshake", TlsHandshake { outcome, sni, ja4, … }}
//! match outcome {
//!     Truncated → ANOMALY (Severity::Warning)
//!     Completed / AlertedByServer / AlertedByClient → skip
//! }
//! ```
//!
//! Note: this detector replaces the historical per-message
//! ClientHello/ServerHello timing pattern. The aggregator
//! parser doesn't expose a precomputed RTT field; the
//! "slow but completed" arm is no longer detected here. For
//! per-RTT alerts on completed handshakes, write a custom rule
//! that subscribes to both `.tls()` (raw messages) and
//! `.tls_handshake()` (aggregator).
//!
//! Usage:
//!     cargo run -p netring --example slow_tls_handshake \
//!         --features tokio,tls -- [interface] [seconds]
//!
//! Defaults: lo, 60s.
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "tls"))]
use std::time::Duration;

#[cfg(all(feature = "tokio", feature = "tls"))]
use flowscope::tls::HandshakeOutcome;
#[cfg(all(feature = "tokio", feature = "tls"))]
use netring::anomaly::{Anomaly, AnomalyRule, Severity};
#[cfg(all(feature = "tokio", feature = "tls"))]
use netring::flow::extract::FiveTupleKey;
#[cfg(all(feature = "tokio", feature = "tls"))]
use netring::protocol::{ProtocolEvent, ProtocolMessage};

#[cfg(all(feature = "tokio", feature = "tls"))]
struct SlowTlsHandshakeRule;

#[cfg(all(feature = "tokio", feature = "tls"))]
impl AnomalyRule<FiveTupleKey> for SlowTlsHandshakeRule {
    fn name(&self) -> &'static str {
        "SlowTlsHandshake"
    }

    fn observe(
        &mut self,
        evt: &ProtocolEvent<FiveTupleKey>,
        emit: &mut Vec<Anomaly<FiveTupleKey>>,
    ) {
        let ProtocolEvent::Message {
            kind: "tls-handshake",
            key,
            message: ProtocolMessage::TlsHandshake(hs),
            ts,
            ..
        } = evt
        else {
            return;
        };
        if !matches!(hs.outcome, HandshakeOutcome::Truncated) {
            return;
        }
        emit.push(
            Anomaly::new(self.name(), Severity::Warning, *ts)
                .with_key(*key)
                .with_observation("sni", hs.sni.as_deref().unwrap_or("<none>"))
                .with_observation("outcome", "truncated"),
        );
    }
}

#[cfg(all(feature = "tokio", feature = "tls"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;

    use futures::StreamExt;
    use netring::AnomalyMonitor;
    use netring::flow::extract::FiveTuple;
    use netring::protocol::ProtocolMonitorBuilder;

    let iface = std::env::args().nth(1).unwrap_or_else(|| "lo".into());
    let seconds: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    eprintln!(
        "[slow-tls] watching {iface} for {seconds}s; \
         alert on TlsHandshake::Truncated outcomes"
    );

    let mut monitor = ProtocolMonitorBuilder::new()
        .interface(&iface)
        .flow()
        .tls_handshake()
        .build(FiveTuple::bidirectional())?;

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new().with_rule(SlowTlsHandshakeRule);

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut alerts = 0u64;

    while Instant::now() < deadline
        && let Some(evt) = monitor.next().await
    {
        let evt = evt?;
        for a in rules.observe(&evt) {
            println!("{a}");
            alerts += 1;
        }
    }

    eprintln!("[done] {alerts} truncated TLS handshakes raised");
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "tls")))]
fn main() {
    eprintln!("Build with --features tokio,tls");
}
