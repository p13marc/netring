//! Anomaly: TLS handshake to an IP this host never DNS-resolved.
//!
//! Real production signal — MITRE ATT&CK T1571 / T1090. A
//! legitimate client almost always resolves a hostname via DNS
//! before opening a TLS connection to its IP. Malware C2,
//! misconfigured services that hardcode IPs, and some kinds of
//! data exfiltration skip DNS entirely. This detector catches
//! that pattern.
//!
//! Architecture (3 protocols joined in one rule):
//!
//! ```text
//! ProtocolMonitor (.flow().dns().tls())
//!       │
//!       ├── DNS Response → cache resolved IPs per source-IP
//!       │     resolved_by_host: HashMap<IpAddr, KeyIndexed<IpAddr, ()>>
//!       │
//!       ├── TLS ClientHello → look up dst IP in source's cache
//!       │     present → fine. absent → ANOMALY (TLS to unresolved IP)
//!       │
//!       └── on_tick → trim aged-out resolutions
//! ```
//!
//! False-positive caveats (documented for production tuning):
//!
//! - Hostsfile entries / local resolver caches bypass DNS over
//!   the wire. Allowlist known internal hosts before alerting.
//! - The first connection after a DNS cache reset can trigger.
//!   In practice this is short-lived.
//! - HTTP/3 / QUIC also skips TLS-over-TCP; this rule only sees
//!   TLS/443. Pair with `ProtocolMessage::QuicInitial` once
//!   flowscope exposes one.
//!
//! Usage:
//!     cargo run -p netring --example tls_to_unresolved_ip \
//!         --features tokio,dns,tls -- [interface] [seconds] [ttl_s]
//!
//! Defaults: lo, 60s, 300s DNS-cache TTL.
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "dns", feature = "tls"))]
use std::time::Duration;

#[cfg(all(feature = "tokio", feature = "dns", feature = "tls"))]
use flowscope::Timestamp;
#[cfg(all(feature = "tokio", feature = "dns", feature = "tls"))]
use flowscope::dns::{DnsMessage, DnsResolutionCache};
#[cfg(all(feature = "tokio", feature = "dns", feature = "tls"))]
use flowscope::tls::TlsMessage;
#[cfg(all(feature = "tokio", feature = "dns", feature = "tls"))]
use netring::anomaly::{Anomaly, AnomalyRule, Severity};
#[cfg(all(feature = "tokio", feature = "dns", feature = "tls"))]
use netring::flow::extract::FiveTupleKey;
#[cfg(all(feature = "tokio", feature = "dns", feature = "tls"))]
use netring::protocol::{ProtocolEvent, ProtocolMessage};

/// TLS connections to IPs the source host never resolved.
#[cfg(all(feature = "tokio", feature = "dns", feature = "tls"))]
struct TlsToUnresolvedIpRule {
    /// flowscope 0.8 `DnsResolutionCache` (plan 85) — TTL'd
    /// per-(client, target) cache with LRU-bounded growth.
    /// Replaces the prior hand-rolled
    /// `HashMap<IpAddr, KeyIndexed<IpAddr, ()>>` shape.
    cache: DnsResolutionCache,
}

#[cfg(all(feature = "tokio", feature = "dns", feature = "tls"))]
impl TlsToUnresolvedIpRule {
    fn new(ttl: Duration) -> Self {
        Self {
            cache: DnsResolutionCache::new(ttl),
        }
    }
}

#[cfg(all(feature = "tokio", feature = "dns", feature = "tls"))]
impl AnomalyRule<FiveTupleKey> for TlsToUnresolvedIpRule {
    fn name(&self) -> &'static str {
        "TlsToUnresolvedIp"
    }

    fn observe(
        &mut self,
        evt: &ProtocolEvent<FiveTupleKey>,
        emit: &mut Vec<Anomaly<FiveTupleKey>>,
    ) {
        match evt {
            // ── DNS Response: record resolutions per client IP ──
            ProtocolEvent::Message {
                kind: flowscope::parser_kinds::DNS_UDP,
                message: ProtocolMessage::Dns(DnsMessage::Response(r)),
                key,
                ts,
                ..
            } => {
                // Server responds to client; key.b is the client.
                self.cache.observe_response(key.b.ip(), r, *ts);
            }
            // ── TLS ClientHello: check dst IP against client's cache ──
            ProtocolEvent::Message {
                kind: flowscope::parser_kinds::TLS,
                message: ProtocolMessage::Tls(TlsMessage::ClientHello(ch)),
                key,
                ts,
                ..
            } => {
                let src = key.a.ip();
                let dst = key.b.ip();
                if !self.cache.was_resolved(src, dst, *ts) {
                    let sni = ch.sni.as_deref().unwrap_or("<none>");
                    emit.push(
                        Anomaly::new(self.name(), Severity::Warning, *ts)
                            .with_key(*key)
                            .with_observation("src_ip", src.to_string())
                            .with_observation("dst_ip", dst.to_string())
                            .with_observation("sni", sni)
                            .with_observation("status", "no_prior_resolution"),
                    );
                }
            }
            _ => {}
        }
    }

    fn on_tick(&mut self, now: Timestamp, _: &mut Vec<Anomaly<FiveTupleKey>>) {
        self.cache.sweep(now);
    }
}

#[cfg(all(feature = "tokio", feature = "dns", feature = "tls"))]
fn wall_clock_ts() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp::new(now.as_secs() as u32, now.subsec_nanos())
}

#[cfg(all(feature = "tokio", feature = "dns", feature = "tls"))]
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
    let ttl_s: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    eprintln!(
        "[tls-unresolved] watching {iface} for {seconds}s; \
         alert if TLS ClientHello dst IP not DNS-resolved within {ttl_s}s prior"
    );

    let mut monitor = ProtocolMonitorBuilder::new()
        .interface(&iface)
        .flow()
        .dns()
        .tls()
        .build(FiveTuple::bidirectional())?;

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new()
        .with_rule(TlsToUnresolvedIpRule::new(Duration::from_secs(ttl_s)));

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut sweep = tokio::time::interval(Duration::from_secs(5));
    let mut last_seen = Timestamp::default();
    let mut alerts = 0u64;

    while Instant::now() < deadline {
        tokio::select! {
            biased;
            Some(evt) = monitor.next() => {
                let evt = evt?;
                last_seen = evt.timestamp();
                for a in rules.observe(&evt) {
                    println!("{a}");
                    alerts += 1;
                }
            }
            _ = sweep.tick() => {
                let now = wall_clock_ts().max(last_seen);
                let _ = rules.on_tick(now);
            }
        }
    }

    eprintln!("[done] {alerts} TLS-to-unresolved-IP alerts raised");
    Ok(())
}

#[cfg(not(all(feature = "tokio", feature = "dns", feature = "tls")))]
fn main() {
    eprintln!("Build with --features tokio,dns,tls");
}
