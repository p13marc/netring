#![allow(deprecated)]
// 0.21 H.3: this file uses the legacy ProtocolMonitor / AnomalyMonitor / AnomalyRule API; remove with the legacy types in 0.22.

//! Anomaly: ICMP-explained vs unexplained connection drops.
//!
//! When a TCP flow tears down with RST or never establishes
//! (idle timeout while still in `SynSent`), the cause is often a
//! preceding ICMP error: Destination Unreachable, Time Exceeded,
//! Fragmentation Needed. `IcmpInner` (new in flowscope 0.7) lifts
//! the embedded original-packet 5-tuple out of the ICMP error so we
//! can correlate the error back to the specific TCP/UDP flow it
//! pertained to.
//!
//! This detector classifies aborted flows into two buckets:
//!
//! - **Explained drop** (`Severity::Info`) — an ICMP error
//!   referencing the same 5-tuple arrived within `window` before
//!   the flow died. Normal network behaviour; logged for context.
//! - **Unexplained drop** (`Severity::Warning`) — the flow died
//!   without a matching ICMP error. Worth surfacing: peer-side RST,
//!   firewall silent-drop, or app-level abort.
//!
//! Architecture:
//!
//! ```text
//! ProtocolMonitor (.flow().icmp())
//!       │
//!       ▼  Message{kind:"icmp", Icmp(IcmpMessage{ ty: DestinationUnreachable{ inner: Some(i), … } })}
//! KeyIndexed<(IpAddr,IpAddr,Option<u16>,Option<u16>,L4Proto), IcmpExplanation>
//!       │
//!       ▼  Flow(FlowEvent::Ended { reason: Rst|IdleTimeout, key, l4, … })
//!       look up matching IcmpInner in cache → "explained" / "unexplained"
//! ```
//!
//! Usage:
//!     cargo run -p netring --example icmp_explained_drop \
//!         --features tokio,icmp -- [interface] [seconds] [window_s]
//!
//! Defaults: lo, 60s, 5s correlation window.
//!
//! Requires `CAP_NET_RAW`. Use `just setcap`.

#[cfg(all(feature = "tokio", feature = "icmp"))]
use std::net::IpAddr;
#[cfg(all(feature = "tokio", feature = "icmp"))]
use std::time::Duration;

#[cfg(all(feature = "tokio", feature = "icmp"))]
use flowscope::icmp::{IcmpInner, IcmpMessage};
#[cfg(all(feature = "tokio", feature = "icmp"))]
use flowscope::{L4Proto, Timestamp};
#[cfg(all(feature = "tokio", feature = "icmp"))]
use netring::anomaly::{Anomaly, AnomalyRule, Severity};
#[cfg(all(feature = "tokio", feature = "icmp"))]
use netring::correlate::KeyIndexed;
#[cfg(all(feature = "tokio", feature = "icmp"))]
use netring::flow::extract::FiveTupleKey;
#[cfg(all(feature = "tokio", feature = "icmp"))]
use netring::protocol::{ProtocolEvent, ProtocolMessage};

/// Cache key: the inner 5-tuple from an ICMP error, in
/// canonical direction (no a-b swap — we look up using the
/// flow's *initiator* side).
#[cfg(all(feature = "tokio", feature = "icmp"))]
type InnerKey = (IpAddr, IpAddr, Option<u16>, Option<u16>, L4Proto);

#[cfg(all(feature = "tokio", feature = "icmp"))]
#[derive(Debug, Clone, Copy)]
struct IcmpExplanation {
    /// Stable variant slug (`"dest_unreachable"`, `"time_exceeded"`,
    /// …) from flowscope's `IcmpType::error_inner()`.
    label: &'static str,
    /// When the ICMP error arrived. The flow-died-vs-ICMP delta is
    /// what users want.
    ts: Timestamp,
}

#[cfg(all(feature = "tokio", feature = "icmp"))]
struct IcmpExplainedDropRule {
    pending: KeyIndexed<InnerKey, IcmpExplanation>,
}

#[cfg(all(feature = "tokio", feature = "icmp"))]
impl IcmpExplainedDropRule {
    fn new(window: Duration) -> Self {
        Self {
            pending: KeyIndexed::new(window),
        }
    }
}

#[cfg(all(feature = "tokio", feature = "icmp"))]
fn extract_icmp_error(msg: &IcmpMessage) -> Option<(&'static str, &IcmpInner)> {
    // flowscope 0.8 (plan 84) ships `IcmpType::error_inner()` and
    // returns `Option<(&'static str, &IcmpInner)>` for every
    // error-class variant on both v4 and v6 in one call. The
    // earlier 40-LoC pattern-match this replaces lives in git
    // history.
    msg.ty.error_inner()
}

#[cfg(all(feature = "tokio", feature = "icmp"))]
fn key_from_inner(i: &IcmpInner) -> InnerKey {
    (i.src, i.dst, i.src_port, i.dst_port, i.proto)
}

#[cfg(all(feature = "tokio", feature = "icmp"))]
fn key_from_flow(k: &FiveTupleKey, l4: L4Proto) -> InnerKey {
    (k.a.ip(), k.b.ip(), Some(k.a.port()), Some(k.b.port()), l4)
}

#[cfg(all(feature = "tokio", feature = "icmp"))]
impl AnomalyRule<FiveTupleKey> for IcmpExplainedDropRule {
    fn name(&self) -> &'static str {
        "IcmpExplainedDrop"
    }

    fn observe(
        &mut self,
        evt: &ProtocolEvent<FiveTupleKey>,
        emit: &mut Vec<Anomaly<FiveTupleKey>>,
    ) {
        match evt {
            ProtocolEvent::Message {
                parser_kind: flowscope::parser_kinds::ICMP,
                message: ProtocolMessage::Icmp(msg),
                ts,
                ..
            } => {
                if let Some((label, inner)) = extract_icmp_error(msg) {
                    self.pending.insert(
                        key_from_inner(inner),
                        IcmpExplanation { label, ts: *ts },
                        *ts,
                    );
                }
            }
            ProtocolEvent::FlowEnded {
                key,
                reason,
                stats,
                l4,
                ..
            } => {
                use flowscope::EndReason;
                // Only correlate aborted / mysterious tear-downs.
                if !matches!(reason, EndReason::Rst | EndReason::IdleTimeout) {
                    return;
                }
                let Some(l4) = l4 else { return };
                let died_ts = stats.last_seen;
                let k = key_from_flow(key, *l4);
                if let Some(expl) = self.pending.remove(&k) {
                    let delta = died_ts.saturating_sub(expl.ts);
                    emit.push(
                        Anomaly::new(self.name(), Severity::Info, died_ts)
                            .with_key(*key)
                            .with_observation("status", "explained")
                            .with_observation("icmp", expl.label)
                            .with_observation("reason", reason.as_str())
                            .with_metric("delta_ms", delta.as_secs_f64() * 1000.0),
                    );
                } else {
                    emit.push(
                        Anomaly::new(self.name(), Severity::Warning, died_ts)
                            .with_key(*key)
                            .with_observation("status", "unexplained")
                            .with_observation("reason", reason.as_str()),
                    );
                }
            }
            _ => {}
        }
    }

    fn on_tick(&mut self, now: Timestamp, _: &mut Vec<Anomaly<FiveTupleKey>>) {
        // Just trim — entries that age out without a matching flow
        // are normal (an ICMP error to an unrelated host).
        self.pending.evict_expired(now);
    }
}

#[cfg(all(feature = "tokio", feature = "icmp"))]
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
    let window_s: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    eprintln!(
        "[icmp-drop] watching {iface} for {seconds}s; \
         correlation window {window_s}s"
    );

    let mut monitor = ProtocolMonitorBuilder::new()
        .interface(&iface)
        .flow()
        .icmp()
        .build(FiveTuple::bidirectional())?;

    let mut rules = AnomalyMonitor::<FiveTupleKey>::new()
        .with_rule(IcmpExplainedDropRule::new(Duration::from_secs(window_s)));

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut sweep = tokio::time::interval(Duration::from_secs(1));
    let mut last_seen = Timestamp::default();
    let (mut n_explained, mut n_unexplained) = (0u64, 0u64);

    while Instant::now() < deadline {
        tokio::select! {
            biased;
            Some(evt) = monitor.next() => {
                let evt = evt?;
                last_seen = evt.timestamp();
                for a in rules.observe(&evt) {
                    println!("{a}");
                    match a.severity {
                        Severity::Info => n_explained += 1,
                        Severity::Warning => n_unexplained += 1,
                        _ => {}
                    }
                }
            }
            _ = sweep.tick() => {
                let now = wall_clock_ts().max(last_seen);
                let _ = rules.on_tick(now);
            }
        }
    }

    eprintln!("[done] {n_explained} explained drops, {n_unexplained} unexplained drops");
    Ok(())
}

#[cfg(all(feature = "tokio", feature = "icmp"))]
fn wall_clock_ts() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp::new(now.as_secs() as u32, now.subsec_nanos())
}

#[cfg(not(all(feature = "tokio", feature = "icmp")))]
fn main() {
    eprintln!("Build with --features tokio,icmp");
}
