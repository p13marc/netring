//! ARP visibility & anomaly detection (feature `arp`).
//!
//! ARP sits at L2 — it has no 5-tuple, so it doesn't flow through the
//! flow tracker or the session/datagram drivers like TCP/UDP L7 does.
//! Instead the Monitor parses each captured Ethernet frame for ARP
//! *inside the zero-copy drain* (alongside the packet-tier subscriptions)
//! using flowscope's free-function [`flowscope::arp::parse_frame`], feeds
//! every sender binding into a [`flowscope::correlate::ArpTable`], and
//! derives [`ArpAnomaly`]s from the resulting [`NeighborEvent`] plus
//! [`ArpMessage::is_likely_spoof`].
//!
//! Two handler surfaces, both registered on the
//! [`MonitorBuilder`](crate::monitor::MonitorBuilder):
//!
//! - [`on_arp`](crate::monitor::MonitorBuilder::on_arp) — every parsed
//!   [`ArpMessage`] (request, reply, gratuitous, RARP), the raw feed.
//! - [`on_arp_anomaly`](crate::monitor::MonitorBuilder::on_arp_anomaly) —
//!   the derived security signal: [`ArpAnomalyKind::SpoofSuspected`] and
//!   [`ArpAnomalyKind::BindingChanged`] (plus opt-in informational
//!   [`Gratuitous`](ArpAnomalyKind::Gratuitous) /
//!   [`NewBinding`](ArpAnomalyKind::NewBinding)).
//!
//! The detector keeps a configurable **warm-up window** (default 5 s) so
//! the first sweep of the network — every host announcing itself — doesn't
//! drown the operator in `NewBinding` / `BindingChanged` noise, plus an
//! **allowlist** of known `IP → MAC` bindings (gateways, anycast VRRP) that
//! never alert.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;

use flowscope::correlate::{ArpTable, NeighborEvent};
use flowscope::{ArpMessage, MacAddr, Timestamp};

use crate::anomaly::Severity;
use crate::ctx::Ctx;
use crate::error::Result;

/// Default warm-up window: anomalies that depend on prior learning
/// ([`NewBinding`](ArpAnomalyKind::NewBinding) /
/// [`BindingChanged`](ArpAnomalyKind::BindingChanged)) are suppressed for
/// this long after the first ARP frame, while the table learns the
/// steady-state topology. `SpoofSuspected` (a self-contained packet
/// property) always fires, even during warm-up.
pub const DEFAULT_ARP_WARMUP: Duration = Duration::from_secs(5);

/// TTL for learned `IP → MAC` bindings. A binding not refreshed within
/// this window is forgotten, so a host that legitimately changes MAC
/// after a long silence re-learns as `NewBinding` rather than alerting.
const ARP_TABLE_TTL: Duration = Duration::from_secs(20 * 60);

/// LRU capacity for the learned-binding table — generous for a single L2
/// segment; bounds memory on a busy or spoofed segment.
const ARP_TABLE_CAPACITY: usize = 8192;

/// What kind of ARP anomaly fired.
///
/// Ordered loosest → strongest signal. [`Self::severity`] maps each to a
/// [`Severity`] so anomaly sinks and `MinSeverity` layers can filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArpAnomalyKind {
    /// A gratuitous ARP **reply** whose announced target MAC differs from
    /// the sender's own MAC and isn't a placeholder — the classic
    /// ARP-spoof / cache-poisoning pattern
    /// ([`ArpMessage::is_likely_spoof`]). The strongest signal; fires
    /// even during warm-up. **Warning.**
    SpoofSuspected,
    /// An IP the table had already learned now announces a **different**
    /// MAC. Legitimate on failover / NIC swap, but also the on-the-wire
    /// signature of a MITM takeover. Carries the prior MAC in
    /// [`ArpAnomaly::prior_mac`]. Suppressed during warm-up. **Warning.**
    BindingChanged,
    /// A gratuitous announcement (`sender_ip == target_ip`) that is *not*
    /// a spoof — a host refreshing peers on boot / IP-change / failover.
    /// Informational and off by default
    /// ([`MonitorBuilder::arp_report_gratuitous`](crate::monitor::MonitorBuilder::arp_report_gratuitous));
    /// useful for an inventory / "who just joined" view. **Info.**
    Gratuitous,
    /// The first time the table sees an `IP → MAC` binding. Informational
    /// and off by default
    /// ([`MonitorBuilder::arp_report_new_binding`](crate::monitor::MonitorBuilder::arp_report_new_binding));
    /// after warm-up it's a "new host appeared" signal. **Info.**
    NewBinding,
}

impl ArpAnomalyKind {
    /// Stable slug for metric labels / EVE records.
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            ArpAnomalyKind::SpoofSuspected => "arp_spoof_suspected",
            ArpAnomalyKind::BindingChanged => "arp_binding_changed",
            ArpAnomalyKind::Gratuitous => "arp_gratuitous",
            ArpAnomalyKind::NewBinding => "arp_new_binding",
        }
    }

    /// Severity tier for this anomaly.
    #[inline]
    pub fn severity(self) -> Severity {
        match self {
            ArpAnomalyKind::SpoofSuspected | ArpAnomalyKind::BindingChanged => Severity::Warning,
            ArpAnomalyKind::Gratuitous | ArpAnomalyKind::NewBinding => Severity::Info,
        }
    }
}

/// A derived ARP anomaly handed to
/// [`on_arp_anomaly`](crate::monitor::MonitorBuilder::on_arp_anomaly)
/// handlers.
///
/// Carries the triggering [`ArpMessage`] verbatim so handlers can read
/// `sender_ip` / `sender` / `oper` without re-parsing, plus the prior MAC
/// for a [`BindingChanged`](ArpAnomalyKind::BindingChanged).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ArpAnomaly {
    /// Which anomaly fired.
    pub kind: ArpAnomalyKind,
    /// The ARP message that triggered it.
    pub msg: ArpMessage,
    /// Capture timestamp of the triggering frame.
    pub ts: Timestamp,
    /// For [`BindingChanged`](ArpAnomalyKind::BindingChanged): the MAC
    /// `msg.sender_ip` was bound to *before* this frame. `None` for the
    /// other kinds.
    pub prior_mac: Option<MacAddr>,
}

impl ArpAnomaly {
    /// The IP whose binding this anomaly concerns (the ARP sender's IP).
    #[inline]
    pub fn ip(&self) -> Ipv4Addr {
        self.msg.sender_ip
    }

    /// The MAC now claiming [`Self::ip`].
    #[inline]
    pub fn mac(&self) -> MacAddr {
        self.msg.sender
    }
}

/// Tuning for the ARP anomaly detector.
#[derive(Clone)]
pub(crate) struct ArpConfig {
    /// Suppress learning-dependent anomalies for this long after the
    /// first ARP frame.
    pub(crate) warmup: Duration,
    /// `IP → MAC` bindings that never alert (gateways, VRRP/HSRP virtual
    /// MACs, known multi-homed hosts).
    pub(crate) allow: HashSet<(Ipv4Addr, MacAddr)>,
    /// Emit [`ArpAnomalyKind::Gratuitous`] (off by default — noisy).
    pub(crate) report_gratuitous: bool,
    /// Emit [`ArpAnomalyKind::NewBinding`] (off by default — noisy on a
    /// first network sweep).
    pub(crate) report_new_binding: bool,
}

impl Default for ArpConfig {
    fn default() -> Self {
        Self {
            warmup: DEFAULT_ARP_WARMUP,
            allow: HashSet::new(),
            report_gratuitous: false,
            report_new_binding: false,
        }
    }
}

/// Boxed `on_arp` handler: every parsed [`ArpMessage`] + `&mut Ctx`.
pub(crate) type ArpMsgHandler = Box<dyn Fn(&ArpMessage, &mut Ctx<'_>) -> Result<()> + Send>;
/// Boxed `on_arp_anomaly` handler: a derived [`ArpAnomaly`] + `&mut Ctx`.
pub(crate) type ArpAnomalyHandler = Box<dyn Fn(&ArpAnomaly, &mut Ctx<'_>) -> Result<()> + Send>;

/// The Monitor's live ARP state: the learned-binding table, the detector
/// config, and the registered handlers. Built by the
/// [`MonitorBuilder`](crate::monitor::MonitorBuilder) when any ARP hook is
/// registered; owned by the run loop (so the table persists across frames)
/// and threaded into each frame's drain.
pub(crate) struct ArpWatch {
    pub(crate) table: ArpTable,
    pub(crate) config: ArpConfig,
    pub(crate) msg_handlers: Vec<ArpMsgHandler>,
    pub(crate) anomaly_handlers: Vec<ArpAnomalyHandler>,
    /// Timestamp of the first ARP frame seen — anchors the warm-up window.
    first_seen: Option<Timestamp>,
}

impl ArpWatch {
    pub(crate) fn new(config: ArpConfig) -> Self {
        let capacity = std::num::NonZeroUsize::new(ARP_TABLE_CAPACITY).expect("capacity > 0");
        Self {
            table: ArpTable::new(ARP_TABLE_TTL, capacity),
            config,
            msg_handlers: Vec::new(),
            anomaly_handlers: Vec::new(),
            first_seen: None,
        }
    }

    /// `true` if no work to do per frame (no handlers). The run loop skips
    /// the parse entirely when this holds, keeping the hot path free.
    pub(crate) fn is_idle(&self) -> bool {
        self.msg_handlers.is_empty() && self.anomaly_handlers.is_empty()
    }

    /// Feed one parsed ARP message into the table and derive an anomaly.
    ///
    /// Mutates the table (learns `sender_ip → sender`) and returns the
    /// derived [`ArpAnomaly`], if any. Pure aside from the table update;
    /// the run loop separately invokes the handlers (so the table can be
    /// borrowed `&` by `Ctx::arp_table` during dispatch).
    pub(crate) fn observe(&mut self, msg: &ArpMessage, ts: Timestamp) -> Option<ArpAnomaly> {
        let first = *self.first_seen.get_or_insert(ts);
        let in_warmup = ts.saturating_sub(first) < self.config.warmup;

        // Self-contained packet property — fires regardless of learning or
        // warm-up. Allowlisted (ip, mac) pairs are trusted and never alert.
        let allowed = self.config.allow.contains(&(msg.sender_ip, msg.sender));
        if msg.is_likely_spoof() && !allowed {
            // Still record the binding so a later legitimate correction
            // isn't itself flagged as a change against a stale entry.
            self.table.observe(msg.sender_ip, msg.sender, ts);
            return Some(ArpAnomaly {
                kind: ArpAnomalyKind::SpoofSuspected,
                msg: *msg,
                ts,
                prior_mac: None,
            });
        }

        // Learn the sender binding. Targets are not authoritative (a
        // request's target MAC is unknown/zero), so only senders teach.
        let event = self.table.observe(msg.sender_ip, msg.sender, ts);

        if allowed {
            return None;
        }

        match event {
            NeighborEvent::Changed { prior, .. } if !in_warmup => Some(ArpAnomaly {
                kind: ArpAnomalyKind::BindingChanged,
                msg: *msg,
                ts,
                prior_mac: Some(prior),
            }),
            NeighborEvent::NewBinding { .. } if self.config.report_new_binding && !in_warmup => {
                Some(ArpAnomaly {
                    kind: ArpAnomalyKind::NewBinding,
                    msg: *msg,
                    ts,
                    prior_mac: None,
                })
            }
            // Gratuitous-but-not-spoof: emitted only when explicitly
            // opted in, and not when it already surfaced as a stronger
            // Changed signal above.
            _ if self.config.report_gratuitous
                && msg.is_gratuitous()
                && !matches!(event, NeighborEvent::Changed { .. }) =>
            {
                Some(ArpAnomaly {
                    kind: ArpAnomalyKind::Gratuitous,
                    msg: *msg,
                    ts,
                    prior_mac: None,
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowscope::ArpOp;

    fn mac(b: u8) -> MacAddr {
        MacAddr([b, b, b, b, b, b])
    }

    fn ip(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, d)
    }

    fn ts(secs: u64) -> Timestamp {
        Timestamp::from_unix_f64(secs as f64)
    }

    /// A normal reply: sender announces its own binding.
    fn reply(sender_ip: Ipv4Addr, sender: MacAddr, target_ip: Ipv4Addr) -> ArpMessage {
        // ArpMessage is #[non_exhaustive] in flowscope; synthesize via the
        // parser so we exercise the real wire shape.
        build_arp(ArpOp::Reply, sender, sender_ip, mac(0xff), target_ip)
    }

    /// Build an ARP frame and parse it back into an `ArpMessage`.
    fn build_arp(
        oper: ArpOp,
        sender: MacAddr,
        sender_ip: Ipv4Addr,
        target: MacAddr,
        target_ip: Ipv4Addr,
    ) -> ArpMessage {
        let op = match oper {
            ArpOp::Request => 1u16,
            ArpOp::Reply => 2,
            ArpOp::RarpRequest => 3,
            ArpOp::RarpReply => 4,
            ArpOp::Other(v) => v,
            _ => 0,
        };
        let mut p = Vec::with_capacity(28);
        p.extend_from_slice(&[0, 1]); // htype: Ethernet
        p.extend_from_slice(&[0x08, 0x00]); // ptype: IPv4
        p.push(6); // hlen
        p.push(4); // plen
        p.extend_from_slice(&op.to_be_bytes());
        p.extend_from_slice(sender.as_bytes());
        p.extend_from_slice(&sender_ip.octets());
        p.extend_from_slice(target.as_bytes());
        p.extend_from_slice(&target_ip.octets());
        flowscope::arp::parse(&p).expect("valid ARP payload")
    }

    #[test]
    fn spoof_reply_fires_even_during_warmup() {
        let mut w = ArpWatch::new(ArpConfig::default());
        // Gratuitous reply where target MAC != sender MAC == spoof.
        let m = build_arp(ArpOp::Reply, mac(0xaa), ip(1), mac(0xbb), ip(1));
        assert!(m.is_likely_spoof());
        let a = w.observe(&m, ts(0)).expect("spoof anomaly");
        assert_eq!(a.kind, ArpAnomalyKind::SpoofSuspected);
        assert_eq!(a.ip(), ip(1));
    }

    #[test]
    fn binding_change_suppressed_in_warmup_then_fires() {
        let mut w = ArpWatch::new(ArpConfig::default());
        // Learn ip(2) -> mac(1) at t=0.
        assert!(w.observe(&reply(ip(2), mac(1), ip(9)), ts(0)).is_none());
        // Change to mac(2) still inside the 5s warm-up → suppressed.
        assert!(w.observe(&reply(ip(2), mac(2), ip(9)), ts(2)).is_none());
        // Change again after warm-up → BindingChanged with prior MAC.
        let a = w
            .observe(&reply(ip(2), mac(3), ip(9)), ts(10))
            .expect("binding change");
        assert_eq!(a.kind, ArpAnomalyKind::BindingChanged);
        assert_eq!(a.prior_mac, Some(mac(2)));
    }

    #[test]
    fn stable_binding_is_silent() {
        let mut w = ArpWatch::new(ArpConfig::default());
        assert!(w.observe(&reply(ip(3), mac(1), ip(9)), ts(0)).is_none());
        // Same binding refreshed long after warm-up → no anomaly.
        assert!(w.observe(&reply(ip(3), mac(1), ip(9)), ts(100)).is_none());
    }

    #[test]
    fn allowlist_silences_spoof_and_change() {
        let mut cfg = ArpConfig::default();
        cfg.allow.insert((ip(4), mac(0xaa)));
        let mut w = ArpWatch::new(cfg);
        // A spoof reply from the allowlisted (ip, mac) → silent.
        let m = build_arp(ArpOp::Reply, mac(0xaa), ip(4), mac(0xbb), ip(4));
        assert!(m.is_likely_spoof());
        assert!(w.observe(&m, ts(0)).is_none());
    }

    #[test]
    fn new_binding_opt_in_after_warmup() {
        let cfg = ArpConfig {
            report_new_binding: true,
            ..Default::default()
        };
        let mut w = ArpWatch::new(cfg);
        // First binding during warm-up → suppressed.
        assert!(w.observe(&reply(ip(5), mac(1), ip(9)), ts(0)).is_none());
        // A *different* IP after warm-up → NewBinding.
        let a = w
            .observe(&reply(ip(6), mac(2), ip(9)), ts(10))
            .expect("new binding");
        assert_eq!(a.kind, ArpAnomalyKind::NewBinding);
    }
}
