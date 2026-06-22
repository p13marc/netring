//! NDP (IPv6 Neighbor Discovery) visibility & anomaly detection (feature
//! `ndp`) — the IPv6 sibling of the [`arp`](crate::monitor::arp) module.
//!
//! NDP (ICMPv6 Neighbor Solicitation / Advertisement, RFC 4861) is the IPv6
//! equivalent of ARP. Like ARP it has no 5-tuple, so the Monitor parses each
//! frame for NDP *inside the zero-copy drain*: it walks the L2/L3 layers to
//! the ICMPv6 message and hands it to flowscope's
//! [`flowscope::ndp::parse_icmpv6`], feeds every `target → MAC` binding into a
//! [`flowscope::correlate::NeighborTable`]`<Ipv6Addr, MacAddr>`,
//! and derives [`NdpAnomaly`]s from the resulting [`NeighborEvent`] plus
//! [`NdpMessage::is_likely_spoof`].
//!
//! Two handler surfaces on the
//! [`MonitorBuilder`](crate::monitor::MonitorBuilder):
//!
//! - [`on_ndp`](crate::monitor::MonitorBuilder::on_ndp) — every parsed
//!   [`NdpMessage`] (NS / NA), the raw feed.
//! - [`on_ndp_anomaly`](crate::monitor::MonitorBuilder::on_ndp_anomaly) — the
//!   derived security signal: [`NdpAnomalyKind::SpoofSuspected`] (unsolicited
//!   override NA carrying a MAC — the SLAAC-poisoning vector) and
//!   [`NdpAnomalyKind::BindingChanged`], plus opt-in informational
//!   [`Unsolicited`](NdpAnomalyKind::Unsolicited) /
//!   [`NewBinding`](NdpAnomalyKind::NewBinding).
//!
//! Same warm-up window + allowlist tuning as ARP. (ARP and NDP are kept as
//! separate `on_arp_*` / `on_ndp_*` surfaces because the message types differ;
//! a unified `on_neighbor_anomaly` is a possible future consolidation.)

use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::time::Duration;

use flowscope::correlate::{NeighborEvent, NeighborTable};
use flowscope::{MacAddr, NdpMessage, Timestamp};

use crate::anomaly::Severity;
use crate::ctx::Ctx;
use crate::error::Result;

/// The learned IPv6 neighbour table — `Ipv6Addr → MacAddr` bindings.
type NdpTable = NeighborTable<Ipv6Addr, MacAddr>;

/// Default warm-up window: learning-dependent anomalies
/// ([`NewBinding`](NdpAnomalyKind::NewBinding) /
/// [`BindingChanged`](NdpAnomalyKind::BindingChanged)) are suppressed for this
/// long after the first NDP frame. `SpoofSuspected` (a self-contained packet
/// property) always fires.
pub const DEFAULT_NDP_WARMUP: Duration = Duration::from_secs(5);

/// TTL for learned `IPv6 → MAC` bindings.
const NDP_TABLE_TTL: Duration = Duration::from_secs(20 * 60);

/// LRU capacity for the learned-binding table.
const NDP_TABLE_CAPACITY: usize = 8192;

/// What kind of NDP anomaly fired. [`Self::severity`] maps each to a
/// [`Severity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NdpAnomalyKind {
    /// An **unsolicited override** Neighbor Advertisement (`S=0, O=1`)
    /// carrying a link-layer address — the NDP-spoof / SLAAC cache-poisoning
    /// pattern ([`NdpMessage::is_likely_spoof`]). Strongest signal; fires even
    /// during warm-up. **Warning.**
    SpoofSuspected,
    /// An IPv6 address the table had already learned now advertises a
    /// **different** MAC. Failover/SLAAC churn, or a MITM takeover. Carries the
    /// prior MAC in [`NdpAnomaly::prior_mac`]. Warm-up suppressed. **Warning.**
    BindingChanged,
    /// An unsolicited NA that isn't a spoof — a host refreshing peers.
    /// Informational, off by default
    /// ([`MonitorBuilder::ndp_report_unsolicited`](crate::monitor::MonitorBuilder::ndp_report_unsolicited)).
    /// **Info.**
    Unsolicited,
    /// First time the table sees an `IPv6 → MAC` binding. Informational, off by
    /// default
    /// ([`MonitorBuilder::ndp_report_new_binding`](crate::monitor::MonitorBuilder::ndp_report_new_binding)).
    /// **Info.**
    NewBinding,
}

impl NdpAnomalyKind {
    /// Stable slug for metric labels / EVE records.
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            NdpAnomalyKind::SpoofSuspected => "ndp_spoof_suspected",
            NdpAnomalyKind::BindingChanged => "ndp_binding_changed",
            NdpAnomalyKind::Unsolicited => "ndp_unsolicited",
            NdpAnomalyKind::NewBinding => "ndp_new_binding",
        }
    }

    /// Severity tier.
    #[inline]
    pub fn severity(self) -> Severity {
        match self {
            NdpAnomalyKind::SpoofSuspected | NdpAnomalyKind::BindingChanged => Severity::Warning,
            NdpAnomalyKind::Unsolicited | NdpAnomalyKind::NewBinding => Severity::Info,
        }
    }
}

/// A derived NDP anomaly handed to
/// [`on_ndp_anomaly`](crate::monitor::MonitorBuilder::on_ndp_anomaly) handlers.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct NdpAnomaly {
    /// Which anomaly fired.
    pub kind: NdpAnomalyKind,
    /// The NDP message that triggered it.
    pub msg: NdpMessage,
    /// Capture timestamp of the triggering frame.
    pub ts: Timestamp,
    /// For [`BindingChanged`](NdpAnomalyKind::BindingChanged): the MAC
    /// `msg.target` was bound to *before* this frame. `None` otherwise.
    pub prior_mac: Option<MacAddr>,
}

impl NdpAnomaly {
    /// The IPv6 address whose binding this anomaly concerns (the NDP target).
    #[inline]
    pub fn ip(&self) -> Ipv6Addr {
        self.msg.target
    }

    /// The MAC now claiming [`Self::ip`] (the message's link-layer address
    /// option). `None` if the triggering message carried no LL address.
    #[inline]
    pub fn mac(&self) -> Option<MacAddr> {
        self.msg.lladdr
    }
}

/// Tuning for the NDP anomaly detector.
#[derive(Clone)]
pub(crate) struct NdpConfig {
    pub(crate) warmup: Duration,
    /// `IPv6 → MAC` bindings that never alert.
    pub(crate) allow: HashSet<(Ipv6Addr, MacAddr)>,
    /// Emit [`NdpAnomalyKind::Unsolicited`] (off by default — noisy).
    pub(crate) report_unsolicited: bool,
    /// Emit [`NdpAnomalyKind::NewBinding`] (off by default — noisy on a first
    /// sweep).
    pub(crate) report_new_binding: bool,
}

impl Default for NdpConfig {
    fn default() -> Self {
        Self {
            warmup: DEFAULT_NDP_WARMUP,
            allow: HashSet::new(),
            report_unsolicited: false,
            report_new_binding: false,
        }
    }
}

/// Boxed `on_ndp` handler: every parsed [`NdpMessage`] + `&mut Ctx`.
pub(crate) type NdpMsgHandler = Box<dyn Fn(&NdpMessage, &mut Ctx<'_>) -> Result<()> + Send>;
/// Boxed `on_ndp_anomaly` handler: a derived [`NdpAnomaly`] + `&mut Ctx`.
pub(crate) type NdpAnomalyHandler = Box<dyn Fn(&NdpAnomaly, &mut Ctx<'_>) -> Result<()> + Send>;

/// The Monitor's live NDP state: the learned-binding table, detector config,
/// and registered handlers. Mirror of [`ArpWatch`](crate::monitor::arp).
pub(crate) struct NdpWatch {
    pub(crate) table: NdpTable,
    pub(crate) config: NdpConfig,
    pub(crate) msg_handlers: Vec<NdpMsgHandler>,
    pub(crate) anomaly_handlers: Vec<NdpAnomalyHandler>,
    first_seen: Option<Timestamp>,
}

impl NdpWatch {
    pub(crate) fn new(config: NdpConfig) -> Self {
        let capacity = std::num::NonZeroUsize::new(NDP_TABLE_CAPACITY).expect("capacity > 0");
        Self {
            table: NdpTable::new(NDP_TABLE_TTL, capacity),
            config,
            msg_handlers: Vec::new(),
            anomaly_handlers: Vec::new(),
            first_seen: None,
        }
    }

    /// Feed one parsed NDP message into the table and derive an anomaly.
    ///
    /// Only messages carrying a link-layer address teach a binding (`target →
    /// lladdr`); an NS/NA without one can't update the table and yields no
    /// anomaly. Mutates the table; the run loop invokes the handlers.
    pub(crate) fn observe(&mut self, msg: &NdpMessage, ts: Timestamp) -> Option<NdpAnomaly> {
        let first = *self.first_seen.get_or_insert(ts);
        let in_warmup = ts.saturating_sub(first) < self.config.warmup;

        // Nothing to learn or alert on without an advertised MAC.
        let mac = msg.lladdr?;
        let allowed = self.config.allow.contains(&(msg.target, mac));

        // Self-contained packet property — fires regardless of learning/warm-up.
        if msg.is_likely_spoof() && !allowed {
            self.table.observe(msg.target, mac, ts);
            return Some(NdpAnomaly {
                kind: NdpAnomalyKind::SpoofSuspected,
                msg: *msg,
                ts,
                prior_mac: None,
            });
        }

        let event = self.table.observe(msg.target, mac, ts);
        if allowed {
            return None;
        }

        match event {
            NeighborEvent::Changed { prior, .. } if !in_warmup => Some(NdpAnomaly {
                kind: NdpAnomalyKind::BindingChanged,
                msg: *msg,
                ts,
                prior_mac: Some(prior),
            }),
            NeighborEvent::NewBinding { .. } if self.config.report_new_binding && !in_warmup => {
                Some(NdpAnomaly {
                    kind: NdpAnomalyKind::NewBinding,
                    msg: *msg,
                    ts,
                    prior_mac: None,
                })
            }
            // Unsolicited-but-not-spoof override NA — opt-in, and not when it
            // already surfaced as a stronger Changed signal.
            _ if self.config.report_unsolicited
                && msg.is_unsolicited_override()
                && !matches!(event, NeighborEvent::Changed { .. }) =>
            {
                Some(NdpAnomaly {
                    kind: NdpAnomalyKind::Unsolicited,
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
    use flowscope::NdpKind;

    fn mac(b: u8) -> MacAddr {
        MacAddr([b, b, b, b, b, b])
    }

    fn ip(d: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, d)
    }

    fn ts(secs: u64) -> Timestamp {
        Timestamp::from_unix_f64(secs as f64)
    }

    /// Build a Neighbor Advertisement and parse it back via the real wire path.
    fn na(target: Ipv6Addr, lladdr: MacAddr, solicited: bool, override_: bool) -> NdpMessage {
        // ICMPv6 NA: type=136, code=0, checksum=0, flags(4) | target(16) |
        // option [type=2 (TLLA), len=1, mac(6)].
        let mut m = Vec::with_capacity(8 + 16 + 8);
        m.push(136);
        m.push(0);
        m.extend_from_slice(&[0, 0]); // checksum
        let mut flags = 0u8;
        if override_ {
            flags |= 0x20; // O
        }
        if solicited {
            flags |= 0x40; // S
        }
        m.push(flags);
        m.extend_from_slice(&[0, 0, 0]); // reserved
        m.extend_from_slice(&target.octets());
        m.extend_from_slice(&[2, 1]); // option type=Target LL Addr, len=1 (8 bytes)
        m.extend_from_slice(lladdr.as_bytes());
        flowscope::ndp::parse_icmpv6(&m).expect("valid NA")
    }

    #[test]
    fn unsolicited_override_na_fires_spoof_even_during_warmup() {
        let mut w = NdpWatch::new(NdpConfig::default());
        let m = na(ip(1), mac(0xbb), false, true); // S=0, O=1 + MAC
        assert_eq!(m.kind, NdpKind::Advertisement);
        assert!(m.is_likely_spoof());
        let a = w.observe(&m, ts(0)).expect("spoof anomaly");
        assert_eq!(a.kind, NdpAnomalyKind::SpoofSuspected);
        assert_eq!(a.ip(), ip(1));
        assert_eq!(a.mac(), Some(mac(0xbb)));
    }

    #[test]
    fn binding_change_suppressed_in_warmup_then_fires() {
        let mut w = NdpWatch::new(NdpConfig::default());
        // Solicited NA (not a spoof) learns ip(2) -> mac(1).
        assert!(w.observe(&na(ip(2), mac(1), true, false), ts(0)).is_none());
        // Change inside warm-up → suppressed.
        assert!(w.observe(&na(ip(2), mac(2), true, false), ts(2)).is_none());
        // Change after warm-up → BindingChanged with prior MAC.
        let a = w
            .observe(&na(ip(2), mac(3), true, false), ts(10))
            .expect("binding change");
        assert_eq!(a.kind, NdpAnomalyKind::BindingChanged);
        assert_eq!(a.prior_mac, Some(mac(2)));
    }

    #[test]
    fn stable_binding_is_silent() {
        let mut w = NdpWatch::new(NdpConfig::default());
        assert!(w.observe(&na(ip(3), mac(1), true, false), ts(0)).is_none());
        assert!(
            w.observe(&na(ip(3), mac(1), true, false), ts(100))
                .is_none()
        );
    }

    #[test]
    fn allowlist_silences_spoof() {
        let mut cfg = NdpConfig::default();
        cfg.allow.insert((ip(4), mac(0xbb)));
        let mut w = NdpWatch::new(cfg);
        let m = na(ip(4), mac(0xbb), false, true);
        assert!(m.is_likely_spoof());
        assert!(w.observe(&m, ts(0)).is_none());
    }
}
