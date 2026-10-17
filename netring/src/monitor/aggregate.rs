//! Traffic aggregation (issue #121) — top talkers, a host-pair traffic matrix,
//! and top DNS names / TLS SNI, all over rolling windows.
//!
//! One [`aggregate`](crate::monitor::MonitorBuilder::aggregate) call arms the
//! enabled dimensions; [`on_aggregate`](crate::monitor::MonitorBuilder::on_aggregate)
//! delivers an [`AggregateReport`] every period. Each dimension is
//! individually toggleable via [`AggregateConfig`] so a deployment pays only for
//! what it reads.
//!
//! Memory is bounded (0.32, #214): each dimension keeps at most
//! [`AggregateConfig::max_keys`] keys per time bucket; traffic from further
//! keys is still counted, under an overflow total, and
//! [`AggregateReport::overflow`] says how often that happened. The report
//! tick also drops buckets that left the window, so a quiet monitor gives the
//! memory back.

use std::net::IpAddr;
use std::time::Duration;

use flowscope::Timestamp;
use flowscope::correlate::BandwidthByKey;

use crate::correlate::RollingRate;

/// Default rolling window / bucket (60 s in 5 s buckets).
pub(crate) const AGG_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const AGG_BUCKET: Duration = Duration::from_secs(5);

/// Default per-bucket key cap of each dimension ([`AggregateConfig::max_keys`]).
pub const AGG_MAX_KEYS: usize = 4096;

/// Which aggregation dimensions to compute (issue #121).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AggregateConfig {
    /// Rolling window width.
    pub window: Duration,
    /// Per-bucket width (resolution).
    pub bucket: Duration,
    /// Track per-source-IP bytes/sec (top talkers).
    pub top_talkers: bool,
    /// Track per-host-pair bytes/sec (traffic matrix), keyed
    /// `(initiator, responder)`.
    pub traffic_matrix: bool,
    /// Track DNS query-name rate (needs the `dns` feature).
    pub top_domains: bool,
    /// Track TLS SNI rate (needs the `tls` feature).
    pub top_sni: bool,
    /// The memory bound: the most keys (source IPs, host pairs, names) each
    /// dimension holds per time bucket. A new key arriving at a full bucket
    /// is folded into an overflow total — counted in
    /// [`AggregateReport::overflow`], absent from the top-N. Memory per
    /// dimension stays within `max_keys × window / bucket` entries. Default
    /// [`AGG_MAX_KEYS`] (4096); `usize::MAX` restores the pre-0.32
    /// unbounded tables. New in 0.32.0 (#214).
    pub max_keys: usize,
}

impl Default for AggregateConfig {
    fn default() -> Self {
        Self {
            window: AGG_WINDOW,
            bucket: AGG_BUCKET,
            top_talkers: true,
            traffic_matrix: true,
            top_domains: true,
            top_sni: true,
            max_keys: AGG_MAX_KEYS,
        }
    }
}

/// StateMap cell holding the enabled aggregation tables.
pub(crate) struct AggregateState {
    pub(crate) talkers: Option<BandwidthByKey<IpAddr>>,
    pub(crate) matrix: Option<BandwidthByKey<(IpAddr, IpAddr)>>,
    pub(crate) domains: Option<RollingRate<String, u64>>,
    pub(crate) sni: Option<RollingRate<String, u64>>,
}

impl AggregateState {
    pub(crate) fn new(cfg: &AggregateConfig) -> Self {
        let (w, b, k) = (cfg.window, cfg.bucket, cfg.max_keys);
        Self {
            talkers: cfg.top_talkers.then(|| BandwidthByKey::new(w, b, k)),
            matrix: cfg.traffic_matrix.then(|| BandwidthByKey::new(w, b, k)),
            domains: cfg.top_domains.then(|| RollingRate::new(w, b, k)),
            sni: cfg.top_sni.then(|| RollingRate::new(w, b, k)),
        }
    }

    /// Drop every bucket that left the window at `now` (the report tick
    /// calls this, so tables shrink while no traffic arrives).
    pub(crate) fn evict_expired(&mut self, now: Timestamp) {
        if let Some(t) = self.talkers.as_mut() {
            t.evict_expired(now);
        }
        if let Some(m) = self.matrix.as_mut() {
            m.evict_expired(now);
        }
        if let Some(d) = self.domains.as_mut() {
            d.evict_expired(now);
        }
        if let Some(s) = self.sni.as_mut() {
            s.evict_expired(now);
        }
    }

    /// How many records each dimension folded into its overflow total.
    pub(crate) fn overflow(&self) -> AggregateOverflow {
        AggregateOverflow {
            talkers: self.talkers.as_ref().map_or(0, |t| t.overflowed()),
            pairs: self.matrix.as_ref().map_or(0, |m| m.overflowed()),
            domains: self.domains.as_ref().map_or(0, |d| d.overflowed()),
            sni: self.sni.as_ref().map_or(0, |s| s.overflowed()),
        }
    }
}

/// How many records each aggregation dimension could not key because its
/// bucket already held [`AggregateConfig::max_keys`] keys — cumulative since
/// the monitor started. Their traffic is in an overflow total, not in the
/// top-N. Non-zero values mean the top-N is a lower bound for the busiest
/// keys and that `max_keys` (or the bucket width) could be raised. New in
/// 0.32.0 (#214).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct AggregateOverflow {
    /// Top-talker records (source IPs) folded into the overflow total.
    pub talkers: u64,
    /// Traffic-matrix records (host pairs) folded into the overflow total.
    pub pairs: u64,
    /// DNS query names folded into the overflow total.
    pub domains: u64,
    /// TLS SNI names folded into the overflow total.
    pub sni: u64,
}

impl AggregateOverflow {
    /// The four counts summed.
    pub fn total(&self) -> u64 {
        self.talkers
            .saturating_add(self.pairs)
            .saturating_add(self.domains)
            .saturating_add(self.sni)
    }
}

impl Default for AggregateState {
    fn default() -> Self {
        Self::new(&AggregateConfig::default())
    }
}

/// The key a DNS name or SNI is counted under. Names are case-insensitive
/// (RFC 4343 — and resolvers randomise the case of queries, "DNS 0x20"), and
/// a trailing dot names the same FQDN: one domain, one key.
#[cfg(any(feature = "dns", feature = "tls"))]
pub(crate) fn name_key(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

#[cfg(all(test, any(feature = "dns", feature = "tls")))]
mod tests {
    #[test]
    fn name_key_folds_case_and_the_trailing_dot() {
        assert_eq!(super::name_key("Login.EXAMPLE.com."), "login.example.com");
        assert_eq!(super::name_key("example.com"), "example.com");
    }
}

/// A read view over the aggregation tables at a fixed instant (issue #121).
pub struct AggregateReport<'a> {
    pub(crate) state: &'a AggregateState,
    pub(crate) now: Timestamp,
}

impl AggregateReport<'_> {
    /// Top-`n` source IPs by bytes/sec, descending. Empty if `top_talkers` off.
    pub fn top_talkers(&self, n: usize) -> Vec<(IpAddr, f64)> {
        self.state
            .talkers
            .as_ref()
            .map(|t| t.top_k(n, self.now))
            .unwrap_or_default()
    }

    /// Top-`n` host pairs by bytes/sec, descending, each `(initiator,
    /// responder)` — the host that opened the flows first; both directions'
    /// bytes count towards the pair (0.32, #215: it was the address-sorted
    /// pair). Empty if `traffic_matrix` off.
    pub fn top_pairs(&self, n: usize) -> Vec<((IpAddr, IpAddr), f64)> {
        self.state
            .matrix
            .as_ref()
            .map(|m| m.top_k(n, self.now))
            .unwrap_or_default()
    }

    /// Top-`n` DNS query names by queries/sec, descending. Empty if `top_domains`
    /// off (or the `dns` feature disabled).
    pub fn top_domains(&self, n: usize) -> Vec<(String, f64)> {
        self.state
            .domains
            .as_ref()
            .map(|d| d.top_k(n, self.now))
            .unwrap_or_default()
    }

    /// Top-`n` TLS SNI by handshakes/sec, descending. Empty if `top_sni` off (or
    /// the `tls` feature disabled).
    pub fn top_sni(&self, n: usize) -> Vec<(String, f64)> {
        self.state
            .sni
            .as_ref()
            .map(|s| s.top_k(n, self.now))
            .unwrap_or_default()
    }

    /// How many records each dimension folded into its overflow total
    /// because a bucket was full ([`AggregateConfig::max_keys`]). New in
    /// 0.32.0 (#214).
    pub fn overflow(&self) -> AggregateOverflow {
        self.state.overflow()
    }

    /// A serializable snapshot of the top-`n` of each enabled dimension.
    pub fn to_snapshot(&self, n: usize) -> AggregateSnapshot {
        AggregateSnapshot {
            talkers: self
                .top_talkers(n)
                .into_iter()
                .map(|(ip, r)| (ip.to_string(), r))
                .collect(),
            pairs: self
                .top_pairs(n)
                .into_iter()
                .map(|((a, b), r)| (a.to_string(), b.to_string(), r))
                .collect(),
            domains: self.top_domains(n),
            sni: self.top_sni(n),
            overflow: self.overflow(),
        }
    }
}

/// Serializable aggregation snapshot (issue #121). `#[non_exhaustive]`
/// since 0.32.0, which added [`Self::overflow`].
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct AggregateSnapshot {
    /// `(src_ip, bytes_per_sec)` top talkers.
    pub talkers: Vec<(String, f64)>,
    /// `(initiator_ip, responder_ip, bytes_per_sec)` top host pairs.
    pub pairs: Vec<(String, String, f64)>,
    /// `(name, queries_per_sec)` top DNS names.
    pub domains: Vec<(String, f64)>,
    /// `(sni, handshakes_per_sec)` top TLS SNI.
    pub sni: Vec<(String, f64)>,
    /// Records the per-bucket key cap folded into overflow totals (#214).
    pub overflow: AggregateOverflow,
}

#[cfg(test)]
mod bound_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn cfg(max_keys: usize) -> AggregateConfig {
        AggregateConfig {
            max_keys,
            ..AggregateConfig::default()
        }
    }

    fn ip(i: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i))
    }

    /// #214: every dimension holds at most `max_keys` keys per bucket and
    /// counts the rest.
    #[test]
    fn each_dimension_is_capped_and_counts_its_overflow() {
        let mut st = AggregateState::new(&cfg(8));
        let now = Timestamp::new(100, 0);
        for i in 0..100 {
            st.talkers.as_mut().unwrap().record_tx(ip(i), 10, now);
            st.matrix
                .as_mut()
                .unwrap()
                .record_tx((ip(i), ip(0)), 10, now);
            st.domains
                .as_mut()
                .unwrap()
                .record(format!("d{i}.example"), 1, now);
            st.sni
                .as_mut()
                .unwrap()
                .record(format!("s{i}.example"), 1, now);
        }
        let report = AggregateReport { state: &st, now };
        assert_eq!(report.top_talkers(1000).len(), 8);
        assert_eq!(report.top_pairs(1000).len(), 8);
        assert_eq!(report.top_domains(1000).len(), 8);
        assert_eq!(report.top_sni(1000).len(), 8);
        let o = report.overflow();
        assert_eq!((o.talkers, o.pairs, o.domains, o.sni), (92, 92, 92, 92));
        assert_eq!(o.total(), 368);
        assert_eq!(report.to_snapshot(3).overflow, o);
    }

    /// The default cap is 4096, and `evict_expired` empties the tables once
    /// the window has passed.
    #[test]
    fn default_cap_and_tick_eviction() {
        assert_eq!(AggregateConfig::default().max_keys, AGG_MAX_KEYS);
        let mut st = AggregateState::new(&AggregateConfig::default());
        let t0 = Timestamp::new(100, 0);
        st.talkers.as_mut().unwrap().record_tx(ip(1), 10, t0);
        st.domains
            .as_mut()
            .unwrap()
            .record("a.example".into(), 1, t0);
        assert!(!st.talkers.as_ref().unwrap().is_empty());
        st.evict_expired(Timestamp::new(100 + 120, 0));
        assert!(st.talkers.as_ref().unwrap().is_empty());
        assert!(st.domains.as_ref().unwrap().is_empty());
    }
}
