//! Traffic aggregation (issue #121) — top talkers, a host-pair traffic matrix,
//! and top DNS names / TLS SNI, all over rolling windows.
//!
//! One [`aggregate`](crate::monitor::MonitorBuilder::aggregate) call arms the
//! enabled dimensions; [`on_aggregate`](crate::monitor::MonitorBuilder::on_aggregate)
//! delivers an [`AggregateReport`] every period. Each dimension is
//! individually toggleable via [`AggregateConfig`] so a deployment pays only for
//! what it reads.

use std::net::IpAddr;
use std::time::Duration;

use flowscope::Timestamp;
use flowscope::correlate::BandwidthByKey;

use crate::correlate::RollingRate;

/// Default rolling window / bucket (60 s in 5 s buckets).
pub(crate) const AGG_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const AGG_BUCKET: Duration = Duration::from_secs(5);

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
    /// Track per-host-pair bytes/sec (traffic matrix).
    pub traffic_matrix: bool,
    /// Track DNS query-name rate (needs the `dns` feature).
    pub top_domains: bool,
    /// Track TLS SNI rate (needs the `tls` feature).
    pub top_sni: bool,
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
        let (w, b) = (cfg.window, cfg.bucket);
        Self {
            talkers: cfg.top_talkers.then(|| BandwidthByKey::new_unbounded(w, b)),
            matrix: cfg
                .traffic_matrix
                .then(|| BandwidthByKey::new_unbounded(w, b)),
            domains: cfg.top_domains.then(|| RollingRate::new_unbounded(w, b)),
            sni: cfg.top_sni.then(|| RollingRate::new_unbounded(w, b)),
        }
    }
}

impl Default for AggregateState {
    fn default() -> Self {
        Self::new(&AggregateConfig::default())
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

    /// Top-`n` host pairs by bytes/sec, descending. Empty if `traffic_matrix` off.
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
        }
    }
}

/// Serializable aggregation snapshot (issue #121).
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AggregateSnapshot {
    /// `(src_ip, bytes_per_sec)` top talkers.
    pub talkers: Vec<(String, f64)>,
    /// `(src_ip, dst_ip, bytes_per_sec)` top host pairs.
    pub pairs: Vec<(String, String, f64)>,
    /// `(name, queries_per_sec)` top DNS names.
    pub domains: Vec<(String, f64)>,
    /// `(sni, handshakes_per_sec)` top TLS SNI.
    pub sni: Vec<(String, f64)>,
}
