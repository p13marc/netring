//! RED metrics (issue #122) — Rate, Errors, Duration per protocol.
//!
//! The SRE "RED method" over passively-observed L7: request **rate**, **error**
//! rate, and a **duration** distribution (latency quantiles), computed per
//! protocol over rolling windows. This release covers DNS (per-response, keyed
//! on rcode + timeouts, latency from the query/response RTT) and flows
//! (per-connection, keyed on the end reason, duration = flow lifetime).
//!
//! HTTP-exchange RED (request→response latency via a paired HTTP exchange
//! parser) is a documented follow-up.

use std::time::Duration;

use flowscope::Timestamp;
use flowscope::correlate::WindowedQuantiles;

use crate::correlate::RollingRate;

/// Default rolling window / bucket (60 s in 5 s buckets).
pub(crate) const RED_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const RED_BUCKET: Duration = Duration::from_secs(5);
/// Default DDSketch relative accuracy and per-window bin cap.
pub(crate) const RED_ALPHA: f64 = 0.01;
pub(crate) const RED_MAX_BINS: usize = 512;

/// Which protocols to compute RED for (issue #122).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RedConfig {
    /// Rolling window width.
    pub window: Duration,
    /// Per-bucket width.
    pub bucket: Duration,
    /// DDSketch relative accuracy for the duration quantiles.
    pub alpha: f64,
    /// Per-window bin cap for the duration sketch.
    pub max_bins: usize,
    /// Compute DNS RED (needs the `dns` feature).
    pub dns: bool,
    /// Compute per-flow RED.
    pub flow: bool,
}

impl Default for RedConfig {
    fn default() -> Self {
        Self {
            window: RED_WINDOW,
            bucket: RED_BUCKET,
            alpha: RED_ALPHA,
            max_bins: RED_MAX_BINS,
            dns: true,
            flow: true,
        }
    }
}

/// The RED tables for one protocol: a request/error rate keyed by class
/// (`"total"` + per-error-class slugs) and a duration-ms quantile sketch.
pub(crate) struct ProtoRed {
    rate: RollingRate<&'static str, u64>,
    duration_ms: WindowedQuantiles,
}

impl ProtoRed {
    fn new(cfg: &RedConfig) -> Self {
        Self {
            rate: RollingRate::new_unbounded(cfg.window, cfg.bucket),
            duration_ms: WindowedQuantiles::new(cfg.window, cfg.bucket, cfg.alpha, cfg.max_bins),
        }
    }

    /// Record one completed request: always a `"total"`, optionally an error
    /// class, optionally a duration in milliseconds.
    pub(crate) fn observe(
        &mut self,
        error_class: Option<&'static str>,
        duration_ms: Option<f64>,
        now: Timestamp,
    ) {
        self.rate.record("total", 1, now);
        if let Some(c) = error_class {
            self.rate.record(c, 1, now);
        }
        if let Some(d) = duration_ms {
            self.duration_ms.record(d, now);
        }
    }
}

/// StateMap cell holding the enabled per-protocol RED tables.
pub(crate) struct RedState {
    pub(crate) dns: Option<ProtoRed>,
    pub(crate) flow: Option<ProtoRed>,
}

impl RedState {
    pub(crate) fn new(cfg: &RedConfig) -> Self {
        Self {
            dns: cfg.dns.then(|| ProtoRed::new(cfg)),
            flow: cfg.flow.then(|| ProtoRed::new(cfg)),
        }
    }
}

impl Default for RedState {
    fn default() -> Self {
        Self::new(&RedConfig::default())
    }
}

/// Which protocol a [`RedReport`] query addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedProto {
    /// DNS (per-response).
    Dns,
    /// Flows (per-connection).
    Flow,
}

/// A read view over the RED tables at a fixed instant (issue #122).
pub struct RedReport<'a> {
    pub(crate) state: &'a RedState,
    pub(crate) now: Timestamp,
}

impl RedReport<'_> {
    fn table(&self, proto: RedProto) -> Option<&ProtoRed> {
        match proto {
            RedProto::Dns => self.state.dns.as_ref(),
            RedProto::Flow => self.state.flow.as_ref(),
        }
    }

    /// Requests/sec for `proto` (`0.0` if the protocol isn't tracked).
    pub fn rate(&self, proto: RedProto) -> f64 {
        self.table(proto)
            .map(|t| t.rate.rate(&"total", self.now))
            .unwrap_or(0.0)
    }

    /// Errors/sec for `proto` (all error classes summed).
    pub fn error_rate(&self, proto: RedProto) -> f64 {
        self.table(proto)
            .map(|t| {
                t.rate
                    .snapshot(self.now)
                    .filter(|(k, _)| *k != "total")
                    .map(|(_, r)| r)
                    .sum()
            })
            .unwrap_or(0.0)
    }

    /// Error fraction (`errors / total`) for `proto`, `0.0..=1.0`.
    pub fn error_ratio(&self, proto: RedProto) -> f64 {
        let total = self.rate(proto);
        if total > 0.0 {
            (self.error_rate(proto) / total).min(1.0)
        } else {
            0.0
        }
    }

    /// Duration quantile `q` (`0.0..=1.0`) in milliseconds for `proto`, if any
    /// samples fall in the window.
    pub fn duration_ms(&self, proto: RedProto, q: f64) -> Option<f64> {
        self.table(proto)
            .and_then(|t| t.duration_ms.quantile(q, self.now))
    }

    /// A serializable snapshot for `proto` (rate / error rate / ratio / p50 / p95
    /// / p99).
    pub fn to_snapshot(&self, proto: RedProto) -> RedSnapshot {
        RedSnapshot {
            rate: self.rate(proto),
            error_rate: self.error_rate(proto),
            error_ratio: self.error_ratio(proto),
            p50_ms: self.duration_ms(proto, 0.50),
            p95_ms: self.duration_ms(proto, 0.95),
            p99_ms: self.duration_ms(proto, 0.99),
        }
    }
}

/// Serializable RED snapshot for one protocol (issue #122).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct RedSnapshot {
    /// Requests/sec.
    pub rate: f64,
    /// Errors/sec.
    pub error_rate: f64,
    /// Error fraction (`0.0..=1.0`).
    pub error_ratio: f64,
    /// p50 duration (ms), if sampled.
    pub p50_ms: Option<f64>,
    /// p95 duration (ms), if sampled.
    pub p95_ms: Option<f64>,
    /// p99 duration (ms), if sampled.
    pub p99_ms: Option<f64>,
}

/// Map a DNS rcode to a stable error-class slug, or `None` for `NoError`.
#[cfg(feature = "dns")]
pub(crate) fn dns_error_class(rcode: flowscope::dns::DnsRcode) -> Option<&'static str> {
    use flowscope::dns::DnsRcode;
    match rcode {
        DnsRcode::NoError => None,
        DnsRcode::NXDomain => Some("nxdomain"),
        DnsRcode::ServFail => Some("servfail"),
        DnsRcode::Refused => Some("refused"),
        _ => Some("other"),
    }
}

/// Record one DNS message into the DNS RED table (issue #122). Responses count
/// as completed requests classified by rcode; unanswered queries are timeouts.
#[cfg(feature = "dns")]
pub(crate) fn observe_dns(state: &mut RedState, msg: &flowscope::dns::DnsMessage, now: Timestamp) {
    let Some(t) = state.dns.as_mut() else {
        return;
    };
    match msg {
        flowscope::dns::DnsMessage::Response(r) => {
            let dur = r.elapsed.map(|d| d.as_secs_f64() * 1000.0);
            t.observe(dns_error_class(r.rcode), dur, now);
        }
        flowscope::dns::DnsMessage::Unanswered(_) => {
            t.observe(Some("timeout"), None, now);
        }
        flowscope::dns::DnsMessage::Query(_) => {}
        _ => {}
    }
}

/// Map a flow end reason to a stable error-class slug, or `None` for a clean end.
pub(crate) fn flow_error_class(reason: flowscope::EndReason) -> Option<&'static str> {
    use flowscope::EndReason;
    match reason {
        EndReason::Rst => Some("reset"),
        EndReason::ParseError => Some("parse_error"),
        _ => None,
    }
}
