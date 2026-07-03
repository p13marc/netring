//! Indicator-of-compromise (IOC) matching (issue #48 / #124).
//!
//! Since 0.29 the indicator set **is** flowscope's
//! [`flowscope::detect::ioc::IocSet`] — a bounded, typed threat-intel
//! membership set with reputation + source metadata, Suricata-dataset
//! `load_feed`, and subdomain-aware domain matching. netring re-exports it here
//! (so the `netring::monitor::ioc::IocSet` path is stable) and adds the
//! [`IocSetExt`] ergonomic builder plus the match-and-emit glue the Monitor
//! uses.
//!
//! Arm it with [`MonitorBuilder::ioc`](crate::monitor::MonitorBuilder::ioc):
//! the Monitor passively matches every observed flow destination/source IP, DNS
//! query name, TLS SNI + JA3/JA4, and HTTP `Host` against the set and emits an
//! `ioc_match` anomaly per hit — no active lookups. The same set also screens
//! flows at [`flow_analysis`](crate::monitor::MonitorBuilder::flow_analysis)
//! finalize time (issue #124), so one reloaded set updates both paths.
//!
//! Domain matching is **subdomain-aware**: an indicator `evil.example` matches
//! `evil.example`, `login.evil.example`, and `a.b.evil.example`, but not
//! `notevil.example`.

use std::net::IpAddr;

use crate::anomaly::Severity;
use crate::ctx::Ctx;
use crate::protocol::FlowKey;

pub use flowscope::detect::ioc::{IocKind, IocMatch, IocSet};

/// Ergonomic fluent constructors for [`IocSet`] (the flowscope type has only
/// the verbose `insert(kind, value, reputation, source)`).
///
/// ```
/// use netring::monitor::ioc::{IocSet, IocSetExt};
/// use std::net::Ipv4Addr;
/// let set = IocSet::new()
///     .ip(Ipv4Addr::new(203, 0, 113, 7).into())
///     .domain("evil.example")
///     .ja4("t13d1516h2_8daaf6152771_b186095e22b6");
/// assert!(set.contains_domain("login.evil.example").is_some());
/// assert!(set.contains_domain("notevil.example").is_none());
/// ```
pub trait IocSetExt: Sized {
    /// Add a single bad IP (host indicator).
    fn ip(self, ip: IpAddr) -> Self;
    /// Add many bad IPs.
    fn ips(self, it: impl IntoIterator<Item = IpAddr>) -> Self;
    /// Add a bad domain (subdomain-aware; case-insensitive).
    fn domain(self, d: impl AsRef<str>) -> Self;
    /// Add many bad domains.
    fn domains<S: AsRef<str>>(self, it: impl IntoIterator<Item = S>) -> Self;
    /// Add a bad JA4 TLS client fingerprint.
    fn ja4(self, fp: impl AsRef<str>) -> Self;
    /// Add a bad JA3 TLS client fingerprint.
    fn ja3(self, fp: impl AsRef<str>) -> Self;
}

impl IocSetExt for IocSet {
    fn ip(mut self, ip: IpAddr) -> Self {
        let kind = match ip {
            IpAddr::V4(_) => IocKind::Ipv4,
            IpAddr::V6(_) => IocKind::Ipv6,
        };
        self.insert(kind, &ip.to_string(), None, None);
        self
    }

    fn ips(mut self, it: impl IntoIterator<Item = IpAddr>) -> Self {
        for ip in it {
            self = self.ip(ip);
        }
        self
    }

    fn domain(mut self, d: impl AsRef<str>) -> Self {
        self.insert(IocKind::Domain, d.as_ref(), None, None);
        self
    }

    fn domains<S: AsRef<str>>(mut self, it: impl IntoIterator<Item = S>) -> Self {
        for d in it {
            self.insert(IocKind::Domain, d.as_ref(), None, None);
        }
        self
    }

    fn ja4(mut self, fp: impl AsRef<str>) -> Self {
        self.insert(IocKind::Ja4, fp.as_ref(), None, None);
        self
    }

    fn ja3(mut self, fp: impl AsRef<str>) -> Self {
        self.insert(IocKind::Ja3, fp.as_ref(), None, None);
        self
    }
}

// ── Internal match-and-emit helpers (used by `MonitorBuilder::ioc`) ──────────

/// Emit one `ioc_match` anomaly for a hit, carrying the indicator kind, the
/// matched indicator, and (when the feed provided them) `source` +
/// `reputation`. `observed` is the concrete value that hit (the queried FQDN,
/// the SNI, …) when it differs from the stored indicator.
#[cfg(any(feature = "dns", feature = "tls", feature = "http"))]
fn emit_match(ctx: &mut Ctx<'_>, key: Option<&FlowKey>, m: &IocMatch, observed: Option<&str>) {
    let mut w = ctx.emit("ioc_match", Severity::Critical);
    if let Some(k) = key {
        w = w.with_key(k);
    }
    w = w.with("ioc_kind", m.kind.as_str());
    w = w.with("indicator", m.value.clone());
    if let Some(obs) = observed
        && obs != m.value
    {
        w = w.with("observed", obs.to_string());
    }
    if let Some(src) = &m.source {
        w = w.with("source", src.clone());
    }
    if let Some(rep) = m.reputation {
        w = w.with_metric("reputation", rep as f64);
    }
    w.emit();
}

/// Match a flow's destination + source IP, emitting one `ioc_match` per side
/// that hits a host indicator.
pub(crate) fn check_flow_ip(set: &IocSet, key: FlowKey, ctx: &mut Ctx<'_>) {
    for (ip, side) in [(key.b.ip(), "dst"), (key.a.ip(), "src")] {
        if let Some(m) = set.contains_ip(ip) {
            let mut w = ctx
                .emit("ioc_match", Severity::Critical)
                .with_key(&key)
                .with("ioc_kind", m.kind.as_str())
                .with("side", side)
                .with("indicator", m.value.clone());
            if let Some(src) = &m.source {
                w = w.with("source", src.clone());
            }
            if let Some(rep) = m.reputation {
                w = w.with_metric("reputation", rep as f64);
            }
            w.emit();
        }
    }
}

/// Match a DNS **query** name against the domain indicators. Only the outbound
/// `Query` is matched — a single lookup also re-surfaces as `Response` /
/// `Unanswered`, so matching all three would double-count one resolution.
#[cfg(feature = "dns")]
pub(crate) fn check_dns(set: &IocSet, msg: &flowscope::dns::DnsMessage, ctx: &mut Ctx<'_>) {
    let flowscope::dns::DnsMessage::Query(q) = msg else {
        return;
    };
    if let Some(name) = q.questions.first().map(|x| x.name.as_str())
        && let Some(m) = set.contains_domain(name)
    {
        emit_match(ctx, None, &m, Some(name));
    }
}

/// Match a TLS handshake's SNI (domain) + JA3/JA4 (fingerprint) indicators.
/// flowscope's [`IocSet::check_tls`] does all three in one pass.
#[cfg(feature = "tls")]
pub(crate) fn check_tls(set: &IocSet, hs: &flowscope::tls::TlsHandshake, ctx: &mut Ctx<'_>) {
    let observed = hs.sni.as_deref();
    for m in set.check_tls(hs) {
        // Only the SNI hit has a meaningful `observed`; JA3/JA4 hits store the
        // fingerprint itself as both indicator and value.
        let obs = if m.kind == IocKind::Domain {
            observed
        } else {
            None
        };
        emit_match(ctx, None, &m, obs);
    }
}

/// Match an HTTP request's `Host` header against the domain indicators.
#[cfg(feature = "http")]
pub(crate) fn check_http(set: &IocSet, msg: &flowscope::http::HttpMessage, ctx: &mut Ctx<'_>) {
    if let flowscope::http::HttpMessage::Request(req) = msg
        && let Some(host) = req.host()
        && let Some(m) = set.contains_domain(host)
    {
        emit_match(ctx, None, &m, Some(host));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn domain_match_is_subdomain_aware_and_case_insensitive() {
        let set = IocSet::new().domain("Evil.Example");
        assert!(set.contains_domain("evil.example").is_some());
        assert!(set.contains_domain("login.EVIL.example.").is_some());
        assert!(set.contains_domain("a.b.evil.example").is_some());
        assert!(set.contains_domain("notevil.example").is_none());
        assert!(set.contains_domain("example").is_none());
    }

    #[test]
    fn ip_and_fp_membership() {
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 7).into();
        let set = IocSet::new().ip(ip).ja4("abc").ja3("def");
        assert!(set.contains_ip(ip).is_some());
        assert!(set.contains_ip(Ipv4Addr::LOCALHOST.into()).is_none());
        assert!(set.contains(IocKind::Ja4, "abc").is_some());
        assert!(set.contains(IocKind::Ja3, "def").is_some());
        assert!(set.contains(IocKind::Ja4, "nope").is_none());
    }

    #[test]
    fn empty_set_matches_nothing() {
        let set = IocSet::new();
        assert!(set.is_empty());
        assert!(set.contains_domain("evil.example").is_none());
        assert!(set.contains_ip(Ipv4Addr::LOCALHOST.into()).is_none());
    }
}
