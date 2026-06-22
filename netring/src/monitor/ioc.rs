//! Indicator-of-compromise (IOC) matching (issue #48).
//!
//! [`IocSet`] holds a set of threat-intel indicators — bad IPs, bad domains
//! (subdomain-aware), and bad JA3/JA4 TLS fingerprints — loaded from a feed
//! (Zeek Intel, a Suricata dataset, MISP, …). Arm it with
//! [`MonitorBuilder::ioc`](crate::monitor::MonitorBuilder::ioc): the Monitor
//! then passively matches every observed flow destination/source IP, DNS query
//! name, TLS SNI + JA3/JA4, and HTTP `Host` against the set and emits an
//! `ioc_match` anomaly per hit — no active lookups.
//!
//! Domain matching is **subdomain-aware**: an indicator `evil.example` matches
//! `evil.example`, `login.evil.example`, and `a.b.evil.example`, but not
//! `notevil.example`. Comparison is case-insensitive and ignores a trailing
//! root dot.
//!
//! The matcher methods ([`IocSet::matches_ip`] / [`matches_domain`](IocSet::matches_domain)
//! / [`matches_ja4`](IocSet::matches_ja4) / [`matches_ja3`](IocSet::matches_ja3))
//! are public, so the set is also reusable from your own handlers.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::anomaly::Severity;
use crate::ctx::Ctx;
use crate::protocol::FlowKey;

/// A set of indicators of compromise to match passively against traffic.
///
/// Build it fluently, then pass it to
/// [`MonitorBuilder::ioc`](crate::monitor::MonitorBuilder::ioc):
///
/// ```
/// use netring::monitor::ioc::IocSet;
/// use std::net::Ipv4Addr;
/// let set = IocSet::new()
///     .ip(Ipv4Addr::new(203, 0, 113, 7).into())
///     .domain("evil.example")
///     .ja4("t13d1516h2_8daaf6152771_b186095e22b6");
/// assert!(set.matches_domain("login.evil.example").is_some());
/// assert!(set.matches_domain("notevil.example").is_none());
/// ```
#[derive(Debug, Clone, Default)]
pub struct IocSet {
    ips: HashSet<IpAddr>,
    /// Domains stored lowercased + trailing-dot-stripped; matched exactly or as
    /// a parent suffix (subdomain-aware).
    domains: HashSet<String>,
    ja4: HashSet<String>,
    ja3: HashSet<String>,
}

fn norm_domain(d: &str) -> String {
    d.trim_end_matches('.').to_ascii_lowercase()
}

impl IocSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single bad IP (host indicator).
    pub fn ip(mut self, ip: IpAddr) -> Self {
        self.ips.insert(ip);
        self
    }

    /// Add many bad IPs.
    pub fn ips(mut self, it: impl IntoIterator<Item = IpAddr>) -> Self {
        self.ips.extend(it);
        self
    }

    /// Add a bad domain (subdomain-aware; case-insensitive).
    pub fn domain(mut self, d: impl AsRef<str>) -> Self {
        self.domains.insert(norm_domain(d.as_ref()));
        self
    }

    /// Add many bad domains.
    pub fn domains<S: AsRef<str>>(mut self, it: impl IntoIterator<Item = S>) -> Self {
        self.domains
            .extend(it.into_iter().map(|d| norm_domain(d.as_ref())));
        self
    }

    /// Add a bad JA4 TLS client fingerprint.
    pub fn ja4(mut self, fp: impl Into<String>) -> Self {
        self.ja4.insert(fp.into());
        self
    }

    /// Add a bad JA3 TLS client fingerprint.
    pub fn ja3(mut self, fp: impl Into<String>) -> Self {
        self.ja3.insert(fp.into());
        self
    }

    /// `true` when the set has no indicators at all.
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.domains.is_empty() && self.ja4.is_empty() && self.ja3.is_empty()
    }

    /// Match an IP against the host indicators.
    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }

    /// Subdomain-aware domain match. Returns the matched **indicator** (the
    /// listed parent domain) when `name` equals or is a subdomain of it.
    pub fn matches_domain(&self, name: &str) -> Option<&str> {
        if self.domains.is_empty() {
            return None;
        }
        let n = norm_domain(name);
        let mut candidate: &str = &n;
        loop {
            if let Some(hit) = self.domains.get(candidate) {
                return Some(hit.as_str());
            }
            match candidate.find('.') {
                Some(pos) => candidate = &candidate[pos + 1..],
                None => return None,
            }
        }
    }

    /// Match a JA4 fingerprint string.
    pub fn matches_ja4(&self, fp: &str) -> bool {
        self.ja4.contains(fp)
    }

    /// Match a JA3 fingerprint string.
    pub fn matches_ja3(&self, fp: &str) -> bool {
        self.ja3.contains(fp)
    }
}

// ── Internal match-and-emit helpers (used by `MonitorBuilder::ioc`) ──────────

/// Match a flow's destination + source IP, emitting one `ioc_match` per side
/// that hits a host indicator.
pub(crate) fn check_flow_ip(set: &IocSet, key: FlowKey, ctx: &mut Ctx<'_>) {
    for (ip, side) in [(key.b.ip(), "dst"), (key.a.ip(), "src")] {
        if set.matches_ip(&ip) {
            ctx.emit("ioc_match", Severity::Critical)
                .with_key(&key)
                .with("ioc_kind", "ip")
                .with("side", side)
                .with("indicator", ip.to_string())
                .emit();
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
        && let Some(indicator) = set.matches_domain(name)
    {
        ctx.emit("ioc_match", Severity::Critical)
            .with("ioc_kind", "dns")
            .with("indicator", indicator.to_string())
            .with("observed", name.to_string())
            .emit();
    }
}

/// Match a TLS handshake's SNI (domain) + JA3/JA4 (fingerprint) indicators.
#[cfg(feature = "tls")]
pub(crate) fn check_tls(set: &IocSet, hs: &flowscope::tls::TlsHandshake, ctx: &mut Ctx<'_>) {
    if let Some(sni) = hs.sni.as_deref()
        && let Some(indicator) = set.matches_domain(sni)
    {
        ctx.emit("ioc_match", Severity::Critical)
            .with("ioc_kind", "sni")
            .with("indicator", indicator.to_string())
            .with("observed", sni.to_string())
            .emit();
    }
    if let Some(ja4) = hs.ja4.as_deref()
        && set.matches_ja4(ja4)
    {
        ctx.emit("ioc_match", Severity::Critical)
            .with("ioc_kind", "ja4")
            .with("indicator", ja4.to_string())
            .emit();
    }
    if let Some(ja3) = hs.ja3.as_deref()
        && set.matches_ja3(ja3)
    {
        ctx.emit("ioc_match", Severity::Critical)
            .with("ioc_kind", "ja3")
            .with("indicator", ja3.to_string())
            .emit();
    }
}

/// Match an HTTP request's `Host` header against the domain indicators.
#[cfg(feature = "http")]
pub(crate) fn check_http(set: &IocSet, msg: &flowscope::http::HttpMessage, ctx: &mut Ctx<'_>) {
    if let flowscope::http::HttpMessage::Request(req) = msg
        && let Some(host) = req.host()
        && let Some(indicator) = set.matches_domain(host)
    {
        ctx.emit("ioc_match", Severity::Critical)
            .with("ioc_kind", "http_host")
            .with("indicator", indicator.to_string())
            .with("observed", host.to_string())
            .emit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn domain_match_is_subdomain_aware_and_case_insensitive() {
        let set = IocSet::new().domain("Evil.Example");
        assert_eq!(set.matches_domain("evil.example"), Some("evil.example"));
        assert_eq!(
            set.matches_domain("login.EVIL.example."),
            Some("evil.example")
        );
        assert_eq!(set.matches_domain("a.b.evil.example"), Some("evil.example"));
        assert!(set.matches_domain("notevil.example").is_none());
        assert!(set.matches_domain("example").is_none());
    }

    #[test]
    fn ip_and_fp_membership() {
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 7).into();
        let set = IocSet::new().ip(ip).ja4("abc").ja3("def");
        assert!(set.matches_ip(&ip));
        assert!(!set.matches_ip(&Ipv4Addr::LOCALHOST.into()));
        assert!(set.matches_ja4("abc"));
        assert!(set.matches_ja3("def"));
        assert!(!set.matches_ja4("nope"));
    }

    #[test]
    fn empty_set_matches_nothing() {
        let set = IocSet::new();
        assert!(set.is_empty());
        assert!(set.matches_domain("evil.example").is_none());
        assert!(!set.matches_ip(&Ipv4Addr::LOCALHOST.into()));
    }
}
