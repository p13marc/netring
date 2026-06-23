//! Sigma rule evaluation over flow/session records (issue #46).
//!
//! [Sigma](https://sigmahq.io) is the vendor-neutral detection-rule format
//! ("Snort for logs"). [`SigmaRuleSet`] loads Sigma YAML rules and, armed with
//! [`MonitorBuilder::sigma`](crate::monitor::MonitorBuilder::sigma), evaluates
//! them against the typed L7 records netring already parses — DNS queries, TLS
//! handshakes, and HTTP requests — emitting a `sigma_match` anomaly per hit. No
//! active probing; the rule body matches the parsed fields plus the flow's
//! 5-tuple.
//!
//! Rules are bucketed by their `logsource.category`, and each event is only
//! evaluated against the matching bucket:
//!
//! | Sigma `logsource.category` | netring surface | feature |
//! |---|---|---|
//! | `dns` | DNS queries | `dns` |
//! | `proxy` / `webserver` / `web` | HTTP requests | `http` |
//! | `firewall` / `network` / `tls` | TLS handshakes | `tls` |
//!
//! A rule whose category isn't one of these is **rejected at load** (a Sigma
//! pack aimed at Windows event logs can't run over a packet monitor) rather
//! than silently ignored. Field names follow the common community taxonomy with
//! several aliases inserted per field (e.g. `host` / `cs-host` / `http.host`)
//! so off-the-shelf rules match without remapping.
//!
//! Severity: every `sigma_match` is emitted at the ruleset's configurable
//! [`severity`](SigmaRuleSet::severity) (default [`Severity::Warning`]); the
//! rule's own Sigma level rides along as a `sigma_level` observation. (The
//! `sigma-rust` crate doesn't expose its `Level` enum publicly, so per-rule
//! level→severity mapping is a follow-up pending an upstream export.)

use std::path::Path;

use sigma_rust::{Event, Rule, rule_from_yaml};

use crate::anomaly::Severity;
use crate::ctx::Ctx;
use crate::protocol::FlowKey;

/// Error loading a [`SigmaRuleSet`].
#[derive(Debug)]
pub enum SigmaError {
    /// A rule's YAML failed to parse.
    Parse(String),
    /// A rule's `logsource.category` isn't a netring-supported L7 surface
    /// (`dns` / `proxy` / `webserver` / `web` / `firewall` / `network` / `tls`).
    UnsupportedLogsource {
        /// The offending rule's title.
        title: String,
        /// Its `logsource.category` (if any).
        category: Option<String>,
    },
    /// Reading a rule file/directory failed.
    Io(std::io::Error),
}

impl std::fmt::Display for SigmaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigmaError::Parse(e) => write!(f, "failed to parse Sigma rule: {e}"),
            SigmaError::UnsupportedLogsource { title, category } => write!(
                f,
                "Sigma rule {title:?} has unsupported logsource category {category:?} \
                 (netring evaluates dns / proxy / webserver / firewall / network / tls)"
            ),
            SigmaError::Io(e) => write!(f, "reading Sigma rules: {e}"),
        }
    }
}

impl std::error::Error for SigmaError {}

impl From<std::io::Error> for SigmaError {
    fn from(e: std::io::Error) -> Self {
        SigmaError::Io(e)
    }
}

/// Which L7 surface a rule's logsource maps to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Category {
    Dns,
    Http,
    Tls,
}

fn category_of(category: Option<&str>) -> Option<Category> {
    match category {
        Some("dns") => Some(Category::Dns),
        Some("proxy") | Some("webserver") | Some("web") => Some(Category::Http),
        Some("firewall") | Some("network") | Some("tls") => Some(Category::Tls),
        _ => None,
    }
}

/// A parsed Sigma rule plus the cheap-to-emit identity strings.
#[derive(Debug)]
struct CompiledRule {
    rule: Rule,
    /// `rule.id` if present, else the title — the stable handle for the alert.
    id: String,
    title: String,
    /// The rule's Sigma level as text (`sigma-rust` doesn't export the enum).
    level: String,
}

impl CompiledRule {
    fn new(rule: Rule) -> Self {
        let title = rule.title.clone();
        let id = rule.id.clone().unwrap_or_else(|| title.clone());
        let level = format!("{:?}", rule.level);
        Self {
            rule,
            id,
            title,
            level,
        }
    }
}

/// A compiled set of Sigma rules, bucketed by the L7 surface they apply to.
///
/// Build it from YAML, then arm it with
/// [`MonitorBuilder::sigma`](crate::monitor::MonitorBuilder::sigma):
///
/// ```
/// use netring::monitor::sigma::SigmaRuleSet;
/// let yaml = r#"
/// title: Suspicious DNS lookup
/// logsource:
///   category: dns
/// detection:
///   selection:
///     query|contains: 'evil'
///   condition: selection
/// "#;
/// let set = SigmaRuleSet::from_yaml_str(yaml).unwrap();
/// assert!(!set.is_empty());
/// ```
#[derive(Debug)]
pub struct SigmaRuleSet {
    severity: Severity,
    dns: Vec<CompiledRule>,
    http: Vec<CompiledRule>,
    tls: Vec<CompiledRule>,
}

impl Default for SigmaRuleSet {
    fn default() -> Self {
        Self::new()
    }
}

impl SigmaRuleSet {
    /// An empty rule set (emits at [`Severity::Warning`]).
    pub fn new() -> Self {
        Self {
            severity: Severity::Warning,
            dns: Vec::new(),
            http: Vec::new(),
            tls: Vec::new(),
        }
    }

    /// Set the severity emitted for every `sigma_match` (default
    /// [`Severity::Warning`]).
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Parse and add one or more Sigma rules from a YAML string. Multiple rules
    /// may be separated by `---` document markers.
    pub fn with_yaml(mut self, yaml: &str) -> Result<Self, SigmaError> {
        for doc in split_yaml_docs(yaml) {
            self.add_rule(doc)?;
        }
        Ok(self)
    }

    /// Build a rule set from a single YAML string (one or more `---`-separated
    /// rules).
    pub fn from_yaml_str(yaml: &str) -> Result<Self, SigmaError> {
        Self::new().with_yaml(yaml)
    }

    /// Load every `*.yml` / `*.yaml` file in `dir` (non-recursive) as Sigma
    /// rules.
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self, SigmaError> {
        let mut set = Self::new();
        let mut paths: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|x| x.to_str()),
                    Some("yml") | Some("yaml")
                )
            })
            .collect();
        // Deterministic load order so errors/IDs are stable across runs.
        paths.sort();
        for path in paths {
            let text = std::fs::read_to_string(&path)?;
            for doc in split_yaml_docs(&text) {
                set.add_rule(doc)?;
            }
        }
        Ok(set)
    }

    fn add_rule(&mut self, yaml: &str) -> Result<(), SigmaError> {
        let rule = rule_from_yaml(yaml).map_err(|e| SigmaError::Parse(e.to_string()))?;
        let category = category_of(rule.logsource.category.as_deref()).ok_or_else(|| {
            SigmaError::UnsupportedLogsource {
                title: rule.title.clone(),
                category: rule.logsource.category.clone(),
            }
        })?;
        let compiled = CompiledRule::new(rule);
        match category {
            Category::Dns => self.dns.push(compiled),
            Category::Http => self.http.push(compiled),
            Category::Tls => self.tls.push(compiled),
        }
        Ok(())
    }

    /// `true` when no rules are loaded.
    pub fn is_empty(&self) -> bool {
        self.dns.is_empty() && self.http.is_empty() && self.tls.is_empty()
    }

    /// Total number of loaded rules across all buckets.
    pub fn len(&self) -> usize {
        self.dns.len() + self.http.len() + self.tls.len()
    }

    pub(crate) fn has_dns(&self) -> bool {
        !self.dns.is_empty()
    }
    pub(crate) fn has_http(&self) -> bool {
        !self.http.is_empty()
    }
    pub(crate) fn has_tls(&self) -> bool {
        !self.tls.is_empty()
    }
}

/// Split a YAML string into documents on `---` separator lines.
fn split_yaml_docs(yaml: &str) -> impl Iterator<Item = &str> {
    yaml.split("\n---")
        .map(|d| d.trim_start_matches("---").trim())
        .filter(|d| !d.is_empty())
}

// ── Event construction ──────────────────────────────────────────────────────

/// The 5-tuple fields shared by every event.
fn base_event(flow: Option<FlowKey>) -> Event {
    let mut e = Event::new();
    if let Some(k) = flow {
        let proto = format!("{:?}", k.proto).to_ascii_lowercase();
        e.insert("src_ip", k.a.ip().to_string());
        e.insert("dst_ip", k.b.ip().to_string());
        e.insert("src_port", k.a.port() as i64);
        e.insert("dst_port", k.b.port() as i64);
        e.insert("proto", proto.clone());
        e.insert("network_protocol", proto);
    }
    e
}

// ── Match-and-emit helpers (used by `MonitorBuilder::sigma`) ─────────────────

fn eval_bucket(rules: &[CompiledRule], event: &Event, severity: Severity, ctx: &mut Ctx<'_>) {
    for cr in rules {
        if cr.rule.is_match(event) {
            // Keep to <=8 observations (the AnomalyWriter inline cap). Owned
            // Strings (cheap, only on a match) — never `with_dynamic`, which
            // would leak the label.
            ctx.emit("sigma_match", severity)
                .with("rule", cr.id.clone())
                .with("title", cr.title.clone())
                .with("sigma_level", cr.level.clone())
                .emit();
        }
    }
}

/// Evaluate the DNS-category rules against a DNS **query** (the outbound side
/// only — a single lookup also re-surfaces as Response/Unanswered).
#[cfg(feature = "dns")]
pub(crate) fn eval_dns(set: &SigmaRuleSet, msg: &flowscope::dns::DnsMessage, ctx: &mut Ctx<'_>) {
    let flowscope::dns::DnsMessage::Query(q) = msg else {
        return;
    };
    let Some(question) = q.questions.first() else {
        return;
    };
    let flow = ctx.flow;
    let mut event = base_event(flow);
    event.insert("query", question.name.clone());
    event.insert("dns.question.name", question.name.clone());
    event.insert("record_type", question.qtype as i64);
    eval_bucket(&set.dns, &event, set.severity, ctx);
}

/// Evaluate the HTTP-category rules against an HTTP **request**.
#[cfg(feature = "http")]
pub(crate) fn eval_http(set: &SigmaRuleSet, msg: &flowscope::http::HttpMessage, ctx: &mut Ctx<'_>) {
    let flowscope::http::HttpMessage::Request(req) = msg else {
        return;
    };
    let flow = ctx.flow;
    let mut event = base_event(flow);
    if let Some(host) = req.host() {
        event.insert("host", host);
        event.insert("cs-host", host);
        event.insert("http.host", host);
    }
    if let Some(method) = req.method_str() {
        event.insert("method", method);
        event.insert("cs-method", method);
        event.insert("http.method", method);
    }
    if let Some(uri) = req.path_str() {
        event.insert("uri", uri);
        event.insert("cs-uri", uri);
        event.insert("http.uri", uri);
    }
    if let Some(ua) = req.user_agent() {
        event.insert("user_agent", ua);
        event.insert("c-useragent", ua);
        event.insert("http.user_agent", ua);
    }
    eval_bucket(&set.http, &event, set.severity, ctx);
}

/// Evaluate the TLS-category rules against a TLS handshake.
#[cfg(feature = "tls")]
pub(crate) fn eval_tls(set: &SigmaRuleSet, hs: &flowscope::tls::TlsHandshake, ctx: &mut Ctx<'_>) {
    let flow = ctx.flow;
    let mut event = base_event(flow);
    if let Some(sni) = hs.sni.as_deref() {
        event.insert("server_name", sni);
        event.insert("sni", sni);
        event.insert("tls.server_name", sni);
    }
    if let Some(ja3) = hs.ja3.as_deref() {
        event.insert("ja3", ja3);
        event.insert("ja3_hash", ja3);
    }
    if let Some(ja4) = hs.ja4.as_deref() {
        event.insert("ja4", ja4);
    }
    if let Some(version) = hs.version {
        event.insert("tls_version", format!("{version:?}"));
    }
    eval_bucket(&set.tls, &event, set.severity, ctx);
}

#[cfg(test)]
mod tests {
    use super::*;

    const DNS_RULE: &str = r#"
title: DNS to evil domain
id: test-dns-1
level: high
logsource:
  category: dns
detection:
  selection:
    query|contains: 'evil'
  condition: selection
"#;

    #[test]
    fn loads_and_buckets_by_category() {
        let set = SigmaRuleSet::from_yaml_str(DNS_RULE).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.has_dns());
        assert!(!set.has_http());
        assert!(!set.has_tls());
    }

    #[test]
    fn unsupported_logsource_is_rejected_at_load() {
        let win = r#"
title: Windows process
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\evil.exe'
  condition: selection
"#;
        let err = SigmaRuleSet::from_yaml_str(win).unwrap_err();
        assert!(matches!(err, SigmaError::UnsupportedLogsource { .. }));
    }

    #[test]
    fn multiple_docs_split_on_separator() {
        let two = format!(
            "{DNS_RULE}\n---\n{}",
            DNS_RULE.replace("test-dns-1", "test-dns-2")
        );
        let set = SigmaRuleSet::from_yaml_str(&two).unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn rule_matches_an_event_with_the_offending_field() {
        let set = SigmaRuleSet::from_yaml_str(DNS_RULE).unwrap();
        // Build the event the way eval_dns would and check the rule fires.
        let mut hit = Event::new();
        hit.insert("query", "login.evil.example");
        assert!(set.dns[0].rule.is_match(&hit));

        let mut miss = Event::new();
        miss.insert("query", "good.example");
        assert!(!set.dns[0].rule.is_match(&miss));
    }

    #[test]
    fn default_severity_is_warning_and_overridable() {
        let set = SigmaRuleSet::from_yaml_str(DNS_RULE).unwrap();
        assert_eq!(set.severity, Severity::Warning);
        let set = set.severity(Severity::Critical);
        assert_eq!(set.severity, Severity::Critical);
    }
}
