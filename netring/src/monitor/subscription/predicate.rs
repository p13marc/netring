//! Subscription filter predicates (0.25 Phase A1/A2).
//!
//! A [`Predicate`] is one boolean expression over packet / flow / session
//! fields. It is the **single AST** every subscription filter lowers to —
//! whether built from the typed combinators
//! ([`packet()`](crate::monitor::subscription::packet) etc.), or (Phase A4)
//! parsed from a `wirefilter` string. Two consumers read it:
//!
//! - **Userspace evaluation** ([`Predicate::eval`]) — gate a handler on the
//!   current event's fields, via a tier-supplied [`FieldSource`].
//! - **Kernel pushdown** (Phase A2/A3) — the *split* partitions the AST into a
//!   kernel-pushable conjunction (L2–L4: proto / ports / host / net / vlan,
//!   classified by [`Atom::is_kernel_pushable`]) lowered to cBPF / an XDP map,
//!   plus a userspace remainder (L7 / stateful) evaluated here. The atom vocab
//!   deliberately mirrors [`MatchFrag`](crate::config::bpf_builder) so the
//!   kernel side lowers 1:1.
//!
//! This module is pure data + evaluation — no I/O, no run-loop coupling — so
//! the boolean semantics are unit-testable in isolation.

use std::net::IpAddr;

use flowscope::L4Proto;

use crate::config::ipnet::IpNet;

/// A boolean predicate over packet / flow / session fields.
///
/// `Always` is the identity used by the `on::<E>` shim (a subscription with
/// no filter). Build larger expressions with [`Self::and`] / [`Self::or`] /
/// [`Self::not`], or via the tier builders' typed combinators.
#[derive(Debug, Clone, PartialEq)]
pub enum Predicate {
    /// Matches every event (the unfiltered subscription).
    Always,
    /// A single field test.
    Atom(Atom),
    /// Conjunction — both sides must match.
    And(Box<Predicate>, Box<Predicate>),
    /// Disjunction — either side matches.
    Or(Box<Predicate>, Box<Predicate>),
    /// Negation.
    Not(Box<Predicate>),
}

impl Predicate {
    /// AND this predicate with `other`. `Always` is the identity, so
    /// `Always.and(p) == p` (kept normalised so the kernel split doesn't
    /// carry dead `Always` nodes).
    pub fn and(self, other: Predicate) -> Predicate {
        match (self, other) {
            (Predicate::Always, p) | (p, Predicate::Always) => p,
            (a, b) => Predicate::And(Box::new(a), Box::new(b)),
        }
    }

    /// OR this predicate with `other`. `Always` is absorbing for OR
    /// (`Always.or(p) == Always`), matching boolean semantics.
    pub fn or(self, other: Predicate) -> Predicate {
        match (self, other) {
            (Predicate::Always, _) | (_, Predicate::Always) => Predicate::Always,
            (a, b) => Predicate::Or(Box::new(a), Box::new(b)),
        }
    }

    /// Negate this predicate.
    pub fn negate(self) -> Predicate {
        Predicate::Not(Box::new(self))
    }

    /// Evaluate the predicate against a tier-supplied [`FieldSource`].
    ///
    /// An [`Atom`] whose field is **absent** for this source (e.g. an SNI
    /// test on a non-TLS flow, or a port test on a source that exposes no
    /// ports) evaluates to `false` — the handler simply does not fire. This
    /// is the conservative choice: a filter only ever *narrows*.
    pub fn eval(&self, src: &dyn FieldSource) -> bool {
        match self {
            Predicate::Always => true,
            Predicate::Atom(a) => a.eval(src),
            Predicate::And(l, r) => l.eval(src) && r.eval(src),
            Predicate::Or(l, r) => l.eval(src) || r.eval(src),
            Predicate::Not(p) => !p.eval(src),
        }
    }
}

/// One field test — the leaf of a [`Predicate`].
///
/// The first group (proto / ports / host / net / vlan) is **kernel-pushable**
/// (mirrors [`MatchFrag`](crate::config::bpf_builder); compiles to cBPF and to
/// the XDP match table). The second group (SNI / HTTP host / DNS qname / byte
/// & packet counts) is **userspace-only** (L7 / stateful). [`Self::is_kernel_pushable`]
/// is the classifier the Phase A2 split uses.
#[derive(Debug, Clone, PartialEq)]
pub enum Atom {
    // --- kernel-pushable (L2–L4) ---
    /// L4 protocol (TCP / UDP / ICMP / ICMPv6).
    Proto(L4Proto),
    /// L4 source port.
    SrcPort(u16),
    /// L4 destination port.
    DstPort(u16),
    /// L4 source OR destination port.
    AnyPort(u16),
    /// Source IP host (full address).
    SrcHost(IpAddr),
    /// Destination IP host.
    DstHost(IpAddr),
    /// Source OR destination host.
    AnyHost(IpAddr),
    /// Source network (address + prefix).
    SrcNet(IpNet),
    /// Destination network.
    DstNet(IpNet),
    /// Source OR destination network.
    AnyNet(IpNet),
    /// 802.1Q VLAN id.
    VlanId(u16),

    // --- userspace-only (L7 / stateful) ---
    /// TLS SNI glob (e.g. `*.bank.example`).
    SniGlob(Glob),
    /// HTTP `Host` header glob.
    HttpHostGlob(Glob),
    /// DNS query-name glob.
    DnsQnameGlob(Glob),
    /// Flow total bytes strictly greater than N.
    BytesOver(u64),
    /// Flow total packets strictly greater than N.
    PacketsOver(u64),
}

impl Atom {
    /// `true` if this atom can be pushed into the kernel (cBPF / XDP map) —
    /// i.e. it tests only L2–L4 header fields available before any L7 parse.
    /// The Phase A2 split keeps these on the kernel side and leaves the rest
    /// (L7 / stateful) as the userspace remainder.
    pub fn is_kernel_pushable(&self) -> bool {
        matches!(
            self,
            Atom::Proto(_)
                | Atom::SrcPort(_)
                | Atom::DstPort(_)
                | Atom::AnyPort(_)
                | Atom::SrcHost(_)
                | Atom::DstHost(_)
                | Atom::AnyHost(_)
                | Atom::SrcNet(_)
                | Atom::DstNet(_)
                | Atom::AnyNet(_)
                | Atom::VlanId(_)
        )
    }

    fn eval(&self, src: &dyn FieldSource) -> bool {
        match self {
            Atom::Proto(p) => src.l4proto() == Some(*p),
            Atom::SrcPort(p) => src.src_port() == Some(*p),
            Atom::DstPort(p) => src.dst_port() == Some(*p),
            Atom::AnyPort(p) => src.src_port() == Some(*p) || src.dst_port() == Some(*p),
            Atom::SrcHost(h) => src.src_ip() == Some(*h),
            Atom::DstHost(h) => src.dst_ip() == Some(*h),
            Atom::AnyHost(h) => src.src_ip() == Some(*h) || src.dst_ip() == Some(*h),
            Atom::SrcNet(n) => src.src_ip().is_some_and(|ip| n.contains(&ip)),
            Atom::DstNet(n) => src.dst_ip().is_some_and(|ip| n.contains(&ip)),
            Atom::AnyNet(n) => {
                src.src_ip().is_some_and(|ip| n.contains(&ip))
                    || src.dst_ip().is_some_and(|ip| n.contains(&ip))
            }
            Atom::VlanId(v) => src.vlan_id() == Some(*v),
            Atom::SniGlob(g) => src.sni().is_some_and(|s| g.matches(s)),
            Atom::HttpHostGlob(g) => src.http_host().is_some_and(|s| g.matches(s)),
            Atom::DnsQnameGlob(g) => src.dns_qname().is_some_and(|s| g.matches(s)),
            Atom::BytesOver(n) => src.total_bytes().is_some_and(|b| b > *n),
            Atom::PacketsOver(n) => src.total_packets().is_some_and(|p| p > *n),
        }
    }
}

/// A minimal case-insensitive `*` glob (the `*.bank` / `api.*` shapes).
///
/// Supports `*` (matches any run, including empty); every other character is
/// literal. Deliberately dependency-free — the common hostname-matching cases
/// need nothing heavier, and a real regex escape hatch arrives with the Phase
/// A4 `wirefilter` field schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    /// Literal segments split on `*`; the pattern matches iff each segment
    /// appears in order, with the first/last anchored unless the pattern
    /// begins/ends with `*`.
    pattern: String,
}

impl Glob {
    /// Build a glob from a pattern string.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into().to_ascii_lowercase(),
        }
    }

    /// `true` if `input` matches the glob (case-insensitive).
    pub fn matches(&self, input: &str) -> bool {
        glob_match(&self.pattern, &input.to_ascii_lowercase())
    }
}

/// Case-insensitive `*`-glob matcher over already-lowercased inputs.
/// Iterative two-pointer with backtracking — O(n·m) worst case, no alloc.
fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<u8> = pat.bytes().collect();
    let t: Vec<u8> = text.bytes().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Backtrack anchors: where the last `*` was, and the text pos to retry.
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if star != usize::MAX {
            // Mismatch under a `*`: consume one more text byte and retry.
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    // Trailing `*`s in the pattern match the empty remainder.
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Field accessor the [`Predicate`] evaluator reads. Each subscription tier
/// supplies an implementation exposing only the fields it has; the rest
/// default to `None` (so an atom over an absent field never matches).
///
/// - **packet tier** → 5-tuple + vlan from the [`PacketView`](flowscope::PacketView).
/// - **flow tier** → 5-tuple + byte/packet counts from flow stats.
/// - **session tier** → 5-tuple + the parsed L7 fields (sni / host / qname).
#[allow(unused_variables)]
pub trait FieldSource {
    /// L4 protocol of the current event, if known.
    fn l4proto(&self) -> Option<L4Proto> {
        None
    }
    /// L4 source port.
    fn src_port(&self) -> Option<u16> {
        None
    }
    /// L4 destination port.
    fn dst_port(&self) -> Option<u16> {
        None
    }
    /// Source IP.
    fn src_ip(&self) -> Option<IpAddr> {
        None
    }
    /// Destination IP.
    fn dst_ip(&self) -> Option<IpAddr> {
        None
    }
    /// 802.1Q VLAN id.
    fn vlan_id(&self) -> Option<u16> {
        None
    }
    /// TLS SNI (session tier).
    fn sni(&self) -> Option<&str> {
        None
    }
    /// HTTP `Host` header (session tier).
    fn http_host(&self) -> Option<&str> {
        None
    }
    /// DNS query name (session tier).
    fn dns_qname(&self) -> Option<&str> {
        None
    }
    /// Flow total bytes (flow tier).
    fn total_bytes(&self) -> Option<u64> {
        None
    }
    /// Flow total packets (flow tier).
    fn total_packets(&self) -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    /// A test field source with a handful of fields set.
    #[derive(Default)]
    struct Fields {
        proto: Option<L4Proto>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        sni: Option<String>,
        bytes: Option<u64>,
    }
    impl FieldSource for Fields {
        fn l4proto(&self) -> Option<L4Proto> {
            self.proto
        }
        fn src_port(&self) -> Option<u16> {
            self.src_port
        }
        fn dst_port(&self) -> Option<u16> {
            self.dst_port
        }
        fn src_ip(&self) -> Option<IpAddr> {
            self.src_ip
        }
        fn dst_ip(&self) -> Option<IpAddr> {
            self.dst_ip
        }
        fn sni(&self) -> Option<&str> {
            self.sni.as_deref()
        }
        fn total_bytes(&self) -> Option<u64> {
            self.bytes
        }
    }

    fn tcp_443() -> Fields {
        Fields {
            proto: Some(L4Proto::Tcp),
            src_port: Some(54321),
            dst_port: Some(443),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            ..Default::default()
        }
    }

    #[test]
    fn always_matches_everything() {
        assert!(Predicate::Always.eval(&Fields::default()));
    }

    #[test]
    fn and_or_not_boolean_semantics() {
        let f = tcp_443();
        let tcp = Predicate::Atom(Atom::Proto(L4Proto::Tcp));
        let p443 = Predicate::Atom(Atom::DstPort(443));
        let p80 = Predicate::Atom(Atom::DstPort(80));

        assert!(tcp.clone().and(p443.clone()).eval(&f));
        assert!(!tcp.clone().and(p80.clone()).eval(&f));
        assert!(p443.clone().or(p80.clone()).eval(&f));
        assert!(p80.clone().negate().eval(&f));
        assert!(!p443.clone().negate().eval(&f));
    }

    #[test]
    fn always_is_and_identity_and_or_absorbing() {
        let tcp = Predicate::Atom(Atom::Proto(L4Proto::Tcp));
        // and-identity: Always.and(p) collapses to p (no And node).
        assert_eq!(Predicate::Always.and(tcp.clone()), tcp);
        assert_eq!(tcp.clone().and(Predicate::Always), tcp);
        // or-absorbing: Always.or(p) stays Always.
        assert_eq!(Predicate::Always.or(tcp.clone()), Predicate::Always);
        assert_eq!(tcp.or(Predicate::Always), Predicate::Always);
    }

    #[test]
    fn absent_field_atom_does_not_match() {
        // SNI test against a source with no SNI → false (not a panic, not true).
        let g = Predicate::Atom(Atom::SniGlob(Glob::new("*.bank")));
        assert!(!g.eval(&tcp_443()));
        // bytes test against a source with no byte count → false.
        let b = Predicate::Atom(Atom::BytesOver(1000));
        assert!(!b.eval(&tcp_443()));
    }

    #[test]
    fn net_and_count_atoms() {
        let f = Fields {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            bytes: Some(2000),
            ..Default::default()
        };
        let net: IpNet = "10.1.0.0/16".parse().unwrap();
        assert!(Predicate::Atom(Atom::SrcNet(net)).eval(&f));
        let other: IpNet = "192.168.0.0/16".parse().unwrap();
        assert!(!Predicate::Atom(Atom::SrcNet(other)).eval(&f));
        assert!(Predicate::Atom(Atom::BytesOver(1999)).eval(&f));
        assert!(!Predicate::Atom(Atom::BytesOver(2000)).eval(&f)); // strict >
    }

    #[test]
    fn sni_glob_matches() {
        let f = Fields {
            sni: Some("login.bank.example".into()),
            ..Default::default()
        };
        assert!(Predicate::Atom(Atom::SniGlob(Glob::new("*.bank.example"))).eval(&f));
        assert!(Predicate::Atom(Atom::SniGlob(Glob::new("*.BANK.*"))).eval(&f)); // case-insensitive
        assert!(!Predicate::Atom(Atom::SniGlob(Glob::new("*.gov"))).eval(&f));
    }

    #[test]
    fn glob_edge_cases() {
        assert!(Glob::new("*").matches("anything"));
        assert!(Glob::new("*").matches(""));
        assert!(Glob::new("abc").matches("abc"));
        assert!(!Glob::new("abc").matches("abcd"));
        assert!(Glob::new("a*c").matches("axxxc"));
        assert!(Glob::new("a*c").matches("ac"));
        assert!(!Glob::new("a*c").matches("ab"));
        assert!(Glob::new("*.bank").matches("x.bank"));
        assert!(!Glob::new("*.bank").matches("bank"));
        assert!(Glob::new("api.*").matches("api.example.com"));
    }

    #[test]
    fn kernel_pushability_classification() {
        assert!(Atom::Proto(L4Proto::Tcp).is_kernel_pushable());
        assert!(Atom::DstPort(443).is_kernel_pushable());
        assert!(Atom::AnyNet("10.0.0.0/8".parse().unwrap()).is_kernel_pushable());
        assert!(Atom::VlanId(100).is_kernel_pushable());
        assert!(!Atom::SniGlob(Glob::new("*.bank")).is_kernel_pushable());
        assert!(!Atom::BytesOver(1).is_kernel_pushable());
        assert!(!Atom::PacketsOver(1).is_kernel_pushable());
    }
}
