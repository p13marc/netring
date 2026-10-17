//! Typed [`BpfFilterBuilder`] — compiles a small match vocabulary
//! into classic BPF bytecode without external tools.
//!
//! See [`BpfFilter::builder`](super::BpfFilter::builder) for the
//! entry point and module-level docs in [`super::bpf`] for an
//! overview.

use std::net::IpAddr;

use super::bpf::{BpfBuildError, BpfFilter};
use super::ipnet::IpNet;

/// One unit of "what to match" — internal IR.
///
/// The builder collects a `Vec<MatchFrag>` (plus optional OR
/// branches and a top-level `negated` flag) and the compiler
/// in [`super::bpf_compile`] turns the collection into bytecode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MatchFrag {
    /// Ethertype check at offset 12 (or 16 if VLAN-shifted).
    EthType(u16),
    /// Marker fragment — adjusts subsequent offsets by +4 to
    /// account for the 802.1Q VLAN tag.
    Vlan,
    /// VLAN ID match (low 12 bits of offset 14, post-shift).
    /// Only meaningful after [`Self::Vlan`].
    VlanId(u16),
    /// IP protocol byte match. Caller composes with `EthType`.
    IpProto(u8),
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
    /// L4 source port (TCP/UDP). Requires `IpProto` to be set
    /// somewhere in the AND chain.
    SrcPort(u16),
    /// L4 destination port.
    DstPort(u16),
    /// L4 source OR destination port.
    AnyPort(u16),
    /// Exactly one of these (single-port) fragments — the OR group a
    /// `ports` / `src_ports` / `dst_ports` set records. It's one term of
    /// the AND chain like any other fragment; the compiler distributes
    /// it into OR blocks once the whole chain is known.
    AnyOf(Vec<MatchFrag>),
}

/// Typed builder for a [`BpfFilter`].
///
/// See module docs and [`BpfFilter::builder`](super::BpfFilter::builder)
/// for the entry point.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct BpfFilterBuilder {
    pub(crate) fragments: Vec<MatchFrag>,
    pub(crate) or_branches: Vec<BpfFilterBuilder>,
    pub(crate) negated: bool,
}

impl BpfFilterBuilder {
    /// Empty builder — accepts every packet (compiles to a single
    /// `ret #65535`).
    pub fn new() -> Self {
        Self::default()
    }

    // ── Ethertype / link layer ──────────────────────────────

    /// Match a specific ethertype. Common values:
    /// `0x0800` (IPv4), `0x86dd` (IPv6), `0x0806` (ARP),
    /// `0x8100` (802.1Q VLAN).
    pub fn eth_type(mut self, ty: u16) -> Self {
        self.fragments.push(MatchFrag::EthType(ty));
        self
    }

    /// Match IPv4 (`eth_type(0x0800)`).
    pub fn ipv4(self) -> Self {
        self.eth_type(0x0800)
    }

    /// Match IPv6 (`eth_type(0x86dd)`).
    pub fn ipv6(self) -> Self {
        self.eth_type(0x86dd)
    }

    /// Match ARP (`eth_type(0x0806)`).
    pub fn arp(self) -> Self {
        self.eth_type(0x0806)
    }

    /// Match 802.1Q VLAN-tagged traffic. Subsequent IP/L4 fragments
    /// emit bytecode shifted by +4 bytes to step over the VLAN tag.
    pub fn vlan(mut self) -> Self {
        self.fragments.push(MatchFrag::Vlan);
        self
    }

    /// Match a specific VLAN ID. Only meaningful after [`Self::vlan`].
    pub fn vlan_id(mut self, id: u16) -> Self {
        self.fragments.push(MatchFrag::VlanId(id));
        self
    }

    // ── IP layer ────────────────────────────────────────────

    /// Match an IP protocol number. Common values: `1` (ICMP),
    /// `6` (TCP), `17` (UDP), `47` (GRE), `58` (ICMPv6).
    pub fn ip_proto(mut self, proto: u8) -> Self {
        self.fragments.push(MatchFrag::IpProto(proto));
        self
    }

    /// Match TCP. Defaults to IPv4 if neither `.ipv4()` nor
    /// `.ipv6()` was called and no IPv6 host/net is in the chain;
    /// chain after `.ipv6()` for IPv6 TCP.
    pub fn tcp(self) -> Self {
        self.ip_proto(6)
    }

    /// Match UDP.
    pub fn udp(self) -> Self {
        self.ip_proto(17)
    }

    /// Match ICMP (IPv4). For ICMPv6 use `.ipv6().ip_proto(58)`.
    pub fn icmp(self) -> Self {
        self.ip_proto(1)
    }

    /// Match a specific source host.
    ///
    /// The address picks the family when neither `.ipv4()` nor
    /// `.ipv6()` is in the chain (an IPv6 address implies `.ipv6()`).
    /// Mixing IPv4 and IPv6 addresses, or contradicting an explicit
    /// `.ipv4()` / `.ipv6()`, fails [`build`](Self::build) with
    /// [`BpfBuildError::ConflictingProtocols`]. The same holds for
    /// every host / net method.
    pub fn src_host(mut self, addr: IpAddr) -> Self {
        self.fragments.push(MatchFrag::SrcHost(addr));
        self
    }

    /// Match a specific destination host.
    pub fn dst_host(mut self, addr: IpAddr) -> Self {
        self.fragments.push(MatchFrag::DstHost(addr));
        self
    }

    /// Match either source or destination host.
    pub fn host(mut self, addr: IpAddr) -> Self {
        self.fragments.push(MatchFrag::AnyHost(addr));
        self
    }

    /// Match a source network (address + prefix length).
    pub fn src_net(mut self, net: IpNet) -> Self {
        self.fragments.push(MatchFrag::SrcNet(net));
        self
    }

    /// Match a destination network.
    pub fn dst_net(mut self, net: IpNet) -> Self {
        self.fragments.push(MatchFrag::DstNet(net));
        self
    }

    /// Match either source or destination network.
    pub fn net(mut self, net: IpNet) -> Self {
        self.fragments.push(MatchFrag::AnyNet(net));
        self
    }

    // ── L4 ports (TCP/UDP) ──────────────────────────────────

    /// Match a TCP/UDP source port. Requires that `tcp()`,
    /// `udp()`, or `ip_proto(...)` is also in the chain.
    pub fn src_port(mut self, port: u16) -> Self {
        self.fragments.push(MatchFrag::SrcPort(port));
        self
    }

    /// Match a TCP/UDP destination port.
    pub fn dst_port(mut self, port: u16) -> Self {
        self.fragments.push(MatchFrag::DstPort(port));
        self
    }

    /// Match either source or destination port.
    pub fn port(mut self, port: u16) -> Self {
        self.fragments.push(MatchFrag::AnyPort(port));
        self
    }

    /// Match source port in any of `ports`. Convenience for multi-port
    /// monitors:
    ///
    /// ```
    /// use netring::BpfFilter;
    /// let f = BpfFilter::builder().tcp().src_ports([80, 8080, 8000]).build().unwrap();
    /// # let _ = f;
    /// ```
    ///
    /// The set is a single AND term: fragments chained before *or
    /// after* it apply to every port, so
    /// `.tcp().src_ports([80, 8080]).dst_host(h)` is
    /// `tcp && (src port 80 || src port 8080) && dst host h`. It
    /// desugars into OR blocks at build time (one per port, the rest of
    /// the chain repeated in each), and two sets in one chain into their
    /// cross product.
    ///
    /// # Panics
    ///
    /// Panics if `ports` is empty. A filter that matches "any source
    /// port" should omit the predicate entirely.
    pub fn src_ports(self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.expand_ports(ports.into_iter().collect(), MatchFrag::SrcPort)
    }

    /// Match destination port in any of `ports`. See
    /// [`Self::src_ports`].
    pub fn dst_ports(self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.expand_ports(ports.into_iter().collect(), MatchFrag::DstPort)
    }

    /// Match either source or destination port in any of `ports`.
    /// Mirrors [`Self::port`] for a set.
    pub fn ports(self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.expand_ports(ports.into_iter().collect(), MatchFrag::AnyPort)
    }

    /// Record `kind_ports([p1, p2, p3])` as one
    /// `AnyOf([kind_port(p1), kind_port(p2), kind_port(p3)])` AND term
    /// (a lone port as the plain fragment). Internal helper for
    /// `src_ports` / `dst_ports` / `ports`; the compiler expands it once
    /// the chain is complete, so later fragments constrain every port.
    fn expand_ports(mut self, ports: Vec<u16>, wrap: impl Fn(u16) -> MatchFrag) -> Self {
        assert!(!ports.is_empty(), "ports() requires at least one port");
        let mut alts: Vec<MatchFrag> = ports.into_iter().map(wrap).collect();
        self.fragments.push(if alts.len() == 1 {
            alts.remove(0)
        } else {
            MatchFrag::AnyOf(alts)
        });
        self
    }

    // ── Composition ─────────────────────────────────────────

    /// Negate the entire builder so far. Calling twice is a no-op.
    pub fn negate(mut self) -> Self {
        self.negated = !self.negated;
        self
    }

    /// Compose with another sub-filter via OR. Either branch
    /// matches independently; the compiled bytecode evaluates the
    /// branches in order and accepts the packet on the first match.
    pub fn or(mut self, build: impl FnOnce(BpfFilterBuilder) -> BpfFilterBuilder) -> Self {
        self.or_branches.push(build(BpfFilterBuilder::new()));
        self
    }

    /// Compile + validate. Returns the filter or a [`BpfBuildError`].
    pub fn build(self) -> Result<BpfFilter, BpfBuildError> {
        super::bpf_compile::compile(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_builder_compiles() {
        // The empty builder accepts every packet — see compile() docs.
        let f = BpfFilterBuilder::new().build().unwrap();
        assert!(!f.is_empty()); // at minimum a `ret #65535`
    }

    #[test]
    fn eth_type_records_fragment() {
        let b = BpfFilterBuilder::new().eth_type(0x0800);
        assert_eq!(b.fragments, vec![MatchFrag::EthType(0x0800)]);
    }

    #[test]
    fn tcp_records_ip_proto_6() {
        let b = BpfFilterBuilder::new().tcp();
        assert_eq!(b.fragments, vec![MatchFrag::IpProto(6)]);
    }

    #[test]
    fn negate_toggles_flag() {
        let b = BpfFilterBuilder::new().tcp().negate();
        assert!(b.negated);
        let b = b.negate();
        assert!(!b.negated);
    }

    #[test]
    fn ports_records_one_and_term() {
        // `.tcp().ports([80, 8080])` is one AND term, not OR branches built
        // from the chain so far (audit A5) — the compiler expands it.
        let b = BpfFilterBuilder::new().tcp().ports([80, 8080]);
        assert_eq!(
            b.fragments,
            vec![
                MatchFrag::IpProto(6),
                MatchFrag::AnyOf(vec![MatchFrag::AnyPort(80), MatchFrag::AnyPort(8080)]),
            ]
        );
        assert!(b.or_branches.is_empty());
    }

    #[test]
    fn src_ports_uses_src_port_fragment() {
        let b = BpfFilterBuilder::new().tcp().src_ports([80, 443]);
        assert_eq!(
            b.fragments,
            vec![
                MatchFrag::IpProto(6),
                MatchFrag::AnyOf(vec![MatchFrag::SrcPort(80), MatchFrag::SrcPort(443)]),
            ]
        );
    }

    #[test]
    fn dst_ports_uses_dst_port_fragment() {
        let b = BpfFilterBuilder::new()
            .udp()
            .dst_ports([53, 5353])
            .src_host("10.0.0.1".parse().unwrap());
        assert_eq!(
            b.fragments,
            vec![
                MatchFrag::IpProto(17),
                MatchFrag::AnyOf(vec![MatchFrag::DstPort(53), MatchFrag::DstPort(5353)]),
                MatchFrag::SrcHost("10.0.0.1".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn ports_single_port_no_or_branch() {
        // Edge case: ports([80]) should be equivalent to port(80) with
        // no OR-branch.
        let b = BpfFilterBuilder::new().tcp().ports([80]);
        assert_eq!(
            b.fragments,
            vec![MatchFrag::IpProto(6), MatchFrag::AnyPort(80)]
        );
        assert!(b.or_branches.is_empty());
    }

    #[test]
    #[should_panic(expected = "at least one port")]
    fn ports_empty_panics() {
        let _ = BpfFilterBuilder::new().tcp().ports([]);
    }

    #[test]
    fn or_collects_branch() {
        let b = BpfFilterBuilder::new().tcp().or(|b| b.udp().port(53));
        assert_eq!(b.or_branches.len(), 1);
        assert_eq!(
            b.or_branches[0].fragments,
            vec![MatchFrag::IpProto(17), MatchFrag::AnyPort(53)]
        );
    }

    #[test]
    fn chained_methods_match_capture_builder_style() {
        let b = BpfFilterBuilder::new()
            .ipv4()
            .tcp()
            .dst_port(80)
            .src_host("10.0.0.1".parse().unwrap());
        assert_eq!(
            b.fragments,
            vec![
                MatchFrag::EthType(0x0800),
                MatchFrag::IpProto(6),
                MatchFrag::DstPort(80),
                MatchFrag::SrcHost("10.0.0.1".parse().unwrap()),
            ]
        );
    }
}
