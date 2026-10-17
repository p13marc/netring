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
    /// "Has a VLAN tag" — the builder's `.vlan()`. The compiler splits a
    /// chain holding it into a [`Self::VlanMeta`] chain and a
    /// [`Self::VlanInFrame`] chain (OR blocks).
    Vlan,
    /// Compiler-internal: the outer tag the kernel stripped into the skb
    /// metadata (`SKF_AD_VLAN_TAG_PRESENT`); later loads stay unshifted.
    VlanMeta,
    /// Compiler-internal: no stripped tag, an 802.1Q / 802.1ad / `0x9100`
    /// tag in the frame; later loads are shifted by +4.
    VlanInFrame,
    /// VLAN ID match (low 12 bits of the outermost tag's TCI).
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
    pub(crate) pass_ip_fragments: bool,
}

impl BpfFilterBuilder {
    /// Empty builder — accepts every packet, whole (compiles to a single
    /// `ret #4294967295`: a socket filter's return value is the number of
    /// bytes to keep, so this never truncates).
    pub fn new() -> Self {
        Self::default()
    }

    // ── Ethertype / link layer ──────────────────────────────

    /// Match a specific ethertype. Common values:
    /// `0x0800` (IPv4), `0x86dd` (IPv6), `0x0806` (ARP).
    ///
    /// The EtherType is read from the frame, so `eth_type(0x8100)` matches
    /// only a tag that is **in the frame** — on a live capture Linux strips
    /// the outer 802.1Q / 802.1ad tag before the socket filter runs (it
    /// matches a QinQ inner tag, or a tag sent by a device without VLAN TX
    /// offload). Use [`vlan`](Self::vlan) to match tagged traffic.
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

    /// Match VLAN-tagged traffic — libpcap's `vlan`, outermost tag.
    ///
    /// On a live capture Linux strips the outer 802.1Q / 802.1ad tag before
    /// the socket filter runs and keeps it in the packet metadata, so the
    /// compiled program checks two cases (#208):
    ///
    /// - a stripped tag (`SKF_AD_VLAN_TAG_PRESENT`): the rest of the chain
    ///   reads the frame at untagged offsets;
    /// - no stripped tag, but an 802.1Q / 802.1ad / `0x9100` tag in the
    ///   frame (a pcap file, a `0x9100` tag, a frame sent by a device
    ///   without VLAN TX offload): the rest of the chain reads past it (+4).
    ///
    /// With a stripped tag present the in-frame case is not tried, so on a
    /// QinQ frame `vlan` / `vlan_id` look at the outer (stripped) tag, as
    /// libpcap does. Offline ([`BpfFilter::matches`]) only the in-frame
    /// case can match; [`BpfFilter::matches_with`] supplies the metadata.
    pub fn vlan(mut self) -> Self {
        self.fragments.push(MatchFrag::Vlan);
        self
    }

    /// Match a specific VLAN ID (the low 12 bits of the outermost tag's
    /// TCI). Only meaningful after [`Self::vlan`].
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

    /// Negate the **whole filter**. The flag applies at
    /// [`build`](Self::build) to the final filter — every fragment and
    /// every [`or`](Self::or) branch, including those chained *after*
    /// this call — so `a.negate().or(b)` is `not (a or b)`, not
    /// `(not a) or b`. Calling it twice is a no-op. (A branch inside
    /// `or()` can't be negated on its own: that fails `build()` with
    /// [`BpfBuildError::NestedOr`].)
    ///
    /// ```
    /// use netring::BpfFilter;
    /// // Ethernet + a bare IPv4 header carrying IP protocol `proto`.
    /// let frame = |proto: u8| {
    ///     let mut f = vec![0u8; 12];
    ///     f.extend_from_slice(&[0x08, 0x00, 0x45, 0, 0, 20, 0, 0, 0, 0, 64, proto, 0, 0]);
    ///     f.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    ///     f
    /// };
    /// let f = BpfFilter::builder().tcp().negate().or(|b| b.udp()).build().unwrap();
    /// assert!(!f.matches(&frame(6))); // tcp
    /// assert!(!f.matches(&frame(17))); // udp: the later branch is negated too
    /// assert!(f.matches(&frame(1))); // icmp: neither
    /// assert_eq!(f.to_human(), "not (tcp or udp)");
    /// ```
    pub fn negate(mut self) -> Self {
        self.negated = !self.negated;
        self
    }

    /// Let IPv4 fragments other than the first pass the **port** terms.
    ///
    /// Only an IPv4 datagram's first fragment carries the TCP / UDP header,
    /// so a port check cannot judge the others; by default (libpcap's
    /// `port` semantics) they fail it. With this flag a non-first fragment
    /// (`frag_off & 0x1fff != 0`) skips the port check instead, while the
    /// address-family, protocol and host / net terms still apply — what an
    /// IP-fragment reassembler behind the filter needs: every fragment of
    /// the datagrams it may want (#217). A first fragment is still checked
    /// against the ports.
    ///
    /// Applies to the whole filter, every [`or`](Self::or) branch included.
    /// IPv6 fragments carry a Fragment extension header the IPv6 templates
    /// do not walk; the flag does not change them. `to_human` renders each
    /// port term as `(port … or ip[6:2] & 0x1fff != 0)`.
    pub fn pass_ip_fragments(mut self) -> Self {
        self.pass_ip_fragments = true;
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
        assert!(!f.is_empty()); // at minimum a `ret #4294967295`
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
