//! Property tests for [`netring::BpfFilter::builder`].
//!
//! Invariants from plan 18 §"Tests / Property tests":
//!
//! 1. Builder doesn't panic on any random valid fragment sequence.
//! 2. Empty builder accepts every random packet.
//! 3. `negate(F)` accepts a packet iff `F` rejects it.
//! 4. `negate(negate(F))` matches the same packets as `F`.
//! 5. `F.or(G)` accepts iff `F` accepts OR `G` accepts.
//! 6. AND-of-(F, G) accepts iff F accepts AND G accepts.
//! 7. Adding a fragment never broadens the matched set
//!    (monotonic narrowing).
//! 8. `BpfFilter::new(builder.instructions().to_vec())`
//!    round-trips (escape hatch consumes builder output cleanly).
//!
//! 9. (#208) A frame whose outer VLAN tag the kernel stripped gets the
//!    same verdict whether the interpreter sees the stripped frame plus the
//!    tag as metadata, or the tag re-inserted (`BpfAncillary::reinserted`).
//! 10. (#208) For a chain starting with `.vlan()`, matching the frame with
//!     the tag in-band offline equals the kernel's verdict on the stripped
//!     frame — the metadata block and the in-frame block agree.
//!
//! Each property runs at proptest's default 256 cases. Run with
//! `PROPTEST_CASES=10000 cargo test ...` to stress.

use std::net::IpAddr;

use netring::{BpfAncillary, BpfFilter, BpfFilterBuilder, IpNet, VlanProto, VlanTag};
use proptest::prelude::*;

// ── Strategies ───────────────────────────────────────────────

fn arb_port() -> impl Strategy<Value = u16> {
    1u16..=65535
}

fn arb_ipv4_octet_set() -> impl Strategy<Value = [u8; 4]> {
    (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255).prop_map(|(a, b, c, d)| [a, b, c, d])
}

fn arb_ipv4_addr() -> impl Strategy<Value = IpAddr> {
    arb_ipv4_octet_set().prop_map(|o| IpAddr::V4(o.into()))
}

fn arb_ipv4_net() -> impl Strategy<Value = IpNet> {
    (arb_ipv4_octet_set(), 0u8..=32u8).prop_map(|(o, prefix)| {
        // Mask off host bits so the constructed net is canonical.
        let raw = u32::from_be_bytes(o);
        let mask = if prefix == 0 {
            0
        } else if prefix >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - prefix as u32)
        };
        let masked = raw & mask;
        let canon = std::net::Ipv4Addr::from(masked.to_be_bytes());
        format!("{canon}/{prefix}").parse::<IpNet>().unwrap()
    })
}

/// Build a synthetic Ethernet+IPv4+TCP frame.
fn synth_eth_ipv4_tcp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(54);
    f.extend_from_slice(&[0u8; 12]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f.push(0x45);
    f.push(0);
    f.extend_from_slice(&20u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.push(64);
    f.push(6);
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&dst_ip);
    f.extend_from_slice(&src_port.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f.extend_from_slice(&0u32.to_be_bytes());
    f.push(0x50);
    f.push(0x02);
    f.extend_from_slice(&8192u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f
}

fn arb_tcp_packet() -> impl Strategy<Value = Vec<u8>> {
    (
        arb_ipv4_octet_set(),
        arb_ipv4_octet_set(),
        arb_port(),
        arb_port(),
    )
        .prop_map(|(s, d, sp, dp)| synth_eth_ipv4_tcp(s, d, sp, dp))
}

/// A VLAN tag Linux strips into the metadata: 802.1Q or 802.1ad, any TCI.
fn arb_stripped_tag() -> impl Strategy<Value = VlanTag> {
    (any::<u16>(), any::<bool>()).prop_map(|(tci, ad)| {
        VlanTag::new(
            tci,
            if ad {
                VlanProto::Dot1Ad
            } else {
                VlanProto::Dot1Q
            },
        )
    })
}

fn tpid_of(tag: &VlanTag) -> u16 {
    if tag.proto == VlanProto::Dot1Ad {
        0x88a8
    } else {
        0x8100
    }
}

/// `frame` with `tag` inserted at bytes 12..16.
fn reinsert(frame: &[u8], tag: &VlanTag) -> Vec<u8> {
    let mut f = frame[..12].to_vec();
    f.extend_from_slice(&tpid_of(tag).to_be_bytes());
    f.extend_from_slice(&tag.tci.to_be_bytes());
    f.extend_from_slice(&frame[12..]);
    f
}

/// A small builder chain over the strategies above: `(vlan?, vlan_id?,
/// l4 port?, host?, negate?)`.
fn arb_chain() -> impl Strategy<Value = BpfFilterBuilder> {
    (
        any::<bool>(),
        prop::option::of(0u16..4096),
        prop::option::of(arb_port()),
        prop::option::of(arb_ipv4_addr()),
        any::<bool>(),
    )
        .prop_map(|(vlan, vid, port, host, negate)| {
            let mut b = BpfFilter::builder();
            if vlan || vid.is_some() {
                b = b.vlan();
            }
            if let Some(v) = vid {
                b = b.vlan_id(v);
            }
            b = b.tcp();
            if let Some(p) = port {
                b = b.dst_port(p);
            }
            if let Some(h) = host {
                b = b.host(h);
            }
            if negate { b.negate() } else { b }
        })
}

// ── Properties ───────────────────────────────────────────────

proptest! {
    /// 1. Builder never panics on any random valid chain.
    #[test]
    fn builder_does_not_panic(
        port in arb_port(),
        host in arb_ipv4_addr(),
    ) {
        let _ = BpfFilter::builder().tcp().dst_port(port).build();
        let _ = BpfFilter::builder().udp().port(port).build();
        let _ = BpfFilter::builder().host(host).build();
        let _ = BpfFilter::builder().ipv4().src_host(host).build();
        let _ = BpfFilter::builder().tcp().port(port).host(host).build();
    }

    /// 2. Empty builder accepts every packet.
    #[test]
    fn empty_builder_accepts_all(pkt in arb_tcp_packet()) {
        let f = BpfFilter::builder().build().unwrap();
        prop_assert!(f.matches(&pkt));
    }

    /// 3. `negate(F)` is the complement of `F`.
    #[test]
    fn negate_is_complement(
        port in arb_port(),
        pkt in arb_tcp_packet(),
    ) {
        let f = BpfFilter::builder().tcp().dst_port(port).build().unwrap();
        let nf = BpfFilter::builder().tcp().dst_port(port).negate().build().unwrap();
        prop_assert_eq!(f.matches(&pkt), !nf.matches(&pkt));
    }

    /// 4. Double negation is identity.
    #[test]
    fn double_negate_is_identity(
        port in arb_port(),
        pkt in arb_tcp_packet(),
    ) {
        let f = BpfFilter::builder().tcp().dst_port(port).build().unwrap();
        let ff = BpfFilter::builder()
            .tcp()
            .dst_port(port)
            .negate()
            .negate()
            .build()
            .unwrap();
        prop_assert_eq!(f.matches(&pkt), ff.matches(&pkt));
    }

    /// 5. OR composition matches the union.
    #[test]
    fn or_is_union(
        port_a in arb_port(),
        port_b in arb_port(),
        pkt in arb_tcp_packet(),
    ) {
        let f_a = BpfFilter::builder().tcp().dst_port(port_a).build().unwrap();
        let f_b = BpfFilter::builder().tcp().dst_port(port_b).build().unwrap();
        let f_or = BpfFilter::builder()
            .tcp()
            .dst_port(port_a)
            .or(|b| b.tcp().dst_port(port_b))
            .build()
            .unwrap();
        prop_assert_eq!(
            f_or.matches(&pkt),
            f_a.matches(&pkt) || f_b.matches(&pkt)
        );
    }

    /// 6. AND chain matches the intersection.
    #[test]
    fn and_is_intersection(
        port in arb_port(),
        host in arb_ipv4_addr(),
        pkt in arb_tcp_packet(),
    ) {
        let f_a = BpfFilter::builder().tcp().dst_port(port).build().unwrap();
        let f_b = BpfFilter::builder().tcp().host(host).build().unwrap();
        let f_and = BpfFilter::builder()
            .tcp()
            .dst_port(port)
            .host(host)
            .build()
            .unwrap();
        prop_assert_eq!(
            f_and.matches(&pkt),
            f_a.matches(&pkt) && f_b.matches(&pkt)
        );
    }

    /// 7. Adding a fragment is monotonic (only narrows the
    /// accepted set).
    #[test]
    fn adding_fragment_monotonic(
        port in arb_port(),
        pkt in arb_tcp_packet(),
    ) {
        let coarse = BpfFilter::builder().tcp().build().unwrap();
        let fine = BpfFilter::builder().tcp().dst_port(port).build().unwrap();
        // Anything `fine` accepts must also be accepted by `coarse`.
        if fine.matches(&pkt) {
            prop_assert!(coarse.matches(&pkt));
        }
    }

    /// 8. The escape hatch `BpfFilter::new` round-trips builder
    /// output (no validation rejection on the legit bytecode).
    #[test]
    fn builder_output_round_trips(
        port in arb_port(),
        host in arb_ipv4_addr(),
    ) {
        let f = BpfFilter::builder()
            .tcp()
            .dst_port(port)
            .host(host)
            .build()
            .unwrap();
        let copy = BpfFilter::new(f.instructions().to_vec()).unwrap();
        prop_assert_eq!(f.len(), copy.len());
        prop_assert_eq!(f.instructions(), copy.instructions());
    }

    /// 9. `src_net` matches iff the packet's src IP is in the network.
    #[test]
    fn src_net_matches_correct_subset(
        net in arb_ipv4_net(),
        candidate_ip in arb_ipv4_octet_set(),
        dst_ip in arb_ipv4_octet_set(),
    ) {
        let f = BpfFilter::builder()
            .ipv4()
            .src_net(net)
            .build()
            .unwrap();
        let pkt = synth_eth_ipv4_tcp(candidate_ip, dst_ip, 1234, 80);
        let candidate_addr = u32::from_be_bytes(candidate_ip);
        let net_addr = match net.addr {
            IpAddr::V4(v) => u32::from_be_bytes(v.octets()),
            IpAddr::V6(_) => unreachable!(),
        };
        let mask = if net.prefix == 0 {
            0
        } else if net.prefix >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - net.prefix as u32)
        };
        let expected = (candidate_addr & mask) == (net_addr & mask);
        prop_assert_eq!(f.matches(&pkt), expected);
    }

    /// 10. dst_port match is exact.
    #[test]
    fn dst_port_match_is_exact(
        target in arb_port(),
        actual in arb_port(),
    ) {
        let f = BpfFilter::builder().tcp().dst_port(target).build().unwrap();
        let pkt = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 9999, actual);
        prop_assert_eq!(f.matches(&pkt), target == actual);
    }

    /// 11. `.ports([P1, P2, P3])` matches iff src or dst port is in the set.
    #[test]
    fn ports_set_matches_membership(
        actual_src in arb_port(),
        actual_dst in arb_port(),
    ) {
        // A fixed 3-port set, exercised against arbitrary src/dst ports.
        let set = [80u16, 443u16, 8080u16];
        let f = BpfFilter::builder().tcp().ports(set).build().unwrap();
        let pkt = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], actual_src, actual_dst);
        let expected = set.contains(&actual_src) || set.contains(&actual_dst);
        prop_assert_eq!(f.matches(&pkt), expected);
    }

    /// 12. `.dst_ports([...])` matches dst-only.
    #[test]
    fn dst_ports_set_matches_dst_only(
        actual_src in arb_port(),
        actual_dst in arb_port(),
    ) {
        let set = [22u16, 23u16, 222u16];
        let f = BpfFilter::builder().tcp().dst_ports(set).build().unwrap();
        let pkt = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], actual_src, actual_dst);
        // Src-only-in-set must NOT match.
        prop_assert_eq!(f.matches(&pkt), set.contains(&actual_dst));
    }

    /// 13. A port set is one AND term: fragments chained *after* it constrain
    /// every port, not just the first (audit A5).
    #[test]
    fn port_set_ands_with_later_fragments(
        actual_src in arb_ipv4_octet_set(),
        actual_dst_port in prop::sample::select(vec![80u16, 443, 8080, 22]),
        pick_host in any::<bool>(),
    ) {
        let host = [10, 0, 0, 1];
        let src = if pick_host { host } else { actual_src };
        let f = BpfFilter::builder()
            .tcp()
            .dst_ports([80, 443])
            .src_host(IpAddr::V4(host.into()))
            .build()
            .unwrap();
        let pkt = synth_eth_ipv4_tcp(src, [2, 2, 2, 2], 40000, actual_dst_port);
        let expected = [80, 443].contains(&actual_dst_port) && src == host;
        prop_assert_eq!(f.matches(&pkt), expected);
    }

    /// 14. Two port sets AND together (their cross product), and a port set in
    /// the main chain stays separate from a user `.or()` branch.
    #[test]
    fn two_port_sets_are_a_conjunction(
        sp in prop::sample::select(vec![1u16, 2, 3, 4]),
        dp in prop::sample::select(vec![1u16, 2, 3, 4]),
    ) {
        let f = BpfFilter::builder()
            .tcp()
            .src_ports([1, 2])
            .dst_ports([3, 4])
            .build()
            .unwrap();
        let pkt = synth_eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], sp, dp);
        prop_assert_eq!(f.matches(&pkt), [1, 2].contains(&sp) && [3, 4].contains(&dp));

        let g = BpfFilter::builder()
            .tcp()
            .dst_ports([3, 4])
            .or(|b| b.tcp().src_port(1))
            .build()
            .unwrap();
        prop_assert_eq!(g.matches(&pkt), [3, 4].contains(&dp) || sp == 1);
    }

    /// 15. (#208) Stripped and re-inserted views of the same frame agree.
    #[test]
    fn stripped_and_reinserted_tags_agree(
        chain in arb_chain(),
        pkt in arb_tcp_packet(),
        tag in arb_stripped_tag(),
    ) {
        let f = chain.build().unwrap();
        prop_assert_eq!(
            f.matches_with(&pkt, &BpfAncillary::stripped(tag)),
            f.matches_with(&reinsert(&pkt, &tag), &BpfAncillary::reinserted(tag))
        );
    }

    /// 16. (#208) For a `.vlan()` chain, the offline verdict on the tagged
    /// frame equals the kernel's on the stripped one.
    #[test]
    fn vlan_chain_offline_equals_kernel_stripped(
        vid in prop::option::of(0u16..4096),
        port in prop::option::of(arb_port()),
        pkt in arb_tcp_packet(),
        tag in arb_stripped_tag(),
    ) {
        let mut b = BpfFilter::builder().vlan();
        if let Some(v) = vid {
            b = b.vlan_id(v);
        }
        b = b.tcp();
        if let Some(p) = port {
            b = b.dst_port(p);
        }
        let f = b.build().unwrap();
        prop_assert_eq!(
            f.matches(&reinsert(&pkt, &tag)),
            f.matches_with(&pkt, &BpfAncillary::stripped(tag))
        );
    }
}

// Re-expose builder type so tests can name it.
#[allow(dead_code)]
fn _builder_type_check() -> BpfFilterBuilder {
    BpfFilter::builder()
}
