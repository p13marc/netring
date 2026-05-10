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
//! Each property runs at proptest's default 256 cases. Run with
//! `PROPTEST_CASES=10000 cargo test ...` to stress.

use std::net::IpAddr;

use netring::{BpfFilter, BpfFilterBuilder, IpNet};
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
}

// Re-expose builder type so tests can name it.
#[allow(dead_code)]
fn _builder_type_check() -> BpfFilterBuilder {
    BpfFilter::builder()
}
