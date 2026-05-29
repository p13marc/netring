//! Plan 25 — corpus tests for `BpfFilter::to_human()` /
//! `impl Display for BpfFilter`. No privileges needed; pure
//! IR-to-string rendering.

use netring::{BpfFilter, BpfInsn};

#[test]
fn empty_filter_renders_as_empty_string() {
    let f = BpfFilter::builder().build().unwrap();
    assert_eq!(f.to_human(), "");
}

#[test]
fn tcp_dst_port_443() {
    let f = BpfFilter::builder().tcp().dst_port(443).build().unwrap();
    assert_eq!(f.to_human(), "tcp and dst port 443");
}

#[test]
fn udp_src_port_53() {
    let f = BpfFilter::builder().udp().src_port(53).build().unwrap();
    assert_eq!(f.to_human(), "udp and src port 53");
}

#[test]
fn http_or_dns() {
    let f = BpfFilter::builder()
        .tcp()
        .dst_port(80)
        .or(|b| b.udp().dst_port(53))
        .build()
        .unwrap();
    assert_eq!(
        f.to_human(),
        "tcp and dst port 80 and (udp and dst port 53)"
    );
}

#[test]
fn not_arp_renders_negation_inline() {
    let f = BpfFilter::builder().eth_type(0x0806).negate().build().unwrap();
    assert_eq!(f.to_human(), "not arp");
}

#[test]
fn raw_bytecode_falls_back_to_count() {
    let raw = BpfFilter::new(vec![BpfInsn {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0xFFFF,
    }])
    .unwrap();
    let s = raw.to_human();
    assert!(s.starts_with("<raw bytecode,"), "got: {s}");
    assert!(s.contains("1 instructions"), "got: {s}");
}

#[test]
fn src_net_emits_canonical_cidr() {
    let f = BpfFilter::builder()
        .src_net("10.0.0.0/8".parse().unwrap())
        .build()
        .unwrap();
    assert_eq!(f.to_human(), "src net 10.0.0.0/8");
}

#[test]
fn dst_net_emits_canonical_cidr() {
    let f = BpfFilter::builder()
        .dst_net("192.168.1.0/24".parse().unwrap())
        .build()
        .unwrap();
    assert_eq!(f.to_human(), "dst net 192.168.1.0/24");
}

#[test]
fn vlan_with_id() {
    let f = BpfFilter::builder().vlan().vlan_id(100).build().unwrap();
    assert_eq!(f.to_human(), "vlan and vlan 100");
}

#[test]
fn host_a_to_host_b() {
    let f = BpfFilter::builder()
        .src_host("10.0.0.1".parse().unwrap())
        .dst_host("10.0.0.2".parse().unwrap())
        .build()
        .unwrap();
    assert_eq!(f.to_human(), "src host 10.0.0.1 and dst host 10.0.0.2");
}

#[test]
fn any_host_renders_unqualified() {
    let f = BpfFilter::builder()
        .host("10.0.0.1".parse().unwrap())
        .build()
        .unwrap();
    assert_eq!(f.to_human(), "host 10.0.0.1");
}

#[test]
fn unknown_ip_proto_falls_back_to_numeric() {
    // IPProto 47 = GRE
    let f = BpfFilter::builder().ip_proto(47).build().unwrap();
    assert_eq!(f.to_human(), "ip proto 47");
}

#[test]
fn unknown_ether_type_emits_hex() {
    let f = BpfFilter::builder().eth_type(0x88CC).build().unwrap();
    assert_eq!(f.to_human(), "ether proto 0x88cc");
}

#[test]
fn icmp_keyword() {
    let f = BpfFilter::builder().icmp().build().unwrap();
    assert_eq!(f.to_human(), "icmp");
}

#[test]
fn ip6_keyword() {
    let f = BpfFilter::builder().ipv6().build().unwrap();
    assert_eq!(f.to_human(), "ip6");
}

#[test]
fn display_impl_matches_to_human() {
    let f = BpfFilter::builder().tcp().dst_port(22).build().unwrap();
    assert_eq!(format!("{f}"), f.to_human());
}

#[test]
fn negated_or_chain_wraps_in_parens() {
    let f = BpfFilter::builder()
        .tcp()
        .or(|b| b.udp())
        .negate()
        .build()
        .unwrap();
    // not (tcp and (udp))  — parens wrap the OR branch, then the
    // full composite body is wrapped by negation.
    assert_eq!(f.to_human(), "not (tcp and (udp))");
}
