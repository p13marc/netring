//! Render a [`BpfFilterBuilder`] IR as a canonical
//! [pcap-filter(7)](https://www.tcpdump.org/manpages/pcap-filter.7.html)
//! expression. Powers [`BpfFilter::to_human`](super::bpf::BpfFilter::to_human).

use std::fmt;

use super::bpf_builder::{BpfFilterBuilder, MatchFrag};

/// Entry point — render `builder` into the provided formatter.
pub(crate) fn render(builder: &BpfFilterBuilder, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let body = render_to_string(builder);

    if builder.negated {
        let body_is_composite = builder.fragments.len() + builder.or_branches.len() > 1
            || !builder.or_branches.is_empty();
        if body.is_empty() {
            // `not <empty>` is the always-drop filter; pcap-filter
            // doesn't have a canonical spelling for it. Emit an
            // explanatory placeholder; round-trip with libpcap
            // isn't promised.
            f.write_str("not ()")
        } else if body_is_composite {
            write!(f, "not ({body})")
        } else {
            write!(f, "not {body}")
        }
    } else {
        f.write_str(&body)
    }
}

/// Render body parts (fragments + OR branches) into a single
/// String. The top-level AND chain is joined with " and ", each OR
/// branch is parenthesised. Returns the empty string for an empty
/// builder.
fn render_to_string(builder: &BpfFilterBuilder) -> String {
    let mut parts: Vec<String> = builder.fragments.iter().map(frag_to_string).collect();
    for branch in &builder.or_branches {
        parts.push(format!("({})", render_branch(branch)));
    }
    parts.join(" and ")
}

/// Render an inner OR branch — same as the top-level body but
/// without the trailing parens (the caller wraps).
fn render_branch(branch: &BpfFilterBuilder) -> String {
    let body = render_to_string(branch);
    if branch.negated {
        let composite =
            branch.fragments.len() + branch.or_branches.len() > 1 || !branch.or_branches.is_empty();
        if body.is_empty() {
            "not ()".to_string()
        } else if composite {
            format!("not ({body})")
        } else {
            format!("not {body}")
        }
    } else {
        body
    }
}

fn frag_to_string(frag: &MatchFrag) -> String {
    match frag {
        MatchFrag::EthType(0x0800) => "ip".to_string(),
        MatchFrag::EthType(0x86DD) => "ip6".to_string(),
        MatchFrag::EthType(0x0806) => "arp".to_string(),
        MatchFrag::EthType(n) => format!("ether proto 0x{n:04x}"),
        MatchFrag::Vlan => "vlan".to_string(),
        MatchFrag::VlanId(id) => format!("vlan {id}"),
        MatchFrag::IpProto(6) => "tcp".to_string(),
        MatchFrag::IpProto(17) => "udp".to_string(),
        MatchFrag::IpProto(1) => "icmp".to_string(),
        MatchFrag::IpProto(58) => "icmp6".to_string(),
        MatchFrag::IpProto(n) => format!("ip proto {n}"),
        MatchFrag::SrcHost(addr) => format!("src host {addr}"),
        MatchFrag::DstHost(addr) => format!("dst host {addr}"),
        MatchFrag::AnyHost(addr) => format!("host {addr}"),
        MatchFrag::SrcNet(net) => format!("src net {net}"),
        MatchFrag::DstNet(net) => format!("dst net {net}"),
        MatchFrag::AnyNet(net) => format!("net {net}"),
        MatchFrag::SrcPort(p) => format!("src port {p}"),
        MatchFrag::DstPort(p) => format!("dst port {p}"),
        MatchFrag::AnyPort(p) => format!("port {p}"),
    }
}
