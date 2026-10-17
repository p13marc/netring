//! Render a [`BpfFilterBuilder`] IR as a canonical
//! [pcap-filter(7)](https://www.tcpdump.org/manpages/pcap-filter.7.html)
//! expression. Powers [`BpfFilter::to_human`](super::bpf::BpfFilter::to_human).

use std::fmt;

use super::bpf_builder::{BpfFilterBuilder, MatchFrag};

/// Entry point — render `builder` into the provided formatter.
///
/// The compiled program is `[not] (chain₀ or chain₁ or …)`: the main
/// AND chain and each `or()` branch are alternatives, and `negate()`
/// applies to the whole disjunction. (A branch can't carry its own
/// `or()` / `negate()` — the compiler rejects that — so only the
/// branches' fragments matter here.)
pub(crate) fn render(builder: &BpfFilterBuilder, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let pass_frags =
        builder.pass_ip_fragments || builder.or_branches.iter().any(|b| b.pass_ip_fragments);
    let body = render_body(builder, pass_frags);

    if builder.negated {
        let body_is_composite = !builder.or_branches.is_empty() || builder.fragments.len() > 1;
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

/// Render the disjunction of the main chain and the OR branches:
/// `chain` alone, or `(a and b) or c or …` — a multi-fragment chain
/// is parenthesised. Returns the empty string for a filter that
/// matches everything (an empty chain, alone or as one alternative).
fn render_body(builder: &BpfFilterBuilder, pass_frags: bool) -> String {
    let chains: Vec<&[MatchFrag]> = std::iter::once(builder.fragments.as_slice())
        .chain(builder.or_branches.iter().map(|b| b.fragments.as_slice()))
        .collect();
    if chains.len() == 1 {
        return render_chain(chains[0], pass_frags);
    }
    if chains.iter().any(|c| c.is_empty()) {
        // An empty AND chain is always true, and so is any OR with it.
        return String::new();
    }
    let alts: Vec<String> = chains
        .iter()
        .map(|c| {
            let s = render_chain(c, pass_frags);
            if c.len() > 1 { format!("({s})") } else { s }
        })
        .collect();
    alts.join(" or ")
}

/// One AND chain: its fragments joined with " and ".
fn render_chain(fragments: &[MatchFrag], pass_frags: bool) -> String {
    let parts: Vec<String> = fragments
        .iter()
        .map(|f| frag_to_string(f, pass_frags))
        .collect();
    parts.join(" and ")
}

/// With `pass_frags`, a port term also accepts a non-first IPv4 fragment:
/// `(port 53 or ip[6:2] & 0x1fff != 0)` — exact pcap-filter (`ip[…]`
/// implies IPv4, so an IPv6 packet still needs the port).
fn frag_to_string(frag: &MatchFrag, pass_frags: bool) -> String {
    let s = frag_text(frag, pass_frags);
    match frag {
        MatchFrag::SrcPort(_) | MatchFrag::DstPort(_) | MatchFrag::AnyPort(_) if pass_frags => {
            format!("({s} or ip[6:2] & 0x1fff != 0)")
        }
        _ => s,
    }
}

fn frag_text(frag: &MatchFrag, pass_frags: bool) -> String {
    match frag {
        MatchFrag::EthType(0x0800) => "ip".to_string(),
        MatchFrag::EthType(0x86DD) => "ip6".to_string(),
        MatchFrag::EthType(0x0806) => "arp".to_string(),
        MatchFrag::EthType(n) => format!("ether proto 0x{n:04x}"),
        MatchFrag::Vlan | MatchFrag::VlanMeta | MatchFrag::VlanInFrame => "vlan".to_string(),
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
        MatchFrag::AnyOf(alts) => {
            let alts: Vec<String> = alts.iter().map(|a| frag_to_string(a, pass_frags)).collect();
            format!("({})", alts.join(" or "))
        }
    }
}
