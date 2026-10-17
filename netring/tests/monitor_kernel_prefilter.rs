//! 0.25 S2: the Monitor's kernel prefilter is the conservative, fail-open
//! OR-union of every consumer's traffic interest. Verified via the
//! `BpfFilter::matches` software interpreter (no live capture needed).
//!
//! The load-bearing property: a consumer can only ever *widen* the filter, so
//! it's always a superset of what any consumer wants (no starvation), and any
//! "wants everything" consumer collapses it to `None` (capture all).

#![cfg(all(
    feature = "tokio",
    feature = "flow",
    feature = "parse",
    feature = "http",
    feature = "dns",
    feature = "tls"
))]

use netring::monitor::Monitor;
use netring::monitor::subscription::packet;
use netring::protocol::builtin::{Dns, Tcp, Tls, Udp};
use netring::protocol::event_typed::{FlowPacket, FlowStarted};

/// Minimal Ethernet/IPv4 frame for `proto` to `dst_port`.
fn frame(proto: u8, dst_port: u16) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // dst mac
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src mac
    f.extend_from_slice(&[0x08, 0x00]); // ipv4
    f.push(0x45);
    f.push(0);
    f.extend_from_slice(&32u16.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.push(64);
    f.push(proto);
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&[10, 0, 0, 2]);
    f.extend_from_slice(&54321u16.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0]);
    f
}

const TCP: u8 = 6;
const UDP: u8 = 17;

/// Minimal Ethernet/IPv6 frame for `proto` to `dst_port`, optionally with an
/// 8-byte Hop-by-Hop extension header between the IPv6 header and L4.
fn frame6(proto: u8, dst_port: u16, hop_by_hop: bool) -> Vec<u8> {
    let mut l4 = Vec::new();
    l4.extend_from_slice(&54321u16.to_be_bytes());
    l4.extend_from_slice(&dst_port.to_be_bytes());
    if proto == TCP {
        l4.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0, 0, 0, 0, 0]);
    } else {
        l4.extend_from_slice(&8u16.to_be_bytes());
        l4.extend_from_slice(&[0, 0]);
    }
    let ext: &[u8] = if hop_by_hop {
        &[proto, 0, 1, 4, 0, 0, 0, 0]
    } else {
        &[]
    };
    let mut f = Vec::new();
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // dst mac
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src mac
    f.extend_from_slice(&[0x86, 0xdd]); // ipv6
    f.extend_from_slice(&[0x60, 0, 0, 0]);
    f.extend_from_slice(&((ext.len() + l4.len()) as u16).to_be_bytes());
    f.push(if hop_by_hop { 0 } else { proto });
    f.push(64);
    let src: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    let dst: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
    f.extend_from_slice(&src.octets());
    f.extend_from_slice(&dst.octets());
    f.extend_from_slice(ext);
    f.extend_from_slice(&l4);
    f
}

// Audit A1: protocol interests are family-agnostic in userspace, so the
// prefilter must not default them to IPv4 — IPv6 TLS / DNS (also behind an
// extension header) has to reach the parsers on live capture.
#[test]
fn ipv6_reaches_protocol_parsers() {
    let bpf = Monitor::builder()
        .interface("lo")
        .protocol::<Tls>()
        .protocol::<Dns>()
        .kernel_prefilter()
        .expect("tls + dns is still a real filter");
    assert!(bpf.matches(&frame6(TCP, 443, false)), "v6 tls");
    assert!(
        bpf.matches(&frame6(TCP, 443, true)),
        "v6 tls behind hop-by-hop"
    );
    assert!(bpf.matches(&frame6(UDP, 53, false)), "v6 dns");
    assert!(
        bpf.matches(&frame6(UDP, 53, true)),
        "v6 dns behind hop-by-hop"
    );
    assert!(
        !bpf.matches(&frame6(TCP, 80, false)),
        "v6 tcp/80 still shed"
    );
    assert!(bpf.matches(&frame(TCP, 443)), "v4 tls unchanged");
    assert!(!bpf.matches(&frame(TCP, 80)), "v4 tcp/80 still shed");
}

#[test]
fn all_l4_passes_ipv6_transport() {
    let bpf = Monitor::builder()
        .interface("lo")
        .all_l4()
        .kernel_prefilter()
        .expect("all_l4 is a proto-only filter");
    for hbh in [false, true] {
        assert!(bpf.matches(&frame6(TCP, 12345, hbh)), "v6 tcp (hbh={hbh})");
        assert!(bpf.matches(&frame6(UDP, 12345, hbh)), "v6 udp (hbh={hbh})");
    }
    assert!(bpf.matches(&frame(TCP, 1)) && bpf.matches(&frame(UDP, 1)));
}

/// A minimal broadcast ARP-request Ethernet frame (EtherType 0x0806).
#[cfg(feature = "arp")]
fn arp_frame() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0xff; 6]); // dst mac: broadcast
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // src mac
    f.extend_from_slice(&[0x08, 0x06]); // ethertype: ARP
    f.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]); // htype/ptype/hlen/plen/oper
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // sha
    f.extend_from_slice(&[10, 0, 0, 1]); // spa
    f.extend_from_slice(&[0; 6]); // tha
    f.extend_from_slice(&[10, 0, 0, 2]); // tpa
    f
}

// Issue #20: an ARP hook contributes a precise EtherType(0x0806) interest, so
// a pure-ARP monitor's kernel prefilter passes ARP and sheds IP — not the old
// fail-open capture-all.
#[cfg(feature = "arp")]
#[test]
fn arp_only_monitor_narrows_to_arp() {
    let bpf = Monitor::builder()
        .interface("lo")
        .on_arp(|_m, _ctx| Ok(()))
        .kernel_prefilter()
        .expect("an ARP-only monitor yields a real filter, not capture-all");
    assert!(bpf.matches(&arp_frame()), "ARP wanted");
    assert!(!bpf.matches(&frame(TCP, 443)), "tcp/443 shed");
    assert!(!bpf.matches(&frame(UDP, 53)), "udp/53 shed");
}

// ARP unions with IP interests rather than collapsing to capture-all.
#[cfg(feature = "arp")]
#[test]
fn arp_plus_protocol_unions() {
    let bpf = Monitor::builder()
        .interface("lo")
        .on_arp_anomaly(|_a, _ctx| Ok(()))
        .protocol::<Tls>()
        .kernel_prefilter()
        .expect("ARP + TLS unions to a filter");
    assert!(bpf.matches(&arp_frame()), "ARP in union");
    assert!(bpf.matches(&frame(TCP, 443)), "tls/443 in union");
    assert!(!bpf.matches(&frame(UDP, 53)), "udp/53 in neither");
}

#[test]
fn single_protocol_narrows_to_its_dispatch() {
    // protocol::<Tls>() → Dispatch::Tcp([443, 8443]) → tcp AND (443 or 8443).
    let bpf = Monitor::builder()
        .interface("lo")
        .protocol::<Tls>()
        .kernel_prefilter()
        .expect("a single narrow protocol yields a filter");
    assert!(bpf.matches(&frame(TCP, 443)), "tcp/443 wanted");
    assert!(bpf.matches(&frame(TCP, 8443)), "tcp/8443 wanted");
    assert!(!bpf.matches(&frame(TCP, 80)), "tcp/80 not a TLS port");
    assert!(!bpf.matches(&frame(UDP, 443)), "udp/443 not TLS");
}

#[test]
fn two_protocols_union_their_interests() {
    // Tls (tcp/443,8443) + Dns (udp/53) → union passes both, rejects others.
    let bpf = Monitor::builder()
        .interface("lo")
        .protocol::<Tls>()
        .protocol::<Dns>()
        .kernel_prefilter()
        .expect("union of two narrow protocols yields a filter");
    assert!(bpf.matches(&frame(TCP, 443)), "tls in union");
    assert!(bpf.matches(&frame(UDP, 53)), "dns in union");
    assert!(!bpf.matches(&frame(TCP, 53)), "tcp/53 in neither");
    assert!(!bpf.matches(&frame(UDP, 443)), "udp/443 in neither");
}

#[test]
fn lifecycle_handler_widens_to_its_l4() {
    // protocol::<Tls>() narrows to tcp/443; adding on::<FlowStarted<Udp>>
    // widens the union to also include all UDP (that handler wants UDP flows).
    let bpf = Monitor::builder()
        .interface("lo")
        .protocol::<Tls>()
        .on::<FlowStarted<Udp>>(|_e: &FlowStarted<Udp>| Ok(()))
        .kernel_prefilter()
        .expect("tcp/443 ∪ udp still expressible");
    assert!(bpf.matches(&frame(TCP, 443)), "tls still wanted");
    assert!(
        bpf.matches(&frame(UDP, 9999)),
        "all udp now wanted (FlowStarted<Udp>)"
    );
    assert!(!bpf.matches(&frame(TCP, 80)), "tcp/80 still unwanted");
}

#[test]
fn broad_handler_collapses_to_capture_all() {
    // on::<FlowPacket> sees every packet's flow event → wants all traffic →
    // the union is Always → no kernel filter (capture everything).
    let pf = Monitor::builder()
        .interface("lo")
        .protocol::<Tls>()
        .on::<FlowPacket>(|_e: &FlowPacket| Ok(()))
        .kernel_prefilter();
    assert!(
        pf.is_none(),
        "a FlowPacket handler must force capture-all (fail-open)"
    );
}

#[test]
fn exporter_forces_capture_all() {
    // An exporter needs every flow → capture all even alongside a narrow proto.
    use netring::export::FlowRecord;
    let pf = Monitor::builder()
        .interface("lo")
        .protocol::<Tls>()
        .export_flows(|_r: &FlowRecord| {})
        .kernel_prefilter();
    assert!(pf.is_none(), "an exporter must force capture-all");
}

#[test]
fn packet_sub_interest_joins_the_union() {
    // A packet tap for tcp/80 alongside protocol::<Dns>() (udp/53):
    // union = tcp/80 ∪ udp/53.
    let bpf = Monitor::builder()
        .interface("lo")
        .protocol::<Dns>()
        .subscribe(packet().tcp().dst_port(80).to(|_v, _c| Ok(())))
        .kernel_prefilter()
        .expect("packet sub + dns union compiles");
    assert!(bpf.matches(&frame(TCP, 80)), "packet-sub interest in union");
    assert!(bpf.matches(&frame(UDP, 53)), "dns interest in union");
    assert!(!bpf.matches(&frame(TCP, 443)), "tcp/443 in neither");
}

#[test]
fn session_subscription_installs_and_contributes_interest() {
    // 0.25 S3b: a session sub installs a predicate-gated on::<Tls> handler and
    // builds; it contributes the Tls protocol's traffic interest (tcp/443,8443)
    // to the kernel prefilter union.
    use flowscope::tls::TlsMessage;
    use netring::monitor::subscription::session;

    let bpf = Monitor::builder()
        .interface("lo")
        .protocol::<Tls>()
        .subscribe(
            session::<Tls>()
                .sni_glob("*.bank")
                .to(|_m: &TlsMessage, _ctx| Ok(())),
        )
        .kernel_prefilter()
        .expect("a tls session sub yields the tcp/443 interest");
    assert!(bpf.matches(&frame(TCP, 443)), "tls/443 wanted");
    assert!(!bpf.matches(&frame(UDP, 53)), "udp/53 not wanted");
}

#[test]
fn pure_l4_protocol_keeps_all_of_that_l4() {
    // protocol::<Tcp>() is the lifecycle marker → Dispatch::AllTcp → all TCP.
    let bpf = Monitor::builder()
        .interface("lo")
        .protocol::<Tcp>()
        .kernel_prefilter()
        .expect("AllTcp is a real (proto-only) filter");
    assert!(bpf.matches(&frame(TCP, 12345)), "any tcp port wanted");
    assert!(
        !bpf.matches(&frame(UDP, 53)),
        "udp not wanted by Tcp marker"
    );
}
