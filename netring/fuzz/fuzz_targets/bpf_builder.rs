#![no_main]
//! Fuzz the typed `BpfFilterBuilder` → cBPF compiler. Arbitrary builder
//! programs must compile without panicking; any filter that compiles must
//! evaluate deterministically and never panic on an untrusted frame.
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use netring::config::BpfFilter;

#[derive(Arbitrary, Debug)]
struct Input {
    tcp: bool,
    udp: bool,
    icmp: bool,
    ipv4: bool,
    vlan: bool,
    vlan_id: Option<u16>,
    negate: bool,
    ports: Vec<u16>,
    frame: Vec<u8>,
}

fuzz_target!(|inp: Input| {
    let mut b = BpfFilter::builder();
    // VLAN fragments: `vlan_id` without `vlan` must be a build error, not a
    // panic; with it the compiler emits the metadata and in-frame blocks.
    if inp.vlan {
        b = b.vlan();
    }
    if let Some(id) = inp.vlan_id {
        b = b.vlan_id(id);
    }
    if inp.ipv4 {
        b = b.ipv4();
    }
    if inp.tcp {
        b = b.tcp();
    }
    if inp.udp {
        b = b.udp();
    }
    if inp.icmp {
        b = b.icmp();
    }
    // Bound the port set so the compiler's OR-chain stays finite. `ports()`
    // has a documented non-empty precondition (asserts) — respect it.
    let ports: Vec<u16> = inp.ports.into_iter().take(32).collect();
    if !ports.is_empty() {
        b = b.ports(ports);
    }
    if inp.negate {
        b = b.negate();
    }

    if let Ok(filter) = b.build() {
        // A compiled filter must evaluate deterministically on any frame.
        let a = filter.matches(&inp.frame);
        let c = filter.matches(&inp.frame);
        assert_eq!(a, c);
        // …and with a stripped VLAN tag in the metadata.
        let tag = netring::config::VlanTag::new(
            inp.vlan_id.unwrap_or(0),
            netring::config::VlanProto::Dot1Q,
        );
        let anc = netring::config::BpfAncillary::stripped(tag);
        assert_eq!(
            filter.matches_with(&inp.frame, &anc),
            filter.matches_with(&inp.frame, &anc)
        );
        // The human-readable rendering must not panic either.
        let _ = filter.to_human();
    }
});
