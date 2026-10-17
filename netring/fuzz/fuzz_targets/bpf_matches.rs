#![no_main]
//! Fuzz the in-tree cBPF software interpreter (`BpfFilter::matches` /
//! `matches_with`) against arbitrary, untrusted frame bytes and ancillary
//! data. The interpreter walks L2–L4 offsets into the frame; it must never
//! panic, read out of bounds, or loop forever on a malformed frame. (miri
//! proves the *interpreter's* unsafe-free logic is UB-clean; this proves
//! it's robust against adversarial input.)
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use netring::config::{BpfAncillary, BpfFilter, VlanProto, VlanTag};

/// An arbitrary [`BpfAncillary`] (the struct is `#[non_exhaustive]`, so it
/// is built through its constructors).
#[derive(Arbitrary, Debug)]
struct Anc {
    vlan: Option<(u16, u16)>,
    in_frame: bool,
}

impl Anc {
    fn tag(&self) -> Option<VlanTag> {
        self.vlan.map(|(tci, tpid)| {
            let proto = match tpid {
                0x8100 => VlanProto::Dot1Q,
                0x88a8 => VlanProto::Dot1Ad,
                other => VlanProto::Other(other),
            };
            VlanTag::new(tci, proto)
        })
    }

    fn get(&self) -> BpfAncillary {
        match (self.tag(), self.in_frame) {
            (None, _) => BpfAncillary::NONE,
            (Some(t), false) => BpfAncillary::stripped(t),
            (Some(t), true) => BpfAncillary::reinserted(t),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    anc: Anc,
    frame: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // Representative filters exercising ethertype + IP-proto + TCP-port
    // offset walks, with and without the VLAN blocks. The frame and the
    // ancillary data are the fuzzed, untrusted input.
    let filters = [
        BpfFilter::builder().tcp().dst_port(443).build().unwrap(),
        BpfFilter::builder()
            .vlan()
            .vlan_id(100)
            .udp()
            .port(53)
            .build()
            .unwrap(),
    ];
    let anc = input.anc.get();
    for filter in &filters {
        let a = filter.matches(&input.frame);
        // Determinism: matching is a pure function of (filter, frame, anc).
        assert_eq!(a, filter.matches(&input.frame));
        let w = filter.matches_with(&input.frame, &anc);
        assert_eq!(w, filter.matches_with(&input.frame, &anc));

        // A stripped tag and the same tag re-inserted give one verdict.
        if let Some(tag) = input.anc.tag()
            && input.frame.len() >= 12
        {
            let tpid = match tag.proto {
                VlanProto::Dot1Q => 0x8100u16,
                VlanProto::Dot1Ad => 0x88a8,
                VlanProto::Other(t) => t,
                _ => return,
            };
            let mut re = input.frame[..12].to_vec();
            re.extend_from_slice(&tpid.to_be_bytes());
            re.extend_from_slice(&tag.tci.to_be_bytes());
            re.extend_from_slice(&input.frame[12..]);
            assert_eq!(
                filter.matches_with(&input.frame, &BpfAncillary::stripped(tag)),
                filter.matches_with(&re, &BpfAncillary::reinserted(tag)),
            );
        }
    }
});
