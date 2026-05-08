//! [`StripVlan`] — pass-through wrapper for VLAN-tagged frames.
//!
//! `etherparse` 0.16 already decodes 802.1Q (and double-tagged
//! Q-in-Q via link extensions) automatically when parsing an
//! Ethernet frame. The base extractors built on `parse::parse_eth`
//! therefore see through VLAN tags without help.
//!
//! `StripVlan` is shipped as an explicit wrapper for documentation
//! and future-proofing — if `etherparse`'s behavior ever changes, or
//! if a custom extractor needs an explicit "I'm operating after
//! VLAN" marker, this combinator is the way to spell that intent.

use crate::extractor::{Extracted, FlowExtractor};
use crate::view::PacketView;

/// Pass-through wrapper indicating the inner extractor should
/// handle VLAN-tagged frames. Currently a no-op because the
/// underlying parser already strips VLAN tags transparently.
#[derive(Debug, Clone, Copy)]
pub struct StripVlan<E>(pub E);

impl<E: FlowExtractor> FlowExtractor for StripVlan<E> {
    type Key = E::Key;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        self.0.extract(view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;
    use crate::extract::FiveTuple;
    use etherparse::{Ethernet2Header, IpNumber, Ipv4Header, SingleVlanHeader, TcpHeader, VlanId};

    /// Build a VLAN-tagged Ethernet/IPv4/TCP frame.
    fn vlan_ipv4_tcp(vlan_id: u16) -> Vec<u8> {
        let payload = b"";
        let mut tcp = TcpHeader::new(1234, 80, 1000, 8192);
        tcp.syn = true;
        let ip = Ipv4Header::new(
            (tcp.header_len() + payload.len()) as u16,
            64,
            IpNumber::TCP,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
        )
        .unwrap();
        let vlan = SingleVlanHeader {
            pcp: 0u8.try_into().unwrap(),
            drop_eligible_indicator: false,
            vlan_id: VlanId::try_new(vlan_id).unwrap(),
            ether_type: etherparse::EtherType::IPV4,
        };
        let eth = Ethernet2Header {
            destination: [0; 6],
            source: [0; 6],
            ether_type: etherparse::EtherType::VLAN_TAGGED_FRAME,
        };
        let mut out = Vec::new();
        eth.write(&mut out).unwrap();
        vlan.write(&mut out).unwrap();
        ip.write(&mut out).unwrap();
        tcp.write(&mut out).unwrap();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn vlan_tagged_frame_extracts() {
        let f = vlan_ipv4_tcp(100);
        let e = StripVlan(FiveTuple::bidirectional())
            .extract(PacketView::new(&f, Timestamp::default()))
            .unwrap();
        assert!(e.tcp.is_some());
    }
}
