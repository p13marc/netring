//! [`IpPair`] — IP address pair, protocol-agnostic.

use std::net::IpAddr;

use crate::extractor::{Extracted, FlowExtractor, L4Proto, Orientation};
use crate::view::PacketView;

use super::parse;

/// Extracts an IP-pair flow key (no ports). Useful for ICMP /
/// ICMPv6 / fragmented flows where ports aren't meaningful, or
/// when you want to track host-level conversations regardless of
/// L4 protocol.
///
/// Bidirectional: A↔B is one flow.
#[derive(Debug, Clone, Copy, Default)]
pub struct IpPair;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct IpPairKey {
    pub a: IpAddr,
    pub b: IpAddr,
}

impl FlowExtractor for IpPair {
    type Key = IpPairKey;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<IpPairKey>> {
        let parsed = parse::parse_eth(view.frame)?;
        let ip = parsed.ip?;
        let (a, b, orientation) = if ip.src > ip.dst {
            (ip.dst, ip.src, Orientation::Reverse)
        } else {
            (ip.src, ip.dst, Orientation::Forward)
        };
        let l4 = match ip.proto {
            1 => L4Proto::Icmp,
            6 => L4Proto::Tcp,
            17 => L4Proto::Udp,
            58 => L4Proto::IcmpV6,
            132 => L4Proto::Sctp,
            p => L4Proto::Other(p),
        };
        Some(Extracted {
            key: IpPairKey { a, b },
            orientation,
            l4: Some(l4),
            tcp: None, // IpPair never populates TCP info
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;
    use crate::extract::parse::test_frames::*;

    #[test]
    fn extracts_ipv4_pair() {
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let e = IpPair
            .extract(PacketView::new(&f, Timestamp::default()))
            .unwrap();
        match (e.key.a, e.key.b) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                assert_eq!(a.octets(), [10, 0, 0, 1]);
                assert_eq!(b.octets(), [10, 0, 0, 2]);
            }
            _ => panic!("expected ipv4 pair"),
        }
        assert_eq!(e.l4, Some(L4Proto::Udp));
        assert!(e.tcp.is_none());
    }

    #[test]
    fn bidirectional_canonical() {
        let fwd = ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 0, 0, b"");
        let rev = ipv4_udp([5, 6, 7, 8], [1, 2, 3, 4], 0, 0, b"");
        let e_fwd = IpPair
            .extract(PacketView::new(&fwd, Timestamp::default()))
            .unwrap();
        let e_rev = IpPair
            .extract(PacketView::new(&rev, Timestamp::default()))
            .unwrap();
        assert_eq!(e_fwd.key, e_rev.key);
        assert_ne!(e_fwd.orientation, e_rev.orientation);
    }
}
