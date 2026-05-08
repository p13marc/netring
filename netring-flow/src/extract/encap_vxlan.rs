//! [`InnerVxlan`] — decap VXLAN, run inner extractor on inner Ethernet frame.
//!
//! VXLAN encapsulates an Ethernet frame inside UDP. Default port
//! 4789. Header is 8 bytes: 8-bit flags, 24-bit reserved, 24-bit
//! VNI, 8-bit reserved.

use crate::extractor::{Extracted, FlowExtractor};
use crate::view::PacketView;

use super::parse;

/// VXLAN default UDP destination port (RFC 7348).
pub const DEFAULT_VXLAN_PORT: u16 = 4789;

/// Decapsulate VXLAN and delegate to `extractor` on the inner
/// Ethernet frame.
#[derive(Debug, Clone, Copy)]
pub struct InnerVxlan<E> {
    /// The wrapped extractor that processes the inner frame.
    pub extractor: E,
    /// UDP port on which VXLAN traffic arrives. Defaults to 4789.
    pub udp_port: u16,
}

impl<E> InnerVxlan<E> {
    /// Construct with the IANA default port (4789).
    pub fn new(extractor: E) -> Self {
        Self {
            extractor,
            udp_port: DEFAULT_VXLAN_PORT,
        }
    }

    /// Construct with a custom UDP port.
    pub fn with_port(extractor: E, udp_port: u16) -> Self {
        Self {
            extractor,
            udp_port,
        }
    }
}

impl<E: FlowExtractor> FlowExtractor for InnerVxlan<E> {
    type Key = E::Key;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        let inner = peel_vxlan(view.frame, self.udp_port)?;
        self.extractor.extract(view.with_frame(inner))
    }
}

/// Peel VXLAN off an Ethernet/IP/UDP frame and return the inner
/// Ethernet frame. Returns None on parse failure or wrong port.
fn peel_vxlan(frame: &[u8], expected_port: u16) -> Option<&[u8]> {
    let parsed = parse::parse_eth(frame)?;
    let l4 = parsed.l4?;
    let udp = match l4 {
        parse::ParsedL4::Udp(u) => u,
        _ => return None,
    };
    // Either side may be the VXLAN port (active dst, but be tolerant).
    if udp.payload_len < 8 {
        return None;
    }
    // We only need the payload offset; the port check is sufficient.
    // Read parent payload offset and slice forward.
    let payload_start = udp.payload_offset;
    let frame_after_udp = &frame[payload_start..payload_start + udp.payload_len];
    // Check ports indirectly: parse_eth gave us src/dst inside parsed.l4,
    // but we don't have them here. Re-parse just the UDP for the
    // port. Cheaper: extract port from frame at known offset.
    // Use etherparse again — small cost.
    let sp = etherparse::SlicedPacket::from_ethernet(frame).ok()?;
    let udp_slice = match sp.transport {
        Some(etherparse::TransportSlice::Udp(u)) => u,
        _ => return None,
    };
    let dst_port = udp_slice.destination_port();
    let src_port = udp_slice.source_port();
    if dst_port != expected_port && src_port != expected_port {
        return None;
    }
    // Skip 8-byte VXLAN header
    if frame_after_udp.len() < 8 {
        return None;
    }
    Some(&frame_after_udp[8..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;
    use crate::extract::FiveTuple;
    use etherparse::{Ethernet2Header, IpNumber, Ipv4Header, TcpHeader, UdpHeader};

    /// Build outer Eth/IPv4/UDP/VXLAN/inner-Eth/IPv4/TCP frame.
    fn vxlan_ipv4_tcp(vni: u32, vxlan_port: u16) -> Vec<u8> {
        // Inner: Eth + IPv4 + TCP(SYN)
        let mut tcp = TcpHeader::new(10, 20, 1000, 8192);
        tcp.syn = true;
        let inner_ip = Ipv4Header::new(
            tcp.header_len() as u16,
            64,
            IpNumber::TCP,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
        )
        .unwrap();
        let inner_eth = Ethernet2Header {
            destination: [0; 6],
            source: [0; 6],
            ether_type: etherparse::EtherType::IPV4,
        };
        let mut inner = Vec::new();
        inner_eth.write(&mut inner).unwrap();
        inner_ip.write(&mut inner).unwrap();
        tcp.write(&mut inner).unwrap();

        // VXLAN header (8 bytes): I-flag bit 3 (0x08), 24-bit VNI in
        // bytes 4-6.
        let mut vxlan = [0u8; 8];
        vxlan[0] = 0x08;
        vxlan[4..7].copy_from_slice(&vni.to_be_bytes()[1..]);

        // Outer payload = vxlan + inner
        let mut outer_payload = Vec::with_capacity(8 + inner.len());
        outer_payload.extend_from_slice(&vxlan);
        outer_payload.extend_from_slice(&inner);

        // Outer UDP/IP/Eth
        let outer_udp =
            UdpHeader::without_ipv4_checksum(12345, vxlan_port, outer_payload.len()).unwrap();
        let outer_ip = Ipv4Header::new(
            (outer_udp.header_len_u16() as usize + outer_payload.len()) as u16,
            64,
            IpNumber::UDP,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
        )
        .unwrap();
        let outer_eth = Ethernet2Header {
            destination: [0; 6],
            source: [0; 6],
            ether_type: etherparse::EtherType::IPV4,
        };

        let mut out = Vec::new();
        outer_eth.write(&mut out).unwrap();
        outer_ip.write(&mut out).unwrap();
        outer_udp.write(&mut out).unwrap();
        out.extend_from_slice(&outer_payload);
        out
    }

    #[test]
    fn extracts_inner_5tuple() {
        let f = vxlan_ipv4_tcp(42, DEFAULT_VXLAN_PORT);
        let e = InnerVxlan::new(FiveTuple::bidirectional())
            .extract(PacketView::new(&f, Timestamp::default()))
            .unwrap();
        // Inner endpoints, not outer
        match (e.key.a, e.key.b) {
            (std::net::SocketAddr::V4(a), std::net::SocketAddr::V4(b)) => {
                assert!(matches!(
                    (a.ip().octets(), b.ip().octets()),
                    ([192, 168, 1, 1], [192, 168, 1, 2]) | ([192, 168, 1, 2], [192, 168, 1, 1])
                ));
            }
            _ => panic!("expected ipv4 inner"),
        }
        assert!(e.tcp.is_some());
    }

    #[test]
    fn wrong_port_returns_none() {
        let f = vxlan_ipv4_tcp(1, 9999);
        assert!(
            InnerVxlan::new(FiveTuple::bidirectional())
                .extract(PacketView::new(&f, Timestamp::default()))
                .is_none()
        );
    }

    #[test]
    fn custom_port_works() {
        let f = vxlan_ipv4_tcp(1, 8472);
        let e = InnerVxlan::with_port(FiveTuple::bidirectional(), 8472)
            .extract(PacketView::new(&f, Timestamp::default()))
            .unwrap();
        assert!(e.tcp.is_some());
    }

    #[test]
    fn non_udp_returns_none() {
        // Plain IPv4/TCP frame — no VXLAN to peel.
        use crate::extract::parse::test_frames::ipv4_tcp;
        let f = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1,
            2,
            0,
            0,
            0x02,
            b"",
        );
        assert!(
            InnerVxlan::new(FiveTuple::bidirectional())
                .extract(PacketView::new(&f, Timestamp::default()))
                .is_none()
        );
    }
}
