//! [`InnerGtpU`] — decap GTP-U, run inner extractor on inner IP datagram.
//!
//! GTP-U encapsulates an IP datagram (no inner Ethernet) inside UDP.
//! Default port 2152. Header is 8 bytes minimum, with optional 4
//! bytes of extensions if any of E/S/PN flags are set in byte 0.
//!
//! Since the inner is a bare IP datagram, this combinator
//! synthesizes a 14-byte Ethernet wrapper around it before
//! delegating, so L2-aware extractors (FiveTuple, etc.) keep working.

use crate::extractor::{Extracted, FlowExtractor};
use crate::view::PacketView;

use super::parse;

/// GTP-U default UDP destination port (3GPP TS 29.281).
pub const DEFAULT_GTPU_PORT: u16 = 2152;

/// Decapsulate GTP-U and delegate to `extractor` on the inner
/// IP datagram (wrapped in a synthetic Ethernet header).
#[derive(Debug, Clone)]
pub struct InnerGtpU<E> {
    /// The wrapped extractor that processes the inner frame.
    pub extractor: E,
    /// UDP port for GTP-U traffic. Defaults to 2152.
    pub udp_port: u16,
}

impl<E> InnerGtpU<E> {
    /// Construct with the standard GTP-U port (2152).
    pub fn new(extractor: E) -> Self {
        Self {
            extractor,
            udp_port: DEFAULT_GTPU_PORT,
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

impl<E: FlowExtractor> FlowExtractor for InnerGtpU<E> {
    type Key = E::Key;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        let inner_ip = peel_gtp_u(view.frame, self.udp_port)?;
        let synthetic = synthesize_eth_for_ip(inner_ip)?;
        self.extractor.extract(PacketView {
            frame: &synthetic,
            timestamp: view.timestamp,
        })
    }
}

fn peel_gtp_u(frame: &[u8], expected_port: u16) -> Option<&[u8]> {
    let parsed = parse::parse_eth(frame)?;
    let l4 = parsed.l4?;
    let udp = match l4 {
        parse::ParsedL4::Udp(u) => u,
        _ => return None,
    };
    // Re-parse via etherparse for ports.
    let sp = etherparse::SlicedPacket::from_ethernet(frame).ok()?;
    let udp_slice = match sp.transport {
        Some(etherparse::TransportSlice::Udp(u)) => u,
        _ => return None,
    };
    if udp_slice.destination_port() != expected_port && udp_slice.source_port() != expected_port {
        return None;
    }

    let payload_start = udp.payload_offset;
    let payload = &frame[payload_start..payload_start + udp.payload_len];

    // GTP-U header: 8 bytes minimum
    if payload.len() < 8 {
        return None;
    }
    let flags = payload[0];
    // E (extension) / S (sequence) / PN (N-PDU number) flags add 4
    // bytes of optional header.
    let has_optional = flags & 0b0000_0111 != 0;
    let mut header_len = 8usize;
    if has_optional {
        header_len += 4;
        // If E flag set, walk extension headers.
        if flags & 0b0000_0100 != 0 {
            // Last byte of optional fields is "next extension type".
            let mut ext_type = payload[11];
            let mut offset = header_len;
            while ext_type != 0 {
                if payload.len() < offset + 1 {
                    return None;
                }
                let ext_len_u32s = payload[offset] as usize;
                if ext_len_u32s == 0 {
                    return None;
                }
                let ext_len_bytes = ext_len_u32s * 4;
                if payload.len() < offset + ext_len_bytes {
                    return None;
                }
                ext_type = payload[offset + ext_len_bytes - 1];
                offset += ext_len_bytes;
                // Sanity: cap extension walk
                if offset > payload.len() {
                    return None;
                }
            }
            header_len = offset;
        }
    }
    if payload.len() <= header_len {
        return None;
    }
    Some(&payload[header_len..])
}

/// Wrap a bare IP datagram with a 14-byte synthetic Ethernet header
/// pointing at the right ethertype. Returns owned `Vec<u8>`.
fn synthesize_eth_for_ip(ip: &[u8]) -> Option<Vec<u8>> {
    if ip.is_empty() {
        return None;
    }
    let ethertype: u16 = match ip[0] >> 4 {
        4 => 0x0800,
        6 => 0x86dd,
        _ => return None,
    };
    let mut out = Vec::with_capacity(14 + ip.len());
    out.extend_from_slice(&[0u8; 12]); // dst+src MAC
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(ip);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;
    use crate::extract::FiveTuple;
    use etherparse::{Ethernet2Header, IpNumber, Ipv4Header, TcpHeader, UdpHeader};

    fn gtpu_ipv4_tcp(teid: u32, port: u16) -> Vec<u8> {
        // Inner IPv4/TCP (no Ethernet)
        let mut tcp = TcpHeader::new(10, 20, 0, 8192);
        tcp.syn = true;
        let inner_ip = Ipv4Header::new(
            tcp.header_len() as u16,
            64,
            IpNumber::TCP,
            [10, 1, 1, 1],
            [10, 1, 1, 2],
        )
        .unwrap();
        let mut inner = Vec::new();
        inner_ip.write(&mut inner).unwrap();
        tcp.write(&mut inner).unwrap();

        // GTP-U header: 8 bytes min. Version=1, PT=1, no E/S/PN.
        let mut gtpu = Vec::with_capacity(8);
        gtpu.push(0x30); // version=1, PT=1
        gtpu.push(0xff); // T-PDU
        gtpu.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        gtpu.extend_from_slice(&teid.to_be_bytes());

        let mut outer_payload = Vec::with_capacity(gtpu.len() + inner.len());
        outer_payload.extend_from_slice(&gtpu);
        outer_payload.extend_from_slice(&inner);

        let udp = UdpHeader::without_ipv4_checksum(40000, port, outer_payload.len()).unwrap();
        let outer_ip = Ipv4Header::new(
            (udp.header_len_u16() as usize + outer_payload.len()) as u16,
            64,
            IpNumber::UDP,
            [203, 0, 113, 1],
            [203, 0, 113, 2],
        )
        .unwrap();
        let eth = Ethernet2Header {
            destination: [0; 6],
            source: [0; 6],
            ether_type: etherparse::EtherType::IPV4,
        };

        let mut out = Vec::new();
        eth.write(&mut out).unwrap();
        outer_ip.write(&mut out).unwrap();
        udp.write(&mut out).unwrap();
        out.extend_from_slice(&outer_payload);
        out
    }

    #[test]
    fn extracts_inner_5tuple() {
        let f = gtpu_ipv4_tcp(0x1234_5678, DEFAULT_GTPU_PORT);
        let e = InnerGtpU::new(FiveTuple::bidirectional())
            .extract(PacketView::new(&f, Timestamp::default()))
            .unwrap();
        assert!(e.tcp.is_some());
        // Verify it's the *inner* endpoints (10.1.1.x), not outer (203.0.113.x).
        match (e.key.a, e.key.b) {
            (std::net::SocketAddr::V4(a), std::net::SocketAddr::V4(b)) => {
                let oct_a = a.ip().octets();
                let oct_b = b.ip().octets();
                assert!(oct_a == [10, 1, 1, 1] || oct_a == [10, 1, 1, 2]);
                assert!(oct_b == [10, 1, 1, 1] || oct_b == [10, 1, 1, 2]);
            }
            _ => panic!("expected ipv4 inner"),
        }
    }

    #[test]
    fn wrong_port_returns_none() {
        let f = gtpu_ipv4_tcp(1, 9999);
        assert!(
            InnerGtpU::new(FiveTuple::bidirectional())
                .extract(PacketView::new(&f, Timestamp::default()))
                .is_none()
        );
    }

    #[test]
    fn non_gtp_returns_none() {
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
            InnerGtpU::new(FiveTuple::bidirectional())
                .extract(PacketView::new(&f, Timestamp::default()))
                .is_none()
        );
    }
}
