//! Internal frame-parsing helpers shared by built-in extractors.
//!
//! Wraps [`etherparse`] for the protocols it handles and adds
//! inline parsers for what it doesn't (MPLS, VXLAN, GTP-U).

use std::net::IpAddr;

use crate::extractor::TcpFlags;

/// Parsed bits of an Ethernet (or post-decap-Ethernet) frame.
pub(crate) struct ParsedFrame<'a> {
    pub ip: Option<ParsedIp<'a>>,
    pub l4: Option<ParsedL4>,
}

pub(crate) struct ParsedIp<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    /// Slice of L4 payload (for inspection or hashing). Lifetime
    /// borrowed from the original frame.
    #[allow(dead_code)] // kept for forward-compat with reassembler
    pub l4_payload: &'a [u8],
}

pub(crate) enum ParsedL4 {
    Tcp(ParsedTcp),
    Udp(ParsedUdp),
    Other,
}

pub(crate) struct ParsedTcp {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: TcpFlags,
    pub seq: u32,
    pub ack: u32,
    /// Offset into the original frame where the TCP payload starts.
    pub payload_offset: usize,
    pub payload_len: usize,
}

pub(crate) struct ParsedUdp {
    pub src_port: u16,
    pub dst_port: u16,
    /// Offset into the original frame where the UDP payload starts.
    #[allow(dead_code)]
    pub payload_offset: usize,
    pub payload_len: usize,
}

/// Parse an L2 Ethernet frame (with optional VLAN/MACsec link
/// extensions handled by `etherparse`).
pub(crate) fn parse_eth(frame: &[u8]) -> Option<ParsedFrame<'_>> {
    let sp = etherparse::SlicedPacket::from_ethernet(frame).ok()?;
    parse_from_sliced(&sp, frame)
}

/// Parse a raw IP datagram (no L2 prefix). Used by GTP-U decap where
/// the inner is a bare IPv4/IPv6 packet.
#[allow(dead_code)]
pub(crate) fn parse_from_ip(frame: &[u8]) -> Option<ParsedFrame<'_>> {
    let sp = etherparse::SlicedPacket::from_ip(frame).ok()?;
    parse_from_sliced(&sp, frame)
}

fn parse_from_sliced<'a>(
    sp: &etherparse::SlicedPacket<'a>,
    frame: &'a [u8],
) -> Option<ParsedFrame<'a>> {
    let net = sp.net.as_ref()?;
    let (src, dst, proto) = match net {
        etherparse::NetSlice::Ipv4(v4) => {
            let h = v4.header();
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
                h.protocol().into(),
            )
        }
        etherparse::NetSlice::Ipv6(v6) => {
            let h = v6.header();
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
                // After any IPv6 extensions, this is the L4 proto.
                v6.payload().ip_number.into(),
            )
        }
    };

    let l4_payload_slice: &[u8] = match net {
        etherparse::NetSlice::Ipv4(v4) => v4.payload().payload,
        etherparse::NetSlice::Ipv6(v6) => v6.payload().payload,
    };

    // Offset of the L4 payload region (header + body for TCP/UDP)
    // relative to the original frame.
    let l4_region_offset = byte_offset(frame, l4_payload_slice)?;

    let l4 = match sp.transport.as_ref() {
        Some(etherparse::TransportSlice::Tcp(tcp)) => {
            let payload = tcp.payload();
            let payload_offset = byte_offset(frame, payload).unwrap_or(l4_region_offset);
            let mut flags = TcpFlags::empty();
            if tcp.fin() {
                flags |= TcpFlags::FIN;
            }
            if tcp.syn() {
                flags |= TcpFlags::SYN;
            }
            if tcp.rst() {
                flags |= TcpFlags::RST;
            }
            if tcp.psh() {
                flags |= TcpFlags::PSH;
            }
            if tcp.ack() {
                flags |= TcpFlags::ACK;
            }
            if tcp.urg() {
                flags |= TcpFlags::URG;
            }
            if tcp.ece() {
                flags |= TcpFlags::ECE;
            }
            if tcp.cwr() {
                flags |= TcpFlags::CWR;
            }
            Some(ParsedL4::Tcp(ParsedTcp {
                src_port: tcp.source_port(),
                dst_port: tcp.destination_port(),
                flags,
                seq: tcp.sequence_number(),
                ack: tcp.acknowledgment_number(),
                payload_offset,
                payload_len: payload.len(),
            }))
        }
        Some(etherparse::TransportSlice::Udp(udp)) => {
            let payload = udp.payload();
            let payload_offset = byte_offset(frame, payload).unwrap_or(l4_region_offset);
            Some(ParsedL4::Udp(ParsedUdp {
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
                payload_offset,
                payload_len: payload.len(),
            }))
        }
        Some(_) => Some(ParsedL4::Other),
        None => None,
    };

    Some(ParsedFrame {
        ip: Some(ParsedIp {
            src,
            dst,
            proto,
            l4_payload: l4_payload_slice,
        }),
        l4,
    })
}

/// Compute the byte offset of `inner` inside `outer`, if `inner` is
/// fully contained within `outer`'s allocation. Returns None if not.
fn byte_offset(outer: &[u8], inner: &[u8]) -> Option<usize> {
    let outer_start = outer.as_ptr() as usize;
    let inner_start = inner.as_ptr() as usize;
    let outer_end = outer_start.checked_add(outer.len())?;
    let inner_end = inner_start.checked_add(inner.len())?;
    if inner_start < outer_start || inner_end > outer_end {
        return None;
    }
    Some(inner_start - outer_start)
}

#[cfg(test)]
pub(crate) mod test_frames {
    //! Synthetic frame builders used across extractor tests.

    /// Build an Ethernet/IPv4/TCP frame with the given fields.
    /// Returns the byte buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn ipv4_tcp(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        use etherparse::{Ethernet2Header, IpNumber, Ipv4Header, TcpHeader};

        let mut tcp = TcpHeader::new(src_port, dst_port, seq, 8192);
        tcp.acknowledgment_number = ack;
        tcp.fin = flags & 0x01 != 0;
        tcp.syn = flags & 0x02 != 0;
        tcp.rst = flags & 0x04 != 0;
        tcp.psh = flags & 0x08 != 0;
        tcp.ack = flags & 0x10 != 0;
        tcp.urg = flags & 0x20 != 0;

        let ip = Ipv4Header::new(
            (tcp.header_len() + payload.len()) as u16,
            64,
            IpNumber::TCP,
            src_ip,
            dst_ip,
        )
        .unwrap();

        let eth = Ethernet2Header {
            destination: dst_mac,
            source: src_mac,
            ether_type: etherparse::EtherType::IPV4,
        };

        let mut out = Vec::new();
        eth.write(&mut out).unwrap();
        ip.write(&mut out).unwrap();
        tcp.write(&mut out).unwrap();
        out.extend_from_slice(payload);
        out
    }

    /// Build an Ethernet/IPv4/UDP frame.
    pub fn ipv4_udp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use etherparse::{Ethernet2Header, IpNumber, Ipv4Header, UdpHeader};

        let udp = UdpHeader::without_ipv4_checksum(src_port, dst_port, payload.len()).unwrap();
        let ip = Ipv4Header::new(
            (udp.header_len_u16() as usize + payload.len()) as u16,
            64,
            IpNumber::UDP,
            src_ip,
            dst_ip,
        )
        .unwrap();
        let eth = Ethernet2Header {
            destination: [0; 6],
            source: [0; 6],
            ether_type: etherparse::EtherType::IPV4,
        };

        let mut out = Vec::new();
        eth.write(&mut out).unwrap();
        ip.write(&mut out).unwrap();
        udp.write(&mut out).unwrap();
        out.extend_from_slice(payload);
        out
    }

    /// Build an Ethernet/IPv6/TCP frame.
    pub fn ipv6_tcp(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        use etherparse::{Ethernet2Header, IpNumber, Ipv6Header, TcpHeader};

        let mut tcp = TcpHeader::new(src_port, dst_port, seq, 8192);
        tcp.syn = flags & 0x02 != 0;
        tcp.ack = flags & 0x10 != 0;

        let ip = Ipv6Header {
            traffic_class: 0,
            flow_label: 0u32.try_into().unwrap(),
            payload_length: (tcp.header_len() + payload.len()) as u16,
            next_header: IpNumber::TCP,
            hop_limit: 64,
            source: src_ip,
            destination: dst_ip,
        };
        let eth = Ethernet2Header {
            destination: [0; 6],
            source: [0; 6],
            ether_type: etherparse::EtherType::IPV6,
        };

        let mut out = Vec::new();
        eth.write(&mut out).unwrap();
        ip.write(&mut out).unwrap();
        tcp.write(&mut out).unwrap();
        out.extend_from_slice(payload);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_frames::*;

    #[test]
    fn parse_ipv4_tcp_basic() {
        let f = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1000,
            0,
            0x02,
            b"",
        );
        let parsed = parse_eth(&f).expect("parse");
        let ip = parsed.ip.unwrap();
        match ip.src {
            std::net::IpAddr::V4(a) => assert_eq!(a.octets(), [10, 0, 0, 1]),
            _ => panic!("expected ipv4"),
        }
        match parsed.l4.unwrap() {
            ParsedL4::Tcp(t) => {
                assert_eq!(t.src_port, 1234);
                assert_eq!(t.dst_port, 80);
                assert!(t.flags.contains(TcpFlags::SYN));
                assert_eq!(t.seq, 1000);
                assert_eq!(t.payload_len, 0);
            }
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn parse_ipv4_tcp_payload_offset_correct() {
        let payload = b"hello";
        let f = ipv4_tcp(
            [0; 6],
            [0; 6],
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            10,
            20,
            0,
            0,
            0x10,
            payload,
        );
        let parsed = parse_eth(&f).unwrap();
        let tcp = match parsed.l4.unwrap() {
            ParsedL4::Tcp(t) => t,
            _ => panic!(),
        };
        // Eth (14) + IP (20) + TCP (20) = 54
        assert_eq!(tcp.payload_offset, 54);
        assert_eq!(tcp.payload_len, payload.len());
        assert_eq!(
            &f[tcp.payload_offset..tcp.payload_offset + tcp.payload_len],
            payload
        );
    }

    #[test]
    fn parse_ipv4_udp_basic() {
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, b"hi");
        let parsed = parse_eth(&f).unwrap();
        match parsed.l4.unwrap() {
            ParsedL4::Udp(u) => {
                assert_eq!(u.src_port, 5353);
                assert_eq!(u.dst_port, 53);
                assert_eq!(u.payload_len, 2);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_ipv6_tcp_basic() {
        let f = ipv6_tcp(
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            12345,
            443,
            500,
            0x12, // SYN | ACK
            b"",
        );
        let parsed = parse_eth(&f).unwrap();
        let ip = parsed.ip.unwrap();
        match ip.src {
            std::net::IpAddr::V6(_) => {}
            _ => panic!(),
        }
        let tcp = match parsed.l4.unwrap() {
            ParsedL4::Tcp(t) => t,
            _ => panic!(),
        };
        assert!(tcp.flags.contains(TcpFlags::SYN));
        assert!(tcp.flags.contains(TcpFlags::ACK));
    }

    #[test]
    fn parse_arp_returns_none_ip() {
        // 64-byte minimum ARP frame: Eth(14) + ARP(28) + padding(22)
        let mut f = vec![0u8; 64];
        f[0..6].copy_from_slice(&[0xff; 6]); // dst MAC
        f[6..12].copy_from_slice(&[0; 6]);
        f[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP ethertype
        // ARP header (HTYPE=1, PTYPE=0x0800, HLEN=6, PLEN=4, OPER=1)
        f[14..16].copy_from_slice(&1u16.to_be_bytes());
        f[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        f[18] = 6;
        f[19] = 4;
        f[20..22].copy_from_slice(&1u16.to_be_bytes());
        let parsed = parse_eth(&f);
        // ARP doesn't yield an IP, parse should return None at the
        // net stage.
        assert!(parsed.is_none() || parsed.unwrap().ip.is_none());
    }

    #[test]
    fn parse_truncated_returns_none() {
        let f = [0u8; 5];
        assert!(parse_eth(&f).is_none());
    }

    #[test]
    fn byte_offset_basic() {
        let outer = [0u8, 1, 2, 3, 4, 5];
        let inner = &outer[2..4];
        assert_eq!(byte_offset(&outer, inner), Some(2));
    }

    #[test]
    fn byte_offset_disjoint_returns_none() {
        let outer = [0u8; 4];
        let other = [0u8; 4];
        assert_eq!(byte_offset(&outer, &other[..]), None);
    }
}
