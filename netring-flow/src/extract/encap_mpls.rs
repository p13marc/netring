//! [`StripMpls`] — strip MPLS label stack before delegating.
//!
//! MPLS uses an Ethertype of 0x8847 (unicast) or 0x8848 (multicast),
//! followed by a stack of 4-byte labels. The bottom-of-stack bit
//! (S, byte 2 bit 0 of each label) marks the last label. After the
//! stack, the inner protocol is determined by inspecting the first
//! nibble: 0x4 → IPv4, 0x6 → IPv6.

use crate::extractor::{Extracted, FlowExtractor};
use crate::view::PacketView;

/// Strip an MPLS label stack from an Ethernet frame and run the
/// inner extractor on the inner IP datagram (synthesizing an
/// Ethernet wrapper so L2-aware extractors keep working).
#[derive(Debug, Clone, Copy)]
pub struct StripMpls<E>(pub E);

impl<E: FlowExtractor> FlowExtractor for StripMpls<E> {
    type Key = E::Key;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        let inner = strip_mpls_to_ip(view.frame)?;
        // Wrap the inner IP datagram with a minimal synthetic
        // Ethernet header so L2-based extractors (FiveTuple etc.)
        // can call SlicedPacket::from_ethernet on it.
        let synthetic = synthesize_eth_for_ip(inner)?;
        self.0.extract(PacketView {
            frame: &synthetic,
            timestamp: view.timestamp,
        })
    }
}

/// Walk an Ethernet+MPLS frame and return a slice over the inner
/// IP datagram. Returns None if the frame isn't MPLS or the stack
/// is malformed.
fn strip_mpls_to_ip(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    // 0x8847 = MPLS unicast, 0x8848 = MPLS multicast
    if ethertype != 0x8847 && ethertype != 0x8848 {
        return None;
    }
    let mut offset = 14usize;
    loop {
        if frame.len() < offset + 4 {
            return None;
        }
        let label = &frame[offset..offset + 4];
        offset += 4;
        // Bottom-of-stack bit: byte 2 bit 0
        let bos = label[2] & 0x01 != 0;
        if bos {
            break;
        }
        // Bound the stack so a malformed frame can't loop forever.
        if offset > 14 + 4 * 16 {
            return None;
        }
    }
    if frame.len() <= offset {
        return None;
    }
    Some(&frame[offset..])
}

/// Build a 14-byte Ethernet header pointing at the inner IP
/// datagram so downstream L2-aware extractors work uniformly.
///
/// Returns a heap-allocated Vec since the inner extractor expects
/// a contiguous slice and we need both header + payload.
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
    use etherparse::{IpNumber, Ipv4Header, TcpHeader};

    /// Build an Ethernet/MPLS/IPv4/TCP frame with a single label.
    fn mpls_ipv4_tcp_single_label(label: u32) -> Vec<u8> {
        let mut out = Vec::new();
        // dst+src MAC
        out.extend_from_slice(&[0u8; 12]);
        // ethertype 0x8847 (MPLS unicast)
        out.extend_from_slice(&0x8847u16.to_be_bytes());
        // label entry: 20-bit label, 3-bit TC, 1-bit BoS, 8-bit TTL
        // BoS bit set; TC=0; TTL=64
        let entry: u32 = (label << 12) | (1 << 8) | 64;
        out.extend_from_slice(&entry.to_be_bytes());

        let payload = b"";
        let mut tcp = TcpHeader::new(1, 2, 0, 8192);
        tcp.syn = true;
        let ip = Ipv4Header::new(
            (tcp.header_len() + payload.len()) as u16,
            64,
            IpNumber::TCP,
            [1, 2, 3, 4],
            [5, 6, 7, 8],
        )
        .unwrap();
        ip.write(&mut out).unwrap();
        tcp.write(&mut out).unwrap();
        out.extend_from_slice(payload);
        out
    }

    /// Two labels (BoS only on second).
    fn mpls_two_labels_ipv4_tcp() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&0x8847u16.to_be_bytes());
        // first label, BoS=0, TC=0, TTL=64
        let l1: u32 = (1000u32 << 12) | 64;
        out.extend_from_slice(&l1.to_be_bytes());
        // second label, BoS=1
        let l2: u32 = (2000u32 << 12) | (1 << 8) | 64;
        out.extend_from_slice(&l2.to_be_bytes());

        let mut tcp = TcpHeader::new(10, 20, 0, 8192);
        tcp.syn = true;
        let ip = Ipv4Header::new(
            tcp.header_len() as u16,
            64,
            IpNumber::TCP,
            [1, 1, 1, 1],
            [2, 2, 2, 2],
        )
        .unwrap();
        ip.write(&mut out).unwrap();
        tcp.write(&mut out).unwrap();
        out
    }

    #[test]
    fn strips_single_label() {
        let f = mpls_ipv4_tcp_single_label(42);
        let e = StripMpls(FiveTuple::bidirectional())
            .extract(PacketView::new(&f, Timestamp::default()))
            .unwrap();
        assert!(e.tcp.is_some());
    }

    #[test]
    fn strips_multi_label_stack() {
        let f = mpls_two_labels_ipv4_tcp();
        let e = StripMpls(FiveTuple::bidirectional())
            .extract(PacketView::new(&f, Timestamp::default()))
            .unwrap();
        assert!(e.tcp.is_some());
    }

    #[test]
    fn non_mpls_returns_none() {
        let f = vec![0u8; 64];
        // ethertype defaults to 0x0000 — not MPLS.
        assert!(
            StripMpls(FiveTuple::bidirectional())
                .extract(PacketView::new(&f, Timestamp::default()))
                .is_none()
        );
    }

    #[test]
    fn truncated_returns_none() {
        let f = vec![0u8; 5];
        assert!(
            StripMpls(FiveTuple::bidirectional())
                .extract(PacketView::new(&f, Timestamp::default()))
                .is_none()
        );
    }
}
