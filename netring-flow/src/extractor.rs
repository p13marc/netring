//! [`FlowExtractor`] trait and its supporting types.
//!
//! Implement this trait to teach the rest of `netring-flow` (the
//! tracker, the reassembler hook) what counts as a flow in your
//! domain. Built-in implementations live in [`crate::extract`].

use crate::view::PacketView;
use bitflags::bitflags;

/// Extract a flow descriptor from one packet.
///
/// Implementations are called once per packet on the hot path —
/// keep them cheap and stateless. Most return `Some(_)`; malformed,
/// non-IP, or out-of-scope packets return `None` and are skipped.
///
/// # Bidirectional flows
///
/// If you want A→B and B→A merged into one flow, your extractor
/// must produce the **same `Key`** for both orientations and report
/// each packet's direction via [`Extracted::orientation`]. The
/// built-in [`crate::extract::FiveTuple::bidirectional`] does this
/// by sorting `(addr, port)` pairs.
///
/// # Bounds
///
/// `Send + Sync + 'static` is required so a tracker generic over
/// this trait can be used from any task / thread.
pub trait FlowExtractor: Send + Sync + 'static {
    /// The flow key. Equality + hashability identify the flow.
    type Key: Eq + std::hash::Hash + Clone + Send + Sync + 'static;

    /// Extract a flow descriptor from `view`.
    ///
    /// Returns `None` if this packet is not part of any flow you
    /// want to track (skipped, malformed, encap-only, ARP, etc.).
    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<Self::Key>>;
}

/// Result of extracting one packet.
///
/// `key` identifies the flow. `orientation` says whether `view` was
/// in the canonical direction or reversed. `l4` and `tcp` carry
/// pre-parsed protocol data that the tracker and reassembler reuse
/// without re-parsing.
#[derive(Debug, Clone)]
pub struct Extracted<K> {
    /// The flow this packet belongs to.
    pub key: K,

    /// Orientation of *this packet* relative to the canonical form
    /// of `key`. `Forward` if the natural src→dst direction matches
    /// the key's a→b ordering; `Reverse` if the extractor swapped
    /// to canonicalize.
    ///
    /// The tracker translates this into [`crate::FlowSide`] (Initiator
    /// / Responder) based on which orientation it saw first.
    pub orientation: Orientation,

    /// L4 protocol if the extractor identified one. Drives the
    /// tracker's choice of timeout and whether to engage TCP state.
    pub l4: Option<L4Proto>,

    /// Pre-parsed TCP info for TCP packets. If `Some`, the tracker
    /// runs the TCP state machine without re-parsing; if `None`,
    /// TCP-specific events (Established, history string) won't fire
    /// for this flow.
    ///
    /// Built-in extractors fill this for ~zero extra cost; custom
    /// extractors that don't care about TCP can leave it `None`.
    pub tcp: Option<TcpInfo>,
}

/// Orientation of a packet relative to its canonical flow key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Orientation {
    /// Packet's natural src→dst matches the key's a→b ordering.
    Forward,
    /// Extractor swapped src/dst to canonicalize; packet is
    /// flowing from key.b to key.a.
    Reverse,
}

/// L4 protocol identified by an extractor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L4Proto {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Sctp,
    Other(u8),
}

/// Pre-parsed TCP information for a packet.
///
/// Filled by built-in extractors. Decoupled from frame layout so
/// downstream tracker / reassembler logic doesn't need to re-parse.
#[derive(Debug, Clone, Copy)]
pub struct TcpInfo {
    /// Decoded TCP flags.
    pub flags: TcpFlags,
    /// TCP sequence number (host byte order).
    pub seq: u32,
    /// TCP acknowledgment number (host byte order).
    pub ack: u32,
    /// Offset into the frame where the TCP payload begins.
    /// Relative to the frame the extractor was called with.
    pub payload_offset: usize,
    /// Number of payload bytes (zero for pure SYN/ACK/FIN).
    pub payload_len: usize,
}

bitflags! {
    /// TCP control flags from the TCP header's flags byte.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TcpFlags: u8 {
        const FIN = 0b0000_0001;
        const SYN = 0b0000_0010;
        const RST = 0b0000_0100;
        const PSH = 0b0000_1000;
        const ACK = 0b0001_0000;
        const URG = 0b0010_0000;
        const ECE = 0b0100_0000;
        const CWR = 0b1000_0000;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_flags_basic() {
        let f = TcpFlags::SYN | TcpFlags::ACK;
        assert!(f.contains(TcpFlags::SYN));
        assert!(f.contains(TcpFlags::ACK));
        assert!(!f.contains(TcpFlags::FIN));
    }

    #[test]
    fn extracted_clone() {
        let e: Extracted<u32> = Extracted {
            key: 42,
            orientation: Orientation::Forward,
            l4: Some(L4Proto::Tcp),
            tcp: Some(TcpInfo {
                flags: TcpFlags::SYN,
                seq: 1,
                ack: 0,
                payload_offset: 54,
                payload_len: 0,
            }),
        };
        let cloned = e.clone();
        assert_eq!(cloned.key, 42);
        assert_eq!(cloned.orientation, Orientation::Forward);
    }

    #[test]
    fn l4_proto_eq() {
        assert_eq!(L4Proto::Tcp, L4Proto::Tcp);
        assert_ne!(L4Proto::Tcp, L4Proto::Udp);
        assert_eq!(L4Proto::Other(1), L4Proto::Other(1));
        assert_ne!(L4Proto::Other(1), L4Proto::Other(2));
    }
}
