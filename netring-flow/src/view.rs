//! `PacketView` — a frame-and-timestamp pair fed to flow extractors.
//!
//! The flow API is source-agnostic: an extractor doesn't care
//! whether the frame came from AF_PACKET, a pcap file, a tun
//! interface, or a synthesized buffer. `PacketView` is the abstract
//! handoff between "any source of bytes" and the extractor pipeline.

use crate::Timestamp;

/// What a [`crate::FlowExtractor`] is given.
///
/// Holds a borrowed frame slice and the timestamp it was observed.
/// Constructed from a `netring::Packet` via `Packet::view()` for live
/// captures, or built directly for pcap-replay / synthetic / test use.
///
/// Decap combinators ([`crate::extract::StripVlan`], etc.) construct
/// new views pointing at inner frames while preserving the timestamp.
#[derive(Debug, Clone, Copy)]
pub struct PacketView<'a> {
    /// The frame bytes, starting from L2 (Ethernet) or L3 (raw IP)
    /// depending on the source. Built-in extractors expect L2.
    pub frame: &'a [u8],

    /// Timestamp at which this packet was observed.
    pub timestamp: Timestamp,
}

impl<'a> PacketView<'a> {
    /// Construct a view from a frame slice and timestamp.
    #[inline]
    pub fn new(frame: &'a [u8], timestamp: Timestamp) -> Self {
        Self { frame, timestamp }
    }

    /// Replace `frame` with a new slice, keep the timestamp. Used by
    /// decap combinators to delegate to an inner extractor without
    /// losing context.
    #[inline]
    pub fn with_frame<'b>(self, frame: &'b [u8]) -> PacketView<'b>
    where
        'a: 'b,
    {
        PacketView {
            frame,
            timestamp: self.timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_fields() {
        let buf = [0u8; 8];
        let v = PacketView::new(&buf, Timestamp::new(1, 2));
        assert_eq!(v.frame.len(), 8);
        assert_eq!(v.timestamp, Timestamp::new(1, 2));
    }

    #[test]
    fn with_frame_replaces_slice_keeps_ts() {
        let outer = [1u8, 2, 3, 4];
        let inner = [9u8, 9];
        let v = PacketView::new(&outer, Timestamp::new(7, 0));
        let w = v.with_frame(&inner);
        assert_eq!(w.frame, &inner);
        assert_eq!(w.timestamp, Timestamp::new(7, 0));
    }
}
