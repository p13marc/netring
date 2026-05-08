//! Sync TCP reassembly hooks.
//!
//! [`Reassembler`] is the trait users implement to consume TCP byte
//! streams from one direction of one session. [`BufferedReassembler`]
//! is the simplest possible impl: in-order accumulation into a
//! `Vec<u8>`, with out-of-order segments dropped.
//!
//! For tokio users with backpressure needs, see `netring`'s
//! `AsyncReassembler` and `channel_factory`.

use crate::event::FlowSide;

/// Receives TCP segments for one direction of one session. Sync —
/// implementors don't await; for blocking consumers (Vec buffer,
/// `std::sync::mpsc`, sync protocol parsers).
pub trait Reassembler: Send + 'static {
    /// New segment arrived in this direction.
    ///
    /// `payload` borrows from the underlying frame — copy if you
    /// need it after returning.
    fn segment(&mut self, seq: u32, payload: &[u8]);

    /// FIN observed in this direction. Default: no-op.
    fn fin(&mut self) {}

    /// RST observed in this direction (or session aborted).
    /// Default: no-op.
    fn rst(&mut self) {}
}

/// Build a [`Reassembler`] for a brand-new session, given its key
/// and side. Modeled after gopacket's `StreamFactory`.
pub trait ReassemblerFactory<K>: Send + 'static {
    type Reassembler: Reassembler;
    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> Self::Reassembler;
}

/// Built-in: drop OOO segments, accumulate in-order bytes into a
/// `Vec<u8>` per direction. Drain via [`take`](Self::take).
///
/// Sync, no channel dep. Users who want a channel send via
/// `std::sync::mpsc` themselves, or use `netring`'s
/// `TokioChannelReassembler` for tokio integration.
#[derive(Debug, Default)]
pub struct BufferedReassembler {
    buffer: Vec<u8>,
    expected_seq: Option<u32>,
    dropped_segments: u64,
}

impl BufferedReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain accumulated in-order bytes, leaving the buffer empty.
    /// `expected_seq` is preserved so subsequent in-order segments
    /// keep accumulating.
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }

    /// Number of segments dropped because they were out of order.
    pub fn dropped_segments(&self) -> u64 {
        self.dropped_segments
    }

    /// Bytes currently buffered (not yet drained).
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

impl Reassembler for BufferedReassembler {
    fn segment(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        match self.expected_seq {
            None => {
                self.expected_seq = Some(seq.wrapping_add(payload.len() as u32));
                self.buffer.extend_from_slice(payload);
            }
            Some(exp) if seq == exp => {
                self.expected_seq = Some(seq.wrapping_add(payload.len() as u32));
                self.buffer.extend_from_slice(payload);
            }
            Some(_) => {
                self.dropped_segments += 1;
            }
        }
    }
}

/// Default factory that builds a fresh [`BufferedReassembler`] per
/// (flow, side). Useful when you want byte buffers without
/// implementing a custom factory.
#[derive(Debug, Default)]
pub struct BufferedReassemblerFactory;

impl<K: Send + 'static> ReassemblerFactory<K> for BufferedReassemblerFactory {
    type Reassembler = BufferedReassembler;

    fn new_reassembler(&mut self, _key: &K, _side: FlowSide) -> BufferedReassembler {
        BufferedReassembler::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_concatenates() {
        let mut r = BufferedReassembler::new();
        r.segment(100, b"abc");
        r.segment(103, b"def");
        r.segment(106, b"gh");
        assert_eq!(r.take(), b"abcdefgh");
        assert_eq!(r.dropped_segments(), 0);
    }

    #[test]
    fn ooo_dropped() {
        let mut r = BufferedReassembler::new();
        r.segment(100, b"hello"); // expect_next = 105
        r.segment(110, b"world"); // out of order — dropped
        assert_eq!(r.take(), b"hello");
        assert_eq!(r.dropped_segments(), 1);
    }

    #[test]
    fn take_resets_buffer_only() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"abc"); // expect_next = 3
        let drained = r.take();
        assert_eq!(drained, b"abc");
        assert_eq!(r.buffered_len(), 0);
        // Subsequent in-order segment continues from where we were.
        r.segment(3, b"def");
        assert_eq!(r.take(), b"def");
        assert_eq!(r.dropped_segments(), 0);
    }

    #[test]
    fn empty_payload_ignored() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"");
        assert_eq!(r.expected_seq, None);
        assert_eq!(r.dropped_segments(), 0);
    }

    #[test]
    fn factory_creates_fresh_reassembler() {
        let mut f = BufferedReassemblerFactory;
        let mut r1: BufferedReassembler = f.new_reassembler(&42u32, FlowSide::Initiator);
        let mut r2: BufferedReassembler = f.new_reassembler(&42u32, FlowSide::Responder);
        r1.segment(0, b"x");
        r2.segment(0, b"y");
        assert_eq!(r1.take(), b"x");
        assert_eq!(r2.take(), b"y");
    }

    #[test]
    fn fin_rst_default_noops_compile() {
        let mut r = BufferedReassembler::new();
        r.fin();
        r.rst();
        // No-op defaults exist; this test just confirms they compile.
    }
}
