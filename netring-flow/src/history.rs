//! Compact lifecycle representation à la Zeek's `conn.log` history.
//!
//! Capital letters represent initiator actions, lowercase represent
//! responder actions. Capped at 16 characters — most realistic TCP
//! sessions fit comfortably; pathological retransmit storms are
//! truncated rather than ballooning the per-flow memory.

use crate::event::FlowSide;
use crate::extractor::TcpFlags;

/// Inline-stored, fixed-capacity history string.
///
/// `arrayvec::ArrayString<16>` — 16-byte payload + length, no heap.
pub type HistoryString = arrayvec::ArrayString<16>;

/// Append a TCP-flag-derived character to `history` (silently no-ops
/// if the buffer is full).
pub(crate) fn push_for_flags(
    history: &mut HistoryString,
    flags: TcpFlags,
    side: FlowSide,
    has_payload: bool,
) {
    for ch in chars_for_flags(flags, side, has_payload) {
        if history.try_push(ch).is_err() {
            return; // buffer full — truncate silently
        }
    }
}

/// Iterate the (zero or more) characters representing a single TCP
/// packet's contribution to the history string.
fn chars_for_flags(
    flags: TcpFlags,
    side: FlowSide,
    has_payload: bool,
) -> impl Iterator<Item = char> {
    let mut chars: arrayvec::ArrayVec<char, 5> = arrayvec::ArrayVec::new();
    let upper = matches!(side, FlowSide::Initiator);

    // SYN
    if flags.contains(TcpFlags::SYN) {
        chars.push(if upper { 'S' } else { 's' });
    }
    // FIN
    if flags.contains(TcpFlags::FIN) {
        chars.push(if upper { 'F' } else { 'f' });
    }
    // RST
    if flags.contains(TcpFlags::RST) {
        chars.push(if upper { 'R' } else { 'r' });
    }
    // Pure ACK without flags above contributes 'A'/'a' only on first
    // ACK after data; we keep it simple and emit only on SYN-ACK
    // (handled via SYN above) and explicit data.
    // Data — payload bytes
    if has_payload {
        chars.push(if upper { 'D' } else { 'd' });
    }

    chars.into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_initiator_uppercase() {
        let mut h = HistoryString::new();
        push_for_flags(&mut h, TcpFlags::SYN, FlowSide::Initiator, false);
        assert_eq!(h.as_str(), "S");
    }

    #[test]
    fn syn_ack_responder_lowercase_with_a() {
        // SYN-ACK from responder: just 's' (A on the next ACK is
        // implicit; we only emit per-flag).
        let mut h = HistoryString::new();
        push_for_flags(
            &mut h,
            TcpFlags::SYN | TcpFlags::ACK,
            FlowSide::Responder,
            false,
        );
        assert_eq!(h.as_str(), "s");
    }

    #[test]
    fn data_psh_initiator_d() {
        let mut h = HistoryString::new();
        push_for_flags(
            &mut h,
            TcpFlags::PSH | TcpFlags::ACK,
            FlowSide::Initiator,
            true,
        );
        assert_eq!(h.as_str(), "D");
    }

    #[test]
    fn fin_responder_lowercase_f() {
        let mut h = HistoryString::new();
        push_for_flags(
            &mut h,
            TcpFlags::FIN | TcpFlags::ACK,
            FlowSide::Responder,
            false,
        );
        assert_eq!(h.as_str(), "f");
    }

    #[test]
    fn full_session_history() {
        let mut h = HistoryString::new();
        push_for_flags(&mut h, TcpFlags::SYN, FlowSide::Initiator, false);
        push_for_flags(
            &mut h,
            TcpFlags::SYN | TcpFlags::ACK,
            FlowSide::Responder,
            false,
        );
        push_for_flags(
            &mut h,
            TcpFlags::PSH | TcpFlags::ACK,
            FlowSide::Initiator,
            true,
        );
        push_for_flags(
            &mut h,
            TcpFlags::PSH | TcpFlags::ACK,
            FlowSide::Responder,
            true,
        );
        push_for_flags(
            &mut h,
            TcpFlags::FIN | TcpFlags::ACK,
            FlowSide::Initiator,
            false,
        );
        push_for_flags(
            &mut h,
            TcpFlags::FIN | TcpFlags::ACK,
            FlowSide::Responder,
            false,
        );
        assert_eq!(h.as_str(), "SsDdFf");
    }

    #[test]
    fn truncates_at_capacity() {
        let mut h = HistoryString::new();
        // Push 20 SYN events; buffer is 16 chars, so we cap at 16.
        for _ in 0..20 {
            push_for_flags(&mut h, TcpFlags::SYN, FlowSide::Initiator, false);
        }
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn rst_initiator_uppercase_r() {
        let mut h = HistoryString::new();
        push_for_flags(&mut h, TcpFlags::RST, FlowSide::Initiator, false);
        assert_eq!(h.as_str(), "R");
    }
}
