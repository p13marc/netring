//! TCP state machine used internally by [`crate::FlowTracker`].
//!
//! Simplified compared to RFC 793's full TCP state machine — we don't
//! need to track connection setup details from the server's
//! perspective, just enough to recognize "open", "closing", and
//! "closed" states for lifecycle event emission.

use crate::event::{FlowSide, FlowState};
use crate::extractor::TcpFlags;

/// Outcome of one TCP-flag transition.
pub(crate) struct Transition {
    /// New state (may equal the old state).
    pub state: FlowState,
    /// True if the transition crosses into Established for the first time.
    pub became_established: bool,
}

/// Compute the next state.
pub(crate) fn transition(state: FlowState, flags: TcpFlags, side: FlowSide) -> Transition {
    // RST forces immediate Reset regardless of state.
    if flags.contains(TcpFlags::RST) {
        return Transition {
            state: FlowState::Reset,
            became_established: false,
        };
    }

    let new_state = match (state, side, flags) {
        // SYN from initiator opens the flow.
        (FlowState::Active, FlowSide::Initiator, f) if f.contains(TcpFlags::SYN) => {
            FlowState::SynSent
        }

        // SYN-ACK from responder.
        (FlowState::SynSent, FlowSide::Responder, f)
            if f.contains(TcpFlags::SYN | TcpFlags::ACK) =>
        {
            FlowState::SynReceived
        }

        // Initiator's ACK completes the 3WHS.
        (FlowState::SynReceived, FlowSide::Initiator, f) if f.contains(TcpFlags::ACK) => {
            FlowState::Established
        }

        // FIN from either side starts the close sequence.
        (FlowState::Established, _, f) if f.contains(TcpFlags::FIN) => FlowState::FinWait,
        (FlowState::FinWait, _, f) if f.contains(TcpFlags::FIN) => FlowState::ClosingTcp,

        // Final ACK closes the connection.
        (FlowState::ClosingTcp, _, f) if f.contains(TcpFlags::ACK) => FlowState::Closed,

        // Otherwise stay where we are.
        _ => state,
    };

    let became_established = state != FlowState::Established && new_state == FlowState::Established;
    Transition {
        state: new_state,
        became_established,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn() -> TcpFlags {
        TcpFlags::SYN
    }
    fn syn_ack() -> TcpFlags {
        TcpFlags::SYN | TcpFlags::ACK
    }
    fn ack() -> TcpFlags {
        TcpFlags::ACK
    }
    fn fin_ack() -> TcpFlags {
        TcpFlags::FIN | TcpFlags::ACK
    }

    #[test]
    fn three_way_handshake() {
        let t1 = transition(FlowState::Active, syn(), FlowSide::Initiator);
        assert_eq!(t1.state, FlowState::SynSent);
        assert!(!t1.became_established);

        let t2 = transition(t1.state, syn_ack(), FlowSide::Responder);
        assert_eq!(t2.state, FlowState::SynReceived);
        assert!(!t2.became_established);

        let t3 = transition(t2.state, ack(), FlowSide::Initiator);
        assert_eq!(t3.state, FlowState::Established);
        assert!(t3.became_established);
    }

    #[test]
    fn graceful_close() {
        let t1 = transition(FlowState::Established, fin_ack(), FlowSide::Initiator);
        assert_eq!(t1.state, FlowState::FinWait);

        let t2 = transition(t1.state, fin_ack(), FlowSide::Responder);
        assert_eq!(t2.state, FlowState::ClosingTcp);

        let t3 = transition(t2.state, ack(), FlowSide::Initiator);
        assert_eq!(t3.state, FlowState::Closed);
    }

    #[test]
    fn rst_in_any_state() {
        let rst = TcpFlags::RST;
        let t1 = transition(FlowState::Established, rst, FlowSide::Initiator);
        assert_eq!(t1.state, FlowState::Reset);

        let t2 = transition(FlowState::SynSent, rst, FlowSide::Responder);
        assert_eq!(t2.state, FlowState::Reset);
    }

    #[test]
    fn unknown_packet_in_active_no_transition() {
        // Pure ACK on a non-TCP-tracked flow — stay in Active.
        let t = transition(FlowState::Active, ack(), FlowSide::Responder);
        assert_eq!(t.state, FlowState::Active);
    }

    #[test]
    fn syn_retransmit_doesnt_advance() {
        let t = transition(FlowState::SynSent, syn(), FlowSide::Initiator);
        assert_eq!(t.state, FlowState::SynSent);
    }

    #[test]
    fn established_data_stays_established() {
        let psh_ack = TcpFlags::PSH | TcpFlags::ACK;
        let t = transition(FlowState::Established, psh_ack, FlowSide::Initiator);
        assert_eq!(t.state, FlowState::Established);
        assert!(!t.became_established);
    }
}
