//! Events emitted by [`crate::FlowTracker`] as packets flow through it.

use crate::Timestamp;
use crate::extractor::L4Proto;
use crate::history::HistoryString;

/// Which side of a flow a packet belongs to.
///
/// Derived from the [`crate::Orientation`] reported by the extractor:
/// - The **first** orientation seen for a flow becomes the
///   `Initiator` direction.
/// - Packets matching that orientation are `Initiator`, packets in
///   the opposite orientation are `Responder`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSide {
    Initiator,
    Responder,
}

/// Why a flow ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// TCP FIN observed (graceful close).
    Fin,
    /// TCP RST observed (abrupt close).
    Rst,
    /// No packets observed within the configured idle timeout.
    IdleTimeout,
    /// Tracker hit `max_flows` and evicted the oldest flow.
    Evicted,
}

/// Aggregate counters maintained per flow.
#[derive(Debug, Clone, Default)]
pub struct FlowStats {
    pub packets_initiator: u64,
    pub packets_responder: u64,
    pub bytes_initiator: u64,
    pub bytes_responder: u64,
    pub started: Timestamp,
    pub last_seen: Timestamp,
}

/// Lifecycle state of a flow as tracked by [`crate::FlowTracker`].
///
/// Non-TCP flows stay in [`FlowState::Active`] until they end.
/// TCP flows transition through `SynSent → Established → FinWait → Closed`
/// (or `Reset`/`Aborted` on irregular termination).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// First TCP SYN observed; awaiting SYN-ACK.
    SynSent,
    /// SYN-ACK observed; awaiting initiator's ACK.
    SynReceived,
    /// 3WHS complete (TCP) **or** non-TCP flow seen.
    Established,
    /// One side has FIN'd; the other is still up.
    FinWait,
    /// Both sides FIN'd; awaiting final ACK.
    ClosingTcp,
    /// Non-TCP flow — no state machine engaged.
    Active,
    /// TCP flow closed gracefully.
    Closed,
    /// TCP flow torn down by RST.
    Reset,
    /// TCP flow aborted (idle timeout while open).
    Aborted,
}

impl FlowState {
    /// True if the state means "this flow won't see more packets".
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            FlowState::Closed | FlowState::Reset | FlowState::Aborted
        )
    }
}

/// Events emitted by the tracker.
///
/// One packet typically produces one or two events. The `Started`
/// event fires on first sight of a flow and is followed by a
/// `Packet` event for the same packet. Subsequent packets of the
/// same flow produce a single `Packet` event each. TCP-aware events
/// (`Established`, `StateChange`) fire only when the extractor
/// supplied [`crate::TcpInfo`].
#[derive(Debug, Clone)]
pub enum FlowEvent<K> {
    /// First packet of a new flow.
    Started {
        key: K,
        side: FlowSide,
        ts: Timestamp,
        l4: Option<L4Proto>,
    },

    /// Subsequent packet on a known flow.
    Packet {
        key: K,
        side: FlowSide,
        len: usize,
        ts: Timestamp,
    },

    /// TCP only — 3WHS completed for this flow.
    Established { key: K, ts: Timestamp },

    /// State machine transitioned. Fires for TCP non-Established
    /// transitions (e.g., `Established → FinWait`).
    StateChange {
        key: K,
        from: FlowState,
        to: FlowState,
        ts: Timestamp,
    },

    /// Flow ended (FIN/RST for TCP, idle/eviction for any flow).
    Ended {
        key: K,
        reason: EndReason,
        stats: FlowStats,
        history: HistoryString,
    },
}

impl<K> FlowEvent<K> {
    /// Borrow the key without moving it. Useful for filter combinators.
    pub fn key(&self) -> &K {
        match self {
            FlowEvent::Started { key, .. }
            | FlowEvent::Packet { key, .. }
            | FlowEvent::Established { key, .. }
            | FlowEvent::StateChange { key, .. }
            | FlowEvent::Ended { key, .. } => key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_state_terminal() {
        assert!(FlowState::Closed.is_terminal());
        assert!(FlowState::Reset.is_terminal());
        assert!(FlowState::Aborted.is_terminal());
        assert!(!FlowState::Active.is_terminal());
        assert!(!FlowState::Established.is_terminal());
        assert!(!FlowState::SynSent.is_terminal());
    }

    #[test]
    fn flow_event_key_borrow() {
        let evt: FlowEvent<u32> = FlowEvent::Packet {
            key: 7,
            side: FlowSide::Initiator,
            len: 100,
            ts: Timestamp::default(),
        };
        assert_eq!(*evt.key(), 7);
    }
}
