//! [`SessionEvent`] — netring's L7 session-stream event type.
//!
//! flowscope 0.20 (#100) demoted its `SessionEvent` to a crate-private
//! engine carrier; the public flowscope vocabulary is now `FlowEvent`
//! (tracker primitive) + `Event<K>` (typed driver). flowscope's RFC
//! recommends downstream stream layers **own** their session-event
//! type, so netring defines its own here. It is the `Stream::Item` of
//! [`SessionStream`] / [`DatagramStream`] / [`PcapSessionStream`] /
//! [`PcapDatagramStream`] and (wrapped in `TaggedEvent`) the multi
//! variants.
//!
//! The variants mirror what netring's `process_session_event` already
//! synthesizes from a [`flowscope::FlowEvent`]: flow lifecycle
//! endpoints (`Started` / `Closed`), the typed L7 `Application`
//! messages a parser flushes in between, and the two live anomaly
//! carriers. Periodic `Tick` snapshots are intentionally not surfaced
//! on the session streams (the contract is "messages and lifecycle
//! endpoints"); the enum is `#[non_exhaustive]` so adding it later is
//! additive.
//!
//! [`SessionStream`]: super::session_stream::SessionStream
//! [`DatagramStream`]: super::datagram_stream::DatagramStream
//! [`PcapSessionStream`]: crate::pcap_flow::PcapSessionStream
//! [`PcapDatagramStream`]: crate::pcap_flow::PcapDatagramStream

use flowscope::{
    AnomalyKind, EndReason, FlowSide, FlowStats, L4Proto, Orientation, ParserKind, Timestamp,
};

/// An event produced by a netring L7 session / datagram stream.
///
/// `K` is the flow key (typically [`flowscope::extract::FiveTupleKey`]);
/// `M` is the parser's message type
/// (`<P as flowscope::SessionParser>::Message`).
#[derive(Debug)]
#[non_exhaustive]
// `Closed` carries a full `FlowStats` (the largest variant) while
// `Started` / `TrackerAnomaly` are small. These events are produced
// one at a time and drained immediately from a `VecDeque`, never held
// in bulk, so the size spread doesn't matter — boxing `stats` would
// just add an allocation on the hot close path.
#[allow(clippy::large_enum_variant)]
pub enum SessionEvent<K, M> {
    /// First packet of a new session.
    Started {
        /// Flow key.
        key: K,
        /// Logical role of the side that opened the flow
        /// (arrival-order-relative; see [`Orientation`] for the
        /// race-stable axis).
        side: FlowSide,
        /// Canonical, address-sorted direction of the opening packet.
        /// Unlike `side`, stable across a tap-merge / multi-queue
        /// arrival race (flowscope 0.20 #118).
        orientation: Orientation,
        /// Timestamp of the opening packet.
        ts: Timestamp,
    },
    /// Parser emitted a complete L7 message.
    Application {
        /// Flow key.
        key: K,
        /// Side of the flow this message arrived on.
        side: FlowSide,
        /// Canonical, address-sorted direction this message arrived on
        /// (flowscope 0.20 #118).
        orientation: Orientation,
        /// The parsed L7 message.
        message: M,
        /// Timestamp of the carrying packet.
        ts: Timestamp,
        /// Identity of the parser that produced this message — the
        /// typed [`ParserKind`] returned by
        /// [`flowscope::SessionParser::parser_kind`] (or the datagram
        /// equivalent). [`ParserKind::Unspecified`] when the parser
        /// doesn't override the default.
        parser_kind: ParserKind,
    },
    /// Session ended (FIN / RST / idle / eviction). Any messages the
    /// parser flushed on close arrive as `Application` events before
    /// the corresponding `Closed`.
    Closed {
        /// Flow key.
        key: K,
        /// Why the flow ended.
        reason: EndReason,
        /// Final per-flow statistics (carries the new 0.20
        /// `source_idx_forward` / `source_idx_reverse` /
        /// `capture_leg_inconsistent` capture-leg fields).
        stats: FlowStats,
        /// L4 protocol of the flow this session was tracked over.
        l4: Option<L4Proto>,
    },
    /// Live, in-flight per-flow anomaly forwarded from
    /// [`flowscope::FlowEvent::FlowAnomaly`].
    FlowAnomaly {
        /// Flow key.
        key: K,
        /// The anomaly.
        kind: AnomalyKind,
        /// When it was observed.
        ts: Timestamp,
    },
    /// Live, in-flight tracker-global anomaly forwarded from
    /// [`flowscope::FlowEvent::TrackerAnomaly`] (carries no flow key).
    TrackerAnomaly {
        /// The anomaly.
        kind: AnomalyKind,
        /// When it was observed.
        ts: Timestamp,
    },
}
