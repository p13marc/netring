//! Which capture source — and which way round — a dispatched flow event
//! belongs to (#216).
//!
//! The run loop tags every packet it tracks with its capture leg
//! (`PacketView::with_source_idx`, 1-based: flowscope treats `0` as
//! "untagged"), so flowscope binds the leg into each flow's stats
//! (`FlowStats::source_idx_forward` / `source_idx_reverse`). An event a
//! packet drove belongs to that packet's source; an event no packet drove
//! — the idle sweep, the shutdown drain — takes its flow's bound leg
//! instead of a made-up source 0.

use flowscope::driver::Event as FsEvent;
use flowscope::{FlowSide, FlowStats, Orientation};

use crate::ctx::SourceIdx;
use crate::protocol::FlowKey;

/// Where a dispatched batch of driver events came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Tracking a packet captured on this source.
    Packet(SourceIdx),
    /// A sweep or the shutdown drain: no packet, no source of its own.
    Housekeeping,
}

impl Origin {
    fn source(self) -> Option<SourceIdx> {
        match self {
            Origin::Packet(s) => Some(s),
            Origin::Housekeeping => None,
        }
    }
}

/// The flows a batch ends, by key (#216): looked up once per event and
/// message of theirs dispatched after the tracker let them go — hashed, as
/// a sweep or a drain can end tens of thousands at once. Cleared and
/// refilled per batch; it keeps its allocation.
pub(crate) type EndedFlows = rustc_hash::FxHashMap<FlowKey, FlowCtx>;

/// What [`lookup`] found for a flow key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Found {
    /// The tracker still has the flow.
    Live(FlowCtx),
    /// The batch being dispatched ended it.
    Ended(FlowCtx),
}

impl Found {
    fn ctx(self) -> FlowCtx {
        match self {
            Found::Live(c) | Found::Ended(c) => c,
        }
    }
}

/// What a flow event's `Ctx` is stamped with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FlowCtx {
    pub(crate) source: Option<SourceIdx>,
    pub(crate) initiator: Option<Orientation>,
}

/// The leg tag of capture source `i`: `i + 1` (flowscope's `0` means
/// "untagged").
pub(crate) fn leg_tag(source: usize) -> u32 {
    u32::try_from(source).map_or(u32::MAX, |i| i.saturating_add(1))
}

/// The capture source a flowscope leg tag stands for (`0`: none).
pub(crate) fn leg_source(leg: u32) -> Option<SourceIdx> {
    leg.checked_sub(1)
        .and_then(|i| u8::try_from(i).ok())
        .map(SourceIdx)
}

impl FlowCtx {
    /// From a flow's stats: the leg its initiator's packets arrived on
    /// (else the responder's), and its initiator's orientation.
    pub(crate) fn of_stats(stats: &FlowStats) -> Self {
        let init = stats.initiator_orientation;
        let leg = stats
            .source_idx_for(init)
            .or_else(|| stats.source_idx_for(init.flipped()));
        Self {
            source: leg.and_then(leg_source),
            initiator: Some(init),
        }
    }
}

/// The initiator's orientation, from a packet's side and orientation.
pub(crate) fn initiator_of(side: FlowSide, orientation: Orientation) -> Orientation {
    match side {
        FlowSide::Initiator => orientation,
        FlowSide::Responder => orientation.flipped(),
    }
}

/// Resolve the context of `evt`, dispatched from a batch of `origin`.
/// `lookup` finds a live flow's context (the tracker), or a flow the
/// batch ended (its `Ended` events, pre-scanned).
///
/// - `Ended` / `Tick`: the flow's bound leg, else the batch's packet.
/// - `Started`: the batch's packet; its orientation is the initiator's.
/// - `Packet`: its own leg, else the batch's packet; initiator from its
///   side and orientation.
/// - A tracker-wide anomaly: no flow, no source.
/// - Anything else (`Established`, parser closes / side stops, flow
///   anomalies, …): see [`resolve_key`].
pub(crate) fn resolve(
    evt: &FsEvent<FlowKey>,
    origin: Origin,
    lookup: &dyn Fn(&FlowKey) -> Option<Found>,
) -> FlowCtx {
    match evt {
        FsEvent::Ended { stats, .. } | FsEvent::Tick { stats, .. } => {
            let ctx = FlowCtx::of_stats(stats);
            FlowCtx {
                source: ctx.source.or(origin.source()),
                ..ctx
            }
        }
        FsEvent::Started { orientation, .. } => FlowCtx {
            source: origin.source(),
            initiator: Some(*orientation),
        },
        FsEvent::Packet {
            side,
            orientation,
            source_idx,
            ..
        } => FlowCtx {
            source: source_idx.and_then(leg_source).or(origin.source()),
            initiator: Some(initiator_of(*side, *orientation)),
        },
        FsEvent::TrackerAnomaly { .. } => FlowCtx::default(),
        other => resolve_key(other.key(), origin, lookup),
    }
}

/// Resolve the context of a flow-keyed event or message without stats of
/// its own (see [`resolve`]):
///
/// - a flow the batch ended: its bound leg, like its `Ended` (else the
///   batch's packet) — a packet of another flow, maybe on another source,
///   can end it (LRU eviction), so the batch's packet is not its source;
/// - a live flow: the batch's packet when there is one, else the flow's
///   bound leg;
/// - the initiator from the flow either way.
pub(crate) fn resolve_key(
    key: Option<&FlowKey>,
    origin: Origin,
    lookup: &dyn Fn(&FlowKey) -> Option<Found>,
) -> FlowCtx {
    match (key.and_then(lookup), origin) {
        (Some(Found::Ended(ctx)), _) => FlowCtx {
            source: ctx.source.or(origin.source()),
            ..ctx
        },
        (found, Origin::Packet(source)) => FlowCtx {
            source: Some(source),
            initiator: found.and_then(|f| f.ctx().initiator),
        },
        (found, Origin::Housekeeping) => found.map(Found::ctx).unwrap_or_default(),
    }
}

/// Look `key` up in the tracker, then in the batch's ended flows.
pub(crate) fn lookup(
    tracker: &flowscope::FlowTracker<flowscope::extract::FiveTuple, ()>,
    ended: &EndedFlows,
    key: &FlowKey,
) -> Option<Found> {
    match tracker.get(key) {
        Some(entry) => {
            let ctx = FlowCtx::of_stats(&entry.stats);
            Some(Found::Live(FlowCtx {
                initiator: Some(entry.initiator_orientation()),
                ..ctx
            }))
        }
        None => ended.get(key).copied().map(Found::Ended),
    }
}

/// Pre-scan a batch: the context of every flow it ends, for the events
/// and messages of those flows dispatched before or after their `Ended`
/// (the tracker no longer has them). Reuses `out`'s allocation.
pub(crate) fn scan_ended(events: &[FsEvent<FlowKey>], out: &mut EndedFlows) {
    out.clear();
    for evt in events {
        if let FsEvent::Ended { key, stats, .. } = evt {
            out.insert(*key, FlowCtx::of_stats(stats));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> FlowKey {
        flowscope::extract::FiveTupleKey::new(
            flowscope::L4Proto::Udp,
            "10.0.0.1:5000".parse().unwrap(),
            "10.0.0.2:53".parse().unwrap(),
        )
    }

    fn stats(forward: Option<u32>, reverse: Option<u32>, init: Orientation) -> FlowStats {
        let mut s = FlowStats::default();
        s.source_idx_forward = forward;
        s.source_idx_reverse = reverse;
        s.initiator_orientation = init;
        s
    }

    fn ended(stats: FlowStats) -> FsEvent<FlowKey> {
        FsEvent::Ended {
            key: key(),
            reason: flowscope::EndReason::IdleTimeout,
            stats,
            history: flowscope::HistoryString::default(),
            l4: Some(flowscope::L4Proto::Udp),
            ts: flowscope::Timestamp::default(),
        }
    }

    /// A leg tag is the 1-based source index.
    #[test]
    fn leg_tags_are_one_based() {
        assert_eq!(leg_tag(0), 1);
        assert_eq!(leg_source(1), Some(SourceIdx(0)));
        assert_eq!(leg_source(3), Some(SourceIdx(2)));
        assert_eq!(leg_source(0), None);
        assert_eq!(leg_source(1_000), None);
    }

    /// #216: an ended flow takes its initiator's leg — falling back to the
    /// responder's, then to the batch's packet — whatever the origin.
    #[test]
    fn ended_flow_takes_its_bound_leg() {
        let none = |_: &FlowKey| None;
        let s = stats(Some(3), None, Orientation::Forward);
        let ctx = resolve(&ended(s), Origin::Housekeeping, &none);
        assert_eq!(ctx.source, Some(SourceIdx(2)));
        assert_eq!(ctx.initiator, Some(Orientation::Forward));
        // Initiator reverse: its leg first.
        let s = stats(Some(1), Some(2), Orientation::Reverse);
        let ctx = resolve(&ended(s), Origin::Packet(SourceIdx(0)), &none);
        assert_eq!(ctx.source, Some(SourceIdx(1)));
        // Only the responder's leg bound.
        let s = stats(None, Some(2), Orientation::Forward);
        assert_eq!(
            resolve(&ended(s), Origin::Housekeeping, &none).source,
            Some(SourceIdx(1))
        );
        // No leg: the batch's packet, or nothing.
        let s = stats(None, None, Orientation::Forward);
        assert_eq!(
            resolve(&ended(s.clone()), Origin::Packet(SourceIdx(4)), &none).source,
            Some(SourceIdx(4))
        );
        assert_eq!(resolve(&ended(s), Origin::Housekeeping, &none).source, None);
    }

    /// A keyed event without stats: the batch's packet when there is one,
    /// else the flow's leg found by the lookup.
    #[test]
    fn keyed_events_use_the_packet_or_the_lookup() {
        let found = FlowCtx {
            source: Some(SourceIdx(7)),
            initiator: Some(Orientation::Reverse),
        };
        let lookup = |_: &FlowKey| Some(Found::Live(found));
        let ctx = resolve_key(Some(&key()), Origin::Packet(SourceIdx(1)), &lookup);
        assert_eq!(ctx.source, Some(SourceIdx(1)));
        assert_eq!(ctx.initiator, Some(Orientation::Reverse));
        assert_eq!(
            resolve_key(Some(&key()), Origin::Housekeeping, &lookup),
            found
        );
        assert_eq!(
            resolve_key(Some(&key()), Origin::Housekeeping, &|_| None),
            FlowCtx::default()
        );
        assert_eq!(
            resolve_key(None, Origin::Housekeeping, &lookup),
            FlowCtx::default()
        );
    }

    /// Review r2: a message of a flow the batch ended — evicted by another
    /// flow's packet, maybe on another source — takes the flow's own leg,
    /// as its `Ended` does, not the batch's packet.
    #[test]
    fn messages_of_ended_flows_take_the_flows_leg() {
        let ended_ctx = FlowCtx {
            source: Some(SourceIdx(0)),
            initiator: Some(Orientation::Forward),
        };
        let lookup = |_: &FlowKey| Some(Found::Ended(ended_ctx));
        let ctx = resolve_key(Some(&key()), Origin::Packet(SourceIdx(1)), &lookup);
        assert_eq!(ctx, ended_ctx);
        // An ended flow without a bound leg: the batch's packet.
        let unbound = FlowCtx {
            source: None,
            ..ended_ctx
        };
        let lookup = |_: &FlowKey| Some(Found::Ended(unbound));
        let ctx = resolve_key(Some(&key()), Origin::Packet(SourceIdx(1)), &lookup);
        assert_eq!(ctx.source, Some(SourceIdx(1)));
    }

    #[test]
    fn initiator_follows_side_and_orientation() {
        use FlowSide::*;
        use Orientation::*;
        assert_eq!(initiator_of(Initiator, Forward), Forward);
        assert_eq!(initiator_of(Responder, Forward), Reverse);
        assert_eq!(initiator_of(Responder, Reverse), Forward);
    }

    #[test]
    fn scan_ended_collects_each_ended_flow() {
        let mut out = EndedFlows::default();
        out.insert(key(), FlowCtx::default());
        let s = stats(Some(2), None, Orientation::Forward);
        scan_ended(&[ended(s)], &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[&key()].source, Some(SourceIdx(1)));
    }
}
