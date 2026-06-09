//! Per-event context passed to handlers.
//!
//! `Ctx` lives on the dispatch stack — never heap-allocated.
//! Handlers borrow from it via the [`FromCtx`] trait; the borrow
//! lifetime is exactly the dispatch call.
//!
//! In Phase B the `Ctx` is constructed but not yet *consumed* by
//! handler closures (the dispatcher + handler-trait machinery
//! land in B.2/B.3/B.4). Defining it first lets the rest of the
//! phase mention `&'a mut Ctx<'_>` in signatures.

use flowscope::Timestamp;

use crate::protocol::FlowKey;

mod extractors;
mod from_ctx;

pub use extractors::{Counter, Now, Sink, State};
pub use from_ctx::{CounterRegistry, FromCtx, StateMap};

/// Tag for which capture source this event came from.
/// `SourceIdx(0)` for single-interface monitors; multi-interface
/// (Phase E) increments per registered iface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceIdx(pub u8);

/// Runtime context passed to every handler invocation.
///
/// Field accesses are gated through the [`FromCtx`] extractor
/// trait in normal code; the `flow` and `ts` fields are `pub`
/// for convenience in closures that just want to read them
/// directly (`ctx.ts`, `ctx.flow`).
pub struct Ctx<'a> {
    /// The flow key for the current event, if any.
    pub flow: Option<&'a FlowKey>,

    /// Timestamp of the current event. `Copy` — extract via [`Now`].
    pub ts: Timestamp,

    /// Source-interface index.
    pub source: SourceIdx,

    /// Per-monitor user state, keyed by `TypeId`.
    pub(crate) state_map: &'a mut StateMap,

    /// The anomaly sink. Phase C fills in the trait body; Phase B
    /// just hands out the trait object via the [`Sink`] extractor.
    pub(crate) sink: &'a mut dyn crate::anomaly::sink::AnomalySink,

    /// Per-monitor counter storage.
    pub(crate) counters: &'a mut CounterRegistry,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::sink::NoopSink;

    #[test]
    fn ctx_constructs_from_borrowed_fields() {
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        let mut sink = NoopSink;
        let _ctx = Ctx {
            flow: None,
            ts: Timestamp::new(0, 0),
            source: SourceIdx(0),
            state_map: &mut state,
            sink: &mut sink,
            counters: &mut counters,
        };
    }

    #[test]
    fn source_idx_roundtrip() {
        assert_eq!(SourceIdx(3), SourceIdx(3));
        assert_ne!(SourceIdx(1), SourceIdx(2));
    }
}
