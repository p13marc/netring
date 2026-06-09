//! Per-event context passed to handlers.
//!
//! `Ctx` lives on the dispatch stack — never heap-allocated.
//! Handlers receive a single `&mut Ctx<'_>` (alongside the typed
//! event payload) and pull what they need via methods on `Ctx`:
//!
//! ```ignore
//! Monitor::builder()
//!     .state::<MyState>()
//!     .counter::<IpAddr>(Duration::from_secs(10), Duration::from_secs(1))
//!     .on_ctx::<Http>(|req, ctx| {
//!         let counters = ctx.counter_mut::<IpAddr>();
//!         counters.bump(req.client_ip(), ctx.ts);
//!         ctx.state_mut::<MyState>().requests += 1;
//!         Ok(())
//!     });
//! ```
//!
//! ## Why method-style instead of axum-style extractors
//!
//! The first cut of this module shipped an `FromCtx` trait with
//! multi-extractor blanket impls (1..=8 arities). It doesn't
//! compile: every `<P as FromCtx>::from_ctx(&mut ctx)` call holds
//! `&mut Ctx` for as long as its return value lives, so the
//! second extractor can't re-borrow. axum gets away with this
//! because async-await sequences the borrows; sync Rust can't.
//!
//! Method accessors on `Ctx` give the same ergonomics without
//! the borrow-checker headache: each call is its own bounded
//! borrow, and the compiler tracks disjoint field accesses
//! (`state_map`, `counters`, `sink`) correctly.

use flowscope::Timestamp;

mod from_ctx;

pub use from_ctx::{CounterRegistry, StateMap};

use crate::correlate::TimeBucketedCounter;
use crate::protocol::FlowKey;

/// Tag for which capture source this event came from.
/// `SourceIdx(0)` for single-interface monitors; multi-interface
/// (Phase E) increments per registered iface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceIdx(pub u8);

/// Runtime context passed to every handler invocation.
///
/// The `flow` / `ts` / `source` fields are `pub` for direct read.
/// State / counter / sink access goes through the typed accessor
/// methods so the storage maps can stay `pub(crate)`.
pub struct Ctx<'a> {
    /// The flow key for the current event, if any.
    ///
    /// Held by value (`FlowKey` is `Copy`) so dispatch sites can
    /// stamp a per-message key without lifetime gymnastics —
    /// borrowing through `Option<&'a FlowKey>` would require a
    /// place to anchor the borrow that outlives the `Ctx`.
    pub flow: Option<FlowKey>,

    /// Timestamp of the current event.
    pub ts: Timestamp,

    /// Source-interface index.
    pub source: SourceIdx,

    /// Per-monitor user state, keyed by `TypeId`.
    pub(crate) state_map: &'a mut StateMap,

    /// The anomaly sink (Phase C fills in the trait body).
    pub(crate) sink: &'a mut dyn crate::anomaly::sink::AnomalySink,

    /// Per-monitor counter storage.
    pub(crate) counters: &'a mut CounterRegistry,
}

impl<'a> Ctx<'a> {
    /// Borrow per-monitor state `T` mutably.
    ///
    /// `T: Default` so the slot is lazy-created on first access.
    /// Pre-register via `MonitorBuilder::state::<T>()` to surface
    /// typos at build time.
    #[inline]
    pub fn state_mut<T: Default + Send + 'static>(&mut self) -> &mut T {
        self.state_map.get_or_init_mut::<T>()
    }

    /// Borrow the `K`-keyed sliding-window counter mutably.
    ///
    /// # Panics
    ///
    /// Panics if no `MonitorBuilder::counter::<K>(...)` call
    /// registered this key — a programmer error caught early in
    /// development.
    #[inline]
    pub fn counter_mut<K>(&mut self) -> &mut TimeBucketedCounter<K>
    where
        K: std::hash::Hash + Eq + Clone + Send + 'static,
    {
        self.counters.get_mut::<K>()
    }

    /// Borrow the anomaly sink mutably. The trait body lands in
    /// Phase C — the Phase B sink is a no-op marker for the
    /// dispatch machinery.
    #[inline]
    pub fn sink_mut(&mut self) -> &mut dyn crate::anomaly::sink::AnomalySink {
        self.sink
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::sink::NoopSink;

    #[derive(Default)]
    struct DemoState {
        n: u64,
    }

    fn make_ctx<'a>(
        state: &'a mut StateMap,
        sink: &'a mut NoopSink,
        counters: &'a mut CounterRegistry,
    ) -> Ctx<'a> {
        Ctx {
            flow: None,
            ts: Timestamp::new(0, 0),
            source: SourceIdx(0),
            state_map: state,
            sink,
            counters,
        }
    }

    #[test]
    fn ctx_constructs_from_borrowed_fields() {
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        let mut sink = NoopSink;
        let _ctx = make_ctx(&mut state, &mut sink, &mut counters);
    }

    #[test]
    fn state_mut_lazy_creates_then_returns_same() {
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        let mut sink = NoopSink;
        let mut ctx = make_ctx(&mut state, &mut sink, &mut counters);
        ctx.state_mut::<DemoState>().n = 7;
        assert_eq!(ctx.state_mut::<DemoState>().n, 7);
    }

    #[test]
    fn sink_mut_returns_dyn_anomalysink() {
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        let mut sink = NoopSink;
        let mut ctx = make_ctx(&mut state, &mut sink, &mut counters);
        let _: &mut dyn crate::anomaly::sink::AnomalySink = ctx.sink_mut();
    }

    #[test]
    fn counter_mut_returns_registered_counter() {
        use std::time::Duration;
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        counters.register::<u16>(TimeBucketedCounter::<u16>::new(
            Duration::from_secs(60),
            Duration::from_secs(1),
        ));
        let mut sink = NoopSink;
        let mut ctx = make_ctx(&mut state, &mut sink, &mut counters);
        ctx.counter_mut::<u16>().bump(42u16, Timestamp::new(0, 0));
    }

    #[test]
    fn source_idx_roundtrip() {
        assert_eq!(SourceIdx(3), SourceIdx(3));
        assert_ne!(SourceIdx(1), SourceIdx(2));
    }
}
