//! Standard [`FromCtx`] extractors.
//!
//! Handler closures name these as parameter types to receive
//! per-event borrowed views of monitor state:
//!
//! ```ignore
//! Monitor::builder()
//!     .state::<MyState>()
//!     .counter::<IpAddr>(Duration::from_secs(10), Duration::from_secs(1))
//!     .on::<FlowStarted<Tcp>>(|_evt, state: State<MyState>, now: Now| {
//!         state.connections += 1;
//!         let _ = now; // current event timestamp
//!         Ok(())
//!     });
//! ```
//!
//! The extractors are zero-sized phantom types — they only carry
//! type information to drive the [`FromCtx`] resolution; the
//! actual borrowed value comes out of [`Ctx`].

use std::marker::PhantomData;

use flowscope::Timestamp;

use crate::anomaly::sink::AnomalySink;
use crate::correlate::TimeBucketedCounter;
use crate::ctx::{Ctx, FromCtx};

/// Per-monitor shared user state. Lazy-initialized via `Default`
/// when first accessed; pre-register via
/// `MonitorBuilder::state::<T>()` to surface typos at build time.
///
/// `PhantomData<fn() -> T>` makes the marker covariant in `T`
/// while staying `Send + Sync` regardless of `T`'s bounds.
pub struct State<T>(PhantomData<fn() -> T>);

impl<T: Default + Send + 'static> FromCtx for State<T> {
    type Target<'a> = &'a mut T;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> &'a mut T {
        ctx.state_map.get_or_init_mut::<T>()
    }
}

/// The anomaly sink. The `A` phantom is reserved for type-tagged
/// sinks in a later phase (`Sink<MetricsSink>`); today the
/// extractor returns `&mut dyn AnomalySink` regardless of `A`.
pub struct Sink<A = ()>(PhantomData<fn() -> A>);

impl<A: 'static> FromCtx for Sink<A> {
    type Target<'a> = &'a mut dyn AnomalySink;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> &'a mut dyn AnomalySink {
        ctx.sink
    }
}

/// Current event timestamp (`Copy`). Equivalent to reading
/// `ctx.ts` directly; the extractor form lets handler closures
/// receive it through their parameter list.
pub struct Now;

impl FromCtx for Now {
    type Target<'a> = Timestamp;
    // The trait's `Target<'a>` is `Copy` here so this `'a` ends up
    // unused — clippy would prefer it elided, but the trait signature
    // mandates it.
    #[allow(clippy::needless_lifetimes)]
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> Timestamp {
        ctx.ts
    }
}

/// Per-key sliding-window counter. Must be registered via
/// `MonitorBuilder::counter::<K>(...)` before any handler uses it;
/// the extractor panics on first access otherwise.
pub struct Counter<K>(PhantomData<fn() -> K>);

impl<K: std::hash::Hash + Eq + Clone + Send + 'static> FromCtx for Counter<K> {
    type Target<'a> = &'a mut TimeBucketedCounter<K>;
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> &'a mut TimeBucketedCounter<K> {
        ctx.counters.get_mut::<K>()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::anomaly::sink::NoopSink;
    use crate::ctx::{CounterRegistry, SourceIdx, StateMap};

    #[derive(Default)]
    struct DemoState {
        n: u64,
    }

    #[test]
    fn state_extractor_lazy_creates() {
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        let mut sink = NoopSink;
        let mut ctx = Ctx {
            flow: None,
            ts: Timestamp::new(0, 0),
            source: SourceIdx(0),
            state_map: &mut state,
            sink: &mut sink,
            counters: &mut counters,
        };
        let s: &mut DemoState = <State<DemoState> as FromCtx>::from_ctx(&mut ctx);
        s.n = 42;
        assert_eq!(<State<DemoState> as FromCtx>::from_ctx(&mut ctx).n, 42);
    }

    #[test]
    fn now_extractor_returns_ctx_ts() {
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        let mut sink = NoopSink;
        let ts = Timestamp::new(1234, 5678);
        let mut ctx = Ctx {
            flow: None,
            ts,
            source: SourceIdx(0),
            state_map: &mut state,
            sink: &mut sink,
            counters: &mut counters,
        };
        assert_eq!(<Now as FromCtx>::from_ctx(&mut ctx), ts);
    }

    #[test]
    fn counter_extractor_returns_registered_counter() {
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        counters.register::<u16>(TimeBucketedCounter::<u16>::new(
            Duration::from_secs(60),
            Duration::from_secs(1),
        ));
        let mut sink = NoopSink;
        let mut ctx = Ctx {
            flow: None,
            ts: Timestamp::new(0, 0),
            source: SourceIdx(0),
            state_map: &mut state,
            sink: &mut sink,
            counters: &mut counters,
        };
        let c = <Counter<u16> as FromCtx>::from_ctx(&mut ctx);
        c.bump(42u16, Timestamp::new(0, 0));
    }

    #[test]
    fn sink_extractor_returns_dyn_anomalysink() {
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        let mut sink = NoopSink;
        let mut ctx = Ctx {
            flow: None,
            ts: Timestamp::new(0, 0),
            source: SourceIdx(0),
            state_map: &mut state,
            sink: &mut sink,
            counters: &mut counters,
        };
        let _: &mut dyn AnomalySink = <Sink<()> as FromCtx>::from_ctx(&mut ctx);
    }
}
