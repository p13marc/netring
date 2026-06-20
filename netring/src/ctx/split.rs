//! Disjoint-field projection helpers on [`Ctx`].
//!
//! ## When you need this
//!
//! The Phase B [`Ctx`] method accessors (`state_mut::<T>()`,
//! `counter_mut::<K>()`, `sink_mut()`) each return a bounded
//! `&mut` borrow tied to one call. That's exactly right for
//! "increment state, then call sink" — the borrows don't overlap.
//!
//! But some handlers want to hold *simultaneous* `&mut` refs to
//! multiple ctx fields — typically `(state, sink)` or
//! `(state, counter)` — so they can interleave reads of one with
//! writes to the other in a single expression. Calling
//! `ctx.state_mut::<T>()` and then `ctx.sink_mut()` doesn't
//! compose, because the first call's `&mut Ctx<'_>` reservation is
//! still live when the second begins.
//!
//! These helpers project the disjoint fields in one step, via
//! audited [`unsafe`]: each method takes `&mut self` and emits
//! several `&mut` references that point at distinct struct
//! fields. Because the fields are distinct, the references can
//! coexist without aliasing.
//!
//! ## Soundness contract
//!
//! - Each `split_*` method consumes `&mut self`, which means the
//!   caller had unique access to `self` at the call site.
//! - The returned references point at distinct, named, struct
//!   fields. Writing through one can never affect another. The
//!   raw-pointer unsafe is purely to extend each individual
//!   borrow to the lifetime of `self` so the compiler can hand
//!   them out simultaneously.
//! - The caller cannot re-call `split_*` while the returned refs
//!   are live — they reborrow `&mut self`. (Once a `split_*`
//!   returns, `self` is borrowed for the returned-references'
//!   lifetime.)
//!
//! The `unsafe` blocks here have inline SAFETY comments tying
//! the pointer use to one of those clauses.

use std::hash::Hash;

use crate::anomaly::sink::AnomalySink;
use crate::correlate::TimeBucketedCounter;
use crate::ctx::Ctx;

impl Ctx<'_> {
    /// Borrow `(&mut T, &mut dyn AnomalySink)` simultaneously.
    ///
    /// `T` is the user-state slot extracted from `state_map`;
    /// `dyn AnomalySink` is the registered sink. They live in
    /// distinct struct fields of `Ctx`, so projecting both at
    /// once is sound.
    pub fn split_state_sink<T>(&mut self) -> (&mut T, &mut dyn AnomalySink)
    where
        T: Default + Send + 'static,
    {
        // Materialise the state ref first; this also lazily creates
        // the T slot via `get_or_init_mut`.
        let state_ptr: *mut T = self.state_map.get_or_init_mut::<T>() as *mut T;
        let sink_ptr: *mut dyn AnomalySink = self.sink;
        // SAFETY: state_map and sink are distinct, named fields
        // of Ctx (one stores typed user state by TypeId; the other
        // is the `&mut dyn AnomalySink` field). Returning two
        // `&mut` references that point at different fields cannot
        // alias. Both references' lifetimes are tied to `&mut self`,
        // so the caller can hold them only as long as it could
        // hold the original `&mut self`.
        unsafe { (&mut *state_ptr, &mut *sink_ptr) }
    }

    /// Borrow `(&mut T, &mut TimeBucketedCounter<K>)` simultaneously.
    pub fn split_state_counter<T, K>(&mut self) -> (&mut T, &mut TimeBucketedCounter<K>)
    where
        T: Default + Send + 'static,
        K: Hash + Eq + Clone + Send + 'static,
    {
        let state_ptr: *mut T = self.state_map.get_or_init_mut::<T>() as *mut T;
        let counter_ptr: *mut TimeBucketedCounter<K> =
            self.counters.get_mut::<K>() as *mut TimeBucketedCounter<K>;
        // SAFETY: state_map and counters are distinct, named fields.
        // The K-keyed counter slot is materialised once via
        // get_mut::<K>(); the resulting reference points at the
        // counters field's interior, independent of state_map.
        unsafe { (&mut *state_ptr, &mut *counter_ptr) }
    }

    /// Borrow `(&mut dyn AnomalySink, &mut TimeBucketedCounter<K>)`
    /// simultaneously — useful for "bump counter, emit anomaly"
    /// in one expression.
    pub fn split_sink_counter<K>(&mut self) -> (&mut dyn AnomalySink, &mut TimeBucketedCounter<K>)
    where
        K: Hash + Eq + Clone + Send + 'static,
    {
        let sink_ptr: *mut dyn AnomalySink = self.sink;
        let counter_ptr: *mut TimeBucketedCounter<K> =
            self.counters.get_mut::<K>() as *mut TimeBucketedCounter<K>;
        // SAFETY: sink and counters are distinct, named fields.
        unsafe { (&mut *sink_ptr, &mut *counter_ptr) }
    }

    /// Borrow `(&mut T, &mut dyn AnomalySink, &mut TimeBucketedCounter<K>)`
    /// — three disjoint Ctx fields at once.
    pub fn split_state_sink_counter<T, K>(
        &mut self,
    ) -> (&mut T, &mut dyn AnomalySink, &mut TimeBucketedCounter<K>)
    where
        T: Default + Send + 'static,
        K: Hash + Eq + Clone + Send + 'static,
    {
        let state_ptr: *mut T = self.state_map.get_or_init_mut::<T>() as *mut T;
        let sink_ptr: *mut dyn AnomalySink = self.sink;
        let counter_ptr: *mut TimeBucketedCounter<K> =
            self.counters.get_mut::<K>() as *mut TimeBucketedCounter<K>;
        // SAFETY: state_map, sink, and counters are three distinct,
        // named fields of Ctx. All three reborrows are tied to
        // `&mut self`'s lifetime; they cannot alias.
        unsafe { (&mut *state_ptr, &mut *sink_ptr, &mut *counter_ptr) }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use flowscope::Timestamp;

    use super::*;
    use crate::anomaly::Severity;
    use crate::anomaly::sink::NoopSink;
    use crate::ctx::{CounterRegistry, SourceIdx, StateMap};

    #[derive(Default)]
    struct State1 {
        n: u64,
    }

    #[derive(Default)]
    struct State2 {
        m: u32,
    }

    fn make_ctx<'a>(
        state: &'a mut StateMap,
        sink: &'a mut NoopSink,
        counters: &'a mut CounterRegistry,
        flow_states: &'a mut crate::ctx::FlowStateRegistry,
    ) -> Ctx<'a> {
        Ctx {
            flow: None,
            ts: Timestamp::new(0, 0),
            source: SourceIdx(0),
            monitor_name: None,
            state_map: state,
            sink,
            counters,
            flow_states,
            label_table: crate::ctx::default_label_table(),
            tracker: None,
            arp_table: None,
        }
    }

    #[test]
    fn split_state_sink_yields_disjoint_borrows() {
        let mut state = StateMap::default();
        let mut sink = NoopSink;
        let mut counters = CounterRegistry::default();
        let mut flow_states = crate::ctx::FlowStateRegistry::default();
        let mut ctx = make_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);

        let (s, k) = ctx.split_state_sink::<State1>();
        s.n = 9;
        k.write("k", Severity::Info, Timestamp::new(0, 0), None, &[], &[]);
        // Both borrows are still live here — the test compiles
        // iff the projection actually emits disjoint refs.
        assert_eq!(s.n, 9);
    }

    #[test]
    fn split_state_counter_yields_disjoint_borrows() {
        let mut state = StateMap::default();
        let mut sink = NoopSink;
        let mut counters = CounterRegistry::default();
        counters.register::<u32>(TimeBucketedCounter::<u32>::new_unbounded(
            Duration::from_secs(10),
            Duration::from_secs(1),
        ));
        let mut flow_states = crate::ctx::FlowStateRegistry::default();
        let mut ctx = make_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);

        let (s, c) = ctx.split_state_counter::<State1, u32>();
        s.n = 7;
        c.bump(1u32, Timestamp::new(0, 0));
        assert_eq!(s.n, 7);
    }

    #[test]
    fn split_sink_counter_yields_disjoint_borrows() {
        let mut state = StateMap::default();
        let mut sink = NoopSink;
        let mut counters = CounterRegistry::default();
        counters.register::<u16>(TimeBucketedCounter::<u16>::new_unbounded(
            Duration::from_secs(10),
            Duration::from_secs(1),
        ));
        let mut flow_states = crate::ctx::FlowStateRegistry::default();
        let mut ctx = make_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);

        let (k, c) = ctx.split_sink_counter::<u16>();
        c.bump(42u16, Timestamp::new(0, 0));
        k.write("k", Severity::Info, Timestamp::new(0, 0), None, &[], &[]);
    }

    #[test]
    fn split_state_sink_counter_yields_three_disjoint_borrows() {
        let mut state = StateMap::default();
        let mut sink = NoopSink;
        let mut counters = CounterRegistry::default();
        counters.register::<u64>(TimeBucketedCounter::<u64>::new_unbounded(
            Duration::from_secs(10),
            Duration::from_secs(1),
        ));
        let mut flow_states = crate::ctx::FlowStateRegistry::default();
        let mut ctx = make_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);

        let (s, k, c) = ctx.split_state_sink_counter::<State2, u64>();
        s.m = 11;
        c.bump(99u64, Timestamp::new(0, 0));
        k.write("k", Severity::Info, Timestamp::new(0, 0), None, &[], &[]);
        assert_eq!(s.m, 11);
    }

    #[test]
    fn sequential_split_calls_compose() {
        // Once the first split's borrows are dropped, a second
        // split is allowed — the reborrow of `&mut self` releases.
        let mut state = StateMap::default();
        let mut sink = NoopSink;
        let mut counters = CounterRegistry::default();
        let mut flow_states = crate::ctx::FlowStateRegistry::default();
        let mut ctx = make_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);

        {
            let (s, _k) = ctx.split_state_sink::<State1>();
            s.n = 1;
        }
        {
            let (s, _k) = ctx.split_state_sink::<State1>();
            assert_eq!(s.n, 1);
            s.n = 2;
        }
    }
}
