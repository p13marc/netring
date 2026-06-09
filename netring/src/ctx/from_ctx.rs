//! [`FromCtx`] trait + per-monitor storage maps.
//!
//! Handler closures receive their arguments by *extracting* them
//! from the per-event [`Ctx`](crate::ctx::Ctx). `FromCtx` is the
//! axum-style extractor trait that defines what an argument type
//! produces when called on `&mut Ctx<'_>`.
//!
//! [`StateMap`] and [`CounterRegistry`] are the storage backings
//! for the [`State<T>`](crate::ctx::State) and
//! [`Counter<K>`](crate::ctx::Counter) extractors. Both are
//! `TypeId`-keyed and Phase B doesn't expose them publicly except
//! as `pub(crate)` fields on `Ctx`.

use std::any::{Any, TypeId};

use rustc_hash::FxHashMap;

use crate::correlate::TimeBucketedCounter;
use crate::ctx::Ctx;

/// Extract a typed view from `&mut Ctx<'_>`.
///
/// `Target<'a>` is the lifetime-bound view returned. For
/// [`State<T>`](crate::ctx::State) this is `&'a mut T`; for
/// [`Sink<()>`](crate::ctx::Sink) it's `&'a mut dyn AnomalySink`;
/// for [`Now`](crate::ctx::Now) it's [`flowscope::Timestamp`] by
/// value.
///
/// Phase B's blanket `Handler<E, M>` impls (B.2) sequence
/// `FromCtx::from_ctx` calls per extractor parameter, so an
/// extractor type may be present 0-or-1 times per handler — two
/// `&mut State<Same>` extractors would conflict at borrow-check
/// (intentionally). Phase C's `Ctx::split_state_sink::<T>()` and
/// friends are the disjoint-borrow escape hatch.
pub trait FromCtx {
    /// The lifetime-bound view returned by extraction. Often
    /// `&'a mut T` or a `Copy` value.
    type Target<'a>;

    /// Pull the view out of the context.
    fn from_ctx<'a>(ctx: &'a mut Ctx<'_>) -> Self::Target<'a>;
}

/// Type-keyed state map. One slot per `T: Default` registered via
/// `MonitorBuilder::state::<T>()` or first-accessed via
/// `State<T>` in a handler. Lazy-initializes on first access.
#[derive(Default)]
pub struct StateMap {
    by_type: FxHashMap<TypeId, Box<dyn Any + Send>>,
}

impl StateMap {
    /// Borrow `T` mutably, default-creating it if absent.
    ///
    /// # Panics
    ///
    /// Never — the only way `downcast_mut` returns `None` is if
    /// the `TypeId` key didn't match the box's runtime type,
    /// which is impossible because we keyed the entry by exactly
    /// `TypeId::of::<T>()`.
    pub fn get_or_init_mut<T: Default + Send + 'static>(&mut self) -> &mut T {
        let id = TypeId::of::<T>();
        self.by_type
            .entry(id)
            .or_insert_with(|| Box::<T>::default())
            .downcast_mut::<T>()
            .expect("StateMap invariant: TypeId keys to its own T")
    }

    /// Number of distinct state slots currently registered.
    /// Useful for tests + diagnostics.
    pub fn len(&self) -> usize {
        self.by_type.len()
    }

    /// `true` when no state slots are registered.
    pub fn is_empty(&self) -> bool {
        self.by_type.is_empty()
    }
}

/// Type-keyed counter registry. Each `K: Eq + Hash` registered
/// via `MonitorBuilder::counter::<K>(window, bucket)` gets one
/// preallocated [`TimeBucketedCounter<K>`].
#[derive(Default)]
pub struct CounterRegistry {
    by_type: FxHashMap<TypeId, Box<dyn Any + Send>>,
}

impl CounterRegistry {
    /// Register a counter for key type `K`. Called by
    /// `MonitorBuilder::counter::<K>(...)`.
    pub fn register<K>(&mut self, counter: TimeBucketedCounter<K>)
    where
        K: std::hash::Hash + Eq + Clone + Send + 'static,
    {
        let id = TypeId::of::<K>();
        self.by_type.insert(id, Box::new(counter));
    }

    /// Borrow the `K`-keyed counter. Panics if the user didn't
    /// register it on the builder — caught early in development;
    /// production code should pair every `Counter<K>` extractor
    /// with a matching `.counter::<K>(...)` builder call.
    pub fn get_mut<K>(&mut self) -> &mut TimeBucketedCounter<K>
    where
        K: std::hash::Hash + Eq + Clone + Send + 'static,
    {
        let id = TypeId::of::<K>();
        self.by_type
            .get_mut(&id)
            .expect("counter::<K> not registered — call .counter::<K>(...) on the builder")
            .downcast_mut::<TimeBucketedCounter<K>>()
            .expect("CounterRegistry invariant: TypeId keys to its own counter")
    }

    /// Number of distinct counter slots registered.
    pub fn len(&self) -> usize {
        self.by_type.len()
    }

    /// `true` when no counters are registered.
    pub fn is_empty(&self) -> bool {
        self.by_type.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[derive(Default)]
    struct Counter1 {
        n: u64,
    }

    #[derive(Default)]
    struct Counter2 {
        m: u32,
    }

    #[test]
    fn state_map_lazy_creates_then_returns_same() {
        let mut m = StateMap::default();
        {
            let c = m.get_or_init_mut::<Counter1>();
            c.n = 7;
        }
        let c = m.get_or_init_mut::<Counter1>();
        assert_eq!(c.n, 7);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn state_map_segregates_by_type() {
        let mut m = StateMap::default();
        m.get_or_init_mut::<Counter1>().n = 1;
        m.get_or_init_mut::<Counter2>().m = 2;
        assert_eq!(m.get_or_init_mut::<Counter1>().n, 1);
        assert_eq!(m.get_or_init_mut::<Counter2>().m, 2);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn state_map_is_empty_initially() {
        let m = StateMap::default();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn counter_registry_returns_registered() {
        let mut r = CounterRegistry::default();
        r.register::<u32>(TimeBucketedCounter::<u32>::new(
            Duration::from_secs(10),
            Duration::from_secs(1),
        ));
        let c = r.get_mut::<u32>();
        c.bump(1u32, flowscope::Timestamp::new(0, 0));
        assert!(!r.is_empty());
        assert_eq!(r.len(), 1);
    }

    #[test]
    #[should_panic(expected = "counter::<K> not registered")]
    fn counter_registry_panics_on_missing_key() {
        let mut r = CounterRegistry::default();
        let _ = r.get_mut::<u64>();
    }
}
