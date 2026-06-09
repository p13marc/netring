//! Storage maps that back [`crate::ctx::Ctx`]'s typed accessors.
//!
//! [`StateMap`] holds per-monitor user state keyed by `TypeId`.
//! [`CounterRegistry`] holds pre-registered
//! [`TimeBucketedCounter`](crate::correlate::TimeBucketedCounter)s
//! by their key-type's `TypeId`.
//!
//! Both are `pub` so [`crate::monitor::MonitorBuilder`] can
//! prepopulate them; the live access path (from inside a handler)
//! is the `Ctx::state_mut` / `Ctx::counter_mut` methods.

use std::any::{Any, TypeId};

use rustc_hash::FxHashMap;

use crate::correlate::TimeBucketedCounter;

/// Type-keyed state map. One slot per `T: Default` registered via
/// `MonitorBuilder::state::<T>()` or first-accessed via
/// `Ctx::state_mut::<T>()`. Lazy-initializes on first access.
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
    pub fn len(&self) -> usize {
        self.by_type.len()
    }

    /// `true` when no state slots are registered.
    pub fn is_empty(&self) -> bool {
        self.by_type.is_empty()
    }
}

/// Type-keyed counter registry. Each `K: Hash + Eq + Clone`
/// registered via `MonitorBuilder::counter::<K>(window, bucket)`
/// gets one preallocated [`TimeBucketedCounter<K>`].
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
    /// register it on the builder.
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
        m.get_or_init_mut::<Counter1>().n = 7;
        assert_eq!(m.get_or_init_mut::<Counter1>().n, 7);
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
