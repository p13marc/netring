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

    /// Borrow `T` mutably, calling `factory()` on absence. Drops the
    /// `Default` requirement of [`Self::get_or_init_mut`]. 0.21 A.4:
    /// lets the builder pre-register non-`Default` types via
    /// `MonitorBuilder::state_init::<T>(factory)`.
    ///
    /// `factory` is not called if `T` is already present; the
    /// existing instance is returned.
    pub fn get_or_init_with<T, F>(&mut self, factory: F) -> &mut T
    where
        T: Send + 'static,
        F: FnOnce() -> T,
    {
        let id = TypeId::of::<T>();
        self.by_type
            .entry(id)
            .or_insert_with(|| Box::new(factory()))
            .downcast_mut::<T>()
            .expect("StateMap invariant: TypeId keys to its own T")
    }

    /// Insert `value` as the `T` slot, overwriting any prior value.
    /// 0.21 A.4 sibling for `MonitorBuilder::state_with(...)` so
    /// caller-supplied initial state replaces the default cleanly.
    pub fn insert<T: Send + 'static>(&mut self, value: T) {
        self.by_type.insert(TypeId::of::<T>(), Box::new(value));
    }

    /// 0.22: immutable, non-creating read of the `T` slot. Returns
    /// `None` if `T` was never registered/touched. Backs
    /// [`crate::ctx::Ctx::state`] and the bandwidth/report views.
    pub fn get<T: 'static>(&self) -> Option<&T> {
        self.by_type
            .get(&TypeId::of::<T>())
            .and_then(|b| b.downcast_ref::<T>())
    }

    /// 0.22 §5.1: remove the slot keyed by `type_id` and return it
    /// boxed (the cross-shard merge worker's "hand me your `T`" probe).
    /// The shard's next `state_mut::<T>()` lazily re-creates
    /// `T::default()`, so this is a take-and-reset: each merge interval
    /// folds the delta accumulated since the previous take.
    pub fn take_dyn(&mut self, type_id: TypeId) -> Option<Box<dyn Any + Send>> {
        self.by_type.remove(&type_id)
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

/// 0.21 I.7: type-keyed map of `flowscope::correlate::FlowStateMap<T,
/// FiveTupleKey>` instances. Each `T: Default + Send + 'static`
/// registered via `MonitorBuilder::flow_state::<T>(idle_timeout)`
/// gets a slot keyed on `TypeId::of::<T>()`. The slot's
/// `FlowStateMap` lazy-creates per-flow `T::default()` instances
/// on first access.
#[derive(Default)]
pub struct FlowStateRegistry {
    by_type: FxHashMap<TypeId, Box<dyn Any + Send>>,
}

impl FlowStateRegistry {
    /// Register a flow-state slot for `T`. Replaces any prior
    /// registration for the same `T`.
    pub fn register<T>(&mut self, idle_timeout: std::time::Duration)
    where
        T: Default + Send + 'static,
    {
        let map: flowscope::correlate::FlowStateMap<T, flowscope::extract::FiveTupleKey> =
            flowscope::correlate::FlowStateMap::new(idle_timeout);
        self.by_type.insert(TypeId::of::<T>(), Box::new(map));
    }

    /// Borrow the `T`-typed `FlowStateMap` mutably. Returns
    /// `None` if `T` was never registered (the user forgot
    /// `MonitorBuilder::flow_state::<T>(...)`).
    pub fn get_mut<T>(
        &mut self,
    ) -> Option<&mut flowscope::correlate::FlowStateMap<T, flowscope::extract::FiveTupleKey>>
    where
        T: Default + Send + 'static,
    {
        self.by_type
            .get_mut(&TypeId::of::<T>())
            .and_then(|b| b.downcast_mut())
    }

    /// `true` when any flow-state slot is registered.
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
    /// 0.21 A.6: parallel name index for build-time validation.
    /// `MonitorBuilder::build()` consults this to spot detectors
    /// declaring counter types that were never registered. Stored
    /// as a `Vec<&'static str>` rather than a set because the
    /// validation walk is one-off and N is tiny (≤ 16 in practice).
    registered_type_names: Vec<&'static str>,
}

impl CounterRegistry {
    /// Register a counter for key type `K`. Called by
    /// `MonitorBuilder::counter::<K>(...)`.
    pub fn register<K>(&mut self, counter: TimeBucketedCounter<K>)
    where
        K: std::hash::Hash + Eq + Clone + Send + 'static,
    {
        let id = TypeId::of::<K>();
        let name = std::any::type_name::<K>();
        if !self.registered_type_names.contains(&name) {
            self.registered_type_names.push(name);
        }
        self.by_type.insert(id, Box::new(counter));
    }

    /// 0.21 A.6: the slugs of every counter `K` registered, in
    /// `std::any::type_name::<K>()` form. Used by
    /// `MonitorBuilder::build()` to validate detector declarations.
    pub fn registered_type_names(&self) -> &[&'static str] {
        &self.registered_type_names
    }

    /// 0.22: immutable, non-panicking read of the `K`-keyed counter.
    /// Returns `None` if unregistered (sibling to the panicking
    /// [`Self::get_mut`]). Backs [`crate::ctx::Ctx::counter`] +
    /// the report snapshot accessors.
    pub fn get<K>(&self) -> Option<&TimeBucketedCounter<K>>
    where
        K: std::hash::Hash + Eq + Clone + Send + 'static,
    {
        self.by_type
            .get(&TypeId::of::<K>())
            .and_then(|b| b.downcast_ref::<TimeBucketedCounter<K>>())
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
    fn take_dyn_removes_slot_and_downcasts() {
        // 0.22 §5.1: the merge worker's take-and-reset probe.
        let mut m = StateMap::default();
        m.get_or_init_mut::<Counter1>().n = 42;
        let taken = m.take_dyn(std::any::TypeId::of::<Counter1>());
        assert_eq!(taken.unwrap().downcast::<Counter1>().unwrap().n, 42);
        assert!(m.is_empty()); // slot removed
        // A second take finds nothing.
        assert!(m.take_dyn(std::any::TypeId::of::<Counter1>()).is_none());
    }

    #[test]
    fn counter_registry_returns_registered() {
        let mut r = CounterRegistry::default();
        r.register::<u32>(TimeBucketedCounter::<u32>::new_unbounded(
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
