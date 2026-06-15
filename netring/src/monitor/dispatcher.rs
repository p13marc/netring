//! `TypeId`-keyed handler dispatcher.
//!
//! Built once at monitor-build time by
//! [`super::registry::HandlerRegistry::into_dispatcher`]; then
//! drained per-event in the run loop. Dispatch is one
//! [`TypeId`] scan over a small inline table (≤16 entries) +
//! one slice index — no hashing on the hot path.

use std::any::TypeId;
use std::sync::Arc;

use arrayvec::ArrayVec;
use rustc_hash::FxHashMap;

use crate::ctx::Ctx;
use crate::error::Result;
use crate::monitor::async_handler::BoxFuture;

/// Hard cap on distinct event-payload types per monitor — the slot-index
/// width (`u16`). Effectively unbounded for any realistic monitor; the
/// build returns [`BuildError::TooManyEventTypes`](crate::error::BuildError)
/// only past this.
///
/// 0.25-B2 lifted the old hard cap of 16: the first `INLINE_EVENT_TYPES`
/// live in a no-hash inline table (the common case, zero hot-path cost);
/// beyond that the table spills to a hash map.
pub const MAX_EVENT_TYPES: usize = u16::MAX as usize;

/// Event types kept in the inline (linear-scan, no-hashing) lookup table
/// before the dispatcher spills to a hash map. Covers any realistic
/// detector with zero hot-path hashing.
const INLINE_EVENT_TYPES: usize = 16;

/// `TypeId` → slot-index lookup. Inline linear scan for the common
/// ≤`INLINE_EVENT_TYPES` case (no hashing on the hot path); spills to a
/// hash map beyond that so there's no hard ceiling (0.25-B2).
// One instance per Dispatcher (not in a Vec / not on a per-event path), and
// the `Inline` arm's size IS the point — boxing it would reintroduce the
// indirection this avoids. So the size asymmetry with `Spilled` is fine.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub(crate) enum TypeSlotTable {
    Inline(ArrayVec<(TypeId, u16), INLINE_EVENT_TYPES>),
    Spilled(FxHashMap<TypeId, u16>),
}

impl TypeSlotTable {
    pub(crate) fn new() -> Self {
        TypeSlotTable::Inline(ArrayVec::new())
    }

    /// Resolve a payload `TypeId` to its slot index, if registered.
    #[inline]
    pub(crate) fn get(&self, ty: TypeId) -> Option<u16> {
        match self {
            TypeSlotTable::Inline(v) => v.iter().copied().find(|(t, _)| *t == ty).map(|(_, i)| i),
            TypeSlotTable::Spilled(m) => m.get(&ty).copied(),
        }
    }

    /// Record `ty → idx`. Migrates inline → spilled on overflow.
    pub(crate) fn insert(&mut self, ty: TypeId, idx: u16) {
        match self {
            TypeSlotTable::Inline(v) => {
                if v.try_push((ty, idx)).is_err() {
                    // The 17th type spills the whole table into a hash map.
                    let mut m: FxHashMap<TypeId, u16> = v.iter().copied().collect();
                    m.insert(ty, idx);
                    *self = TypeSlotTable::Spilled(m);
                }
            }
            TypeSlotTable::Spilled(m) => {
                m.insert(ty, idx);
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            TypeSlotTable::Inline(v) => v.len(),
            TypeSlotTable::Spilled(m) => m.len(),
        }
    }
}

/// Type-erased shared handler. The raw payload pointer at call
/// time is keyed by [`TypeId`] in the dispatcher table; the
/// payload's runtime type matches `E::Payload` for the slot the
/// handler was registered into (registry invariant).
///
/// `Arc<dyn Fn + Send + Sync>` lets Phase C's `Dispatcher::clone_for_shard`
/// hand out per-shard dispatchers cheaply — refcount bump per slot,
/// not a deep clone. The blanket impls in `handler.rs` already require
/// `F: Fn + Send + Sync + 'static`; the trampoline closure in
/// `registry::HandlerRegistry::register` calls `handler.call(&self, …)`
/// so the trampoline is naturally `Fn`. Previously stored as
/// `Box<dyn FnMut + Send>` — unnecessarily restrictive.
pub(crate) type BoxedHandler = Arc<dyn Fn(*const (), &mut Ctx<'_>) -> Result<()> + Send + Sync>;

/// Async dispatch trampoline. The user's typed
/// `AsyncHandler<E>` is wrapped in an `AsyncHandlerWrapper` that
/// erases `E` and implements [`DynAsyncHandler`]. The wrapper's
/// `call` casts the type-erased payload pointer back to
/// `&E::Payload` and produces a 'static-future from the user's
/// closure (the closure must own anything it `.await`s on).
pub(crate) trait DynAsyncHandler: Send + Sync {
    /// SAFETY contract — see [`super::registry::HandlerRegistry::register_async`].
    /// `ptr` must point at a `E::Payload` of the same TypeId used
    /// at registration.
    fn call(&self, ptr: *const ()) -> BoxFuture<Result<()>>;
}

/// Shared async handler — same Arc shape as [`BoxedHandler`] for
/// per-shard cloning (Phase C).
pub(crate) type BoxedAsyncHandler = Arc<dyn DynAsyncHandler>;

/// 0.25-B1 effect dispatch trampoline. Erases `E` like
/// [`DynAsyncHandler`], but the call **reads `&Ctx`** (synchronously, to
/// build the future) and the future resolves to [`Effects`] the run loop
/// applies after the batch.
pub(crate) trait DynEffectHandler: Send + Sync {
    /// `ptr` must point at a `E::Payload` of the same TypeId used at
    /// registration. `ctx` is borrowed only for the synchronous prologue;
    /// the returned future is `'static` and must not capture it.
    fn call(
        &self,
        ptr: *const (),
        ctx: &Ctx<'_>,
    ) -> BoxFuture<Result<crate::monitor::effect::Effects>>;
}

/// Shared effect handler — Arc shape for per-shard cloning.
pub(crate) type BoxedEffectHandler = Arc<dyn DynEffectHandler>;

pub(crate) struct HandlerSlot {
    pub(crate) handler: BoxedHandler,
}

pub(crate) struct AsyncHandlerSlot {
    pub(crate) handler: BoxedAsyncHandler,
}

pub(crate) struct EffectHandlerSlot {
    pub(crate) handler: BoxedEffectHandler,
}

/// The build-time-finalized dispatcher. Constructed via
/// [`super::registry::HandlerRegistry::into_dispatcher`].
///
/// `Debug` skips the boxed closure bodies — it just prints the
/// slot table shape so test failures stay readable.
pub struct Dispatcher {
    /// `TypeId::of::<E::Payload>()` → slot index. Inline ≤16, spills beyond.
    /// One row covers both sync and async handlers for the same event type
    /// (parallel slot vectors below).
    slot_by_type: TypeSlotTable,
    /// Slot table — sync handlers grouped by payload type.
    slots: Box<[Vec<HandlerSlot>]>,
    /// Slot table — async handlers grouped by payload type, in
    /// lockstep with `slots`. Both vectors are indexed by the same
    /// `slot_by_type` lookup.
    async_slots: Box<[Vec<AsyncHandlerSlot>]>,
    /// Slot table — 0.25-B1 effect handlers, in lockstep with `slots`.
    effect_slots: Box<[Vec<EffectHandlerSlot>]>,
    /// 0.25-B2 type-tag: `slot index → registered TypeId`, parallel to
    /// `slots`. Read only by the `debug_assertions` check in dispatch — it
    /// proves the `slot_by_type` → `slots` mapping stays consistent (a build
    /// bug routing a type to the wrong slot would make the type-erased
    /// `*const ()` cast in a handler UB). Built once; a `Box<[TypeId]>` of
    /// `type_count` entries (negligible), so it's stored unconditionally to
    /// keep the constructor signature cfg-free.
    #[allow(dead_code)] // read only under debug_assertions
    slot_types: Box<[TypeId]>,
}

impl Dispatcher {
    pub(crate) fn new(
        slot_by_type: TypeSlotTable,
        slots: Box<[Vec<HandlerSlot>]>,
        async_slots: Box<[Vec<AsyncHandlerSlot>]>,
        effect_slots: Box<[Vec<EffectHandlerSlot>]>,
        slot_types: Box<[TypeId]>,
    ) -> Self {
        Self {
            slot_by_type,
            slots,
            async_slots,
            effect_slots,
            slot_types,
        }
    }

    /// Dispatch the typed payload `P` through all registered
    /// handlers for that event type. Unknown payload types are a
    /// no-op (no error) — a handler simply hasn't been registered
    /// for that event.
    ///
    /// Stops on the first handler error and returns it. Other
    /// handlers for the same event are skipped — Phase D will add
    /// a retry/catch layer.
    #[inline]
    pub fn dispatch<P: 'static>(&mut self, payload: &P, ctx: &mut Ctx<'_>) -> Result<()> {
        let target = TypeId::of::<P>();
        let Some(slot_idx) = self.slot_by_type.get(target) else {
            return Ok(());
        };
        // 0.25-B2: in debug, prove the slot index really maps to `target`
        // before we hand a `*const P` to handlers registered for that slot.
        #[cfg(debug_assertions)]
        debug_assert_eq!(
            self.slot_types[slot_idx as usize], target,
            "dispatcher slot/type desync — type-erased cast would be UB"
        );

        let ptr = payload as *const P as *const ();
        for slot in &mut self.slots[slot_idx as usize] {
            (slot.handler)(ptr, ctx)?;
        }
        Ok(())
    }

    /// Dispatch async handlers for the typed payload `P`.
    ///
    /// The future resolves once *all* registered async handlers
    /// for this event type have run to completion. Stops on the
    /// first handler error (same short-circuit semantics as
    /// [`Self::dispatch`]).
    ///
    /// Each async handler boxes its future; that allocation is
    /// the documented cost of `MonitorBuilder::on_async`.
    ///
    /// # `Send` run loop
    ///
    /// The type-erased payload pointer (`*const ()`) is `!Send`, so
    /// it must **never be held across an `.await`** — otherwise the
    /// enclosing run-loop future becomes `!Send` and
    /// `Monitor::run_for(..)` could not be `tokio::spawn`'d. Each
    /// handler future is therefore constructed *before* any await,
    /// inside a block that confines the pointer; the resulting boxed
    /// futures are `'static + Send` (see [`AsyncHandler`]) and don't
    /// borrow the payload, so they are safe to await afterwards.
    ///
    /// [`AsyncHandler`]: crate::monitor::AsyncHandler
    ///
    /// The 0- and 1-handler cases (the overwhelming majority) take
    /// allocation-free fast paths, preserving the dhat Δ0 invariant
    /// for monitors without async handlers.
    pub async fn dispatch_async<P: 'static>(&mut self, payload: &P) -> Result<()> {
        let target = TypeId::of::<P>();
        let Some(slot_idx) = self.slot_by_type.get(target) else {
            return Ok(());
        };
        #[cfg(debug_assertions)]
        debug_assert_eq!(
            self.slot_types[slot_idx as usize], target,
            "dispatcher slot/type desync — type-erased cast would be UB"
        );

        let slots = &self.async_slots[slot_idx as usize];
        match slots.len() {
            // No async handlers for this type: nothing to await, no
            // allocation. This is the hot path for the common case
            // where a type has only sync handlers.
            0 => Ok(()),
            // Exactly one handler: build its future in a block that
            // drops the `*const ()` before the await, then await.
            // Exact one-at-a-time semantics, zero allocation.
            1 => {
                let fut = {
                    let ptr = payload as *const P as *const ();
                    slots[0].handler.call(ptr)
                };
                fut.await
            }
            // Two or more handlers (rare): construct every future up
            // front while the pointer is in scope, then await each in
            // order. The `Vec` is the only allocation and only occurs
            // on this uncommon multi-async-handler path.
            _ => {
                let mut futures: Vec<BoxFuture<Result<()>>> = Vec::with_capacity(slots.len());
                {
                    let ptr = payload as *const P as *const ();
                    for slot in slots.iter() {
                        futures.push(slot.handler.call(ptr));
                    }
                }
                for fut in futures {
                    fut.await?;
                }
                Ok(())
            }
        }
    }

    /// 0.25-B1: dispatch effect handlers for the typed payload `P`.
    ///
    /// Two phases: build every handler's future while holding only an
    /// **immutable** `&Ctx` + the `*const ()` payload pointer (both confined to
    /// the build block so neither crosses an `.await`), then await each and
    /// **apply its [`Effects`]** with `&mut Ctx`. The futures are `'static`
    /// (they own what they `move`d out of `Ctx`).
    ///
    /// `&mut Ctx` IS held across the `.await` in the apply phase (to write the
    /// effects to the sink). That is `Send`-safe only because every `Ctx` field
    /// is `Send` — see `effect.rs` for the invariant. What must *not* cross the
    /// await is the type-erased `*const ()` (it isn't — it's scoped to phase 1).
    ///
    /// [`Effects`]: crate::monitor::effect::Effects
    pub async fn dispatch_effects<P: 'static>(
        &mut self,
        payload: &P,
        ctx: &mut Ctx<'_>,
    ) -> Result<()> {
        let target = TypeId::of::<P>();
        let Some(slot_idx) = self.slot_by_type.get(target) else {
            return Ok(());
        };
        #[cfg(debug_assertions)]
        debug_assert_eq!(
            self.slot_types[slot_idx as usize], target,
            "dispatcher slot/type desync — type-erased cast would be UB"
        );

        if self.effect_slots[slot_idx as usize].is_empty() {
            return Ok(());
        }

        // PHASE 1 (read): build the futures under an immutable `&ctx`
        // borrow + the type-erased pointer, both confined to this block.
        let mut futures: Vec<BoxFuture<Result<crate::monitor::effect::Effects>>> =
            Vec::with_capacity(self.effect_slots[slot_idx as usize].len());
        {
            let ptr = payload as *const P as *const ();
            for slot in &self.effect_slots[slot_idx as usize] {
                futures.push(slot.handler.call(ptr, &*ctx));
            }
        }

        // PHASE 2 (await + write): no `&ctx`/`ptr` borrow is live here.
        for fut in futures {
            let effects = fut.await?;
            if !effects.is_empty() {
                effects.apply(&mut *ctx.sink);
            }
        }
        Ok(())
    }

    /// Clone this dispatcher for use in a per-CPU shard (Phase C).
    /// Each handler slot stores `Arc<dyn Fn>` so cloning is a
    /// refcount bump per slot — O(slots × handlers), practically free.
    /// The slot table (`ArrayVec<TypeId>`) is a deep `Copy`; the
    /// outer `Vec<HandlerSlot>` is rebuilt with refcounted handlers.
    ///
    /// Allowed dead until Phase C wires sharding; the test below
    /// exercises the path. `#[allow(dead_code)]` is removed at C.4.
    #[allow(dead_code)]
    pub(crate) fn clone_for_shard(&self) -> Self {
        Self {
            slot_by_type: self.slot_by_type.clone(),
            slots: self
                .slots
                .iter()
                .map(|v| {
                    v.iter()
                        .map(|s| HandlerSlot {
                            handler: Arc::clone(&s.handler),
                        })
                        .collect()
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            async_slots: self
                .async_slots
                .iter()
                .map(|v| {
                    v.iter()
                        .map(|s| AsyncHandlerSlot {
                            handler: Arc::clone(&s.handler),
                        })
                        .collect()
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            effect_slots: self
                .effect_slots
                .iter()
                .map(|v| {
                    v.iter()
                        .map(|s| EffectHandlerSlot {
                            handler: Arc::clone(&s.handler),
                        })
                        .collect()
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            slot_types: self.slot_types.clone(),
        }
    }

    /// Number of distinct event types registered. Useful for tests.
    pub fn type_count(&self) -> usize {
        self.slot_by_type.len()
    }

    /// Total handler count across all slots.
    pub fn handler_count(&self) -> usize {
        self.slots.iter().map(|s| s.len()).sum()
    }

    /// Total async handler count across all slots.
    pub fn async_handler_count(&self) -> usize {
        self.async_slots.iter().map(|s| s.len()).sum()
    }

    /// Total effect handler count across all slots (0.25-B1).
    pub fn effect_handler_count(&self) -> usize {
        self.effect_slots.iter().map(|s| s.len()).sum()
    }
}

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher")
            .field("type_count", &self.type_count())
            .field("handler_count", &self.handler_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use flowscope::Timestamp;

    use super::*;
    use crate::anomaly::sink::NoopSink;
    use crate::ctx::{CounterRegistry, SourceIdx, StateMap};

    fn fresh_ctx<'a>(
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
        }
    }

    #[test]
    fn clone_for_shard_produces_independent_dispatcher_sharing_handlers() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicU32, Ordering};

        // Shared counter — both shards' Arc<dyn Fn> closures point
        // at the same underlying Arc<AtomicU32>, so dispatches from
        // either shard increment the same counter.
        let count = StdArc::new(AtomicU32::new(0));
        let count_h = StdArc::clone(&count);

        let handler: BoxedHandler = Arc::new(move |_ptr, _ctx| {
            count_h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });

        let mut slot_by_type = TypeSlotTable::new();
        slot_by_type.insert(TypeId::of::<u32>(), 0);
        let slots = vec![vec![HandlerSlot { handler }]].into_boxed_slice();
        let async_slots = vec![vec![]].into_boxed_slice();
        let effect_slots = vec![vec![]].into_boxed_slice();
        let slot_types = vec![TypeId::of::<u32>()].into_boxed_slice();
        let primary = Dispatcher::new(slot_by_type, slots, async_slots, effect_slots, slot_types);

        // Clone for a hypothetical shard.
        let mut shard = primary.clone_for_shard();
        let mut primary = primary; // primary dispatcher must remain usable
        assert_eq!(primary.type_count(), 1);
        assert_eq!(shard.type_count(), 1);
        assert_eq!(primary.handler_count(), 1);
        assert_eq!(shard.handler_count(), 1);

        let payload: u32 = 42;
        let mut s = StateMap::default();
        let mut sink = NoopSink;
        let mut c = CounterRegistry::default();
        let mut fs = crate::ctx::FlowStateRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut sink, &mut c, &mut fs);

        primary.dispatch::<u32>(&payload, &mut ctx).unwrap();
        shard.dispatch::<u32>(&payload, &mut ctx).unwrap();
        shard.dispatch::<u32>(&payload, &mut ctx).unwrap();

        // 1 primary + 2 shard = 3
        assert_eq!(count.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn type_slot_table_stays_inline_then_spills_preserving_lookups() {
        // Distinct TypeIds via distinct unit types. Use primitive arrays of
        // increasing size so each has a unique TypeId.
        let mut t = TypeSlotTable::new();
        let tys: [TypeId; 4] = [
            TypeId::of::<u8>(),
            TypeId::of::<u16>(),
            TypeId::of::<u32>(),
            TypeId::of::<u64>(),
        ];
        for (i, ty) in tys.iter().enumerate() {
            t.insert(*ty, i as u16);
        }
        assert!(matches!(t, TypeSlotTable::Inline(_)), "≤16 stays inline");
        for (i, ty) in tys.iter().enumerate() {
            assert_eq!(t.get(*ty), Some(i as u16));
        }
        assert_eq!(t.get(TypeId::of::<i8>()), None);
        assert_eq!(t.len(), 4);

        // Fill past the inline cap (16) to force a spill, keeping earlier
        // entries resolvable. Reuse a fresh table with 17 synthetic types.
        let mut big = TypeSlotTable::new();
        fn synth_ty(n: usize) -> TypeId {
            // 17 distinct concrete types → 17 distinct TypeIds.
            const TYS: [fn() -> TypeId; 17] = [
                || TypeId::of::<[u8; 0]>(),
                || TypeId::of::<[u8; 1]>(),
                || TypeId::of::<[u8; 2]>(),
                || TypeId::of::<[u8; 3]>(),
                || TypeId::of::<[u8; 4]>(),
                || TypeId::of::<[u8; 5]>(),
                || TypeId::of::<[u8; 6]>(),
                || TypeId::of::<[u8; 7]>(),
                || TypeId::of::<[u8; 8]>(),
                || TypeId::of::<[u8; 9]>(),
                || TypeId::of::<[u8; 10]>(),
                || TypeId::of::<[u8; 11]>(),
                || TypeId::of::<[u8; 12]>(),
                || TypeId::of::<[u8; 13]>(),
                || TypeId::of::<[u8; 14]>(),
                || TypeId::of::<[u8; 15]>(),
                || TypeId::of::<[u8; 16]>(),
            ];
            TYS[n]()
        }
        for i in 0..17 {
            big.insert(synth_ty(i), i as u16);
        }
        assert!(matches!(big, TypeSlotTable::Spilled(_)), "17 spills to map");
        assert_eq!(big.len(), 17);
        // Both an early (inline-era) and the spilled entry resolve.
        assert_eq!(big.get(synth_ty(0)), Some(0));
        assert_eq!(big.get(synth_ty(16)), Some(16));
    }

    #[test]
    fn empty_dispatch_is_noop() {
        let mut d = Dispatcher::new(
            TypeSlotTable::new(),
            Vec::new().into_boxed_slice(),
            Vec::new().into_boxed_slice(),
            Vec::new().into_boxed_slice(),
            Vec::new().into_boxed_slice(),
        );
        let mut s = StateMap::default();
        let mut k = NoopSink;
        let mut c = CounterRegistry::default();
        let mut fs = crate::ctx::FlowStateRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut k, &mut c, &mut fs);

        // Dispatch a payload nobody registered for — no error.
        let payload: u32 = 7;
        assert!(d.dispatch::<u32>(&payload, &mut ctx).is_ok());
        assert_eq!(d.type_count(), 0);
        assert_eq!(d.handler_count(), 0);
    }

    #[test]
    fn dispatch_routes_to_matching_slot_only() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let u32_count = Arc::new(AtomicU32::new(0));
        let u64_count = Arc::new(AtomicU32::new(0));

        let u32_count_h = Arc::clone(&u32_count);
        let u64_count_h = Arc::clone(&u64_count);

        let u32_handler: BoxedHandler = Arc::new(move |ptr, _ctx| {
            // SAFETY: dispatcher only invokes this for TypeId::of::<u32>() slot.
            let _val: u32 = unsafe { *(ptr as *const u32) };
            u32_count_h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        let u64_handler: BoxedHandler = Arc::new(move |ptr, _ctx| {
            let _val: u64 = unsafe { *(ptr as *const u64) };
            u64_count_h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });

        let mut slot_by_type = TypeSlotTable::new();
        slot_by_type.insert(TypeId::of::<u32>(), 0);
        slot_by_type.insert(TypeId::of::<u64>(), 1);
        let slots: Box<[Vec<HandlerSlot>]> = vec![
            vec![HandlerSlot {
                handler: u32_handler,
            }],
            vec![HandlerSlot {
                handler: u64_handler,
            }],
        ]
        .into_boxed_slice();
        let async_slots: Box<[Vec<AsyncHandlerSlot>]> =
            vec![Vec::new(), Vec::new()].into_boxed_slice();
        let effect_slots: Box<[Vec<EffectHandlerSlot>]> =
            vec![Vec::new(), Vec::new()].into_boxed_slice();
        let slot_types = vec![TypeId::of::<u32>(), TypeId::of::<u64>()].into_boxed_slice();
        let mut d = Dispatcher::new(slot_by_type, slots, async_slots, effect_slots, slot_types);

        let mut s = StateMap::default();
        let mut k = NoopSink;
        let mut c = CounterRegistry::default();
        let mut fs = crate::ctx::FlowStateRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut k, &mut c, &mut fs);

        let u32_payload: u32 = 7;
        d.dispatch::<u32>(&u32_payload, &mut ctx).unwrap();
        assert_eq!(u32_count.load(Ordering::Relaxed), 1);
        assert_eq!(u64_count.load(Ordering::Relaxed), 0);

        let u64_payload: u64 = 13;
        d.dispatch::<u64>(&u64_payload, &mut ctx).unwrap();
        assert_eq!(u32_count.load(Ordering::Relaxed), 1);
        assert_eq!(u64_count.load(Ordering::Relaxed), 1);

        assert_eq!(d.type_count(), 2);
        assert_eq!(d.handler_count(), 2);
    }
}
