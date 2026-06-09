//! `TypeId`-keyed handler dispatcher.
//!
//! Built once at monitor-build time by
//! [`super::registry::HandlerRegistry::into_dispatcher`]; then
//! drained per-event in the run loop. Dispatch is one
//! [`TypeId`] scan over a small inline table (≤16 entries) +
//! one slice index — no hashing on the hot path.

use std::any::TypeId;

use arrayvec::ArrayVec;

use crate::ctx::Ctx;
use crate::error::Result;

/// Maximum distinct event-payload types per monitor.
///
/// Sized so the `ArrayVec` lookup stays inline / branch-predictable.
/// In practice 4–8 covers any realistic detector; raising this
/// later is backwards-compatible.
pub const MAX_EVENT_TYPES: usize = 16;

/// Type-erased boxed handler. The raw payload pointer at call
/// time is keyed by [`TypeId`] in the dispatcher table; the
/// payload's runtime type matches `E::Payload` for the slot the
/// handler was registered into (registry invariant).
///
/// `FnMut` so handler state can be captured by-value (a closure
/// that mutates its environment). The Handler trait itself takes
/// `&self`, so the boxed closure body uses `&handler.call(...)`,
/// but the box must hold the `FnMut` capture pattern to keep
/// future flexibility.
pub(crate) type BoxedHandler = Box<dyn FnMut(*const (), &mut Ctx<'_>) -> Result<()> + Send>;

pub(crate) struct HandlerSlot {
    pub(crate) handler: BoxedHandler,
}

/// The build-time-finalized dispatcher. Constructed via
/// [`super::registry::HandlerRegistry::into_dispatcher`].
///
/// `Debug` skips the boxed closure bodies — it just prints the
/// slot table shape so test failures stay readable.
pub struct Dispatcher {
    /// `TypeId::of::<E::Payload>()` → u8 slot index. ≤ MAX_EVENT_TYPES entries.
    slot_by_type: ArrayVec<(TypeId, u8), MAX_EVENT_TYPES>,
    /// Slot table — handlers grouped by payload type.
    slots: Box<[Vec<HandlerSlot>]>,
}

impl Dispatcher {
    pub(crate) fn new(
        slot_by_type: ArrayVec<(TypeId, u8), MAX_EVENT_TYPES>,
        slots: Box<[Vec<HandlerSlot>]>,
    ) -> Self {
        Self {
            slot_by_type,
            slots,
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
        let Some((_, slot_idx)) = self
            .slot_by_type
            .iter()
            .copied()
            .find(|(t, _)| *t == target)
        else {
            return Ok(());
        };

        let ptr = payload as *const P as *const ();
        for slot in &mut self.slots[slot_idx as usize] {
            (slot.handler)(ptr, ctx)?;
        }
        Ok(())
    }

    /// Number of distinct event types registered. Useful for tests.
    pub fn type_count(&self) -> usize {
        self.slot_by_type.len()
    }

    /// Total handler count across all slots.
    pub fn handler_count(&self) -> usize {
        self.slots.iter().map(|s| s.len()).sum()
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
    fn empty_dispatch_is_noop() {
        let mut d = Dispatcher::new(ArrayVec::new(), Vec::new().into_boxed_slice());
        let mut s = StateMap::default();
        let mut k = NoopSink;
        let mut c = CounterRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut k, &mut c);

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

        let u32_handler: BoxedHandler = Box::new(move |ptr, _ctx| {
            // SAFETY: dispatcher only invokes this for TypeId::of::<u32>() slot.
            let _val: u32 = unsafe { *(ptr as *const u32) };
            u32_count_h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        let u64_handler: BoxedHandler = Box::new(move |ptr, _ctx| {
            let _val: u64 = unsafe { *(ptr as *const u64) };
            u64_count_h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });

        let mut slot_by_type = ArrayVec::new();
        slot_by_type.push((TypeId::of::<u32>(), 0));
        slot_by_type.push((TypeId::of::<u64>(), 1));
        let slots: Box<[Vec<HandlerSlot>]> = vec![
            vec![HandlerSlot {
                handler: u32_handler,
            }],
            vec![HandlerSlot {
                handler: u64_handler,
            }],
        ]
        .into_boxed_slice();
        let mut d = Dispatcher::new(slot_by_type, slots);

        let mut s = StateMap::default();
        let mut k = NoopSink;
        let mut c = CounterRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut k, &mut c);

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
