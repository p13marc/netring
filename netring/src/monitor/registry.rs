//! Build-time handler + protocol registries.
//!
//! [`HandlerRegistry`] collects boxed handlers under
//! `TypeId::of::<E::Payload>()` keys; at build time it freezes
//! into a [`super::dispatcher::Dispatcher`].
//!
//! [`TypedProtocolSlot<P>`] wraps a flowscope
//! [`SlotHandle<P::Message, FiveTupleKey>`] and drains it into
//! the dispatcher each run-loop iteration. The trait object
//! [`ProtocolSlot`] hides the generic over `P` so the run loop
//! can hold a `Vec<Box<dyn ProtocolSlot>>` of mixed protocols.

use std::any::TypeId;
use std::marker::PhantomData;
use std::sync::Arc;

use arrayvec::ArrayVec;
use flowscope::driver::{SlotHandle, SlotMessage};
use rustc_hash::FxHashMap;

use crate::ctx::Ctx;
use crate::error::Result as NetringResult;
use crate::error::{BuildError, Result};
use crate::monitor::async_handler::{AsyncHandler, BoxFuture};
use crate::monitor::dispatcher::{
    AsyncHandlerSlot, BoxedAsyncHandler, BoxedHandler, Dispatcher, DynAsyncHandler, HandlerSlot,
    MAX_EVENT_TYPES,
};
use crate::monitor::handler::Handler;
use crate::protocol::Protocol;
use crate::protocol::event_typed::Event;

/// Build-time bag of boxed handlers, grouped by event-payload TypeId.
#[derive(Default)]
pub struct HandlerRegistry {
    by_type: FxHashMap<TypeId, Vec<BoxedHandler>>,
    async_by_type: FxHashMap<TypeId, Vec<BoxedAsyncHandler>>,
    /// 0.21 D.1: for each registered event-payload TypeId, the
    /// `Protocol` marker TypeId + stable name that the event
    /// REQUIRES on the builder's `.protocol::<P>()` list — gathered
    /// at register time via [`crate::protocol::event_typed::Event::protocol_marker`].
    /// Events that don't need a slot (`Tick`, lifecycle events,
    /// `AnyFlowAnomaly`) are absent from the map.
    /// `MonitorBuilder::build` consults this map alongside its
    /// declared-protocol set to surface
    /// `BuildError::HandlerForUnregisteredProtocol`.
    required_protocols: FxHashMap<TypeId, (TypeId, &'static str)>,
}

impl HandlerRegistry {
    /// Add a handler `H` for event type `E`.
    ///
    /// The handler is boxed and stored under
    /// `TypeId::of::<E::Payload>()`. At dispatch time the boxed
    /// closure casts the raw payload pointer back to
    /// `&E::Payload` and calls `H::call(&typed_payload, ctx)`.
    pub fn register<E, H, M>(&mut self, handler: H)
    where
        E: Event,
        H: Handler<E, M>,
        M: 'static,
    {
        let boxed: BoxedHandler = Arc::new(move |ptr, ctx| {
            // SAFETY: Soundness contract — `HandlerRegistry` only
            // inserts handlers keyed by
            // `TypeId::of::<E::Payload>()`, and the dispatcher
            // (see `Dispatcher::dispatch`) only invokes a slot
            // when the runtime payload type matches that key. So
            // `ptr` is a `*const E::Payload` here.
            let typed: &E::Payload = unsafe { &*(ptr as *const E::Payload) };
            handler.call(typed, ctx)
        });
        self.by_type
            .entry(TypeId::of::<E::Payload>())
            .or_default()
            .push(boxed);
        if let Some(p_id) = E::protocol_marker() {
            self.required_protocols
                .entry(TypeId::of::<E::Payload>())
                .or_insert((p_id, E::protocol_name()));
        }
    }

    /// Add an async handler `H` for event type `E`.
    ///
    /// Each dispatch produces one boxed future per async handler;
    /// prefer the sync [`Self::register`] when the handler body
    /// doesn't actually `.await`.
    pub fn register_async<E, H>(&mut self, handler: H)
    where
        E: Event,
        H: AsyncHandler<E>,
    {
        let boxed: BoxedAsyncHandler = Arc::new(AsyncHandlerWrapper::<E, H>::new(handler));
        self.async_by_type
            .entry(TypeId::of::<E::Payload>())
            .or_default()
            .push(boxed);
        if let Some(p_id) = E::protocol_marker() {
            self.required_protocols
                .entry(TypeId::of::<E::Payload>())
                .or_insert((p_id, E::protocol_name()));
        }
    }

    /// 0.21 D.1: returns an iterator over `(protocol_TypeId, protocol_name)`
    /// pairs that handlers required during registration. Each unique
    /// (event_type → marker) pair appears once. Consumed by
    /// `MonitorBuilder::build` to validate against the declared
    /// protocol set.
    pub fn required_protocols(&self) -> impl Iterator<Item = (TypeId, &'static str)> + '_ {
        self.required_protocols.values().copied()
    }

    /// Number of distinct event types registered (sync + async
    /// combined; a type that has both kinds counts once).
    pub fn type_count(&self) -> usize {
        let mut ids: std::collections::HashSet<TypeId> = std::collections::HashSet::new();
        ids.extend(self.by_type.keys().copied());
        ids.extend(self.async_by_type.keys().copied());
        ids.len()
    }

    /// Total sync handler count across all event types.
    pub fn handler_count(&self) -> usize {
        self.by_type.values().map(|v| v.len()).sum()
    }

    /// Total async handler count across all event types.
    pub fn async_handler_count(&self) -> usize {
        self.async_by_type.values().map(|v| v.len()).sum()
    }

    /// Freeze into a [`Dispatcher`]. Fails if more than
    /// [`MAX_EVENT_TYPES`] distinct event types are registered
    /// (sync + async combined).
    pub fn into_dispatcher(mut self) -> std::result::Result<Dispatcher, BuildError> {
        // Collect the union of event TypeIds — sync and async
        // share the same slot index so dispatch can find both
        // sets in one lookup.
        let mut all_types: Vec<TypeId> = self
            .by_type
            .keys()
            .copied()
            .chain(self.async_by_type.keys().copied())
            .collect();
        all_types.sort_unstable_by_key(|t| format!("{t:?}"));
        all_types.dedup();

        if all_types.len() > MAX_EVENT_TYPES {
            return Err(BuildError::TooManyEventTypes {
                limit: MAX_EVENT_TYPES,
                actual: all_types.len(),
            });
        }

        let mut slot_by_type: ArrayVec<(TypeId, u8), MAX_EVENT_TYPES> = ArrayVec::new();
        let mut slots: Vec<Vec<HandlerSlot>> = Vec::with_capacity(all_types.len());
        let mut async_slots: Vec<Vec<AsyncHandlerSlot>> = Vec::with_capacity(all_types.len());

        for (i, type_id) in all_types.into_iter().enumerate() {
            slot_by_type.push((type_id, i as u8));
            slots.push(
                self.by_type
                    .remove(&type_id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|h| HandlerSlot { handler: h })
                    .collect(),
            );
            async_slots.push(
                self.async_by_type
                    .remove(&type_id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|h| AsyncHandlerSlot { handler: h })
                    .collect(),
            );
        }
        Ok(Dispatcher::new(
            slot_by_type,
            slots.into_boxed_slice(),
            async_slots.into_boxed_slice(),
        ))
    }
}

/// Wraps a typed [`AsyncHandler<E>`] in a trait object that
/// can be stored as `Box<dyn DynAsyncHandler>` without exposing
/// the (E, H) type params to the dispatcher.
struct AsyncHandlerWrapper<E, H> {
    handler: H,
    _marker: PhantomData<fn() -> E>,
}

impl<E, H> AsyncHandlerWrapper<E, H> {
    fn new(handler: H) -> Self {
        Self {
            handler,
            _marker: PhantomData,
        }
    }
}

impl<E, H> DynAsyncHandler for AsyncHandlerWrapper<E, H>
where
    E: Event,
    H: AsyncHandler<E>,
{
    fn call(&self, ptr: *const ()) -> BoxFuture<NetringResult<()>> {
        // SAFETY: registry only inserts wrappers keyed by
        // `TypeId::of::<E::Payload>()`, and the dispatcher only
        // invokes a slot when the runtime payload type matches.
        let typed: &E::Payload = unsafe { &*(ptr as *const E::Payload) };
        self.handler.call(typed)
    }
}

/// Drain a flowscope `SlotHandle` and dispatch each typed
/// message through the netring dispatcher. Hides the generic
/// `P: Protocol` parameter so the run loop can hold
/// `Vec<Box<dyn ProtocolSlot>>`.
pub trait ProtocolSlot {
    /// Drain pending messages from the wrapped flowscope handle
    /// and dispatch each one through the supplied dispatcher.
    fn drain_and_dispatch(&mut self, dispatcher: &mut Dispatcher, ctx: &mut Ctx<'_>) -> Result<()>;
}

/// Generic, concrete impl: holds the flowscope `SlotHandle` for a
/// `Protocol` `P` plus a reusable scratch buffer for drained
/// messages.
pub struct TypedProtocolSlot<P: Protocol> {
    handle: SlotHandle<P::Message, flowscope::extract::FiveTupleKey>,
    scratch: Vec<SlotMessage<P::Message, flowscope::extract::FiveTupleKey>>,
    _marker: PhantomData<fn() -> P>,
}

impl<P: Protocol> TypedProtocolSlot<P> {
    /// Wrap a flowscope handle. Scratch capacity grows on demand.
    pub fn new(handle: SlotHandle<P::Message, flowscope::extract::FiveTupleKey>) -> Self {
        Self {
            handle,
            scratch: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Borrow the underlying handle (mainly for diagnostics + tests).
    pub fn handle(&self) -> &SlotHandle<P::Message, flowscope::extract::FiveTupleKey> {
        &self.handle
    }
}

impl<P: Protocol> ProtocolSlot for TypedProtocolSlot<P> {
    fn drain_and_dispatch(&mut self, dispatcher: &mut Dispatcher, ctx: &mut Ctx<'_>) -> Result<()> {
        self.scratch.clear();
        let n = self.handle.drain(&mut self.scratch);
        if n == 0 {
            return Ok(());
        }

        // Per-message flow + ts override for the dispatch call;
        // restored after each message so a partial drain doesn't
        // leak state into the lifecycle dispatch path.
        let saved_flow = ctx.flow;
        let saved_ts = ctx.ts;

        for slot_msg in self.scratch.drain(..) {
            // `FiveTupleKey` is `Copy` — stamp it on the ctx by
            // value so the borrow checker doesn't have to reason
            // about a borrow that aliases the drained message.
            ctx.flow = Some(slot_msg.key);
            ctx.ts = slot_msg.ts;
            dispatcher.dispatch::<P::Message>(&slot_msg.message, ctx)?;
        }

        ctx.flow = saved_flow;
        ctx.ts = saved_ts;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use flowscope::Timestamp;

    use super::*;
    use crate::anomaly::sink::NoopSink;
    use crate::ctx::{CounterRegistry, SourceIdx, StateMap};
    use crate::error::Error;
    use crate::protocol::builtin::Tcp;
    use crate::protocol::event_typed::FlowStarted;

    fn fresh_ctx<'a>(
        state: &'a mut StateMap,
        sink: &'a mut NoopSink,
        counters: &'a mut CounterRegistry,
    ) -> Ctx<'a> {
        Ctx {
            flow: None,
            ts: Timestamp::new(0, 0),
            source: SourceIdx(0),
            monitor_name: None,
            state_map: state,
            sink,
            counters,
        }
    }

    fn dummy_flow_started() -> FlowStarted<Tcp> {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let key = flowscope::extract::FiveTupleKey {
            proto: flowscope::L4Proto::Tcp,
            a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
            b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
        };
        FlowStarted::<Tcp>::new(key, Some(flowscope::L4Proto::Tcp), Timestamp::new(0, 0))
    }

    #[test]
    fn register_one_handler_then_dispatch_fires_it() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);

        let mut reg = HandlerRegistry::default();
        reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>| {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        assert_eq!(reg.type_count(), 1);
        assert_eq!(reg.handler_count(), 1);
        let mut disp = reg.into_dispatcher().unwrap();

        let mut s = StateMap::default();
        let mut sink = NoopSink;
        let mut cr = CounterRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut sink, &mut cr);

        let evt = dummy_flow_started();
        disp.dispatch::<FlowStarted<Tcp>>(&evt, &mut ctx).unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn register_two_handlers_for_same_event_both_fire() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let a = Arc::new(AtomicU32::new(0));
        let b = Arc::new(AtomicU32::new(0));
        let a_h = Arc::clone(&a);
        let b_h = Arc::clone(&b);

        let mut reg = HandlerRegistry::default();
        reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>| {
            a_h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>| {
            b_h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        assert_eq!(reg.type_count(), 1);
        assert_eq!(reg.handler_count(), 2);
        let mut disp = reg.into_dispatcher().unwrap();

        let mut s = StateMap::default();
        let mut sink = NoopSink;
        let mut cr = CounterRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut sink, &mut cr);

        let evt = dummy_flow_started();
        disp.dispatch::<FlowStarted<Tcp>>(&evt, &mut ctx).unwrap();
        assert_eq!(a.load(Ordering::Relaxed), 1);
        assert_eq!(b.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handler_error_short_circuits_remaining_handlers() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let after = Arc::new(AtomicU32::new(0));
        let after_h = Arc::clone(&after);

        let mut reg = HandlerRegistry::default();
        reg.register::<FlowStarted<Tcp>, _, _>(|_evt: &FlowStarted<Tcp>| {
            Err(Error::Config("boom".into()))
        });
        reg.register::<FlowStarted<Tcp>, _, _>(move |_evt: &FlowStarted<Tcp>| {
            after_h.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        let mut disp = reg.into_dispatcher().unwrap();

        let mut s = StateMap::default();
        let mut sink = NoopSink;
        let mut cr = CounterRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut sink, &mut cr);

        let evt = dummy_flow_started();
        let res = disp.dispatch::<FlowStarted<Tcp>>(&evt, &mut ctx);
        assert!(res.is_err());
        assert_eq!(
            after.load(Ordering::Relaxed),
            0,
            "second handler must not fire after first errored"
        );
    }

    #[test]
    fn too_many_event_types_errors_at_build() {
        // Synthesize >MAX_EVENT_TYPES distinct event types by
        // registering with distinct wrapper struct types. Each
        // unit struct is auto-Send + auto-Sync, so the Event impl
        // just needs `type Payload`.
        macro_rules! synth {
            ($($name:ident),+ $(,)?) => {
                $(
                    #[derive(Debug)]
                    struct $name;
                    impl Event for $name { type Payload = $name; }
                )+
            };
        }
        synth!(
            E0, E1, E2, E3, E4, E5, E6, E7, E8, E9, E10, E11, E12, E13, E14, E15, E16
        );

        let mut reg = HandlerRegistry::default();
        reg.register::<E0, _, _>(|_: &E0| Ok(()));
        reg.register::<E1, _, _>(|_: &E1| Ok(()));
        reg.register::<E2, _, _>(|_: &E2| Ok(()));
        reg.register::<E3, _, _>(|_: &E3| Ok(()));
        reg.register::<E4, _, _>(|_: &E4| Ok(()));
        reg.register::<E5, _, _>(|_: &E5| Ok(()));
        reg.register::<E6, _, _>(|_: &E6| Ok(()));
        reg.register::<E7, _, _>(|_: &E7| Ok(()));
        reg.register::<E8, _, _>(|_: &E8| Ok(()));
        reg.register::<E9, _, _>(|_: &E9| Ok(()));
        reg.register::<E10, _, _>(|_: &E10| Ok(()));
        reg.register::<E11, _, _>(|_: &E11| Ok(()));
        reg.register::<E12, _, _>(|_: &E12| Ok(()));
        reg.register::<E13, _, _>(|_: &E13| Ok(()));
        reg.register::<E14, _, _>(|_: &E14| Ok(()));
        reg.register::<E15, _, _>(|_: &E15| Ok(()));
        reg.register::<E16, _, _>(|_: &E16| Ok(()));

        let err = reg.into_dispatcher().unwrap_err();
        match err {
            BuildError::TooManyEventTypes { limit, actual } => {
                assert_eq!(limit, MAX_EVENT_TYPES);
                assert_eq!(actual, MAX_EVENT_TYPES + 1);
            }
            other => panic!("expected TooManyEventTypes, got {other:?}"),
        }
    }
}
