//! Handler trait + blanket impls.
//!
//! A handler is a callable that runs once per event of type `E`
//! and returns `Result<()>`. Phase B ships two arities via the
//! axum coherence-marker trick:
//!
//! - `|payload: &E::Payload| -> Result<()>` — no ctx
//! - `|payload: &E::Payload, ctx: &mut Ctx<'_>| -> Result<()>` — full ctx access
//!
//! Multi-extractor handler signatures (axum-style `State<T>`,
//! `Counter<K>`, …) were considered but don't compile in sync
//! Rust: sequential `from_ctx(&mut ctx)` calls all hold `&mut
//! Ctx` simultaneously. The same ergonomics are recovered by
//! methods on [`Ctx`] (`state_mut::<T>()`,
//! `counter_mut::<K>()`, `sink_mut()`), since each method call
//! is its own bounded borrow and the compiler tracks disjoint
//! field accesses correctly.

use crate::ctx::Ctx;
use crate::error::Result;
use crate::protocol::event_typed::Event;

/// A handler is a callable that runs once per event of type `E`
/// and returns `Result<()>`.
///
/// `Marker` is the axum coherence phantom — users never name it.
/// Two blanket impls (with and without `&mut Ctx`) live below.
pub trait Handler<E: Event, Marker>: Send + Sync + 'static {
    /// Invoke the handler with the typed payload + per-event ctx.
    fn call(&self, payload: &E::Payload, ctx: &mut Ctx<'_>) -> Result<()>;
}

/// Marker for handlers that take only a typed payload.
pub struct PayloadOnly;
/// Marker for handlers that take a typed payload + `&mut Ctx`.
pub struct PayloadCtx;

// 0-arg ctx: closure shape is `Fn(&E::Payload) -> Result<()>`.
impl<E, F> Handler<E, PayloadOnly> for F
where
    E: Event,
    F: Fn(&E::Payload) -> Result<()> + Send + Sync + 'static,
{
    #[inline]
    fn call(&self, p: &E::Payload, _ctx: &mut Ctx<'_>) -> Result<()> {
        self(p)
    }
}

// Full ctx: closure shape is `Fn(&E::Payload, &mut Ctx<'_>) -> Result<()>`.
impl<E, F> Handler<E, PayloadCtx> for F
where
    E: Event,
    F: for<'a> Fn(&'a E::Payload, &'a mut Ctx<'_>) -> Result<()> + Send + Sync + 'static,
{
    #[inline]
    fn call(&self, p: &E::Payload, ctx: &mut Ctx<'_>) -> Result<()> {
        self(p, ctx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use flowscope::Timestamp;

    use super::*;
    use crate::anomaly::sink::NoopSink;
    use crate::correlate::TimeBucketedCounter;
    use crate::ctx::{CounterRegistry, SourceIdx, StateMap};
    use crate::protocol::builtin::Tcp;
    use crate::protocol::event_typed::FlowStarted;

    #[derive(Default)]
    struct Counters {
        flows: u64,
    }

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

    fn invoke<E, H, M>(h: H, p: &E::Payload, ctx: &mut Ctx<'_>) -> Result<()>
    where
        E: Event,
        H: Handler<E, M>,
        M: 'static,
    {
        h.call(p, ctx)
    }

    #[test]
    fn payload_only_handler_runs() {
        let mut s = StateMap::default();
        let mut k = NoopSink;
        let mut c = CounterRegistry::default();
        let mut fs = crate::ctx::FlowStateRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut k, &mut c, &mut fs);
        let evt = dummy_flow_started();

        let h = |_p: &FlowStarted<Tcp>| Ok(());
        invoke::<FlowStarted<Tcp>, _, PayloadOnly>(h, &evt, &mut ctx).unwrap();
    }

    #[test]
    fn payload_ctx_handler_can_mutate_state() {
        let mut s = StateMap::default();
        let mut k = NoopSink;
        let mut c = CounterRegistry::default();
        let mut fs = crate::ctx::FlowStateRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut k, &mut c, &mut fs);
        let evt = dummy_flow_started();

        let h = |_p: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
            ctx.state_mut::<Counters>().flows += 1;
            Ok(())
        };
        invoke::<FlowStarted<Tcp>, _, PayloadCtx>(h, &evt, &mut ctx).unwrap();
        invoke::<FlowStarted<Tcp>, _, PayloadCtx>(h, &evt, &mut ctx).unwrap();
        assert_eq!(ctx.state_mut::<Counters>().flows, 2);
    }

    #[test]
    fn payload_ctx_handler_multi_field_access() {
        let mut s = StateMap::default();
        let mut k = NoopSink;
        let mut c = CounterRegistry::default();
        c.register::<u16>(TimeBucketedCounter::<u16>::new_unbounded(
            Duration::from_secs(60),
            Duration::from_secs(1),
        ));
        let mut fs = crate::ctx::FlowStateRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut k, &mut c, &mut fs);
        ctx.ts = Timestamp::new(7, 0);
        let evt = dummy_flow_started();

        // Three distinct ctx-method calls = three disjoint borrows
        // of the ctx fields. Borrow checker is happy.
        let h = |_p: &FlowStarted<Tcp>, ctx: &mut Ctx<'_>| {
            ctx.state_mut::<Counters>().flows += 1;
            let now = ctx.ts;
            ctx.counter_mut::<u16>().bump(42u16, now);
            Ok(())
        };
        invoke::<FlowStarted<Tcp>, _, PayloadCtx>(h, &evt, &mut ctx).unwrap();
        assert_eq!(ctx.state_mut::<Counters>().flows, 1);
    }
}
