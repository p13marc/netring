//! Declarative `detector!` macro — terse stateless detector
//! definitions for use with [`crate::monitor::Monitor`].
//!
//! The macro expands to a closure that satisfies the sync
//! [`crate::monitor::Handler`] trait for the configured event
//! type, ready to register via
//! `Monitor::builder().on::<E, _, _>(detector!{...})` or its
//! sugar alias `.detect(...)`.
//!
//! Grammar:
//!
//! ```text
//! detector! {
//!     name:     <string literal>,        // documentation only — pass to sink.begin()
//!     severity: <Severity variant>,      // documentation only — used by your emit body
//!     event:    <Event type>,            // the event marker (e.g. Http, FlowStarted<Tcp>)
//!     // Optional guard:
//!     matches:  |payload| <bool-expr>,
//!     // Required emit body — receives (&payload, &mut ctx):
//!     emit:     |payload, ctx| <statement-list>,
//! }
//! ```
//!
//! ## Phase E shape
//!
//! The Phase B redesign collapsed axum-style multi-extractor
//! handlers into ctx-method accessors, so this macro produces a
//! `PayloadCtx` closure: `Fn(&E::Payload, &mut Ctx<'_>) -> Result<()>`.
//! The `name` and `severity` slugs are kept in the grammar for
//! readability and IDE-completion; they are not threaded through
//! to the dispatcher (a future revision could use them to stamp
//! tracing spans or default the `sink.begin(kind=…)` argument).
//!
//! ## Example
//!
//! ```ignore
//! use netring::prelude::*;
//!
//! let det = detector! {
//!     name:     "TruncatedTls",
//!     severity: Warning,
//!     event:    TlsHandshake,
//!     matches:  |hs| hs.outcome == flowscope::tls::HandshakeOutcome::Truncated,
//!     emit:     |hs, ctx| {
//!         let now = ctx.ts;
//!         ctx.sink_mut()
//!             .begin("TruncatedTls", Severity::Warning, now)
//!             .with("sni", hs.sni.as_deref().unwrap_or("<none>"))
//!             .emit();
//!     },
//! };
//!
//! Monitor::builder()
//!     .interface("eth0")
//!     .protocol::<TlsHandshake>()
//!     .detect(det)
//!     .build()?;
//! ```

/// Build a stateless detector closure for the 0.20
/// [`Monitor`](crate::monitor::Monitor) builder.
///
/// See the module rustdoc for the grammar; the macro returns a
/// closure that satisfies
/// `Handler<E, PayloadCtx>` for the configured `E` event type.
#[macro_export]
macro_rules! detector {
    (
        name: $name:literal,
        severity: $sev:ident,
        event: $ev:ty,
        $( matches: |$guard_pat:pat_param| $guard_expr:expr, )?
        emit: |$payload:pat_param, $ctx:pat_param| $emit_body:expr $(,)?
    ) => {{
        // The slugs aren't threaded through the runtime yet —
        // bind them so the compiler verifies `name:` is a literal
        // and `severity:` is a real Severity variant; the binding
        // ends up as compile-time dead code.
        let _ = $name;
        let _: $crate::anomaly::Severity = $crate::anomaly::Severity::$sev;

        move |__payload: &<$ev as $crate::protocol::event_typed::Event>::Payload,
              __ctx: &mut $crate::ctx::Ctx<'_>|
              -> $crate::error::Result<()> {
            $(
                {
                    let $guard_pat = __payload;
                    if !($guard_expr) {
                        return ::std::result::Result::Ok(());
                    }
                }
            )?
            let $payload = __payload;
            let $ctx = __ctx;
            { $emit_body }
            ::std::result::Result::Ok(())
        }
    }};
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use flowscope::Timestamp;

    use crate::anomaly::Severity;
    use crate::anomaly::sink::NoopSink;
    use crate::ctx::{CounterRegistry, Ctx, SourceIdx, StateMap};
    use crate::error::Result;
    use crate::monitor::Handler;
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
    fn macro_without_guard_produces_a_handler() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);

        let det = crate::detector! {
            name: "NoGuard",
            severity: Info,
            event: FlowStarted<Tcp>,
            emit: |_evt, _ctx| {
                c.fetch_add(1, Ordering::Relaxed);
            },
        };

        // Confirm it satisfies Handler<E, PayloadCtx>.
        let mut s = StateMap::default();
        let mut k = NoopSink;
        let mut cr = CounterRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut k, &mut cr);
        let evt = dummy_flow_started();
        Handler::<FlowStarted<Tcp>, crate::monitor::PayloadCtx>::call(&det, &evt, &mut ctx)
            .unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn macro_guard_filters_non_matching_events() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);

        let det = crate::detector! {
            name: "EvenL4Only",
            severity: Warning,
            event: FlowStarted<Tcp>,
            matches: |evt| matches!(evt.l4, Some(flowscope::L4Proto::Udp)),
            emit: |_evt, _ctx| {
                c.fetch_add(1, Ordering::Relaxed);
            },
        };

        let mut s = StateMap::default();
        let mut k = NoopSink;
        let mut cr = CounterRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut k, &mut cr);
        // Event is L4=Tcp; matches says L4=Udp → fires zero times.
        let evt = dummy_flow_started();
        Handler::<FlowStarted<Tcp>, crate::monitor::PayloadCtx>::call(&det, &evt, &mut ctx)
            .unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn macro_emit_body_can_call_ctx_sink_mut() {
        // Type-checks against the AnomalySink trait surface.
        fn _det_compiles<F>(_: F)
        where
            F: Handler<FlowStarted<Tcp>, crate::monitor::PayloadCtx>,
        {
        }
        let det = crate::detector! {
            name: "Emits",
            severity: Critical,
            event: FlowStarted<Tcp>,
            emit: |_evt, ctx| {
                let now = ctx.ts;
                ctx.sink_mut()
                    .begin("Emits", Severity::Critical, now)
                    .with("note", "hi")
                    .emit();
            },
        };
        _det_compiles(det);
    }

    #[test]
    fn macro_used_with_real_dispatch_path() -> Result<()> {
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);

        let det = crate::detector! {
            name: "DispatchPath",
            severity: Info,
            event: FlowStarted<Tcp>,
            emit: |_evt, _ctx| {
                c.fetch_add(1, Ordering::Relaxed);
            },
        };

        let mut reg = crate::monitor::HandlerRegistry::default();
        reg.register::<FlowStarted<Tcp>, _, _>(det);
        let mut disp = reg.into_dispatcher().expect("dispatcher");

        let mut s = StateMap::default();
        let mut k = NoopSink;
        let mut cr = CounterRegistry::default();
        let mut ctx = fresh_ctx(&mut s, &mut k, &mut cr);

        disp.dispatch::<FlowStarted<Tcp>>(&dummy_flow_started(), &mut ctx)?;
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        Ok(())
    }
}
