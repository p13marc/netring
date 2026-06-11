//! Declarative `detector!` macro — terse stateless detector
//! definitions for use with [`crate::monitor::Monitor`].
//!
//! The macro expands to a closure that satisfies the sync
//! [`crate::monitor::Handler`] trait for the configured event
//! type, ready to register via
//! `Monitor::builder().on_ctx::<E>(detector!{...})` or its
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

/// Typed detector wrapper produced by the [`crate::detector!`] macro.
///
/// Carries the event type `E` and the handler closure `F`
/// together so [`crate::monitor::MonitorBuilder::detect`] can
/// infer `E` from the macro's return value — users avoid the
/// `.detect::<E, _, _>(...)` turbofish papercut.
///
/// You usually never name this type — `detector! { … }` returns
/// it; the builder unwraps it.
pub struct Detector<E, F> {
    /// The detector's handler closure (satisfies
    /// `Handler<E, PayloadCtx>`).
    pub handler: F,
    /// 0.21 A.9: stable detector slug threaded from the macro's
    /// `name:` field. Used by [`crate::monitor::Monitor::detector_names`]
    /// for introspection (legacy `ProtocolMonitor` had
    /// `rule_names()`; the new typed API matches it). Default is
    /// `"unnamed"` for `Detector::new(...)` constructions that
    /// don't go through the macro.
    pub name: &'static str,
    /// 0.21 A.6: counter key-type slugs this detector touches via
    /// `ctx.counter_mut::<K>`. Stamped by the macro's optional
    /// `counters: [K1, K2, ...]` clause via
    /// `vec![type_name::<K1>(), …]`. Empty (`Vec::new()`) by
    /// default — raw `Detector::new(...)` constructions opt out
    /// of validation. `MonitorBuilder::build()` walks this list
    /// against `CounterRegistry::registered_type_names()` and
    /// returns `BuildError::CounterNotRegistered` on miss.
    ///
    /// Owned `Vec` (rather than `&'static [&'static str]`)
    /// because `std::any::type_name` is not yet const-stable, so
    /// the macro can't synthesise a `'static` slice at compile
    /// time. The cost is one tiny allocation per detector at
    /// builder time — well below the noise floor of the
    /// `.protocol::<P>()` registration that follows.
    pub declared_counters: Vec<&'static str>,
    /// Carries `E` at the type level so the builder can
    /// dispatch through it.
    pub _marker: ::std::marker::PhantomData<fn() -> E>,
}

impl<E, F> Detector<E, F> {
    /// Build from a closure + phantom event tag. Used by the
    /// `detector!` macro; rarely called directly.
    pub fn new(handler: F) -> Self {
        Self {
            handler,
            name: "unnamed",
            declared_counters: Vec::new(),
            _marker: ::std::marker::PhantomData,
        }
    }

    /// Stamp a stable name slug onto a detector. Lets raw
    /// `Detector::new(closure)` users participate in
    /// [`crate::monitor::Monitor::detector_names`] introspection.
    ///
    /// Returns `self` for fluent chaining (the `detector!` macro
    /// internally calls this with the macro's `name:` literal).
    pub fn with_name(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }

    /// 0.21 A.6: stamp the counter key-type slugs this detector
    /// touches. `MonitorBuilder::build()` validates each slug
    /// against the registered counters and rejects the build with
    /// [`crate::error::BuildError::CounterNotRegistered`] on
    /// mismatch. The slugs come from `std::any::type_name::<K>()`
    /// — the `detector!` macro's `counters: [K1, K2]` clause
    /// substitutes these automatically.
    pub fn with_declared_counters(mut self, slugs: Vec<&'static str>) -> Self {
        self.declared_counters = slugs;
        self
    }
}

/// `Detector<E, F>` forwards to its wrapped `F`. Lets users
/// register a detector via the raw [`crate::monitor::HandlerRegistry`]
/// or hand-roll dispatch in tests without unwrapping.
impl<E, F> crate::monitor::handler::Handler<E, crate::monitor::handler::PayloadCtx>
    for Detector<E, F>
where
    E: crate::protocol::event_typed::Event,
    F: crate::monitor::handler::Handler<E, crate::monitor::handler::PayloadCtx>,
{
    #[inline]
    fn call(
        &self,
        payload: &E::Payload,
        ctx: &mut crate::ctx::Ctx<'_>,
    ) -> crate::error::Result<()> {
        self.handler.call(payload, ctx)
    }
}

/// Build a stateless detector for the 0.20
/// [`Monitor`](crate::monitor::Monitor) builder.
///
/// Returns a [`Detector<E, F>`] where `E` is the configured event
/// type and `F` is an opaque closure satisfying
/// `Handler<E, PayloadCtx>`. Pair with
/// [`crate::monitor::MonitorBuilder::detect`] — `E` is inferred
/// from the macro's return value, no turbofish needed.
#[macro_export]
macro_rules! detector {
    (
        name: $name:literal,
        $( counters: [ $( $counter:ty ),+ $(,)? ], )?
        severity: $sev:ident,
        event: $ev:ty,
        $( matches: |$guard_pat:pat_param| $guard_expr:expr, )?
        emit: |$payload:pat_param, $ctx:pat_param| $emit_body:expr $(,)?
    ) => {{
        // Compile-time check that `severity:` is a real Severity variant.
        let _: $crate::anomaly::Severity = $crate::anomaly::Severity::$sev;

        let __handler = move |__payload: &<$ev as $crate::protocol::event_typed::Event>::Payload,
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
            // Wrapping in a `()`-returning inner closure lets the
            // user's emit body use a bare `return;` for early-exit
            // (e.g. inside an `if let … else { return }` pattern)
            // without colliding with the outer closure's
            // `Result<()>` return type. clippy's
            // `redundant_closure_call` doesn't see the early-exit
            // motive — silence locally.
            #[allow(clippy::redundant_closure_call)]
            (|| -> () { $emit_body })();
            ::std::result::Result::Ok(())
        };
        // 0.21 A.9: thread the `name:` literal into the Detector so
        // `Monitor::detector_names()` can surface it for diagnostics.
        // 0.21 A.6: when the `counters:` clause is present, stamp
        // `std::any::type_name::<K>()` for each declared `K` into
        // `declared_counters` so `MonitorBuilder::build()` can
        // validate that `.counter::<K>(...)` was actually called.
        let __det = $crate::detector_macro::Detector::<$ev, _>::new(__handler).with_name($name);
        $(
            let __declared_counters: ::std::vec::Vec<&'static str> = ::std::vec![
                $( ::std::any::type_name::<$counter>() ),+
            ];
            let __det = __det.with_declared_counters(__declared_counters);
        )?
        __det
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
