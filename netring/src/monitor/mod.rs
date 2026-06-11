//! Top-level `Monitor` builder + run loop.
//!
//! ```no_run
//! # #[cfg(all(feature = "tokio", feature = "flow", feature = "http"))]
//! # async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::Duration;
//! use netring::monitor::Monitor;
//! use netring::protocol::builtin::Http;
//!
//! Monitor::builder()
//!     .interface("lo")
//!     .protocol::<Http>()
//!     .on::<Http>(|msg: &flowscope::http::HttpMessage| {
//!         println!("http: {msg:?}");
//!         Ok(())
//!     })
//!     .build()?
//!     .run_for(Duration::from_secs(1))
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! ## Phase B scope
//!
//! - Single interface only (multi-iface lands in Phase E).
//! - Sync handlers only (`on_async` is Phase D).
//! - Tick handlers can be registered but don't yet fire — Phase F
//!   adds the periodic tick pump alongside the packet stream.
//! - The default sink is a no-op; `.sink(...)` accepts any
//!   [`AnomalySink`]. The sink trait body fills out in Phase C.
//!
//! ## `!Send` `Monitor`
//!
//! flowscope's `SlotHandle` holds a `Rc<RefCell<…>>`, so `Monitor`
//! is `!Send`. Use it on the same task / thread that drives the
//! `tokio` runtime — `#[tokio::main(flavor = "current_thread")]`
//! works out of the box; multi-thread runtimes need
//! `LocalSet::run_until` to keep the future pinned.

use std::time::{Duration, Instant};

use flowscope::driver::{Driver, DriverBuilder};
use flowscope::extract::FiveTuple;

use crate::anomaly::sink::{AnomalySink, NoopSink};
use crate::correlate::TimeBucketedCounter;
use crate::ctx::{CounterRegistry, StateMap};
use crate::error::{BuildError, Result};
use crate::layer::Layer;
use crate::protocol::Protocol;
use crate::protocol::event_typed::{Event, Tick};

pub mod async_handler;
pub mod dispatcher;
pub mod handler;
pub mod registry;
pub mod run;
pub mod tick;

pub use async_handler::{AsyncHandler, BoxFuture};
pub use dispatcher::{Dispatcher, MAX_EVENT_TYPES};
pub use handler::{Handler, PayloadCtx, PayloadOnly};
pub use registry::{HandlerRegistry, ProtocolSlot, TypedProtocolSlot};
pub use tick::TickRegistration;

/// The 0.20 top-level monitor — a fully-constructed graph of
/// (driver, dispatcher, parser-slots, state) that runs to a
/// stop condition.
///
/// `interfaces` carries one or more capture interfaces. Phase F.1
/// shipped multi-interface support; events are tagged with
/// [`crate::ctx::SourceIdx`] reflecting which interface the packet
/// came from (in builder-registration order).
pub struct Monitor {
    pub(crate) interfaces: Vec<String>,
    pub(crate) driver: Driver<FiveTuple>,
    pub(crate) dispatcher: Dispatcher,
    pub(crate) protocol_slots: Vec<Box<dyn ProtocolSlot>>,
    pub(crate) state_map: StateMap,
    pub(crate) counters: CounterRegistry,
    pub(crate) sink: Box<dyn AnomalySink>,
    pub(crate) tick_handlers: Vec<TickRegistration>,
    /// 0.21 A.9: registration-order detector slugs from
    /// `MonitorBuilder::detect(...)` and `on_named(...)`. Raw
    /// `.on::<E>(closure)` registrations stay anonymous (not in
    /// this list). Surfaces via [`Self::detector_names`].
    pub(crate) detector_names: Vec<&'static str>,
    /// 0.21 D.4: optional monitor name set via
    /// [`MonitorBuilder::name`]. Borrowed at dispatch time into
    /// [`crate::ctx::Ctx::monitor_name`]. `Box<str>` over `String`
    /// because the storage is write-once at build time and never
    /// reallocated — saves the 8-byte capacity overhead.
    pub(crate) monitor_name: Option<Box<str>>,
}

impl Monitor {
    /// Begin building a [`Monitor`]. See module docs for the full
    /// builder surface.
    pub fn builder() -> MonitorBuilder {
        MonitorBuilder::default()
    }

    /// Run until the wall-clock reaches `deadline`.
    pub async fn run_until(self, deadline: Instant) -> Result<()> {
        run::run_loop(self, run::StopCondition::Deadline(deadline)).await
    }

    /// Run for `duration`.
    pub async fn run_for(self, duration: Duration) -> Result<()> {
        self.run_until(Instant::now() + duration).await
    }

    /// Run until Ctrl-C (SIGINT) / SIGTERM.
    pub async fn run_until_signal(self) -> Result<()> {
        run::run_loop(self, run::StopCondition::Signal).await
    }

    /// Registered detector slugs in builder-registration order.
    /// 0.21 A.9: includes every name from `.detect(detector!{ name: "X", … })`
    /// and `.on_named("X", handler)`. Anonymous `.on::<E>(closure)`
    /// registrations are excluded (no metadata).
    ///
    /// Useful for diagnostics dashboards and audit logs that need
    /// the runtime set of active detectors — mirrors the legacy
    /// `AnomalyMonitor::rule_names` accessor for parity.
    pub fn detector_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.detector_names.iter().copied()
    }
}

impl std::fmt::Debug for Monitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Monitor")
            .field("interfaces", &self.interfaces)
            .field("dispatcher", &self.dispatcher)
            .field("protocol_slots", &self.protocol_slots.len())
            .field("tick_handlers", &self.tick_handlers.len())
            .finish_non_exhaustive()
    }
}

/// Builder for [`Monitor`]. Construct via [`Monitor::builder`].
#[derive(Default)]
pub struct MonitorBuilder {
    interfaces: Vec<String>,
    driver_builder: Option<DriverBuilder<FiveTuple>>,
    protocol_slots: Vec<Box<dyn ProtocolSlot>>,
    handlers: HandlerRegistry,
    state_map: StateMap,
    counters: CounterRegistry,
    sink: Option<Box<dyn AnomalySink>>,
    /// Layers in registration order — outermost-first. Applied
    /// innermost-first at [`Self::build`] time, so the first
    /// `.layer(X)` call wraps the final composed chain.
    layers: Vec<Box<dyn Layer>>,
    tick_handlers: Vec<TickRegistration>,
    /// 0.21 A.9: detector-name slugs collected via `.detect(...)`
    /// (macro-stamped name) and `.on_named(name, ...)`.
    detector_names: Vec<&'static str>,
    /// 0.21 A.6: per-detector counter declarations collected via
    /// `.detect(...)`. Each entry pairs the detector's `name` slug
    /// with the list of counter key-type slugs the detector
    /// declared (via `detector! { counters: [K1, K2], … }`).
    /// `Self::build` walks these and validates against
    /// [`CounterRegistry::registered_type_names`].
    declared_counters: Vec<(&'static str, Vec<&'static str>)>,
    /// 0.21 D.4: optional human-readable monitor name set via
    /// [`Self::name`]. Propagates to [`Monitor::monitor_name`]
    /// and through to handler-visible [`crate::ctx::Ctx::monitor_name`].
    monitor_name: Option<Box<str>>,
}

impl MonitorBuilder {
    /// Set the capture interface(s). Phase F.1 enables N > 1 —
    /// each event is tagged with its source-interface index
    /// (`SourceIdx(0)` for the first interface in registration
    /// order, etc.). Handlers can branch on `ctx.source` if
    /// per-interface behaviour is needed.
    ///
    /// All interfaces share the same driver, dispatcher, state,
    /// and sink — multi-interface is fan-in, not fan-out. For
    /// per-CPU fan-out on a single interface, see Phase F.3's
    /// `fanout_per_cpu` (when shipped).
    pub fn interfaces<I, S>(mut self, ifaces: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.interfaces = ifaces.into_iter().map(Into::into).collect();
        self
    }

    /// Single-interface convenience.
    pub fn interface(self, iface: impl Into<String>) -> Self {
        self.interfaces([iface])
    }

    /// 0.21 D.4: tag this monitor with a human-readable name.
    ///
    /// The name surfaces on every dispatched [`Ctx`] as
    /// [`Ctx::monitor_name`] (`Option<&'a str>`); user handlers
    /// running under multiple monitors in the same process can
    /// branch on it to disambiguate.
    ///
    /// Pattern: stamp the name as an observation on each
    /// emission so downstream sinks carry it through —
    ///
    /// ```ignore
    /// .on_ctx::<FlowStarted<Tcp>>(|_evt, ctx| {
    ///     let monitor = ctx.monitor_name.unwrap_or("default");
    ///     ctx.emit("FlowStarted", Severity::Info)
    ///         .with("monitor", monitor.to_string())
    ///         .emit();
    ///     Ok(())
    /// })
    /// ```
    ///
    /// Storage shape: `Box<str>` — one allocation for the
    /// lifetime of the monitor; `&str` view at dispatch time.
    pub fn name(mut self, name: impl Into<Box<str>>) -> Self {
        self.monitor_name = Some(name.into());
        self
    }

    /// Register a protocol. Calls `P::register(driver_builder)` to
    /// install the parser slot (if any) and stores the resulting
    /// [`TypedProtocolSlot`].
    ///
    /// Lifecycle-only markers ([`crate::protocol::builtin::Tcp`] /
    /// [`crate::protocol::builtin::Udp`]) return `Err` from
    /// `register` — the builder treats that as "no parser slot to
    /// stash; the central tracker covers lifecycle events" and
    /// silently moves on.
    pub fn protocol<P: Protocol>(mut self) -> Self {
        let builder = self
            .driver_builder
            .get_or_insert_with(|| Driver::builder(FiveTuple::bidirectional()));
        if let Ok(handle) = P::register(builder) {
            self.protocol_slots
                .push(Box::new(TypedProtocolSlot::<P>::new(handle)));
        }
        // Err(_) = lifecycle-only; nothing to register.
        self
    }

    /// Register a payload-only handler for event type `E`.
    ///
    /// Closure shape: `Fn(&E::Payload) -> Result<()>`. The marker
    /// type is fixed at `PayloadOnly`, so users name only `E`:
    ///
    /// ```ignore
    /// Monitor::builder()
    ///     .protocol::<Http>()
    ///     .on::<Http>(|msg: &flowscope::http::HttpMessage| {
    ///         println!("{msg:?}");
    ///         Ok(())
    ///     })
    /// ```
    ///
    /// For handlers that also need `&mut Ctx<'_>`, use
    /// [`Self::on_ctx`]. The 0.20 three-generic form
    /// [`Self::on_with_marker`] is `#[deprecated]`.
    pub fn on<E: Event>(
        mut self,
        handler: impl Handler<E, crate::monitor::handler::PayloadOnly>,
    ) -> Self {
        self.handlers
            .register::<E, _, crate::monitor::handler::PayloadOnly>(handler);
        self
    }

    /// Register a handler that also receives `&mut Ctx<'_>`.
    ///
    /// Closure shape: `Fn(&E::Payload, &mut Ctx<'_>) -> Result<()>`.
    ///
    /// ```ignore
    /// Monitor::builder()
    ///     .protocol::<Tcp>()
    ///     .state::<MyState>()
    ///     .on_ctx::<FlowStarted<Tcp>>(|evt, ctx| {
    ///         ctx.state_mut::<MyState>().bump();
    ///         Ok(())
    ///     })
    /// ```
    pub fn on_ctx<E: Event>(
        mut self,
        handler: impl Handler<E, crate::monitor::handler::PayloadCtx>,
    ) -> Self {
        self.handlers
            .register::<E, _, crate::monitor::handler::PayloadCtx>(handler);
        self
    }

    /// Deprecated three-generic handler registration.
    ///
    /// Replaced by [`Self::on`] (payload-only) and [`Self::on_ctx`]
    /// (payload + ctx); both take one generic each — the marker
    /// type is fixed per method instead of `_, _`-inferred. Removed
    /// in netring 0.22.
    #[deprecated(
        since = "0.21.0",
        note = "use `.on::<E>(handler)` (payload-only) or `.on_ctx::<E>(handler)` (payload + ctx); the marker is fixed per method"
    )]
    pub fn on_with_marker<E, H, M>(mut self, handler: H) -> Self
    where
        E: Event,
        H: Handler<E, M>,
        M: 'static,
    {
        self.handlers.register::<E, H, M>(handler);
        self
    }

    /// Register a [`crate::detector_macro::Detector<E, F>`] produced by the
    /// [`crate::detector!`] macro. Inference flows from the
    /// Detector's `E` type parameter, so users don't need to
    /// spell out a turbofish:
    ///
    /// ```ignore
    /// Monitor::builder()
    ///     .protocol::<TlsHandshake>()
    ///     .detect(detector! {
    ///         name: "TruncatedTls", severity: Warning, event: TlsHandshake,
    ///         emit: |hs, ctx| { /* … */ },
    ///     })
    ///     .build()?
    /// ```
    ///
    /// For raw closures not produced by `detector!`, use
    /// [`Self::on`] / [`Self::on_ctx`] directly.
    pub fn detect<E, F>(mut self, detector: crate::detector_macro::Detector<E, F>) -> Self
    where
        E: Event,
        F: Handler<E, crate::monitor::handler::PayloadCtx>,
    {
        self.detector_names.push(detector.name);
        // 0.21 A.6: stash `(name, declared_counters)` so `build()`
        // can validate. Empty `declared_counters` is fine — raw
        // `Detector::new(...)` defaults to `&[]` and skips
        // validation (documented limitation; macro use is the
        // recommended path).
        if !detector.declared_counters.is_empty() {
            self.declared_counters
                .push((detector.name, detector.declared_counters));
        }
        self.on_ctx::<E>(detector.handler)
        // Note: we move `detector.handler` last so the prior
        // `.declared_counters` move + name push completed before
        // `detector` is consumed.
    }

    /// Register a payload+ctx handler with an explicit detector name
    /// slug. Like [`Self::on_ctx`] but the supplied `name` is
    /// recorded in [`Monitor::detector_names`] for introspection /
    /// diagnostics. 0.21 A.9: matches the legacy `AnomalyRule::name`
    /// surface and pairs with the `detector!` macro's `name:` field.
    pub fn on_named<E: Event>(
        mut self,
        name: &'static str,
        handler: impl Handler<E, crate::monitor::handler::PayloadCtx>,
    ) -> Self {
        self.detector_names.push(name);
        self.on_ctx::<E>(handler)
    }

    /// Register an async handler for event type `E`.
    ///
    /// The handler closure receives `&E::Payload` only — no
    /// `&mut Ctx<'_>` access. Async closures that need shared
    /// state should capture an `Arc<…>` themselves; closures
    /// that need to emit anomalies should pair with a
    /// [`crate::anomaly::shipped_sinks::ChannelSink`] in the
    /// sync `on::<E>` path (anomalies cross the channel to a
    /// downstream async task that does the I/O).
    ///
    /// Each dispatched event pays **one boxed-future allocation
    /// per async handler**. Prefer sync [`Self::on`] when the body
    /// doesn't actually `.await`.
    ///
    /// Sync and async handlers for the same event compose: sync
    /// runs first (zero-cost dispatch), then async fires
    /// sequentially.
    pub fn on_async<E, H>(mut self, handler: H) -> Self
    where
        E: Event,
        H: AsyncHandler<E>,
    {
        self.handlers.register_async::<E, H>(handler);
        self
    }

    /// Pre-register a `T: Default` state slot. Optional —
    /// `Ctx::state_mut::<T>()` lazy-creates on first access; this
    /// call surfaces typos at build time and lets you set
    /// non-default initial state by reaching through the builder
    /// (see [`Self::state_with`]).
    pub fn state<T: Default + Send + 'static>(mut self) -> Self {
        let _ = self.state_map.get_or_init_mut::<T>();
        self
    }

    /// Pre-register `T` with a caller-supplied initial value.
    /// Replaces any prior `T` in the slot. 0.21 A.4: the `Default`
    /// bound is dropped — any `T: Send + 'static` works now.
    pub fn state_with<T: Send + 'static>(mut self, value: T) -> Self {
        self.state_map.insert(value);
        self
    }

    /// Pre-register `T` via a factory closure. Lets you populate the
    /// state map with types that don't implement `Default` (e.g.
    /// `Arc<DashMap>`, `Mutex<X>`, anything wrapping a non-default
    /// handle). Closure runs once at build time; the resulting `T` is
    /// inserted via [`StateMap::insert`]. Equivalent to
    /// `state_with(factory())` but reads cleaner when the factory has
    /// side effects (opening a file, allocating an arena, etc.).
    pub fn state_init<T, F>(mut self, factory: F) -> Self
    where
        T: Send + 'static,
        F: FnOnce() -> T,
    {
        self.state_map.insert(factory());
        self
    }

    /// Register a [`TimeBucketedCounter<K>`] with the given
    /// sliding-window + per-bucket widths.
    pub fn counter<K>(mut self, window: Duration, bucket: Duration) -> Self
    where
        K: std::hash::Hash + Eq + Clone + Send + 'static,
    {
        // 0.21 G: flowscope's `TimeBucketedCounter::new` grew a 3rd
        // capacity arg; use `new_unbounded` to preserve the 2-arg
        // builder shape.
        self.counters
            .register::<K>(TimeBucketedCounter::new_unbounded(window, bucket));
        self
    }

    /// Replace the default [`NoopSink`] with a user-supplied sink.
    pub fn sink<S: AnomalySink + 'static>(mut self, sink: S) -> Self {
        self.sink = Some(Box::new(sink));
        self
    }

    /// Wrap the sink chain in `layer`. **The first registered
    /// layer is the outermost** — it sees every emission first,
    /// before subsequent layers and the underlying sink.
    ///
    /// ```ignore
    /// .layer(MinSeverity::warning())    // outermost
    /// .layer(DedupeAnomalies::within(Duration::from_secs(60)))
    /// .sink(StdoutJsonSink::default())  // innermost
    /// ```
    ///
    /// At runtime: emit → MinSeverity.write → Dedupe.write →
    /// StdoutJsonSink.write. So `MinSeverity` drops anything
    /// below Warning before `Dedupe` ever sees it.
    pub fn layer<L: Layer + 'static>(mut self, layer: L) -> Self {
        self.layers.push(Box::new(layer));
        self
    }

    /// Periodic tick handler.
    ///
    /// Phase F.2 lights this up — the run loop now polls a per-handler
    /// tokio interval alongside the packet stream. The first tick
    /// fires one `period` after run-loop start (not immediately);
    /// missed ticks (from a slow handler) are skipped, not queued.
    ///
    /// On each fire, the framework runs:
    /// 1. The closure passed here (the "ergonomic" registration),
    /// 2. The dispatcher's typed `Tick` slot — so any
    ///    `.on::<Tick>(handler)` registrations also fire.
    ///
    /// Both paths receive the same [`Tick`] payload + `&mut Ctx`.
    pub fn tick<H, M>(mut self, period: Duration, handler: H) -> Self
    where
        H: Handler<Tick, M>,
        M: 'static,
    {
        self.tick_handlers
            .push(TickRegistration::new(period, handler));
        self
    }

    /// Freeze the builder into a [`Monitor`].
    pub fn build(self) -> Result<Monitor> {
        if self.interfaces.is_empty() {
            return Err(BuildError::NoInterface.into());
        }
        // 0.21 A.6: build-time validation — every counter type
        // a detector declared via `detector! { counters: [K] }`
        // must have been registered via `.counter::<K>(...)` on
        // this builder. Catches the typo `:: counter ::<Ipv4>`
        // vs `IpAddr` before the first packet arrives.
        let registered = self.counters.registered_type_names();
        for (detector, slugs) in &self.declared_counters {
            for slug in slugs {
                if !registered.contains(slug) {
                    return Err(BuildError::CounterNotRegistered {
                        detector,
                        type_name: slug,
                    }
                    .into());
                }
            }
        }
        let driver = self
            .driver_builder
            .unwrap_or_else(|| Driver::builder(FiveTuple::bidirectional()))
            .build();
        let dispatcher = self.handlers.into_dispatcher()?;
        let base_sink: Box<dyn AnomalySink> = self.sink.unwrap_or_else(|| Box::new(NoopSink));
        // Apply layers innermost-first so the first .layer(X)
        // call ends up outermost in the runtime chain. See the
        // .layer rustdoc for the ordering convention.
        let mut sink = base_sink;
        for layer in self.layers.into_iter().rev() {
            sink = layer.wrap(sink);
        }
        Ok(Monitor {
            interfaces: self.interfaces,
            driver,
            dispatcher,
            protocol_slots: self.protocol_slots,
            detector_names: self.detector_names,
            state_map: self.state_map,
            counters: self.counters,
            sink,
            tick_handlers: self.tick_handlers,
            monitor_name: self.monitor_name,
        })
    }
}

impl std::fmt::Debug for MonitorBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitorBuilder")
            .field("interfaces", &self.interfaces)
            .field("protocol_slots", &self.protocol_slots.len())
            .field("handler_type_count", &self.handlers.type_count())
            .field("handler_count", &self.handlers.handler_count())
            .field("state_slots", &self.state_map.len())
            .field("counter_slots", &self.counters.len())
            .field("tick_handlers", &self.tick_handlers.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::Ctx;
    use crate::protocol::builtin::Tcp;
    use crate::protocol::event_typed::FlowStarted;

    #[test]
    fn build_without_interface_fails() {
        let err = Monitor::builder().build().unwrap_err();
        match err {
            crate::error::Error::Build(BuildError::NoInterface) => {}
            other => panic!("expected NoInterface, got {other:?}"),
        }
    }

    #[test]
    fn detector_names_records_on_named_and_detect_in_order() {
        let m = Monitor::builder()
            .interface("lo")
            .on_named::<FlowStarted<Tcp>>("Alpha", |_e: &FlowStarted<Tcp>, _c: &mut Ctx<'_>| Ok(()))
            .on_named::<FlowStarted<Tcp>>("Beta", |_e: &FlowStarted<Tcp>, _c: &mut Ctx<'_>| Ok(()))
            // Anonymous registrations do not show up in detector_names.
            .on::<FlowStarted<Tcp>>(|_e: &FlowStarted<Tcp>| Ok(()))
            .build()
            .unwrap();
        let names: Vec<&'static str> = m.detector_names().collect();
        assert_eq!(names, vec!["Alpha", "Beta"]);
    }

    #[test]
    fn state_init_accepts_non_default_type() {
        struct Handle(u32);
        impl Handle {
            fn open() -> Self {
                Self(42)
            }
        }
        let mut m = Monitor::builder()
            .interface("lo")
            .state_init::<Handle, _>(Handle::open)
            .build()
            .unwrap();
        // State map carries Handle even though it has no Default.
        let h: &mut Handle = m.state_map.get_or_init_with::<Handle, _>(|| Handle(0));
        assert_eq!(h.0, 42);
    }

    #[test]
    fn build_with_multiple_interfaces_succeeds() {
        // Phase F.1: multi-interface accepted. Build doesn't open
        // any AF_PACKET rings — that happens at run-loop start —
        // so two interfaces succeed at build even without root.
        let m = Monitor::builder()
            .interfaces(["lo", "eth0"])
            .on::<FlowStarted<Tcp>>(|_evt: &FlowStarted<Tcp>| Ok(()))
            .build()
            .unwrap();
        assert_eq!(m.interfaces, vec!["lo".to_string(), "eth0".to_string()]);
    }

    #[test]
    fn build_with_single_interface_succeeds() {
        // 0.21 A.2: `.on::<E>` takes one generic (E), marker fixed
        // to `PayloadOnly`. The `, _` is for the closure's H type
        // inferred by the compiler.
        let m = Monitor::builder()
            .interface("lo")
            .on::<FlowStarted<Tcp>>(|_evt: &FlowStarted<Tcp>| Ok(()))
            .build()
            .unwrap();
        assert_eq!(m.interfaces, vec!["lo".to_string()]);
    }

    #[test]
    #[allow(deprecated)]
    fn build_with_legacy_on_with_marker_still_compiles() {
        // 0.21 A.2 deprecation gate: confirm the 0.20 three-generic
        // form still compiles for one cycle. Removed in 0.22.
        let _ = Monitor::builder()
            .interface("lo")
            .on_with_marker::<FlowStarted<Tcp>, _, _>(|_evt: &FlowStarted<Tcp>| Ok(()))
            .build()
            .unwrap();
    }

    #[test]
    fn builder_state_pre_registration_visible_at_build() {
        #[derive(Default)]
        struct S;
        let m = Monitor::builder()
            .interface("lo")
            .state::<S>()
            .build()
            .unwrap();
        assert_eq!(m.state_map.len(), 1);
    }

    #[test]
    fn builder_state_with_initialiser_replaces_default() {
        #[derive(Default, Debug, PartialEq)]
        struct S {
            n: u32,
        }
        let mut m = Monitor::builder()
            .interface("lo")
            .state_with(S { n: 17 })
            .build()
            .unwrap();
        assert_eq!(m.state_map.get_or_init_mut::<S>().n, 17);
    }

    #[test]
    fn builder_counter_registration_visible_at_build() {
        let mut m = Monitor::builder()
            .interface("lo")
            .counter::<u32>(Duration::from_secs(10), Duration::from_secs(1))
            .build()
            .unwrap();
        assert_eq!(m.counters.len(), 1);
        m.counters
            .get_mut::<u32>()
            .bump(1u32, flowscope::Timestamp::new(0, 0));
    }

    #[test]
    fn builder_tick_registration_is_recorded() {
        let m = Monitor::builder()
            .interface("lo")
            .tick(Duration::from_millis(100), |_t: &Tick| Ok(()))
            .build()
            .unwrap();
        assert_eq!(m.tick_handlers.len(), 1);
    }

    #[cfg(feature = "http")]
    #[test]
    fn builder_with_http_protocol_registers_slot() {
        use crate::protocol::builtin::Http;
        let m = Monitor::builder()
            .interface("lo")
            .protocol::<Http>()
            .build()
            .unwrap();
        assert_eq!(m.protocol_slots.len(), 1);
    }

    #[test]
    fn builder_with_lifecycle_only_marker_skips_slot() {
        let m = Monitor::builder()
            .interface("lo")
            .protocol::<Tcp>()
            .build()
            .unwrap();
        assert_eq!(m.protocol_slots.len(), 0);
    }
}
