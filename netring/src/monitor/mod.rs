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
//!     .on::<Http>(|msg| {
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
pub struct Monitor {
    pub(crate) interface: String,
    pub(crate) driver: Driver<FiveTuple>,
    pub(crate) dispatcher: Dispatcher,
    pub(crate) protocol_slots: Vec<Box<dyn ProtocolSlot>>,
    pub(crate) state_map: StateMap,
    pub(crate) counters: CounterRegistry,
    pub(crate) sink: Box<dyn AnomalySink>,
    pub(crate) tick_handlers: Vec<TickRegistration>,
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
}

impl std::fmt::Debug for Monitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Monitor")
            .field("interface", &self.interface)
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
    tick_handlers: Vec<TickRegistration>,
}

impl MonitorBuilder {
    /// Set the capture interface(s). Phase B accepts a single
    /// interface; calling with more produces
    /// [`BuildError::MultiInterfaceNotYetSupported`] at
    /// [`Self::build`] time.
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

    /// Register a handler for event type `E`.
    pub fn on<E, H, M>(mut self, handler: H) -> Self
    where
        E: Event,
        H: Handler<E, M>,
        M: 'static,
    {
        self.handlers.register::<E, H, M>(handler);
        self
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
    /// Replaces any prior `T` in the slot.
    pub fn state_with<T: Default + Send + 'static>(mut self, value: T) -> Self {
        *self.state_map.get_or_init_mut::<T>() = value;
        self
    }

    /// Register a [`TimeBucketedCounter<K>`] with the given
    /// sliding-window + per-bucket widths.
    pub fn counter<K>(mut self, window: Duration, bucket: Duration) -> Self
    where
        K: std::hash::Hash + Eq + Clone + Send + 'static,
    {
        self.counters
            .register::<K>(TimeBucketedCounter::new(window, bucket));
        self
    }

    /// Replace the default [`NoopSink`] with a user-supplied sink.
    pub fn sink<S: AnomalySink + 'static>(mut self, sink: S) -> Self {
        self.sink = Some(Box::new(sink));
        self
    }

    /// Periodic tick handler. **Phase B accepts the registration
    /// but does not yet fire the handler** — Phase F's per-CPU
    /// run loop adds the tick pump. The registration round-trips
    /// through the builder so user code can be written today
    /// without an API churn later.
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
        if self.interfaces.len() > 1 {
            return Err(BuildError::MultiInterfaceNotYetSupported.into());
        }
        let driver = self
            .driver_builder
            .unwrap_or_else(|| Driver::builder(FiveTuple::bidirectional()))
            .build();
        let dispatcher = self.handlers.into_dispatcher()?;
        let sink = self.sink.unwrap_or_else(|| Box::new(NoopSink));
        // interfaces.len() == 1 — pop it off so we don't keep two copies.
        let mut ifaces = self.interfaces;
        let interface = ifaces.remove(0);
        Ok(Monitor {
            interface,
            driver,
            dispatcher,
            protocol_slots: self.protocol_slots,
            state_map: self.state_map,
            counters: self.counters,
            sink,
            tick_handlers: self.tick_handlers,
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
    fn build_with_multiple_interfaces_fails() {
        let err = Monitor::builder()
            .interfaces(["lo", "eth0"])
            .build()
            .unwrap_err();
        match err {
            crate::error::Error::Build(BuildError::MultiInterfaceNotYetSupported) => {}
            other => panic!("expected MultiInterfaceNotYetSupported, got {other:?}"),
        }
    }

    #[test]
    fn build_with_single_interface_succeeds() {
        // Type-inference papercut: `.on` has three generics (E, H, M);
        // only E is named explicitly, so users supply `_, _` for the
        // others. Documented in the module rustdoc.
        let m = Monitor::builder()
            .interface("lo")
            .on::<FlowStarted<Tcp>, _, _>(|_evt: &FlowStarted<Tcp>| Ok(()))
            .build()
            .unwrap();
        assert_eq!(m.interface, "lo");
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
