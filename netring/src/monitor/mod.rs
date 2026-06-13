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
use crate::ctx::{Ctx, CounterRegistry, FlowStateRegistry, StateMap};
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
pub use handler::{CtxOnly, Handler, PayloadCtx, PayloadOnly};
pub use registry::{HandlerRegistry, ProtocolSlot, TypedBroadcastProtocolSlot, TypedProtocolSlot};
pub use tick::TickRegistration;

pub mod subscribe;
pub use subscribe::EventStream;

pub mod shard;
pub use shard::ShardedRunner;

// 0.22 §2.3: bandwidth-by-app primitive (gated with the rest of the
// monitor API on `flow + tokio`).
pub mod bandwidth;
pub use bandwidth::{BandwidthEntry, BandwidthReport, BandwidthSnapshot};

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
    /// 0.21 D.2: maximum time the run loop spends draining
    /// residual events after the stop condition fires. Default:
    /// 1 second. Tunable via [`MonitorBuilder::drain_timeout`].
    pub(crate) drain_timeout: Duration,
    /// 0.21 F: per-protocol broadcast handles keyed by
    /// `TypeId::of::<P>()`. Populated by
    /// [`MonitorBuilder::with_broadcast`]; consulted at
    /// [`Self::subscribe`] time to mint new subscribers via
    /// `BroadcastSlotHandle::clone`.
    pub(crate) broadcast_handles:
        rustc_hash::FxHashMap<std::any::TypeId, Box<dyn std::any::Any + Send + Sync>>,
    /// 0.21 E.1: declared pcap source path; consumed by
    /// [`Self::replay`] / [`Self::replay_with_config`].
    #[cfg(all(feature = "pcap", feature = "tokio"))]
    pub(crate) pcap_source_path: Option<std::path::PathBuf>,
    /// 0.21 E.1: pcap replay pacing factor. Threaded into the
    /// default `AsyncPcapConfig` used by `Self::replay`.
    #[cfg(all(feature = "pcap", feature = "tokio"))]
    pub(crate) pcap_speed_factor: Option<f32>,
    /// 0.21 I.7: per-flow user-state slots registered via
    /// [`MonitorBuilder::flow_state`]. Each entry's
    /// `FlowStateMap` lazy-creates `T::default()` per-flow on
    /// first `ctx.flow_state_mut::<T>()` access.
    pub(crate) flow_states: FlowStateRegistry,
    /// 0.21 C: optional AF_PACKET fanout config. When set, the
    /// run loop opens each `AsyncCapture` via `Capture::builder()
    /// .fanout(mode, group_id)` instead of the plain
    /// `AsyncCapture::open(iface)`. Used both by single-shard
    /// monitors (just one ring tagged with a fanout group_id) and
    /// by [`crate::monitor::shard::ShardedRunner`] (each shard
    /// thread shares the same group_id, kernel hashes packets to
    /// shards).
    pub(crate) fanout: Option<(crate::config::FanoutMode, u16)>,
    /// 0.22: active well-known label table for app/protocol-label
    /// lookups. Set via [`MonitorBuilder::label_table`]; defaults to
    /// flowscope's built-in table. Borrowed into every
    /// [`crate::ctx::Ctx`] at dispatch time.
    pub(crate) label_table: flowscope::well_known::LabelTable,
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

    /// 0.21 E.1: drive the dispatcher from a pcap/pcapng file
    /// instead of a live interface. Reads to EOF, runs the
    /// graceful drain phase, then returns.
    ///
    /// Requires the `pcap` Cargo feature + that
    /// [`MonitorBuilder::pcap_source`] was called.
    ///
    /// Single-source: pcap replay doesn't fan in across multiple
    /// files (use a small driver loop yourself if you need that).
    /// Tick handlers registered on the builder are NOT fired —
    /// pcap timestamps drift from wall-clock, so scheduling
    /// ticks against them is ambiguous. Use `.on::<Tick>(...)`
    /// for capture-time-based aggregation in live mode; for
    /// pcap, hook the lifecycle events directly.
    ///
    /// Returns
    /// [`crate::error::BuildError::PcapSourceRequired`] when
    /// `pcap_source` was not set on the builder.
    #[cfg(all(feature = "pcap", feature = "tokio"))]
    pub async fn replay(self) -> Result<()> {
        let path = self
            .pcap_source_path
            .clone()
            .ok_or(BuildError::PcapSourceRequired)?;
        // 0.21 E.1: pick up `pcap_speed_factor` if the builder set
        // it. Other fields stay at AsyncPcapConfig defaults; users
        // wanting full control reach for `replay_with_config`.
        let mut config = crate::pcap_source::AsyncPcapConfig::default();
        if let Some(factor) = self.pcap_speed_factor {
            config.replay_speed = factor;
        }
        run::replay_loop(self, path, config).await
    }

    /// 0.21 E.1: as [`Self::replay`] but with a caller-supplied
    /// [`crate::pcap_source::AsyncPcapConfig`] — useful when
    /// you need a tighter queue depth, packet-timestamp pacing,
    /// or loop-at-EOF behavior.
    #[cfg(all(feature = "pcap", feature = "tokio"))]
    pub async fn replay_with_config(
        self,
        config: crate::pcap_source::AsyncPcapConfig,
    ) -> Result<()> {
        let path = self
            .pcap_source_path
            .clone()
            .ok_or(BuildError::PcapSourceRequired)?;
        run::replay_loop(self, path, config).await
    }

    /// 0.21 F: subscribe to broadcast messages for broadcast-registered protocol `P`.
    ///
    /// Returns an [`EventStream`] over `P::Message` — each
    /// subscriber has its own private queue and receives every
    /// emitted message (until the queue overflows
    /// [`crate::monitor::EventStream::pending`] caps, which is
    /// caller-managed via `recv_many`'s `max`).
    ///
    /// Requires that `P` was registered via
    /// [`MonitorBuilder::with_broadcast`], not the regular
    /// [`MonitorBuilder::protocol`]. Returns
    /// [`crate::error::BuildError::ProtocolNotBroadcast`] on the
    /// mismatch — caught at first `subscribe()` call rather than
    /// silently never firing.
    ///
    /// Takes `&self`: a monitor may have multiple subscribers
    /// minted before being moved into `run_until` / `run_for` /
    /// `run_until_signal`. The subscribers outlive the run loop.
    pub fn subscribe<P: crate::protocol::MessageProtocol>(
        &self,
    ) -> Result<EventStream<P::Message>>
    where
        P::Message: Send + Sync + Clone + 'static,
    {
        let id = std::any::TypeId::of::<P>();
        let not_broadcast = BuildError::ProtocolNotBroadcast {
            protocol_name: P::NAME,
        };
        let handle = self.broadcast_handles.get(&id).ok_or(not_broadcast)?;
        let handle = handle
            .downcast_ref::<flowscope::driver::BroadcastSlotHandle<
                P::Message,
                flowscope::extract::FiveTupleKey,
            >>()
            .ok_or(BuildError::ProtocolNotBroadcast {
                protocol_name: P::NAME,
            })?;
        Ok(EventStream::new(handle.clone()))
    }

    /// 0.21 E.2: run until `window` of inactivity.
    ///
    /// The run loop resets a deadline each time a packet batch
    /// arrives (or a tick fires); if the deadline expires before
    /// the next event, the loop exits. Useful for:
    ///
    /// - **pcap replay** — auto-stop after EOF + a small grace
    ///   window so trailing periodic-sweep events still land.
    /// - **one-shot scans** — record traffic until the upstream
    ///   source stops cleanly.
    /// - **test fixtures** — exit deterministically once the
    ///   synthetic traffic generator is done.
    ///
    /// The initial deadline starts ticking from `run_until_idle`
    /// invocation, not from the first packet — so a monitor that
    /// never sees any traffic will exit after `window` regardless.
    pub async fn run_until_idle(self, window: Duration) -> Result<()> {
        run::run_loop(self, run::StopCondition::Idle(window)).await
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

    /// 0.21 C: how many shards this monitor represents.
    ///
    /// A regular [`Monitor`] returns `1` — it is a single shard.
    /// Multi-shard execution lives in
    /// [`crate::monitor::ShardedRunner`] which spawns N copies of
    /// independent monitors. This accessor exists for symmetry
    /// with `ShardedRunner::shard_count` so user code can
    /// instrument without branching on the runner type.
    pub fn shard_count(&self) -> usize {
        1
    }

    /// 0.21 C: the AF_PACKET fanout config set via
    /// [`MonitorBuilder::fanout`], or `None` if not configured.
    pub fn fanout(&self) -> Option<(crate::config::FanoutMode, u16)> {
        self.fanout
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
    /// 0.21 D.2: graceful-drain budget. `None` until
    /// [`Self::drain_timeout`] is called; defaults to 1 second
    /// at [`Self::build`] time.
    drain_timeout: Option<Duration>,
    /// 0.21 D.1: TypeIds of protocol markers registered via
    /// `.protocol::<P>()`, paired with each marker's stable
    /// `Protocol::NAME` slug. Consulted at `build()` time against
    /// [`HandlerRegistry::required_protocols`] to surface
    /// [`BuildError::HandlerForUnregisteredProtocol`] when a
    /// handler requires a slot that was never installed.
    declared_protocols: rustc_hash::FxHashMap<std::any::TypeId, &'static str>,
    /// 0.21 F: per-protocol broadcast handles keyed by
    /// `TypeId::of::<P>()`. Populated by [`Self::with_broadcast`],
    /// passed through to [`Monitor::broadcast_handles`] at
    /// `build()` time.
    broadcast_handles:
        rustc_hash::FxHashMap<std::any::TypeId, Box<dyn std::any::Any + Send + Sync>>,
    /// 0.21 E.1: when `Some`, build() relaxes the [`Self::interface`]
    /// requirement (replay mode doesn't open AF_PACKET rings).
    /// The path itself is consumed by [`Monitor::replay`] /
    /// [`Monitor::replay_with_config`]; storing it on the
    /// builder rather than `Monitor` so replay-mode builders
    /// can short-circuit `NoInterface`.
    #[cfg(all(feature = "pcap", feature = "tokio"))]
    pcap_source_path: Option<std::path::PathBuf>,
    /// 0.21 I.7: per-flow state slot registry.
    flow_states: FlowStateRegistry,
    /// 0.21 C: optional AF_PACKET fanout config; see
    /// [`Monitor::fanout`].
    fanout: Option<(crate::config::FanoutMode, u16)>,
    /// 0.21 E.1: pcap replay pacing factor; threaded into the
    /// default `AsyncPcapConfig` used by `Monitor::replay`. `None`
    /// = no pacing (as-fast-as-possible). Set via
    /// [`Self::pcap_speed_factor`].
    #[cfg(all(feature = "pcap", feature = "tokio"))]
    pcap_speed_factor: Option<f32>,
    /// 0.22: optional custom well-known label table. `None` → the
    /// flowscope built-in table is used. Set via
    /// [`Self::label_table`]; moved into [`Monitor::label_table`] at
    /// build.
    label_table: Option<flowscope::well_known::LabelTable>,
    /// 0.22 §2.3: set once `bandwidth_by_app` / `bandwidth_windowed` /
    /// `on_bandwidth` has installed the recorder, so repeated calls
    /// (e.g. `on_bandwidth` after an explicit `bandwidth_windowed`)
    /// don't double-register the per-packet handler and double-count.
    bandwidth_registered: bool,
}

impl MonitorBuilder {
    /// 0.22: use a custom [`LabelTable`](flowscope::well_known::LabelTable)
    /// for app/protocol-label lookups in this monitor.
    ///
    /// Site deployments register internal services (e.g. gRPC on
    /// 8765, telemetry on 9101) without forking flowscope's
    /// well-known table:
    ///
    /// ```ignore
    /// let mut table = flowscope::well_known::LabelTable::new(); // inherits built-ins
    /// table.set(flowscope::L4Proto::Tcp, 8765, "grpc");
    /// Monitor::builder().interface("eth0").label_table(table)…
    /// ```
    ///
    /// The table is read at dispatch via
    /// [`Ctx::label_table`](crate::ctx::Ctx::label_table) and used by
    /// [`MonitorBuilder::bandwidth_by_app`] (0.22) when both are set.
    /// Defaults to flowscope's built-in table when unset.
    pub fn label_table(mut self, table: flowscope::well_known::LabelTable) -> Self {
        self.label_table = Some(table);
        self
    }

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
    /// The name surfaces on every dispatched
    /// [`Ctx`](crate::ctx::Ctx) as
    /// [`Ctx::monitor_name`](crate::ctx::Ctx::monitor_name)
    /// (`Option<&'a str>`); user handlers
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

    /// 0.21 D.2: maximum time the run loop spends draining
    /// residual events after the stop condition fires.
    ///
    /// On shutdown (SIGINT/SIGTERM or deadline reached), the run
    /// loop calls `driver.finish()` to flush in-flight flows, then
    /// drains each protocol slot's queued messages, then flushes
    /// the anomaly sink. Each step is best-effort and bounded by
    /// this budget; if the deadline expires, the remaining drain
    /// steps are skipped to avoid hanging on a stuck sink.
    ///
    /// Default: 1 second. Pass `Duration::ZERO` to skip the drain
    /// entirely (events queued at shutdown are dropped on the
    /// floor — useful for fail-fast smoke tests).
    pub fn drain_timeout(mut self, t: Duration) -> Self {
        self.drain_timeout = Some(t);
        self
    }

    /// 0.21 E.1: declare a pcap source. Setting this:
    ///
    /// - Skips the `BuildError::NoInterface` check in
    ///   [`Self::build`] (replay mode doesn't open AF_PACKET).
    /// - Records the path on the builder for
    ///   [`Monitor::replay`] / [`Monitor::replay_with_config`].
    ///
    /// Requires the `pcap` Cargo feature.
    #[cfg(all(feature = "pcap", feature = "tokio"))]
    pub fn pcap_source(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.pcap_source_path = Some(path.into());
        self
    }

    /// 0.21 E.1: pace pcap replay by `factor`.
    ///
    /// - `0.0` (default; unset) — replay as fast as possible.
    /// - `1.0` — replay at the packet's recorded wire rate.
    /// - `0.5` / `2.0` — half / double the recorded speed.
    ///
    /// Wire-speed pacing relies on `std::thread::sleep`, which on
    /// Linux has ~1–10 ms granularity; sub-millisecond timing
    /// stretches are best-effort.
    ///
    /// Equivalent to setting `replay_speed = factor` on an
    /// [`AsyncPcapConfig`](crate::pcap_source::AsyncPcapConfig)
    /// directly, but more ergonomic for the common "just slow
    /// it down to wire-speed" case.
    ///
    /// Requires the `pcap` Cargo feature.
    #[cfg(all(feature = "pcap", feature = "tokio"))]
    pub fn pcap_speed_factor(mut self, factor: f32) -> Self {
        self.pcap_speed_factor = Some(factor);
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
            // 0.22 §2.5: the protocol chooses its slot type. Default is
            // `TypedProtocolSlot<P>`; `Icmp` installs an `IcmpSlot`.
            self.protocol_slots.push(P::make_slot(handle));
        }
        // Err(_) = lifecycle-only; nothing to register on the driver
        // side. Still record the marker in `declared_protocols` so
        // 0.21 D.1's handler-protocol validation accepts handlers
        // typed on lifecycle markers when `.protocol::<Tcp>()` was
        // called for symmetry.
        self.declared_protocols
            .insert(std::any::TypeId::of::<P>(), P::NAME);
        self
    }

    /// 0.22 §2.7: register every L4 protocol in one call —
    /// `Tcp` + `Udp` + `Icmp` (the ICMP arm is present only with the
    /// `icmp` feature). Removes the "registered Tcp + Udp but forgot
    /// Icmp, why aren't my unreachables firing?" foot-gun.
    pub fn all_l4(self) -> Self {
        let s = self
            .protocol::<crate::protocol::builtin::Tcp>()
            .protocol::<crate::protocol::builtin::Udp>();
        #[cfg(feature = "icmp")]
        let s = s.protocol::<crate::protocol::builtin::Icmp>();
        s
    }

    /// 0.22 §2.7: register every available L7 parser — `Http`, `Dns`,
    /// `Tls`, and `TlsHandshake`, each gated on its Cargo feature. On
    /// a build with none of `http`/`dns`/`tls`, this method is absent.
    #[cfg(any(feature = "http", feature = "dns", feature = "tls"))]
    pub fn all_l7(self) -> Self {
        let s = self;
        #[cfg(feature = "http")]
        let s = s.protocol::<crate::protocol::builtin::Http>();
        #[cfg(feature = "dns")]
        let s = s.protocol::<crate::protocol::builtin::Dns>();
        #[cfg(feature = "tls")]
        let s = s
            .protocol::<crate::protocol::builtin::Tls>()
            .protocol::<crate::protocol::builtin::TlsHandshake>();
        s
    }

    /// 0.22 §2.6: handle TCP connection resets.
    ///
    /// The handler fires for each
    /// [`TcpRst`](crate::protocol::event_typed::TcpRst) synthesised
    /// from a `FlowEnded<Tcp>` whose `reason == EndReason::Rst` —
    /// clean FIN / idle eviction don't fire it. The handler receives
    /// the reset plus `&mut Ctx` (so it can emit). Implicitly declares
    /// `Tcp`. (Fixed `PayloadCtx` shape — like `on_ctx` — so untyped
    /// closures infer cleanly; for payload-only, ignore the `ctx` arg.)
    ///
    /// ```ignore
    /// Monitor::builder()
    ///     .interface("eth0")
    ///     .on_tcp_reset(|rst, ctx| {
    ///         ctx.emit("TcpReset", if rst.zero_payload { Severity::Info } else { Severity::Warning })
    ///             .with_key(&rst.key)
    ///             .emit();
    ///         Ok(())
    ///     })
    /// ```
    pub fn on_tcp_reset(
        self,
        handler: impl Handler<
            crate::protocol::event_typed::TcpRst,
            crate::monitor::handler::PayloadCtx,
        >,
    ) -> Self {
        let mut s = self.protocol::<crate::protocol::builtin::Tcp>();
        s.handlers
            .register::<crate::protocol::event_typed::TcpRst, _, crate::monitor::handler::PayloadCtx>(
                handler,
            );
        s
    }

    /// 0.22 §2.3: register a per-app rolling byte-rate keyed by the
    /// flow's well-known app label (`"http"`, `"https"`, `"dns"`,
    /// site-custom labels from a [`Self::label_table`]).
    ///
    /// Implicitly declares `Tcp` + `Udp` and installs one internal
    /// per-packet recorder. Read the rate back via
    /// [`Ctx::bandwidth`](crate::ctx::Ctx::bandwidth) or, more
    /// ergonomically, [`Self::on_bandwidth`]. Idempotent — calling it
    /// more than once (or alongside `on_bandwidth`) registers the
    /// recorder exactly once. Default window/bucket are 10s/1s; use
    /// [`Self::bandwidth_windowed`] to override.
    pub fn bandwidth_by_app(self) -> Self {
        self.bandwidth_windowed(bandwidth::BW_WINDOW, bandwidth::BW_BUCKET)
    }

    /// 0.22 §2.3: as [`Self::bandwidth_by_app`], with an explicit
    /// rolling `window` and `bucket` width (e.g. a wider window for a
    /// low-rate link). The first bandwidth registration on a builder
    /// wins; later ones are no-ops.
    pub fn bandwidth_windowed(mut self, window: Duration, bucket: Duration) -> Self {
        if self.bandwidth_registered {
            return self;
        }
        self.bandwidth_registered = true;
        self.protocol::<crate::protocol::builtin::Tcp>()
            .protocol::<crate::protocol::builtin::Udp>()
            .state_init::<bandwidth::BandwidthState, _>(move || {
                bandwidth::BandwidthState::new(window, bucket)
            })
            .on_ctx::<crate::protocol::event_typed::FlowPacket>(
                |evt: &crate::protocol::event_typed::FlowPacket, ctx: &mut Ctx<'_>| {
                    // app_label_with is always-some (&'static str); the
                    // label borrow ends at the statement, then we take a
                    // disjoint &mut on the state slot.
                    let label = evt.key.app_label_with(ctx.label_table());
                    let ts = ctx.ts;
                    ctx.state_mut::<bandwidth::BandwidthState>()
                        .0
                        .record(label, evt.len as u64, ts);
                    Ok(())
                },
            )
    }

    /// 0.22 §2.3: the high-level fused bandwidth monitor. Registers
    /// `bandwidth_by_app()` (if not already) **and** a periodic report;
    /// the closure receives a ready [`BandwidthReport`] every `period`.
    ///
    /// ```ignore
    /// Monitor::builder()
    ///     .interface(iface)
    ///     .on_bandwidth(Duration::from_secs(5), |bw| {
    ///         for (app, bps) in bw.top(10) { println!("{app}: {bps:>10.0} B/s"); }
    ///         Ok(())
    ///     })
    ///     .run_until_signal().await?;
    /// ```
    pub fn on_bandwidth<F>(self, period: Duration, f: F) -> Self
    where
        F: Fn(&BandwidthReport<'_>) -> Result<()> + Send + Sync + 'static,
    {
        self.bandwidth_by_app().tick(
            period,
            move |_tick: &crate::protocol::event_typed::Tick, ctx: &mut Ctx<'_>| {
                if let Some(report) = ctx.bandwidth() {
                    f(&report)?;
                }
                Ok(())
            },
        )
    }

    /// 0.22 §2.5: handle ICMP errors — Destination Unreachable / Time
    /// Exceeded / Parameter Problem / PMTU (v4 + v6), pre-classified and
    /// with the originating flow joined.
    ///
    /// Implicitly declares `Icmp`, which installs the
    /// `IcmpError`-synthesising drain slot. The handler receives the
    /// [`IcmpError`](crate::protocol::event_typed::IcmpError) plus
    /// `&mut Ctx`. Sync-only for 0.22.
    ///
    /// ```ignore
    /// .on_icmp_error(|err, ctx| {
    ///     if let Some(flow) = err.correlated_flow {
    ///         ctx.emit("FlowKilledByIcmp", Severity::Warning)
    ///             .with_key(&flow)
    ///             .with("kind", err.kind.as_str())
    ///             .emit();
    ///     }
    ///     Ok(())
    /// })
    /// ```
    #[cfg(feature = "icmp")]
    pub fn on_icmp_error(
        self,
        handler: impl Handler<
            crate::protocol::event_typed::IcmpError,
            crate::monitor::handler::PayloadCtx,
        >,
    ) -> Self {
        let mut s = self.protocol::<crate::protocol::builtin::Icmp>();
        s.handlers.register::<crate::protocol::event_typed::IcmpError, _, crate::monitor::handler::PayloadCtx>(
            handler,
        );
        s
    }

    /// 0.21 F: register `P` for broadcast delivery.
    ///
    /// Calls [`Protocol::register_broadcast`] on the underlying
    /// flowscope driver — only protocols that override the
    /// default (currently [`crate::protocol::builtin::Http`])
    /// accept this. The returned [`flowscope::driver::BroadcastSlotHandle`]
    /// is cloned twice: one clone wraps a
    /// [`TypedBroadcastProtocolSlot`] for the run loop's dispatch
    /// drain; the other lives in the monitor's `broadcast_handles`
    /// map so [`Monitor::subscribe`] can clone fresh subscribers.
    ///
    /// Mutually exclusive with [`Self::protocol::<P>`] — call ONE
    /// or the other, not both. (Calling both would register two
    /// slots for the same parser.)
    ///
    /// ```ignore
    /// let monitor = Monitor::builder()
    ///     .interface("eth0")
    ///     .with_broadcast::<Http>()    // not `.protocol::<Http>()`
    ///     .build()?;
    /// let mut stream = monitor.subscribe::<Http>()?;
    /// ```
    pub fn with_broadcast<P: crate::protocol::MessageProtocol>(mut self) -> Self
    where
        P::Message: Send + Sync + Clone + 'static,
    {
        let builder = self
            .driver_builder
            .get_or_insert_with(|| Driver::builder(FiveTuple::bidirectional()));
        match P::register_broadcast(builder) {
            Ok(handle) => {
                // Clone twice: one for the dispatcher slot drain,
                // one stored for subscribe() to clone from.
                let dispatcher_clone = handle.clone();
                self.protocol_slots
                    .push(Box::new(TypedBroadcastProtocolSlot::<P>::new(
                        dispatcher_clone,
                    )));
                self.broadcast_handles
                    .insert(std::any::TypeId::of::<P>(), Box::new(handle));
            }
            Err(_) => {
                // The default `register_broadcast` returns Err for
                // any Protocol that hasn't overridden it. Treat it
                // as a quiet no-op here; the user will discover the
                // mismatch when `monitor.subscribe::<P>()` fails
                // with `BuildError::ProtocolNotBroadcast`.
            }
        }
        self.declared_protocols
            .insert(std::any::TypeId::of::<P>(), P::NAME);
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

    // 0.22: the deprecated three-generic `on_with_marker` is removed —
    // use `.on::<E>(handler)` or `.on_ctx::<E>(handler)`.

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

    /// 0.21 I.7: register a per-flow state slot of type `T`.
    ///
    /// `idle_timeout` mirrors the underlying flow tracker's
    /// idle-timeout for eviction cadence — a slot ages out of
    /// the [`flowscope::correlate::FlowStateMap`] after this
    /// many seconds of inactivity.
    ///
    /// `T: Default` because the slot lazily creates on first
    /// `ctx.flow_state_mut::<T>()` access. For `T` types
    /// without a `Default` impl, wrap with
    /// `Default`-implementing newtype or pre-register
    /// per-handler via [`Self::state_init`] (which is global
    /// per-monitor, not per-flow).
    ///
    /// ```ignore
    /// Monitor::builder()
    ///     .interface("eth0")
    ///     .flow_state::<MyPerFlowState>(Duration::from_secs(60))
    ///     .protocol::<Tcp>()
    ///     .on_ctx::<FlowStarted<Tcp>>(|_e, ctx| {
    ///         let s = ctx.flow_state_mut::<MyPerFlowState>().unwrap();
    ///         s.bytes = 0;
    ///         Ok(())
    ///     });
    /// ```
    pub fn flow_state<T>(mut self, idle_timeout: Duration) -> Self
    where
        T: Default + Send + 'static,
    {
        self.flow_states.register::<T>(idle_timeout);
        self
    }

    /// 0.21 C: tag this monitor's [`crate::AsyncCapture`] with an
    /// AF_PACKET fanout group.
    ///
    /// Single-shard usage: lets the kernel distribute packets
    /// across multiple `Capture`s sharing the same group_id (e.g.
    /// one Capture per CPU, all calling this with the same id).
    /// netring's `ShardedRunner` uses this internally to wire its
    /// per-shard captures into one shared fanout group.
    ///
    /// `group_id` must be the same across all shards/captures
    /// that should share traffic; the kernel hashes per the
    /// `mode` (Cpu, Hash, EBPF, …) to select the destination
    /// ring for each packet.
    ///
    /// Most users on a single shard don't need this — just
    /// `.interface("eth0")` opens a normal ring. Set this only
    /// when interoperating with other AF_PACKET consumers or
    /// running [`crate::monitor::shard::ShardedRunner`].
    pub fn fanout(mut self, mode: crate::config::FanoutMode, group_id: u16) -> Self {
        self.fanout = Some((mode, group_id));
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

    /// 0.22 §7.4: periodic handler that ignores the `Tick` payload —
    /// `.tick_ctx(period, |ctx| { … })`.
    ///
    /// The same as [`Self::tick`] but with the
    /// [`CtxOnly`](crate::monitor::CtxOnly) marker fixed, so an untyped
    /// `|ctx|` closure isn't ambiguous between "payload only" and "ctx
    /// only" (both are arity-1). Most tick handlers never read the
    /// `Tick` fields, so this is the common case.
    pub fn tick_ctx(
        self,
        period: Duration,
        handler: impl Handler<Tick, crate::monitor::handler::CtxOnly>,
    ) -> Self {
        self.tick(period, handler)
    }

    /// 0.22 §3: periodic report — every `period`, call `f` with a typed
    /// [`ReportSnapshot`](crate::report::ReportSnapshot) of the
    /// monitor's registered primitives (bandwidth, counters, state).
    /// The ad-hoc / println form; see [`Self::report_to`] for a typed
    /// `Report` shipped to a [`ReportSink`](crate::report::ReportSink).
    pub fn report<F>(self, period: Duration, f: F) -> Self
    where
        F: Fn(crate::report::ReportSnapshot<'_, '_>) -> Result<()> + Send + Sync + 'static,
    {
        self.tick(period, move |tick: &Tick, ctx: &mut Ctx<'_>| {
            f(crate::report::ReportSnapshot {
                ctx,
                now: tick.now,
            })
        })
    }

    /// 0.22 §3: ship a typed [`Report`](crate::report::Report) to a
    /// [`ReportSink`](crate::report::ReportSink) every `period`.
    /// `build` constructs the `R` from a
    /// [`ReportSnapshot`](crate::report::ReportSnapshot); the framework
    /// drives the cadence.
    ///
    /// ```ignore
    /// .bandwidth_by_app()
    /// .report_to(Duration::from_secs(5),
    ///     |snap| snap.bandwidth().unwrap().to_snapshot(10),
    ///     JsonReportSink)
    /// ```
    pub fn report_to<R, B, S>(self, period: Duration, build: B, sink: S) -> Self
    where
        R: crate::report::Report,
        B: Fn(crate::report::ReportSnapshot<'_, '_>) -> R + Send + Sync + 'static,
        S: crate::report::ReportSink<R> + 'static,
    {
        // Tick handlers are stored behind `Arc<dyn Fn + Send + Sync>`, so
        // the sink needs interior mutability. The lock is taken once per
        // cadence tick (seconds), never on the packet path.
        let sink = std::sync::Mutex::new(sink);
        self.tick(period, move |tick: &Tick, ctx: &mut Ctx<'_>| {
            let report = build(crate::report::ReportSnapshot {
                ctx,
                now: tick.now,
            });
            if let Ok(mut s) = sink.lock() {
                s.record(&report);
            }
            Ok(())
        })
    }

    /// Freeze the builder into a [`Monitor`].
    pub fn build(self) -> Result<Monitor> {
        // 0.21 E.1: when a pcap source is declared, the
        // `NoInterface` check is relaxed — replay mode never
        // opens AF_PACKET.
        #[cfg(all(feature = "pcap", feature = "tokio"))]
        let interface_required = self.pcap_source_path.is_none();
        #[cfg(not(all(feature = "pcap", feature = "tokio")))]
        let interface_required = true;
        if interface_required && self.interfaces.is_empty() {
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
        // 0.21 D.1: every handler whose Event::protocol_marker
        // returns Some(p) must have `.protocol::<p>()` on the
        // builder. Catches handlers for L7 parser-emitted message
        // types where the user forgot to register the parser slot
        // — without this, the handler silently never fires.
        for (marker, name) in self.handlers.required_protocols() {
            if !self.declared_protocols.contains_key(&marker) {
                return Err(BuildError::HandlerForUnregisteredProtocol {
                    protocol_name: name,
                }
                .into());
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
            drain_timeout: self.drain_timeout.unwrap_or(Duration::from_secs(1)),
            broadcast_handles: self.broadcast_handles,
            #[cfg(all(feature = "pcap", feature = "tokio"))]
            pcap_source_path: self.pcap_source_path,
            #[cfg(all(feature = "pcap", feature = "tokio"))]
            pcap_speed_factor: self.pcap_speed_factor,
            flow_states: self.flow_states,
            fanout: self.fanout,
            // NOT `unwrap_or_default()`: `LabelTable::default()` derives
            // `inherit_builtin = false` (whitelist-only, like
            // `standalone()`), whereas `new()` inherits flowscope's
            // built-in well-known port table — which is what an
            // unconfigured monitor must get so `app_label` resolves
            // "http"/"dns"/… out of the box. (flowscope 0.15 wishlist:
            // make `Default` == `new`.)
            #[allow(clippy::unwrap_or_default)]
            label_table: self
                .label_table
                .unwrap_or_else(flowscope::well_known::LabelTable::new),
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
