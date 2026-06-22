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
use crate::ctx::{CounterRegistry, Ctx, FlowStateRegistry, StateMap};
use crate::error::{BuildError, Result};
use crate::layer::Layer;
use crate::protocol::Protocol;
use crate::protocol::event_typed::{Event, Tick};

// L2 ARP visibility + spoof/binding-change detection (feature `arp`).
#[cfg(feature = "arp")]
pub mod arp;
// L3 IPv6 Neighbor Discovery — the ARP sibling (feature `ndp`).
pub mod async_handler;
pub(crate) mod backend;
pub mod dispatcher;
pub mod effect;
#[cfg(feature = "tls")]
pub mod fingerprint;
pub mod handler;
pub mod health;
#[cfg(feature = "ndp")]
pub mod ndp;
pub mod registry;
pub mod run;
pub mod telemetry;
pub mod tick;

#[cfg(feature = "arp")]
pub use arp::{ArpAnomaly, ArpAnomalyKind};
pub use async_handler::{AsyncHandler, BoxFuture};
pub use dispatcher::{Dispatcher, MAX_EVENT_TYPES};
pub use effect::{EffectHandler, Effects};
#[cfg(all(feature = "http", feature = "ja4plus"))]
pub use fingerprint::HttpFingerprint;
#[cfg(feature = "tls")]
pub use fingerprint::TlsFingerprint;
pub use handler::{CtxOnly, Handler, PayloadCtx, PayloadOnly};
pub use health::{MonitorHealth, MonitorHealthSnapshot};
#[cfg(feature = "ndp")]
pub use ndp::{NdpAnomaly, NdpAnomalyKind};
pub use registry::{HandlerRegistry, ProtocolSlot, TypedBroadcastProtocolSlot, TypedProtocolSlot};
pub use telemetry::{CaptureHealth, CaptureTelemetry};
pub use tick::TickRegistration;

pub mod subscribe;
pub use subscribe::EventStream;

pub mod subscription;

pub mod shard;
pub use shard::ShardedRunner;

// Issue #6 M5 (Tier 2): per-queue sharded AF_XDP capture.
#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
pub mod xdp_shard;
#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
pub use xdp_shard::XdpShardedRunner;

// 0.22 §5.1: cross-shard state merging (internal; driven by ShardedRunner).
pub(crate) mod merge;

// 0.22 §2.3: bandwidth-by-app primitive (gated with the rest of the
// monitor API on `flow + tokio`).
pub mod bandwidth;
pub use bandwidth::{BandwidthEntry, BandwidthReport, BandwidthSnapshot};

/// How an AF_XDP capture interface obtains its redirect program (0.25 W1a).
///
/// A bare AF_XDP socket receives no packets until an XDP program redirects
/// traffic into its XSKMAP. `self_load` distinguishes the two ways a Monitor
/// gets one:
/// - `false` ([`MonitorBuilder::xdp_interface`]): the caller attaches a
///   redirect program out of band; the Monitor opens a plain socket.
/// - `true` ([`MonitorBuilder::xdp_interface_loaded`], requires `xdp-loader`):
///   the Monitor itself attaches the built-in redirect-all program and
///   registers the socket on its XSKMAP, so no external loader is needed.
#[cfg(feature = "af-xdp")]
#[derive(Clone, Debug)]
pub(crate) struct XdpIfaceSpec {
    pub(crate) iface: String,
    /// Only consulted on the `xdp-loader` path (the run loop's
    /// `open_xdp_backend`); without that feature it's always `false` and unread.
    #[cfg_attr(not(feature = "xdp-loader"), allow(dead_code))]
    pub(crate) self_load: bool,
    /// Issue #6: which RX queues to bind (self-loading path only). Stamped from
    /// the monitor-wide [`MonitorBuilder::xdp_queues`] when the run loop builds
    /// the backend specs; the constructors leave it at the default.
    #[cfg_attr(not(feature = "xdp-loader"), allow(dead_code))]
    pub(crate) queues: crate::xdp::Queues,
}

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
    /// 0.24 Phase B: AF_XDP capture interfaces (feature `af-xdp`). The run
    /// loop opens an `AnyBackend::Xdp` for each, alongside the AF_PACKET
    /// `interfaces`. See [`MonitorBuilder::xdp_interface`].
    #[cfg(feature = "af-xdp")]
    pub(crate) xdp_interfaces: Vec<XdpIfaceSpec>,
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
    /// 0.22 §5.1: when this monitor runs as a shard under a
    /// [`ShardedRunner`] with a registered merge, the run loop polls
    /// this for "hand me your `T` slot" probes. `None` for ordinary
    /// (non-merged) monitors — the run-loop branch is then disabled at
    /// zero cost. Injected by `ShardedRunner::run_inner` via
    /// [`Self::set_merge_rx`].
    pub(crate) merge_rx: Option<tokio::sync::mpsc::UnboundedReceiver<merge::MergeRequest>>,
    /// 0.24 Phase B: what to do when a handler returns `Err`. Default
    /// [`HandlerErrorPolicy::Propagate`] (tear down the monitor — the historic
    /// behavior); [`HandlerErrorPolicy::Isolate`] logs + counts and continues so
    /// one misbehaving detector or flow can't kill the pipeline.
    pub(crate) handler_error_policy: HandlerErrorPolicy,
    /// 0.24 Phase B: what to do when a capture backend errors. Default
    /// [`BackendErrorPolicy::FailFast`].
    pub(crate) backend_error_policy: BackendErrorPolicy,
    /// 0.24 Phase C1/C2: optional capture-telemetry sampling hook set via
    /// [`MonitorBuilder::on_capture_stats`]. When `None` the run loop
    /// never arms the sampling interval (zero cost). When `Some`, the run
    /// loop samples each source's cumulative kernel counters every
    /// `period` and invokes the handler with a [`CaptureTelemetry`] +
    /// `&mut Ctx`.
    pub(crate) capture_stats: Option<telemetry::CaptureStatsRegistration>,
    /// 0.24 Phase C4: shared health state. Always present (cheap — a
    /// handful of atomics); the run loop updates it and
    /// [`Self::health`] hands out cloneable [`MonitorHealth`] readers.
    pub(crate) health: std::sync::Arc<health::HealthState>,
    /// 0.24 Phase D1: flow exporters registered via
    /// [`MonitorBuilder::export_flows`]. The run loop builds a
    /// [`crate::export::FlowRecord`] for every `FlowEnded` and hands it
    /// to each. Empty (the common case) is zero cost.
    pub(crate) flow_exporters: Vec<Box<dyn crate::export::FlowExporter>>,
    /// 0.25 W1c: active-timeout period for interim flow-record export. When
    /// `Some` (and exporters exist), the run loop emits ongoing `FlowRecord`s
    /// for long-lived flows every period. See [`MonitorBuilder::export_active_timeout`].
    pub(crate) flow_active_timeout: Option<std::time::Duration>,
    /// 0.25 A1: packet-tier subscriptions. Dispatched inside the zero-copy
    /// drain (before flow tracking) for every captured frame matching the
    /// sub's filter. Empty (the common case) keeps the `track_into`-only
    /// hot loop — zero cost, dhat `Δ 0`.
    pub(crate) packet_subs: Vec<subscription::PacketSubscription>,
    /// 0.25 S2: the conservative kernel prefilter (OR-union of every consumer's
    /// traffic interest), or `None` for capture-all. Computed at build from the
    /// full consumer set so it's a superset (no starvation); the run loop
    /// applies it to each AF_PACKET capture via `set_filter`.
    pub(crate) kernel_prefilter: Option<crate::config::BpfFilter>,
    /// Issue #4: put every capture interface (AF_PACKET + AF_XDP) into
    /// promiscuous mode for the run's lifetime. Set via
    /// [`MonitorBuilder::promiscuous`].
    pub(crate) promiscuous: bool,
    /// Issue #6: which RX queues each self-loading AF_XDP interface binds.
    /// Default `Queues::Single(0)`; `Queues::Auto` captures the whole NIC.
    #[cfg(feature = "af-xdp")]
    pub(crate) xdp_queues: crate::xdp::Queues,
    /// Issue #6 M5 (Tier 2): pre-built AF_XDP backends injected by
    /// [`XdpShardedRunner`](crate::monitor::xdp_shard::XdpShardedRunner) — one
    /// per shard, drained as `AnyBackend::Xdp`. Not reopenable (the program +
    /// registration live outside the Monitor).
    #[cfg(feature = "af-xdp")]
    pub(crate) injected_xdp: Vec<crate::AsyncXdpSocket>,
    /// Issue #12: live ARP detector state (table + config + handlers). `Some`
    /// when any ARP hook was registered; the run loop parses each frame for
    /// ARP and drives this. `None` (the common case) keeps the drain free of
    /// the ARP parse.
    #[cfg(feature = "arp")]
    pub(crate) arp_watch: Option<arp::ArpWatch>,
    /// Issue #24: live NDP detector state (the ARP sibling). `Some` when any
    /// NDP hook was registered.
    #[cfg(feature = "ndp")]
    pub(crate) ndp_watch: Option<ndp::NdpWatch>,
}

/// How the run loop reacts when a handler (detector / sink / async handler)
/// returns an error. See [`MonitorBuilder::handler_error_policy`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HandlerErrorPolicy {
    /// Propagate the error and stop the monitor (the default; historic behavior).
    #[default]
    Propagate,
    /// Log + count the error and continue to the next event/packet. One bad
    /// detector or flow does not tear down the capture pipeline.
    Isolate,
}

/// How the run loop reacts when a capture backend errors (e.g. a readiness or
/// receive failure). See [`MonitorBuilder::backend_error_policy`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BackendErrorPolicy {
    /// Propagate the error and stop the monitor (the default).
    #[default]
    FailFast,
    /// Log + count the error and keep servicing the other capture sources.
    SkipSource,
    /// Log + count the error and **re-open** the failed source in place (0.25
    /// W1e) — same kind/filter as the original — so a transient backend fault
    /// (interface flap, driver reset) self-heals without tearing down the
    /// monitor. If the re-open itself fails, the source is left out (like
    /// [`Self::SkipSource`]) and retried on its next error; after many
    /// consecutive failures the monitor gives up (circuit breaker).
    Reopen,
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
    pub fn subscribe<P: crate::protocol::MessageProtocol>(&self) -> Result<EventStream<P::Message>>
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

    /// 0.24 Phase C4: a cloneable [`MonitorHealth`] handle for this
    /// monitor.
    ///
    /// Grab it **before** spawning the run loop, clone it into your
    /// health endpoint, and poll readiness/liveness while the loop runs:
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use netring::monitor::Monitor;
    /// # use netring::protocol::builtin::Tcp;
    /// # #[tokio::main] async fn main() -> Result<(), netring::Error> {
    /// let monitor = Monitor::builder().interface("eth0").protocol::<Tcp>().build()?;
    /// let health = monitor.health();
    /// let run = tokio::spawn(monitor.run_for(Duration::from_secs(30)));
    /// // ... in a /readyz handler: `health.is_ready()` ...
    /// // ... in a /healthz handler: `health.is_live(Duration::from_secs(10))` ...
    /// # let _ = (health, run);
    /// # Ok(())
    /// # }
    /// ```
    pub fn health(&self) -> MonitorHealth {
        MonitorHealth::new(self.health.clone())
    }

    /// 0.21 C: the AF_PACKET fanout config set via
    /// [`MonitorBuilder::fanout`], or `None` if not configured.
    pub fn fanout(&self) -> Option<(crate::config::FanoutMode, u16)> {
        self.fanout
    }

    /// 0.22 §5.2: wrap the already-built sink chain in one more
    /// [`Layer`](crate::layer::Layer). Used by
    /// [`ShardedRunner::layer`](crate::monitor::ShardedRunner::layer) to
    /// apply per-shard secondary layers *outside* the builder-registered
    /// ones (so a runner spec runs first). The layer wraps the current
    /// composed sink and becomes the new outermost sink.
    pub(crate) fn wrap_sink(&mut self, layer: Box<dyn crate::layer::Layer>) {
        let inner = std::mem::replace(&mut self.sink, Box::new(crate::anomaly::sink::NoopSink));
        self.sink = layer.wrap(inner);
    }

    /// 0.22 §5.1: inject the merge-request receiver so this shard's run
    /// loop answers the merge worker's probes. Called by
    /// `ShardedRunner::run_inner` after `build`.
    pub(crate) fn set_merge_rx(
        &mut self,
        rx: tokio::sync::mpsc::UnboundedReceiver<merge::MergeRequest>,
    ) {
        self.merge_rx = Some(rx);
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
    /// 0.24 Phase B: AF_XDP capture interfaces. See [`Self::xdp_interface`].
    #[cfg(feature = "af-xdp")]
    xdp_interfaces: Vec<XdpIfaceSpec>,
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
    /// 0.24 Phase B: resilience policies. Default `Propagate` / `FailFast`
    /// (historic behavior). See [`Self::handler_error_policy`] /
    /// [`Self::backend_error_policy`].
    handler_error_policy: HandlerErrorPolicy,
    backend_error_policy: BackendErrorPolicy,
    /// 0.25 W1e: catch panics from **sync** handlers and convert them to
    /// `Error::HandlerPanic` (then handled by `handler_error_policy`). Off by
    /// default. Set via [`Self::catch_handler_panics`].
    catch_handler_panics: bool,
    /// 0.24 Phase C1/C2: optional capture-telemetry sampling hook.
    /// `None` until [`Self::on_capture_stats`] is called. Moved into
    /// [`Monitor::capture_stats`] at [`Self::build`].
    capture_stats: Option<telemetry::CaptureStatsRegistration>,
    /// 0.24 Phase D1: flow exporters registered via
    /// [`Self::export_flows`]. Moved into [`Monitor::flow_exporters`].
    flow_exporters: Vec<Box<dyn crate::export::FlowExporter>>,
    /// 0.25 W1c: active-timeout period set via [`Self::export_active_timeout`].
    flow_active_timeout: Option<std::time::Duration>,
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
    /// Issue #34: the central flow tracker's config (flowscope 0.18). Carries
    /// the reassembler-hardening knobs — TCP overlap-resolution policy,
    /// reassembly memcap + policy, active/idle threshold. Applied to the
    /// `DriverBuilder` at build. Default mirrors flowscope's defaults
    /// (`TcpOverlapPolicy::First`, no memcap, 1s active/idle threshold).
    tracker_config: flowscope::FlowTrackerConfig,
    /// 0.22 §2.3: set once `bandwidth_by_app` / `bandwidth_windowed` /
    /// `on_bandwidth` has installed the recorder, so repeated calls
    /// (e.g. `on_bandwidth` after an explicit `bandwidth_windowed`)
    /// don't double-register the per-packet handler and double-count.
    bandwidth_registered: bool,
    /// 0.25 A1: packet-tier subscriptions (`packet()…​.to(h)`). Run in the
    /// zero-copy drain before flow tracking; moved into
    /// [`Monitor::packet_subs`] at build.
    packet_subs: Vec<subscription::PacketSubscription>,
    /// 0.25 S1: per-consumer **traffic-interest** predicates, recorded as
    /// handlers / protocols are registered (each event's
    /// [`Event::traffic_class`](crate::protocol::event_typed::Event::traffic_class)
    /// or a protocol's [`Dispatch`](crate::protocol::Dispatch)). Folded into the
    /// kernel-prefilter union at [`Self::kernel_prefilter`] — a consumer can
    /// only widen it, so the kernel filter is always a superset (no starvation).
    traffic_interests: Vec<subscription::Predicate>,
    /// Issue #4: monitor-wide promiscuous mode for every capture interface.
    /// Set via [`Self::promiscuous`]; defaults to `false`.
    promiscuous: bool,
    /// Issue #6: monitor-wide RX-queue selection for self-loading AF_XDP
    /// interfaces. Set via [`Self::xdp_queues`]; defaults to `Queues::Single(0)`.
    #[cfg(feature = "af-xdp")]
    xdp_queues: crate::xdp::Queues,
    /// Issue #6 M5: pre-built AF_XDP backends injected via
    /// [`Self::inject_xdp_backend`] (the `XdpShardedRunner` Tier-2 seam).
    #[cfg(feature = "af-xdp")]
    injected_xdp: Vec<crate::AsyncXdpSocket>,
    /// Issue #12: ARP detector config, accumulated by
    /// [`Self::arp_allow`] / [`Self::arp_warmup`] / etc. Folded into the
    /// [`arp::ArpWatch`] at build alongside the handler vecs.
    #[cfg(feature = "arp")]
    arp_config: arp::ArpConfig,
    /// Issue #12: `on_arp` raw-message handlers.
    #[cfg(feature = "arp")]
    arp_msg_handlers: Vec<arp::ArpMsgHandler>,
    /// Issue #12: `on_arp_anomaly` derived-anomaly handlers.
    #[cfg(feature = "arp")]
    arp_anomaly_handlers: Vec<arp::ArpAnomalyHandler>,
    /// Issue #12: set once any ARP hook (`on_arp` / `on_arp_anomaly` /
    /// `arp_allow` / ...) is registered, so the run loop builds an
    /// [`arp::ArpWatch`] and arms the per-frame parse.
    #[cfg(feature = "arp")]
    arp_enabled: bool,
    /// Issue #24: NDP detector config (the ARP sibling).
    #[cfg(feature = "ndp")]
    ndp_config: ndp::NdpConfig,
    /// Issue #24: `on_ndp` raw-message handlers.
    #[cfg(feature = "ndp")]
    ndp_msg_handlers: Vec<ndp::NdpMsgHandler>,
    /// Issue #24: `on_ndp_anomaly` derived-anomaly handlers.
    #[cfg(feature = "ndp")]
    ndp_anomaly_handlers: Vec<ndp::NdpAnomalyHandler>,
    /// Issue #24: set once any NDP hook is registered.
    #[cfg(feature = "ndp")]
    ndp_enabled: bool,
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
    /// Monitor::builder().interface("eth0").label_table(table);
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

    /// Issue #34: set the **TCP overlap-resolution policy** for the
    /// reassembler — which segment's bytes win when two segments carry
    /// different data for the same sequence range.
    ///
    /// Without an explicit policy the analyzer is, by construction, evadable
    /// (Ptacek–Newsham): an attacker can make the monitor reassemble a
    /// *different* byte stream than the destination host. Match the policy to
    /// the monitored hosts' OS family. Default
    /// [`TcpOverlapPolicy::First`](flowscope::TcpOverlapPolicy::First) (BSD —
    /// the safest when host OS is unknown); use
    /// [`HigherSeq`](flowscope::TcpOverlapPolicy::HigherSeq) for Linux-heavy
    /// segments, [`Last`](flowscope::TcpOverlapPolicy::Last) for Windows.
    pub fn tcp_overlap_policy(mut self, policy: flowscope::TcpOverlapPolicy) -> Self {
        self.tracker_config.tcp_overlap_policy = policy;
        self
    }

    /// Issue #34: bound the reassembler's buffered memory and choose what
    /// happens when the cap is hit — the defense against state-holding DoS
    /// (an attacker streaming deliberate gaps to force unbounded buffers).
    ///
    /// `bytes` is the global reassembly memcap; `policy` governs the response
    /// (e.g. [`MemcapPolicy::DropFlow`](flowscope::MemcapPolicy)). Default is
    /// unbounded ([`MemcapPolicy::Ignore`](flowscope::MemcapPolicy)) — set a
    /// cap for any internet-facing deployment.
    pub fn reassembly_memcap(mut self, bytes: u64, policy: flowscope::MemcapPolicy) -> Self {
        self.tracker_config.reassembly_memcap = Some(bytes);
        self.tracker_config.reassembly_memcap_policy = policy;
        self
    }

    /// Issue #34: the active/idle threshold for CICFlowMeter-style
    /// active/idle-period accounting (flowscope 0.18 `ml_features`). A gap
    /// longer than this between packets ends an "active" period and starts an
    /// "idle" one. Default `1s` (CICFlowMeter). `None` disables the split.
    pub fn active_idle_threshold(mut self, threshold: Option<Duration>) -> Self {
        self.tracker_config.active_idle_threshold = threshold;
        self
    }

    /// Issue #34: inspect the flow-tracker config this builder will apply
    /// (overlap policy, memcap, active/idle threshold) — for tests / debugging.
    pub fn tracker_config(&self) -> &flowscope::FlowTrackerConfig {
        &self.tracker_config
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

    /// 0.24 Phase B: add an **AF_XDP** capture interface (feature
    /// `af-xdp`).
    ///
    /// The run loop opens an AF_XDP socket on `iface` and drains it through
    /// the same backend-agnostic path as AF_PACKET — composable with
    /// `.interface(...)` (a monitor can mix AF_PACKET and AF_XDP sources).
    ///
    /// **Requires an attached XDP redirect program** to receive packets:
    /// build the socket yourself with
    /// [`XdpSocketBuilder::with_default_program`](crate::XdpSocketBuilder)
    /// (feature `xdp-loader`) and attach it out of band, or run a custom
    /// loader. A bare `xdp_interface` with no program bound sees no
    /// traffic — use [`Self::xdp_interface_loaded`] (feature `xdp-loader`)
    /// to have the Monitor attach the built-in redirect program for you.
    #[cfg(feature = "af-xdp")]
    pub fn xdp_interface(mut self, iface: impl Into<String>) -> Self {
        self.xdp_interfaces.push(XdpIfaceSpec {
            iface: iface.into(),
            self_load: false,
            queues: crate::xdp::Queues::default(),
        });
        self
    }

    /// 0.25 W1a: add an **AF_XDP** capture interface and have the Monitor
    /// **load + attach the built-in redirect-all XDP program** itself
    /// (feature `xdp-loader`).
    ///
    /// Unlike [`Self::xdp_interface`] (which needs an externally-attached
    /// redirect program), this is the one-call AF_XDP recipe: on run, the
    /// Monitor builds the socket via
    /// [`XdpSocketBuilder::with_default_program`](crate::XdpSocketBuilder),
    /// which attaches the vendored `redirect_all` program in `SKB_MODE` (works
    /// on `lo` and unprivileged interfaces) and registers the socket on the
    /// program's XSKMAP. The attachment is RAII-tied to the socket and detaches
    /// when the Monitor's run loop ends. For native-driver zero-copy on a real
    /// NIC, build the socket yourself with `.xdp_attach_flags(XdpFlags::DRV_MODE)`
    /// and use [`Self::xdp_interface`].
    ///
    /// **Queue selection.** Defaults to **queue 0** only. On a multi-queue NIC,
    /// RSS spreads traffic across queues, so the default captures just queue 0's
    /// share — even with [`Self::promiscuous`]. Add [`Self::xdp_queues`]
    /// (`Queues::Auto`) to capture **every** queue (one socket per queue behind a
    /// single program, drained round-robin).
    #[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
    pub fn xdp_interface_loaded(mut self, iface: impl Into<String>) -> Self {
        self.xdp_interfaces.push(XdpIfaceSpec {
            iface: iface.into(),
            self_load: true,
            queues: crate::xdp::Queues::default(),
        });
        self
    }

    /// Put **every** capture interface into promiscuous mode for the run's
    /// lifetime (issue #4). Default: `false`.
    ///
    /// Applies to both AF_PACKET (`interface`/`interfaces`) and AF_XDP
    /// (`xdp_interface`/`xdp_interface_loaded`) sources — promiscuity is a
    /// `netdev` property, so the monitor flag is backend-agnostic. Enable it
    /// when the monitor is a passive observer that must see traffic not
    /// addressed to the local MAC (SPAN/mirror ports, sniffing); leave it off
    /// for host-local monitoring.
    ///
    /// ```ignore
    /// Monitor::builder()
    ///     .xdp_interface_loaded("eth0")
    ///     .promiscuous(true)            // capture all traffic on eth0
    ///     .protocol::<Tcp>()
    ///     .build()?;
    /// ```
    ///
    /// The Monitor holds promiscuity through a self-cleaning AF_PACKET
    /// `PACKET_MR_PROMISC` guard tied to each socket's lifetime — see
    /// [`XdpSocketBuilder::promiscuous`](crate::XdpSocketBuilder::promiscuous)
    /// for the mechanism and the multi-queue / `IFF_PROMISC`-visibility caveats.
    /// For per-interface control, or one AF_XDP socket per NIC queue, build the
    /// sockets yourself with the low-level builders.
    pub fn promiscuous(mut self, enable: bool) -> Self {
        self.promiscuous = enable;
        self
    }

    /// Capture **all RX queues** of each self-loading AF_XDP interface
    /// (feature `af-xdp`; issue #6). Default: `Queues::Single(0)`.
    ///
    /// An AF_XDP socket binds one queue, and RSS spreads traffic across queues,
    /// so the default single-queue bind silently under-captures a multi-queue
    /// NIC — even with [`Self::promiscuous`]. Set `Queues::Auto` (or an explicit
    /// `Queues::range(..)`) to open one socket per queue behind a single program
    /// and drain them through a unified round-robin:
    ///
    /// ```ignore
    /// Monitor::builder()
    ///     .xdp_interface_loaded("eth0")
    ///     .xdp_queues(Queues::Auto)     // every RSS queue, not just queue 0
    ///     .promiscuous(true)
    ///     .protocol::<Tcp>()
    ///     .build()?;
    /// ```
    ///
    /// Monitor-wide (applies to every [`Self::xdp_interface_loaded`] interface),
    /// mirroring [`Self::promiscuous`]. Single-reactor (one core); for line rate
    /// across cores, drive [`XdpCapture`](crate::xdp::XdpCapture) sockets with one
    /// worker per queue. Ignored for the bare [`Self::xdp_interface`] path (an
    /// externally-attached program owns the redirect map).
    #[cfg(feature = "af-xdp")]
    pub fn xdp_queues(mut self, queues: crate::xdp::Queues) -> Self {
        self.xdp_queues = queues;
        self
    }

    /// Issue #6 M5: inject a pre-built AF_XDP backend (one queue's socket) that
    /// this Monitor drains directly, instead of opening its own from a spec.
    ///
    /// The seam behind [`XdpShardedRunner`](crate::monitor::xdp_shard::XdpShardedRunner):
    /// the runner attaches one program, opens one socket per queue, and hands
    /// each shard its socket here. Counts as a capture source for `build()`.
    /// Not reopenable — the program/registration live outside the Monitor, so a
    /// backend error on an injected socket is terminal for that shard.
    #[cfg(feature = "af-xdp")]
    pub(crate) fn inject_xdp_backend(mut self, socket: crate::AsyncXdpSocket) -> Self {
        self.injected_xdp.push(socket);
        self
    }

    /// 0.21 D.4: tag this monitor with a human-readable name.
    ///
    /// The name surfaces on every dispatched
    /// [`Ctx`] as
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

    /// 0.24 Phase B: set the handler-error policy.
    ///
    /// Default [`HandlerErrorPolicy::Propagate`] stops the monitor on the first
    /// handler error (historic behavior). [`HandlerErrorPolicy::Isolate`] logs +
    /// counts the error and continues to the next event/packet — recommended for
    /// production, so one misbehaving detector or malformed flow can't tear down
    /// the whole capture pipeline.
    pub fn handler_error_policy(mut self, policy: HandlerErrorPolicy) -> Self {
        self.handler_error_policy = policy;
        self
    }

    /// 0.24 Phase B: set the capture-backend error policy.
    ///
    /// Default [`BackendErrorPolicy::FailFast`] stops the monitor on a backend
    /// error. [`BackendErrorPolicy::SkipSource`] logs + counts and keeps
    /// servicing the other capture sources (useful for multi-interface monitors
    /// where one NIC can fail independently). [`BackendErrorPolicy::Reopen`]
    /// (0.25 W1e) additionally tries to **re-open** the failed source so a
    /// transient error (e.g. an interface flap) self-heals.
    pub fn backend_error_policy(mut self, policy: BackendErrorPolicy) -> Self {
        self.backend_error_policy = policy;
        self
    }

    /// 0.25 W1e: catch panics from **synchronous** handlers (`on` / `on_ctx` /
    /// detectors / sinks) and convert them into `Error::HandlerPanic`, then
    /// route that through the configured
    /// [`handler_error_policy`](Self::handler_error_policy) — so pairing this
    /// with [`HandlerErrorPolicy::Isolate`] means one panicking handler is
    /// logged + counted and the capture pipeline keeps running instead of
    /// unwinding.
    ///
    /// Off by default (a panic is a bug; the default is to surface it). The
    /// default panic hook still prints the panic to stderr, so nothing is
    /// silently swallowed. **Async** handlers / effect futures are not covered
    /// (their panics propagate) — keep async bodies panic-free or guard them
    /// internally.
    pub fn catch_handler_panics(mut self, on: bool) -> Self {
        self.catch_handler_panics = on;
        self
    }

    /// 0.24 Phase C: sample each capture source's kernel counters every
    /// `period` and hand them to `handler`.
    ///
    /// The handler is called **once per capture source** each period
    /// with that source's [`CaptureTelemetry`] (cumulative
    /// packets/drops/freezes + a windowed drop rate) and a `&mut Ctx`,
    /// so it can update monitor state, emit anomalies, or feed a report
    /// — the same context handlers get. This is the "is my capture
    /// keeping up?" hook: rising
    /// [`drop_rate`](CaptureTelemetry::drop_rate) means the consumer
    /// isn't draining the ring fast enough.
    ///
    /// Sampling reads cumulative stats, so it's cheap and never resets
    /// the user-visible counters. A monitor that never calls this pays
    /// nothing — the sampling interval is only armed when a handler is
    /// registered (same gating as the tick / merge branches). Calling it
    /// again replaces the previous handler.
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use netring::monitor::Monitor;
    /// # use netring::protocol::builtin::Tcp;
    /// # fn _ex() -> Result<(), netring::Error> {
    /// let monitor = Monitor::builder()
    ///     .interface("eth0")
    ///     .protocol::<Tcp>()
    ///     .on_capture_stats(Duration::from_secs(5), |t, _ctx| {
    ///         if t.is_degraded(0.01) {
    ///             eprintln!("source {:?}: losing {:.1}% of packets", t.source, t.drop_rate * 100.0);
    ///         }
    ///         Ok(())
    ///     })
    ///     .build()?;
    /// # let _ = monitor;
    /// # Ok(())
    /// # }
    /// ```
    pub fn on_capture_stats<F>(mut self, period: Duration, handler: F) -> Self
    where
        F: FnMut(&CaptureTelemetry, &mut Ctx<'_>) -> Result<()> + Send + 'static,
    {
        self.capture_stats = Some(telemetry::CaptureStatsRegistration {
            period,
            handler: Box::new(handler),
        });
        self
    }

    /// 0.24 Phase C: ship per-source capture health to a
    /// [`ReportSink`](crate::report::ReportSink) every `period`.
    ///
    /// The no-code-required form of [`Self::on_capture_stats`]: each
    /// period every capture source's [`CaptureTelemetry`] is flattened
    /// into a [`CaptureHealth`] report and handed to `sink.record(..)`.
    /// Pair with [`StdoutReportSink`](crate::report::StdoutReportSink)
    /// for a quick health line, [`JsonReportSink`](crate::report::JsonReportSink)
    /// for newline-delimited JSON (Vector / Loki), or any custom
    /// `ReportSink<CaptureHealth>`.
    ///
    /// This is sugar over [`Self::on_capture_stats`] and shares its
    /// single-handler slot — calling either after the other replaces the
    /// previous registration.
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use netring::monitor::Monitor;
    /// # use netring::protocol::builtin::Tcp;
    /// # use netring::report::StdoutReportSink;
    /// # fn _ex() -> Result<(), netring::Error> {
    /// let monitor = Monitor::builder()
    ///     .interface("eth0")
    ///     .protocol::<Tcp>()
    ///     .capture_health(Duration::from_secs(10), StdoutReportSink)
    ///     .build()?;
    /// # let _ = monitor;
    /// # Ok(())
    /// # }
    /// ```
    pub fn capture_health<S>(self, period: Duration, mut sink: S) -> Self
    where
        S: crate::report::ReportSink<CaptureHealth> + 'static,
    {
        self.on_capture_stats(period, move |t, _ctx| {
            sink.record(&CaptureHealth::from(*t));
            Ok(())
        })
    }

    /// 0.24 Phase C: export per-source capture telemetry as Prometheus
    /// gauges every `period` (feature `metrics`).
    ///
    /// Sugar over [`Self::on_capture_stats`] that calls
    /// [`CaptureTelemetry::record_metrics`] each sample —
    /// `netring_capture_{packets,drops,freezes,drop_rate}` tagged
    /// `source="<idx>"`. Needs a `metrics` recorder installed by the host
    /// app (e.g. `metrics-exporter-prometheus`) to actually surface.
    ///
    /// Shares the single `on_capture_stats` slot with
    /// [`Self::capture_health`] / [`Self::on_capture_stats`] — to do both
    /// metrics *and* a report, write one `on_capture_stats` handler that
    /// calls `t.record_metrics()` and ships your report.
    #[cfg(feature = "metrics")]
    pub fn capture_metrics(self, period: Duration) -> Self {
        self.on_capture_stats(period, |t, _ctx| {
            t.record_metrics();
            Ok(())
        })
    }

    /// 0.24 Phase D: emit a [`FlowRecord`](crate::export::FlowRecord) for
    /// every completed flow to `exporter`.
    ///
    /// The run loop builds a record from each `FlowEnded` (FIN / RST /
    /// idle / eviction / parser close) — 5-tuple + directional byte/packet
    /// counts + start/end + reason — and hands it to the exporter. The
    /// NetFlow / IPFIX / Zeek `conn.log` output shape, the fourth beside
    /// anomalies, reports, and broadcast streams.
    ///
    /// Call repeatedly to fan out to several exporters. A bare
    /// `FnMut(&FlowRecord)` is a [`FlowExporter`](crate::export::FlowExporter),
    /// so the quick path is a closure:
    ///
    /// ```no_run
    /// # use netring::monitor::Monitor;
    /// # use netring::protocol::builtin::Tcp;
    /// # fn _ex() -> Result<(), netring::Error> {
    /// let monitor = Monitor::builder()
    ///     .interface("eth0")
    ///     .protocol::<Tcp>()
    ///     .export_flows(|rec: &netring::export::FlowRecord| {
    ///         println!("{:?} {} ↔ {} : {} bytes", rec.proto, rec.a, rec.b, rec.total_bytes());
    ///     })
    ///     .build()?;
    /// # let _ = monitor;
    /// # Ok(())
    /// # }
    /// ```
    pub fn export_flows<E>(mut self, exporter: E) -> Self
    where
        E: crate::export::FlowExporter + 'static,
    {
        self.flow_exporters.push(Box::new(exporter));
        self
    }

    /// Emit interim [`FlowRecord`](crate::export::FlowRecord)s for **long-lived
    /// flows** on an active timeout (0.25 W1c) — the NetFlow/IPFIX behaviour
    /// where a flow alive longer than the active-timeout interval gets periodic
    /// snapshots, not just one record when it finally ends.
    ///
    /// Every `period`, each live flow that has been active for at least
    /// `period` since its last record gets a `FlowRecord` with
    /// [`reason`](crate::export::FlowRecord::reason) `= None`
    /// ([`is_ongoing`](crate::export::FlowRecord::is_ongoing) `== true`)
    /// dispatched to every registered [`export_flows`](Self::export_flows)
    /// exporter. The final end-of-flow record (reason `Some(_)`) still fires on
    /// `FlowEnded` as before. No-op unless at least one exporter is registered.
    ///
    /// Counters in interim records are cumulative-to-date (not per-interval
    /// deltas), matching IPFIX active-timeout semantics.
    pub fn export_active_timeout(mut self, period: std::time::Duration) -> Self {
        self.flow_active_timeout = Some(period);
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
        // 0.25 S1: a registered parser only consumes the traffic its dispatch
        // describes — record that interest for the kernel-prefilter union.
        self.traffic_interests
            .push(subscription::kernel_filter::dispatch_interest(
                &P::dispatch(),
            ));
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
        handler: impl Handler<crate::protocol::event_typed::TcpRst, crate::monitor::handler::PayloadCtx>,
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
                    ctx.state_mut::<bandwidth::BandwidthState>().0.record(
                        label,
                        evt.len as u64,
                        ts,
                    );
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

    /// Issue #12: observe every parsed [`ArpMessage`](flowscope::ArpMessage)
    /// — request, reply, gratuitous, RARP — captured on any interface.
    ///
    /// ARP is L2 (no 5-tuple), so it doesn't flow through the flow tracker;
    /// the Monitor parses each frame for ARP inside the zero-copy drain and
    /// hands the message to your closure with a `&mut Ctx`. Arming any ARP
    /// hook adds a precise `EtherType(0x0806)` term to the kernel prefilter
    /// (issue #20), so a pure-ARP monitor sheds non-ARP traffic in-kernel; an
    /// ARP+IP monitor unions `arp OR (the IP interests)`.
    ///
    /// ```ignore
    /// Monitor::builder().interface("eth0")
    ///     .on_arp(|m, _ctx| {
    ///         println!("{} is-at {:?} (op {:?})", m.sender_ip, m.sender, m.oper);
    ///         Ok(())
    ///     });
    /// ```
    ///
    /// For the security signal (spoof / binding-change) use
    /// [`Self::on_arp_anomaly`] instead — it's far less noisy.
    #[cfg(feature = "arp")]
    pub fn on_arp<F>(mut self, handler: F) -> Self
    where
        F: Fn(&flowscope::ArpMessage, &mut Ctx<'_>) -> Result<()> + Send + 'static,
    {
        self.arp_enabled = true;
        self.arp_msg_handlers.push(Box::new(handler));
        self
    }

    /// Issue #12: receive derived [`ArpAnomaly`]s — the security view of the
    /// ARP feed.
    ///
    /// The Monitor learns every sender's `IP → MAC` binding into an internal
    /// [`ArpTable`](flowscope::correlate::ArpTable) and emits:
    /// - [`ArpAnomalyKind::SpoofSuspected`] — a gratuitous reply whose target
    ///   MAC ≠ sender MAC (cache poisoning). Fires even during warm-up.
    /// - [`ArpAnomalyKind::BindingChanged`] — a known IP now claims a
    ///   different MAC (failover or MITM). Suppressed during the warm-up
    ///   window ([`Self::arp_warmup`], default 5 s).
    ///
    /// Opt into the informational kinds with [`Self::arp_report_gratuitous`]
    /// / [`Self::arp_report_new_binding`]. Allowlist trusted bindings
    /// (gateways, VRRP) with [`Self::arp_allow`].
    ///
    /// ```ignore
    /// Monitor::builder().interface("eth0")
    ///     .arp_allow("10.0.0.1".parse().unwrap(), MacAddr([0,0,0x5e,0,1,1]))
    ///     .on_arp_anomaly(|a, ctx| {
    ///         ctx.emit(a.kind.as_str(), a.kind.severity())
    ///             .with("ip", a.ip().to_string())
    ///             .emit();
    ///         Ok(())
    ///     });
    /// ```
    #[cfg(feature = "arp")]
    pub fn on_arp_anomaly<F>(mut self, handler: F) -> Self
    where
        F: Fn(&arp::ArpAnomaly, &mut Ctx<'_>) -> Result<()> + Send + 'static,
    {
        self.arp_enabled = true;
        self.arp_anomaly_handlers.push(Box::new(handler));
        self
    }

    /// Issue #19: arm ARP learning without registering an ARP handler, so the
    /// `IP → MAC` binding table is maintained. Implied by [`Self::on_arp`] /
    /// [`Self::on_arp_anomaly`] / [`Self::arp_allow`], so an explicit call is
    /// only needed if you want the table built but register no ARP hook — e.g.
    /// to enrich flow/TLS handlers with peer MACs via
    /// [`Ctx::arp_table`](crate::ctx::Ctx::arp_table) (issue #23) without any
    /// ARP detector of your own.
    #[cfg(feature = "arp")]
    pub fn arp_table(mut self) -> Self {
        self.arp_enabled = true;
        self
    }

    /// Issue #12: trust an `IP → MAC` binding — it never raises an ARP
    /// anomaly. Use for gateways, VRRP/HSRP virtual MACs, and known
    /// multi-homed hosts. Arms ARP detection (like [`Self::on_arp_anomaly`]).
    #[cfg(feature = "arp")]
    pub fn arp_allow(mut self, ip: std::net::Ipv4Addr, mac: flowscope::MacAddr) -> Self {
        self.arp_enabled = true;
        self.arp_config.allow.insert((ip, mac));
        self
    }

    /// Issue #12: set the warm-up window during which learning-dependent
    /// anomalies ([`ArpAnomalyKind::BindingChanged`] /
    /// [`ArpAnomalyKind::NewBinding`]) are suppressed while the table learns
    /// the steady-state topology. Default
    /// [`DEFAULT_ARP_WARMUP`](arp::DEFAULT_ARP_WARMUP) (5 s).
    /// `SpoofSuspected` is unaffected — it always fires.
    #[cfg(feature = "arp")]
    pub fn arp_warmup(mut self, window: Duration) -> Self {
        self.arp_enabled = true;
        self.arp_config.warmup = window;
        self
    }

    /// Issue #12: also emit [`ArpAnomalyKind::Gratuitous`] for benign
    /// gratuitous announcements (boot / IP-change / failover). Off by
    /// default — useful for an inventory / "who just joined" view.
    #[cfg(feature = "arp")]
    pub fn arp_report_gratuitous(mut self, enabled: bool) -> Self {
        self.arp_enabled = true;
        self.arp_config.report_gratuitous = enabled;
        self
    }

    /// Issue #12: also emit [`ArpAnomalyKind::NewBinding`] the first time a
    /// post-warm-up `IP → MAC` binding is learned ("new host appeared"). Off
    /// by default — noisy on a first network sweep.
    #[cfg(feature = "arp")]
    pub fn arp_report_new_binding(mut self, enabled: bool) -> Self {
        self.arp_enabled = true;
        self.arp_config.report_new_binding = enabled;
        self
    }

    /// Issue #24: observe every parsed [`NdpMessage`](flowscope::NdpMessage)
    /// (IPv6 Neighbor Solicitation / Advertisement) — the raw NDP feed. The
    /// IPv6 sibling of [`Self::on_arp`]. Parsed per-frame in the drain (walk
    /// the layers to ICMPv6 types 135/136); arming an NDP hook narrows the
    /// kernel prefilter to ICMPv6 (proto 58) rather than capture-all.
    #[cfg(feature = "ndp")]
    pub fn on_ndp<F>(mut self, handler: F) -> Self
    where
        F: Fn(&flowscope::NdpMessage, &mut Ctx<'_>) -> Result<()> + Send + 'static,
    {
        self.ndp_enabled = true;
        self.ndp_msg_handlers.push(Box::new(handler));
        self
    }

    /// Issue #24: receive derived [`NdpAnomaly`]s — the IPv6 neighbour security
    /// signal. `SpoofSuspected` (unsolicited override NA carrying a MAC — the
    /// SLAAC-poisoning vector) + `BindingChanged`; opt-in `Unsolicited` /
    /// `NewBinding`. The IPv6 sibling of [`Self::on_arp_anomaly`].
    #[cfg(feature = "ndp")]
    pub fn on_ndp_anomaly<F>(mut self, handler: F) -> Self
    where
        F: Fn(&ndp::NdpAnomaly, &mut Ctx<'_>) -> Result<()> + Send + 'static,
    {
        self.ndp_enabled = true;
        self.ndp_anomaly_handlers.push(Box::new(handler));
        self
    }

    /// Issue #24: trust an `IPv6 → MAC` binding — it never raises an NDP
    /// anomaly (gateways, known SLAAC hosts). Arms NDP detection.
    #[cfg(feature = "ndp")]
    pub fn ndp_allow(mut self, ip: std::net::Ipv6Addr, mac: flowscope::MacAddr) -> Self {
        self.ndp_enabled = true;
        self.ndp_config.allow.insert((ip, mac));
        self
    }

    /// Issue #24: warm-up window suppressing learning-dependent NDP anomalies
    /// ([`BindingChanged`](ndp::NdpAnomalyKind::BindingChanged) /
    /// [`NewBinding`](ndp::NdpAnomalyKind::NewBinding)). Default
    /// [`DEFAULT_NDP_WARMUP`](ndp::DEFAULT_NDP_WARMUP) (5 s); `SpoofSuspected`
    /// is unaffected.
    #[cfg(feature = "ndp")]
    pub fn ndp_warmup(mut self, window: Duration) -> Self {
        self.ndp_enabled = true;
        self.ndp_config.warmup = window;
        self
    }

    /// Issue #24: also emit [`ndp::NdpAnomalyKind::Unsolicited`]
    /// for benign unsolicited override NAs (off by default — noisy).
    #[cfg(feature = "ndp")]
    pub fn ndp_report_unsolicited(mut self, enabled: bool) -> Self {
        self.ndp_enabled = true;
        self.ndp_config.report_unsolicited = enabled;
        self
    }

    /// Issue #24: also emit [`ndp::NdpAnomalyKind::NewBinding`]
    /// for first-seen post-warm-up bindings (off by default — noisy on a first
    /// sweep).
    #[cfg(feature = "ndp")]
    pub fn ndp_report_new_binding(mut self, enabled: bool) -> Self {
        self.ndp_enabled = true;
        self.ndp_config.report_new_binding = enabled;
        self
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
    /// [`Self::on_ctx`].
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

    /// 0.24 Phase E: handle each completed TLS handshake as a
    /// [`TlsFingerprint`] bundle (SNI + ALPN + JA3 / JA4 / JA4S + flow
    /// key).
    ///
    /// Sugar over `.on_ctx::<TlsHandshake>(…)`: the handshake's
    /// identity fields are gathered into one struct, the flow key is
    /// pulled from the dispatch context, and your handler gets
    /// `(&TlsFingerprint, &mut Ctx)`. The canonical shape for IOC
    /// matching (a JA4/JA4S blocklist) and TLS asset inventory.
    ///
    /// Auto-registers the [`TlsHandshake`](crate::protocol::builtin::TlsHandshake)
    /// protocol if it wasn't already declared, so a one-liner suffices.
    /// JA3/JA4/JA4S are populated only when the `tls` build runs against
    /// flowscope's fingerprinting (the `TlsHandshakeParser` enables it by
    /// default); otherwise those fields are `None`.
    ///
    /// ```no_run
    /// # use netring::monitor::Monitor;
    /// # fn _ex() -> Result<(), netring::Error> {
    /// let monitor = Monitor::builder()
    ///     .interface("eth0")
    ///     .on_fingerprint(|fp, _ctx| {
    ///         if let Some(ja4) = &fp.ja4 {
    ///             println!("{} -> {ja4} (sni={:?})", "tls", fp.sni);
    ///         }
    ///         Ok(())
    ///     })
    ///     .build()?;
    /// # let _ = monitor;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "tls")]
    pub fn on_fingerprint<F>(mut self, handler: F) -> Self
    where
        F: Fn(&TlsFingerprint, &mut Ctx<'_>) -> Result<()> + Send + Sync + 'static,
    {
        use crate::protocol::builtin::TlsHandshake;
        // Register the handshake protocol once (calling `.protocol` twice
        // would install a duplicate session parser).
        if !self
            .declared_protocols
            .contains_key(&std::any::TypeId::of::<TlsHandshake>())
        {
            self = self.protocol::<TlsHandshake>();
        }
        self.on_ctx::<TlsHandshake>(
            move |hs: &flowscope::tls::TlsHandshake, ctx: &mut Ctx<'_>| {
                let fp = TlsFingerprint::from_handshake(hs, ctx.flow);
                handler(&fp, ctx)
            },
        )
    }

    /// Register a handler fired once per HTTP **request**, handed an
    /// [`HttpFingerprint`] bundle
    /// (the JA4H FoxIO fingerprint + method / host / user-agent + flow key).
    ///
    /// The HTTP analogue of [`on_fingerprint`](Self::on_fingerprint): it
    /// auto-registers the [`Http`](crate::protocol::builtin::Http) protocol if
    /// it isn't already declared, then wraps an `on_ctx::<Http>` handler that
    /// computes JA4H over each `HttpMessage::Request` and skips responses.
    ///
    /// JA4H is **FoxIO License 1.1** (non-commercial; patent pending), so this
    /// method is gated behind the opt-in `ja4plus` feature (alongside JA4S /
    /// JA4X) — commercial use requires a FoxIO OEM license.
    ///
    /// ```no_run
    /// # #[cfg(all(feature = "http", feature = "ja4plus", feature = "tokio"))]
    /// # fn demo() {
    /// use netring::monitor::Monitor;
    /// Monitor::builder()
    ///     .interface("eth0")
    ///     .on_http_fingerprint(|fp, _ctx| {
    ///         println!("{} {:?} ja4h={}", fp.method.as_deref().unwrap_or("?"), fp.host, fp.ja4h);
    ///         Ok(())
    ///     });
    /// # }
    /// ```
    #[cfg(all(feature = "http", feature = "ja4plus"))]
    pub fn on_http_fingerprint<F>(mut self, handler: F) -> Self
    where
        F: Fn(&crate::monitor::fingerprint::HttpFingerprint, &mut Ctx<'_>) -> Result<()>
            + Send
            + Sync
            + 'static,
    {
        use crate::monitor::fingerprint::HttpFingerprint;
        use crate::protocol::builtin::Http;
        // Register the HTTP protocol once (a second `.protocol::<Http>()` would
        // install a duplicate session parser).
        if !self
            .declared_protocols
            .contains_key(&std::any::TypeId::of::<Http>())
        {
            self = self.protocol::<Http>();
        }
        self.on_ctx::<Http>(
            move |msg: &flowscope::http::HttpMessage, ctx: &mut Ctx<'_>| {
                // JA4H is a *client* fingerprint — only requests carry it.
                if let flowscope::http::HttpMessage::Request(req) = msg {
                    let fp = HttpFingerprint::from_request(req, ctx.flow);
                    handler(&fp, ctx)
                } else {
                    Ok(())
                }
            },
        )
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

    /// Register an **async effect handler** for event type `E` (0.25-B1).
    ///
    /// The handler reads the [`Ctx`] **synchronously** (`&Ctx<'_>`) and
    /// returns a `'static` future resolving to an [`Effects`] value —
    /// a deferred, owned description of the writes (anomalies to emit,
    /// …) to apply once the future completes. The run loop awaits the
    /// future, then applies the effects to the sink under a short
    /// `&mut Ctx` write phase. The **handler** never captures `Ctx` (its
    /// future is `'static`); the run-loop future stays `Send` because every
    /// `Ctx` field is `Send` (see `effect.rs`), unlike a hypothetical
    /// `Fn(&mut Ctx) -> Future` shape where the user's future would borrow
    /// `Ctx` across the await.
    ///
    /// Use this when an async body needs to *both* `.await`
    /// (e.g. an enrichment lookup, an async I/O probe) *and* emit an
    /// anomaly derived from the result — the case [`Self::on_async`]
    /// (payload-only, no `Ctx`) and sync [`Self::on`] (`&mut Ctx` but
    /// no `.await`) each cover only half of.
    ///
    /// Effect handlers fire **after** the sync and async passes for the
    /// same event, in registration order.
    pub fn on_effect<E: Event>(mut self, handler: impl EffectHandler<E>) -> Self {
        self.handlers.register_effect::<E, _>(handler);
        self
    }

    /// Register a **packet-tier subscription** (0.25 Phase A1).
    ///
    /// Build one with the typed [`packet()`](subscription::packet()) tier:
    ///
    /// ```no_run
    /// use netring::monitor::Monitor;
    /// use netring::monitor::subscription::packet;
    ///
    /// let _m = Monitor::builder()
    ///     .interface("eth0")
    ///     .subscribe(packet().tcp().dst_port(443).to(|view, _ctx| {
    ///         // sees every TCP/443 frame as a borrowed PacketView, pre-tracking
    ///         let _ = view.frame.len();
    ///         Ok(())
    ///     }))
    ///     .build();
    /// ```
    ///
    /// The handler runs synchronously inside the zero-copy drain, **before**
    /// flow tracking, for every frame matching the filter. Monitors that
    /// register no packet subs keep the `track_into`-only hot loop (zero cost).
    ///
    /// Accepts any tier (0.25 S3): a [`PacketSubscription`] (every frame,
    /// pre-tracking), or a [`FlowSubscription`] (`flow::<P>()…​.to(h)` —
    /// delivered once per flow at its end, with final stats). Session-tier
    /// `.to()` lands next.
    ///
    /// [`PacketSubscription`]: subscription::PacketSubscription
    /// [`FlowSubscription`]: subscription::FlowSubscription
    pub fn subscribe<S: subscription::Subscribable>(self, sub: S) -> Self {
        sub.install(self)
    }

    /// Push a packet-tier subscription onto the zero-copy drain. The
    /// installation hook for [`subscription::PacketSubscription`].
    pub(crate) fn add_packet_sub(mut self, sub: subscription::PacketSubscription) -> Self {
        self.packet_subs.push(sub);
        self
    }

    /// Issue #20: the kernel-filter interest contributed by an armed ARP hook
    /// — a precise `EtherType(0x0806)` term so the prefilter passes ARP up to
    /// `on_arp`/`on_arp_anomaly` (issue #12) without falling back to
    /// capture-all. `None` when no ARP hook is armed (or the `arp` feature is
    /// off), so non-ARP monitors are unaffected.
    #[cfg(feature = "arp")]
    #[inline]
    fn arp_interest(&self) -> Option<subscription::Predicate> {
        self.arp_enabled.then_some(subscription::Predicate::Atom(
            subscription::Atom::EtherType(0x0806),
        ))
    }
    #[cfg(not(feature = "arp"))]
    #[inline]
    fn arp_interest(&self) -> Option<subscription::Predicate> {
        None
    }

    /// Issue #24: the kernel-filter interest contributed by an armed NDP hook —
    /// `Proto(IcmpV6)` so the prefilter passes ICMPv6 (NDP rides types 135/136)
    /// up to `on_ndp`/`on_ndp_anomaly`. Cheaper than ARP's EtherType term — no
    /// fail-open needed. `None` when no NDP hook is armed.
    #[cfg(feature = "ndp")]
    #[inline]
    fn ndp_interest(&self) -> Option<subscription::Predicate> {
        self.ndp_enabled
            .then_some(subscription::Predicate::Atom(subscription::Atom::Proto(
                flowscope::L4Proto::IcmpV6,
            )))
    }
    #[cfg(not(feature = "ndp"))]
    #[inline]
    fn ndp_interest(&self) -> Option<subscription::Predicate> {
        None
    }

    /// The classic-BPF **kernel prefilter** this monitor compiles to (0.25
    /// S2): the conservative OR-union of **every** consumer's traffic interest
    /// — packet subs, registered handlers (via `Event::traffic_class`),
    /// and protocol parsers (via their [`Dispatch`](crate::protocol::Dispatch))
    /// — lowered to [`BpfFilter`](crate::config::BpfFilter).
    ///
    /// `None` means **capture everything** (filter in userspace): it's returned
    /// when any consumer wants all traffic (a broad handler, an exporter, a
    /// tick/report, broadcast, bandwidth), the union is empty, or it can't be
    /// expressed within the cBPF budget. Because the union is a *superset* of
    /// every consumer's interest, the filter never drops a frame any consumer
    /// wants — **fail-open and starvation-free by construction**, which is what
    /// makes it safe to auto-apply (see [`Monitor::run_*`](Monitor)).
    ///
    /// Also exposed for **inspection / debugging** (what STAGE-0 would shed).
    pub fn kernel_prefilter(&self) -> Option<crate::config::BpfFilter> {
        // Broad consumers that need every flow regardless of L4: an exporter,
        // a periodic tick/report, a broadcast subscriber, or bandwidth
        // accounting. Any one forces capture-all (fail-open).
        let wants_all = !self.flow_exporters.is_empty()
            || !self.tick_handlers.is_empty()
            || !self.broadcast_handles.is_empty()
            || self.bandwidth_registered;

        let interests = self
            .handlers
            .traffic_interests()
            .iter()
            .cloned()
            .chain(self.traffic_interests.iter().cloned())
            .chain(self.packet_subs.iter().map(|s| s.predicate.clone()))
            // Issue #20: ARP rides the kernel filter as a precise EtherType
            // term (0x0806), not the old fail-open capture-all. A pure-ARP
            // monitor now sheds non-ARP at the kernel; an ARP+IP monitor unions
            // `ethertype arp OR (the IP interests)`. The union stays a superset
            // (fail-open) — this only *narrows* toward what's actually wanted.
            .chain(self.arp_interest())
            // Issue #24: NDP rides ICMPv6 (proto 58) — add it to the union so a
            // pure-NDP monitor sheds non-ICMPv6 at the kernel.
            .chain(self.ndp_interest())
            .chain(wants_all.then_some(subscription::Predicate::Always));

        subscription::kernel_filter::compile_union(interests)
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
    /// [`CtxOnly`] marker fixed, so an untyped
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
            f(crate::report::ReportSnapshot { ctx, now: tick.now })
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
            let report = build(crate::report::ReportSnapshot { ctx, now: tick.now });
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
        // 0.24 Phase B: an AF_XDP-only monitor (no AF_PACKET interface) is
        // valid too — only error when *no* capture source of any kind is set.
        #[cfg(feature = "af-xdp")]
        let no_capture_source = self.interfaces.is_empty()
            && self.xdp_interfaces.is_empty()
            && self.injected_xdp.is_empty();
        #[cfg(not(feature = "af-xdp"))]
        let no_capture_source = self.interfaces.is_empty();
        if interface_required && no_capture_source {
            return Err(BuildError::NoInterface.into());
        }
        // 0.25 S2: compute the kernel prefilter while the full consumer set is
        // still on the builder (before fields are moved into the Monitor).
        let kernel_prefilter = self.kernel_prefilter();
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
        // Issue #34: apply the reassembler-hardening config (overlap policy,
        // memcap, active/idle threshold) to the central tracker before build.
        let mut driver_builder = self
            .driver_builder
            .unwrap_or_else(|| Driver::builder(FiveTuple::bidirectional()));
        driver_builder.config(self.tracker_config);
        let driver = driver_builder.build();
        let mut dispatcher = self.handlers.into_dispatcher()?;
        dispatcher.set_catch_panics(self.catch_handler_panics);
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
            #[cfg(feature = "af-xdp")]
            xdp_interfaces: self.xdp_interfaces,
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
            merge_rx: None,
            handler_error_policy: self.handler_error_policy,
            backend_error_policy: self.backend_error_policy,
            capture_stats: self.capture_stats,
            health: health::HealthState::new(),
            flow_exporters: self.flow_exporters,
            flow_active_timeout: self.flow_active_timeout,
            packet_subs: self.packet_subs,
            kernel_prefilter,
            promiscuous: self.promiscuous,
            #[cfg(feature = "af-xdp")]
            xdp_queues: self.xdp_queues,
            #[cfg(feature = "af-xdp")]
            injected_xdp: self.injected_xdp,
            #[cfg(feature = "arp")]
            arp_watch: self.arp_enabled.then(|| {
                let mut w = arp::ArpWatch::new(self.arp_config);
                w.msg_handlers = self.arp_msg_handlers;
                w.anomaly_handlers = self.arp_anomaly_handlers;
                w
            }),
            #[cfg(feature = "ndp")]
            ndp_watch: self.ndp_enabled.then(|| {
                let mut w = ndp::NdpWatch::new(self.ndp_config);
                w.msg_handlers = self.ndp_msg_handlers;
                w.anomaly_handlers = self.ndp_anomaly_handlers;
                w
            }),
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
    fn promiscuous_defaults_off_and_flag_toggles() {
        // Monitor-wide promiscuous is opt-in and backend-agnostic (issue #4).
        let b = Monitor::builder();
        assert!(!b.promiscuous, "default is off");

        let b = Monitor::builder().interface("lo").promiscuous(true);
        assert!(b.promiscuous);

        // The flag survives into the built Monitor and reaches the run loop.
        let m = b.build().expect("build monitor");
        assert!(m.promiscuous);
    }

    #[cfg(feature = "af-xdp")]
    #[test]
    fn xdp_queues_defaults_single_zero_and_flag_plumbs() {
        use crate::xdp::Queues;

        // Default is the historical single-queue-0 bind (no behavior change).
        let b = Monitor::builder();
        assert!(matches!(b.xdp_queues, Queues::Single(0)));

        // Opting into Auto plumbs through to the built Monitor (→ run loop → XdpMq).
        let m = Monitor::builder()
            .interface("lo")
            .xdp_queues(Queues::Auto)
            .build()
            .expect("build monitor");
        assert!(matches!(m.xdp_queues, Queues::Auto));
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
