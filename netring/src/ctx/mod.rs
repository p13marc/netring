//! Per-event context passed to handlers.
//!
//! `Ctx` lives on the dispatch stack — never heap-allocated.
//! Handlers receive a single `&mut Ctx<'_>` (alongside the typed
//! event payload) and pull what they need via methods on `Ctx`:
//!
//! ```ignore
//! Monitor::builder()
//!     .state::<MyState>()
//!     .counter::<IpAddr>(Duration::from_secs(10), Duration::from_secs(1))
//!     .on_ctx::<Http>(|req, ctx| {
//!         let counters = ctx.counter_mut::<IpAddr>();
//!         counters.bump(req.client_ip(), ctx.ts);
//!         ctx.state_mut::<MyState>().requests += 1;
//!         Ok(())
//!     });
//! ```
//!
//! ## Why method-style instead of axum-style extractors
//!
//! The first cut of this module shipped an `FromCtx` trait with
//! multi-extractor blanket impls (1..=8 arities). It doesn't
//! compile: every `<P as FromCtx>::from_ctx(&mut ctx)` call holds
//! `&mut Ctx` for as long as its return value lives, so the
//! second extractor can't re-borrow. axum gets away with this
//! because async-await sequences the borrows; sync Rust can't.
//!
//! Method accessors on `Ctx` give the same ergonomics without
//! the borrow-checker headache: each call is its own bounded
//! borrow, and the compiler tracks disjoint field accesses
//! (`state_map`, `counters`, `sink`) correctly.

use std::sync::LazyLock;

use flowscope::Timestamp;
use flowscope::well_known::LabelTable;

mod from_ctx;
mod split;

pub use from_ctx::{CounterRegistry, FlowStateRegistry, StateMap};

use crate::correlate::TimeBucketedCounter;
use crate::protocol::FlowKey;

/// Process-wide default well-known label table (inherits flowscope's
/// built-in port map). Used as the fallback for any [`Ctx`] built
/// without a monitor-supplied table — synthetic test/bench `Ctx`s and
/// the lifecycle/tick paths before a custom `.label_table(...)` lands.
static DEFAULT_LABEL_TABLE: LazyLock<LabelTable> = LazyLock::new(LabelTable::new);

/// `&'static` borrow of [`DEFAULT_LABEL_TABLE`]. The `LazyLock`
/// deref-coerces to `&LabelTable`; the static lives forever so the
/// borrow is `'static` and fits any `Ctx<'a>`.
pub(crate) fn default_label_table() -> &'static LabelTable {
    &DEFAULT_LABEL_TABLE
}

/// Tag for which capture source this event came from.
/// `SourceIdx(0)` for single-interface monitors; multi-interface
/// (Phase E) increments per registered iface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceIdx(pub u8);

/// Runtime context passed to every handler invocation.
///
/// The `flow` / `ts` / `source` fields are `pub` for direct read.
/// State / counter / sink access goes through the typed accessor
/// methods so the storage maps can stay `pub(crate)`.
pub struct Ctx<'a> {
    /// The flow key for the current event, if any.
    ///
    /// Held by value (`FlowKey` is `Copy`) so dispatch sites can
    /// stamp a per-message key without lifetime gymnastics —
    /// borrowing through `Option<&'a FlowKey>` would require a
    /// place to anchor the borrow that outlives the `Ctx`.
    ///
    /// **Prefer `payload.key` over `ctx.flow` when the event
    /// payload carries one.** For lifecycle events
    /// (`FlowStarted/Ended/Established<P>`) and message events
    /// (`HttpMessage`, `DnsMessage`, …), `payload.key` is the
    /// typed value with no `Option` indirection. For non-flow
    /// events (`Tick`) `ctx.flow` is `None`. The same key is
    /// available through both paths for flow events; the field
    /// is preserved as a stable accessor for cross-cutting
    /// handlers (e.g. a tick handler that logs the most recent
    /// flow, where the typed payload doesn't carry one).
    pub flow: Option<FlowKey>,

    /// Timestamp of the current event.
    pub ts: Timestamp,

    /// Source-interface index.
    pub source: SourceIdx,

    /// 0.21 D.4: optional human-readable name set on the parent
    /// monitor via [`crate::monitor::MonitorBuilder::name`].
    /// Handlers running under multiple monitors in the same
    /// process can branch on this to disambiguate (e.g. log
    /// `target = monitor_name` or stamp `with("monitor", name)`
    /// on emitted anomalies). Borrowed from the
    /// [`Monitor`](crate::monitor::Monitor)'s
    /// owned `Box<str>` storage at dispatch time; `None` when
    /// `.name(...)` was not called.
    pub monitor_name: Option<&'a str>,

    /// Per-monitor user state, keyed by `TypeId`.
    pub(crate) state_map: &'a mut StateMap,

    /// The anomaly sink (Phase C fills in the trait body).
    pub(crate) sink: &'a mut dyn crate::anomaly::sink::AnomalySink,

    /// Per-monitor counter storage.
    pub(crate) counters: &'a mut CounterRegistry,

    /// 0.21 I.7: per-flow user state. Each `T: Default + Send +
    /// 'static` registered via
    /// [`crate::monitor::MonitorBuilder::flow_state`] gets a
    /// per-flow slot lazily created on
    /// [`Self::flow_state_mut::<T>`] access. Backed by
    /// [`flowscope::correlate::FlowStateMap`].
    pub(crate) flow_states: &'a mut FlowStateRegistry,

    /// 0.22: active well-known label table for app/protocol-label
    /// lookups (`FiveTupleKey::app_label_with`). Defaults to
    /// flowscope's built-in table; overridden per-monitor via
    /// [`crate::monitor::MonitorBuilder::label_table`]. Read through
    /// [`Self::label_table`].
    pub(crate) label_table: &'a LabelTable,

    /// 0.22: read-only flow tracker for ICMP→flow correlation
    /// ([`Self::lookup_icmp_flow`]). `Some` on the live per-packet
    /// dispatch path (the run loop borrows `driver.tracker()` here);
    /// `None` on synthetic / tick / drain `Ctx`s that have no live
    /// capture behind them.
    pub(crate) tracker: Option<&'a flowscope::FlowTracker<flowscope::extract::FiveTuple, ()>>,

    /// Issue #19: read-only ARP binding table for cross-protocol IP→MAC
    /// lookups (e.g. a TLS handler annotating a flow with the peer's MAC).
    /// `Some` only inside the ARP drain (`dispatch_arp`), where the table is
    /// borrowed `&` *after* the current frame's binding was learned; `None`
    /// everywhere else. Read through [`Self::arp_table`] (feature `arp`). The
    /// field is the unconditional `NeighborTable` type so the dozen `Ctx`
    /// construction sites stay feature-agnostic.
    #[cfg_attr(not(feature = "arp"), allow(dead_code))]
    pub(crate) arp_table:
        Option<&'a flowscope::correlate::NeighborTable<std::net::Ipv4Addr, flowscope::MacAddr>>,
}

impl<'a> Ctx<'a> {
    /// Bench-only constructor — `benches/zero_alloc.rs` needs to
    /// manually assemble a `Ctx` to drive the dispatcher without
    /// a full `Monitor`. Not part of the public API outside the
    /// bench feature.
    #[cfg(feature = "bench-zero-alloc")]
    pub fn new_for_bench(
        ts: Timestamp,
        state_map: &'a mut StateMap,
        sink: &'a mut dyn crate::anomaly::sink::AnomalySink,
        counters: &'a mut CounterRegistry,
        flow_states: &'a mut FlowStateRegistry,
    ) -> Self {
        Self {
            flow: None,
            ts,
            source: SourceIdx(0),
            monitor_name: None,
            state_map,
            sink,
            counters,
            flow_states,
            label_table: default_label_table(),
            tracker: None,
            arp_table: None,
        }
    }

    /// Constructor exposed for integration tests that need to
    /// drive the dispatcher with a custom `Ctx`. Not part of the
    /// documented public API (`#[doc(hidden)]`). `monitor_name`
    /// defaults to `None`; the `label_table` defaults to the
    /// built-in table and `tracker` to `None`; production callers
    /// in the run loop set those via the [`Ctx`] struct literal
    /// directly.
    #[doc(hidden)]
    pub fn new(
        flow: Option<FlowKey>,
        ts: Timestamp,
        source: SourceIdx,
        state_map: &'a mut StateMap,
        sink: &'a mut dyn crate::anomaly::sink::AnomalySink,
        counters: &'a mut CounterRegistry,
        flow_states: &'a mut FlowStateRegistry,
    ) -> Self {
        Self {
            flow,
            ts,
            source,
            monitor_name: None,
            state_map,
            sink,
            counters,
            flow_states,
            label_table: default_label_table(),
            tracker: None,
            arp_table: None,
        }
    }

    /// Borrow per-monitor state `T` mutably.
    ///
    /// `T: Default` so the slot is lazy-created on first access.
    /// Pre-register via `MonitorBuilder::state::<T>()` to surface
    /// typos at build time.
    #[inline]
    pub fn state_mut<T: Default + Send + 'static>(&mut self) -> &mut T {
        self.state_map.get_or_init_mut::<T>()
    }

    /// 0.22: immutable, non-creating read of per-monitor state `T`.
    ///
    /// Sibling to [`Self::state_mut`] that neither requires `Default`
    /// nor lazy-creates: returns `None` if `T` was never registered
    /// or touched. Used by read-only views (`bandwidth()`, report
    /// snapshots) that must not mutate state behind a shared borrow.
    #[inline]
    pub fn state<T: 'static>(&self) -> Option<&T> {
        self.state_map.get::<T>()
    }

    /// 0.22: the active well-known label table for this monitor.
    ///
    /// Always returns something — the default is flowscope's built-in
    /// table; a custom one is installed via
    /// [`crate::monitor::MonitorBuilder::label_table`]. Pair with
    /// [`flowscope::extract::FiveTupleKey::app_label_with`] /
    /// `protocol_label_with` for site-custom port labelling.
    #[inline]
    pub fn label_table(&self) -> &LabelTable {
        self.label_table
    }

    /// 0.22 §3: immutable, non-panicking read of the `K`-keyed
    /// sliding-window counter. `None` if unregistered (sibling to the
    /// panicking [`Self::counter_mut`]). Used by report snapshots.
    #[inline]
    pub fn counter<K>(&self) -> Option<&TimeBucketedCounter<K>>
    where
        K: std::hash::Hash + Eq + Clone + Send + 'static,
    {
        self.counters.get::<K>()
    }

    /// 0.22 §2.3: a [`BandwidthReport`](crate::monitor::BandwidthReport)
    /// snapshot of the bandwidth slot, if
    /// [`bandwidth_by_app`](crate::monitor::MonitorBuilder::bandwidth_by_app)
    /// / [`on_bandwidth`](crate::monitor::MonitorBuilder::on_bandwidth)
    /// registered it; `None` otherwise. The report captures `self.ts`
    /// as its instant, so callers never handle a raw `Timestamp`.
    #[inline]
    pub fn bandwidth(&self) -> Option<crate::monitor::BandwidthReport<'_>> {
        let state = self.state::<crate::monitor::bandwidth::BandwidthState>()?;
        Some(crate::monitor::BandwidthReport {
            rate: &state.0,
            now: self.ts,
        })
    }

    /// 0.22: join an ICMP error's embedded inner 5-tuple back to a
    /// live flow + its stats.
    ///
    /// Returns `None` when no tracker is wired onto this `Ctx`
    /// (synthetic / tick / drain contexts) or no live flow matches
    /// the inner tuple (already evicted / never tracked). Backs the
    /// `IcmpError.stats` join in the ICMP synthesis slot.
    #[cfg(feature = "icmp")]
    #[inline]
    pub fn lookup_icmp_flow(
        &self,
        inner: &flowscope::icmp::IcmpInner,
    ) -> Option<(FlowKey, flowscope::FlowStats)> {
        self.tracker?.stats_for_inner(inner)
    }

    /// Issue #19: the read-only ARP binding table (`IP → MAC`) — the learned
    /// neighbour map behind the ARP detector.
    ///
    /// `Some` while dispatching an ARP hook
    /// ([`on_arp`](crate::monitor::MonitorBuilder::on_arp) /
    /// [`on_arp_anomaly`](crate::monitor::MonitorBuilder::on_arp_anomaly)),
    /// where it reflects the table *including* the current frame's binding —
    /// so a detector can look **beyond** the triggering message: cross-check
    /// the sender's gateway, count how many IPs claim one MAC (ARP-scan), or
    /// read a binding's change history. `None` on every other dispatch path
    /// (flow / session / tick / packet subs) — those don't run inside the ARP
    /// drain. Enroll learning without a handler via
    /// [`MonitorBuilder::arp_table`](crate::monitor::MonitorBuilder::arp_table).
    ///
    /// **Cross-protocol lookup** (a flow/TLS handler resolving a peer IP to
    /// its MAC) would need the table threaded into the post-borrow
    /// dispatchers too — a tracked follow-up; today it's exposed on the ARP
    /// drain only.
    ///
    /// Look up a binding with
    /// [`peek`](flowscope::correlate::NeighborTable::peek):
    /// ```ignore
    /// if let Some(t) = ctx.arp_table()
    ///     && let Some(b) = t.peek(&some_ipv4, ctx.ts)
    /// {
    ///     // b.addr is the MAC; b.change_count, b.prior_addr, … available too.
    /// }
    /// ```
    #[cfg(feature = "arp")]
    #[inline]
    pub fn arp_table(&self) -> Option<&flowscope::correlate::ArpTable> {
        self.arp_table
    }

    /// Borrow the `K`-keyed sliding-window counter mutably.
    ///
    /// # Panics
    ///
    /// Panics if no `MonitorBuilder::counter::<K>(...)` call
    /// registered this key — a programmer error caught early in
    /// development.
    #[inline]
    pub fn counter_mut<K>(&mut self) -> &mut TimeBucketedCounter<K>
    where
        K: std::hash::Hash + Eq + Clone + Send + 'static,
    {
        self.counters.get_mut::<K>()
    }

    /// Borrow the anomaly sink mutably.
    #[inline]
    pub fn sink_mut(&mut self) -> &mut dyn crate::anomaly::sink::AnomalySink {
        self.sink
    }

    /// 0.21 I.7: borrow per-flow user state `T` mutably.
    ///
    /// Returns `None` when:
    /// - `T` was not registered via
    ///   [`crate::monitor::MonitorBuilder::flow_state::<T>`].
    /// - This `Ctx` doesn't carry a flow key
    ///   ([`Tick`](crate::protocol::event_typed::Tick) and
    ///   `TrackerAnomaly` are the only such events).
    ///
    /// Lazy-creates `T::default()` on first access for a given
    /// flow key; subsequent accesses return the same `&mut T`.
    /// The slot's last-seen timestamp refreshes on every access.
    /// Eviction happens via `FlowStateMap::feed(FlowEvent::Ended)`
    /// — when `FlowEnded<P>` lands, the slot for that key is
    /// freed.
    ///
    /// Typical use: aggregate per-flow stats inside a
    /// `FlowStarted<P>` handler, read+emit in `FlowEnded<P>`:
    ///
    /// ```ignore
    /// .on_ctx::<FlowStarted<Tcp>>(|_e, ctx| {
    ///     let s = ctx.flow_state_mut::<MyState>().unwrap();
    ///     s.bytes = 0;
    ///     Ok(())
    /// })
    /// .on_ctx::<FlowEnded<Tcp>>(|e, ctx| {
    ///     let s = ctx.flow_state_mut::<MyState>().unwrap();
    ///     ctx.emit("FlowDone", Severity::Info)
    ///         .with_metric("bytes", s.bytes as f64)
    ///         .emit();
    ///     Ok(())
    /// })
    /// ```
    #[inline]
    pub fn flow_state_mut<T>(&mut self) -> Option<&mut T>
    where
        T: Default + Send + 'static,
    {
        let key = self.flow?;
        let ts = self.ts;
        let map = self.flow_states.get_mut::<T>()?;
        Some(map.get_or_default(&key, ts))
    }

    /// Shortcut: begin an anomaly emission keyed by `kind` + `severity`
    /// using `self.ts` as the timestamp. Equivalent to
    /// `self.sink_mut().begin(kind, severity, self.ts)` but reads
    /// cleaner:
    ///
    /// ```ignore
    /// ctx.emit("FlowStartedTcp", Severity::Info)
    ///     .with_key(&evt.key)
    ///     .with_metric("count", n as f64)
    ///     .emit();
    /// ```
    ///
    /// The returned [`AnomalyWriter`](crate::anomaly::sink::AnomalyWriter)
    /// borrows the sink for its lifetime; no temporaries needed.
    #[inline]
    pub fn emit(
        &mut self,
        kind: &'static str,
        severity: crate::anomaly::Severity,
    ) -> crate::anomaly::sink::AnomalyWriter<'_> {
        let ts = self.ts;
        self.sink.begin(kind, severity, ts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::sink::NoopSink;

    #[derive(Default)]
    struct DemoState {
        n: u64,
    }

    fn make_ctx<'a>(
        state: &'a mut StateMap,
        sink: &'a mut NoopSink,
        counters: &'a mut CounterRegistry,
        flow_states: &'a mut FlowStateRegistry,
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
            label_table: default_label_table(),
            tracker: None,
            arp_table: None,
        }
    }

    #[test]
    fn ctx_constructs_from_borrowed_fields() {
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        let mut sink = NoopSink;
        let mut flow_states = FlowStateRegistry::default();
        let _ctx = make_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);
    }

    #[test]
    fn state_mut_lazy_creates_then_returns_same() {
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        let mut sink = NoopSink;
        let mut flow_states = FlowStateRegistry::default();
        let mut ctx = make_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);
        ctx.state_mut::<DemoState>().n = 7;
        assert_eq!(ctx.state_mut::<DemoState>().n, 7);
    }

    #[test]
    fn sink_mut_returns_dyn_anomalysink() {
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        let mut sink = NoopSink;
        let mut flow_states = FlowStateRegistry::default();
        let mut ctx = make_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);
        let _: &mut dyn crate::anomaly::sink::AnomalySink = ctx.sink_mut();
    }

    #[test]
    fn counter_mut_returns_registered_counter() {
        use std::time::Duration;
        let mut state = StateMap::default();
        let mut counters = CounterRegistry::default();
        counters.register::<u16>(TimeBucketedCounter::<u16>::new_unbounded(
            Duration::from_secs(60),
            Duration::from_secs(1),
        ));
        let mut sink = NoopSink;
        let mut flow_states = FlowStateRegistry::default();
        let mut ctx = make_ctx(&mut state, &mut sink, &mut counters, &mut flow_states);
        ctx.counter_mut::<u16>().bump(42u16, Timestamp::new(0, 0));
    }

    #[test]
    fn source_idx_roundtrip() {
        assert_eq!(SourceIdx(3), SourceIdx(3));
        assert_ne!(SourceIdx(1), SourceIdx(2));
    }
}
