//! nPrint per-flow header-bit matrix export (issue #72).
//!
//! flowscope ships [`NPrintMatrix`](flowscope::nprint::NPrintMatrix) — the
//! nPrint (CCS 2021) per-packet header-bit representation for model-agnostic
//! ML pipelines. This module accumulates one matrix **per flow** by feeding
//! every tracked packet's borrowed [`PacketView`] into it during the run-loop
//! drain, then hands the completed matrix to an
//! [`on_nprint`](crate::monitor::MonitorBuilder::on_nprint) handler at flow
//! end.
//!
//! Per-packet retention is non-trivial (~43 KiB per flow at the 100-packet
//! default), so the feature is opt-in and the live-flow set is bounded by
//! [`max_tracked_nprint_flows`](crate::monitor::MonitorBuilder::max_tracked_nprint_flows);
//! once the cap is reached, *new* flows are skipped (existing matrices keep
//! filling) — the live capture is never blocked.
//!
//! Like [`ml_features`](crate::monitor::ml_features), the run loop stays
//! feature-agnostic: it holds `Box<dyn FlowByteAccumulator>`s and only names
//! [`FlowByteAccumulator`] + [`FlowKey`] + [`PacketView`] (all
//! always-compiled). The concrete accumulator — and the `NPrintMatrix` it
//! stores — is gated on `nprint`.

use flowscope::PacketView;

use crate::protocol::FlowKey;

/// What per-flow accumulators hold, for the health handle (#214).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AccumulatorStats {
    /// Flows with a live matrix / buffer.
    pub(crate) live_flows: usize,
    /// Flows not accumulated because the live-flow cap was reached.
    pub(crate) skipped_flows: u64,
    /// Bytes of buffer capacity held (YARA's payload buffers).
    pub(crate) buffered_bytes: usize,
    /// Payload bytes not buffered because the memory budget was reached
    /// (YARA).
    pub(crate) skipped_bytes: u64,
}

impl std::ops::AddAssign for AccumulatorStats {
    fn add_assign(&mut self, o: Self) {
        self.live_flows = self.live_flows.saturating_add(o.live_flows);
        self.skipped_flows = self.skipped_flows.saturating_add(o.skipped_flows);
        self.buffered_bytes = self.buffered_bytes.saturating_add(o.buffered_bytes);
        self.skipped_bytes = self.skipped_bytes.saturating_add(o.skipped_bytes);
    }
}

/// Accumulates per-flow data from the packets the flow tracker tracked and
/// flushes it at flow end. Object-safe and always compiled so the run loop
/// can thread `Box<dyn FlowByteAccumulator>`s without a `nprint` cfg.
///
/// Fed **after** the tracker (#214): `pkt` is what it made of the packet —
/// its flow key (the one `FlowEnded` carries), side, and L4 payload location
/// — and `view` the frame it tracked: with IP reassembly armed, a whole
/// reassembled datagram, never a raw fragment. So every key fed ends with a
/// `FlowEnded` ([`Self::flush`]), and [`Self::retain`] drops the rare flow
/// that left the tracker without one.
pub(crate) trait FlowByteAccumulator: Send {
    /// Feed one tracked packet — called per frame inside the drain
    /// (synchronous, so its borrow drops before the dispatch `.await`).
    fn feed(&mut self, pkt: &flowscope::PacketInfo<FlowKey>, view: &PacketView<'_>);
    /// Flush the data of a completed flow to the handlers, then drop it.
    fn flush(&mut self, key: &FlowKey);
    /// Drop every flow `alive` rejects (gone from the tracker).
    fn retain(&mut self, alive: &dyn Fn(&FlowKey) -> bool);
    /// What it holds.
    fn stats(&self) -> AccumulatorStats;
}

/// A completed-flow nPrint callback. Only needed under `nprint` (it names the
/// gated `NPrintMatrix`).
#[cfg(feature = "nprint")]
pub(crate) type NprintHandler = Box<dyn FnMut(&FlowKey, &flowscope::nprint::NPrintMatrix) + Send>;

/// Per-flow nPrint matrix accumulator, keyed by the tracker's flow key.
#[cfg(feature = "nprint")]
pub(crate) struct NprintAccumulator {
    config: flowscope::nprint::NPrintConfig,
    flows: rustc_hash::FxHashMap<FlowKey, flowscope::nprint::NPrintMatrix>,
    handlers: Vec<NprintHandler>,
    max_flows: usize,
    /// New flows not given a matrix because the live-flow set was full.
    skipped_flows: u64,
}

#[cfg(feature = "nprint")]
impl NprintAccumulator {
    pub(crate) fn new(
        config: flowscope::nprint::NPrintConfig,
        max_flows: usize,
        handlers: Vec<NprintHandler>,
    ) -> Self {
        Self {
            config,
            flows: rustc_hash::FxHashMap::default(),
            handlers,
            max_flows,
            skipped_flows: 0,
        }
    }
}

#[cfg(feature = "nprint")]
impl FlowByteAccumulator for NprintAccumulator {
    fn feed(&mut self, pkt: &flowscope::PacketInfo<FlowKey>, view: &PacketView<'_>) {
        if let Some(matrix) = self.flows.get_mut(&pkt.key) {
            // `push_view` returns false once `max_packets` is hit; the matrix
            // stays put until flow end either way.
            matrix.push_view(view);
        } else if self.flows.len() < self.max_flows {
            let mut matrix = flowscope::nprint::NPrintMatrix::new(self.config);
            matrix.push_view(view);
            self.flows.insert(pkt.key, matrix);
        } else if pkt.is_new {
            self.skipped_flows = self.skipped_flows.saturating_add(1);
        }
    }

    fn flush(&mut self, key: &FlowKey) {
        if let Some(matrix) = self.flows.remove(key) {
            for handler in self.handlers.iter_mut() {
                handler(key, &matrix);
            }
        }
    }

    fn retain(&mut self, alive: &dyn Fn(&FlowKey) -> bool) {
        self.flows.retain(|key, _| alive(key));
    }

    fn stats(&self) -> AccumulatorStats {
        AccumulatorStats {
            live_flows: self.flows.len(),
            skipped_flows: self.skipped_flows,
            ..AccumulatorStats::default()
        }
    }
}

/// Feed the tracker's view of the packet it just tracked — `view` being
/// the frame it tracked — to every accumulator. A frame it didn't track
/// (non-IP, deduplicated) feeds nothing.
pub(crate) fn feed_tracked(
    accumulators: &mut [Box<dyn FlowByteAccumulator>],
    driver: &flowscope::driver::Driver<flowscope::extract::FiveTuple>,
    view: &PacketView<'_>,
) {
    if accumulators.is_empty() {
        return;
    }
    if let Some(pkt) = driver.flow_driver().last_packet() {
        for acc in accumulators.iter_mut() {
            acc.feed(pkt, view);
        }
    }
}

/// Drop the accumulators' flows the tracker no longer has, then publish what
/// they hold to the health handle. Called after each sweep.
pub(crate) fn retain_tracked(
    accumulators: &mut [Box<dyn FlowByteAccumulator>],
    tracker: &flowscope::FlowTracker<flowscope::extract::FiveTuple, ()>,
    health: &crate::monitor::health::HealthState,
) {
    if accumulators.is_empty() {
        return;
    }
    for acc in accumulators.iter_mut() {
        acc.retain(&|key| tracker.get(key).is_some());
    }
    publish(accumulators, health);
}

/// Publish what the accumulators hold to the health handle.
pub(crate) fn publish(
    accumulators: &[Box<dyn FlowByteAccumulator>],
    health: &crate::monitor::health::HealthState,
) {
    if accumulators.is_empty() {
        return;
    }
    let mut total = AccumulatorStats::default();
    for acc in accumulators {
        total += acc.stats();
    }
    health.record_accumulators(total);
}
