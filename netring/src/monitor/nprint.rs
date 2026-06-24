//! nPrint per-flow header-bit matrix export (issue #72).
//!
//! flowscope ships [`NPrintMatrix`](flowscope::nprint::NPrintMatrix) — the
//! nPrint (CCS 2021) per-packet header-bit representation for model-agnostic
//! ML pipelines. This module accumulates one matrix **per flow** by feeding
//! every packet's borrowed [`PacketView`] into it during the run-loop drain,
//! then hands the completed matrix to an
//! [`on_nprint`](crate::monitor::MonitorBuilder::on_nprint) handler at flow
//! end.
//!
//! Per-packet retention is non-trivial (~43 KiB per flow at the 100-packet
//! default), so the feature is opt-in and the live-flow set is bounded by
//! [`max_tracked_nprint_flows`](crate::monitor::MonitorBuilder::max_tracked_nprint_flows);
//! once the cap is reached, packets for *new* flows are skipped (existing
//! matrices keep filling) — the live capture is never blocked.
//!
//! Like [`ml_features`](crate::monitor::ml_features), the run loop stays
//! feature-agnostic: it holds an `Option<Box<dyn FlowByteAccumulator>>` and
//! only names [`FlowByteAccumulator`] + [`FlowKey`] + [`PacketView`] (all
//! always-compiled). The concrete accumulator — and the `NPrintMatrix` it
//! stores — is gated on `nprint`.

use flowscope::PacketView;

use crate::protocol::FlowKey;

/// Feeds raw packet views into per-flow accumulators and flushes them at flow
/// end. Object-safe and always compiled so the run loop can thread an
/// `Option<Box<dyn FlowByteAccumulator>>` without a `nprint` cfg.
pub(crate) trait FlowByteAccumulator: Send {
    /// Feed one packet's zero-copy view — called per frame inside the drain
    /// (synchronous, so its borrow drops before the dispatch `.await`).
    fn feed(&mut self, view: &PacketView<'_>);
    /// Flush the matrix for a completed flow to the handlers, then drop it.
    fn flush(&mut self, key: &FlowKey);
}

/// A completed-flow nPrint callback. Only needed under `nprint` (it names the
/// gated `NPrintMatrix`).
#[cfg(feature = "nprint")]
pub(crate) type NprintHandler = Box<dyn FnMut(&FlowKey, &flowscope::nprint::NPrintMatrix) + Send>;

/// Per-flow nPrint matrix accumulator. Keys flows the **same** way the tracker
/// keys `FlowEnded` (bidirectional `FiveTuple`, `a < b`), so `flush` always
/// finds the matrix built in `feed`.
#[cfg(feature = "nprint")]
pub(crate) struct NprintAccumulator {
    config: flowscope::nprint::NPrintConfig,
    extractor: flowscope::extract::FiveTuple,
    flows: rustc_hash::FxHashMap<FlowKey, flowscope::nprint::NPrintMatrix>,
    handlers: Vec<NprintHandler>,
    max_flows: usize,
    /// Packets dropped because the live-flow set was already at `max_flows`.
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
            // Bidirectional so A→B and B→A fold into one matrix, under the
            // canonical key the tracker also uses for FlowEnded.
            extractor: flowscope::extract::FiveTuple::bidirectional(),
            flows: rustc_hash::FxHashMap::default(),
            handlers,
            max_flows,
            skipped_flows: 0,
        }
    }
}

#[cfg(feature = "nprint")]
impl FlowByteAccumulator for NprintAccumulator {
    fn feed(&mut self, view: &PacketView<'_>) {
        use flowscope::FlowExtractor;
        // Re-key the frame canonically. Non-IP / unparseable frames have no
        // 5-tuple and are simply not nPrinted.
        let Some(extracted) = self.extractor.extract(*view) else {
            return;
        };
        if let Some(matrix) = self.flows.get_mut(&extracted.key) {
            // `push_view` returns false once `max_packets` is hit; the matrix
            // stays put until flow end either way.
            matrix.push_view(view);
        } else if self.flows.len() < self.max_flows {
            let mut matrix = flowscope::nprint::NPrintMatrix::new(self.config);
            matrix.push_view(view);
            self.flows.insert(extracted.key, matrix);
        } else {
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
}
