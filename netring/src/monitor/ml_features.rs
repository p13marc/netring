//! CICFlowMeter ML-feature export (issue #32).
//!
//! At flow end the Monitor has the full `flowscope::FlowStats` (per-packet
//! IAT + active/idle Welford accumulators, TCP flag counts) — the data the
//! summary [`FlowRecord`](crate::export::FlowRecord) throws away. This module
//! bridges that live `FlowStats` into flowscope's
//! [`CicFlowFeatures`](flowscope::CicFlowFeatures) (CICFlowMeter parity:
//! totals / throughput + the 12 IAT + 8 active/idle features), delivered to a
//! handler registered with
//! [`MonitorBuilder::on_ml_features`](crate::monitor::MonitorBuilder::on_ml_features).
//!
//! The run loop is feature-agnostic: it hands the raw `(key, stats, reason)`
//! to a boxed `FlowEndHandler`; the `CicFlowFeatures` construction lives
//! entirely in `make_handler` (gated on `ml-features`), so `run.rs` never
//! names a `ml-features`-only type.

use crate::protocol::FlowKey;

/// A flow-end callback over the raw tracker data. Always available (it names
/// only `flow`-level types), so the run loop can thread a slice of these
/// without a `ml-features` cfg; the vec is simply empty unless
/// [`on_ml_features`](crate::monitor::MonitorBuilder::on_ml_features) was
/// called.
pub(crate) type FlowEndHandler =
    Box<dyn FnMut(&FlowKey, &flowscope::event::FlowStats, flowscope::event::EndReason) + Send>;

/// Wrap a user `FnMut(&CicFlowFeatures)` into a `FlowEndHandler` that builds
/// the CICFlowMeter feature vector from the live `FlowStats` at flow end.
///
/// Goes through flowscope's IANA-IE-keyed `ipfix::FlowRecord` (the canonical
/// shape `CicFlowFeatures::from_flow_record` consumes) and then folds in the
/// IAT / active-idle block via `with_iat` — so none of the rich per-packet
/// timing is lost (unlike the summary `FlowRecord`).
#[cfg(feature = "ml-features")]
pub(crate) fn make_handler<F>(mut handler: F) -> FlowEndHandler
where
    F: FnMut(&flowscope::CicFlowFeatures) + Send + 'static,
{
    Box::new(move |key, stats, reason| {
        let record = flowscope::ipfix::FlowRecord::from_key_fields(stats, key, Some(reason));
        let features = flowscope::CicFlowFeatures::from_flow_record(&record).with_iat(stats);
        handler(&features);
    })
}
