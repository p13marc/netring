//! Owner-attributed bandwidth (issue #130).
//!
//! Where [`bandwidth`](crate::monitor::bandwidth) keys throughput by application
//! label, this keys it by a caller-defined **owner**: a
//! [`with_flow_attribution`](crate::monitor::MonitorBuilder::with_flow_attribution)
//! hook maps each flow's 5-tuple to an [`Attribution`] (an opaque `u64` — a
//! tenant, container, cgroup, subscriber, VLAN, whatever the deployment means by
//! "who"). The Monitor then tracks per-owner tx/rx rates and the share of
//! traffic it couldn't attribute.

use std::sync::Arc;
use std::time::Duration;

use flowscope::correlate::{Attribution, BandwidthByKey, ByteSemantics};
use rustc_hash::FxHashMap;

use crate::protocol::FlowKey;

/// Default rolling window / bucket for owner bandwidth (10 s in 1 s buckets).
pub(crate) const OWNER_BW_WINDOW: Duration = Duration::from_secs(10);
pub(crate) const OWNER_BW_BUCKET: Duration = Duration::from_secs(1);

/// The flow→owner attribution hook. `None` = "couldn't attribute this flow".
pub type AttributionHook = Arc<dyn Fn(&FlowKey) -> Option<Attribution> + Send + Sync + 'static>;

/// StateMap cell: the attribution hook, a per-flow owner cache (populated at
/// first packet, evicted at flow end), the per-owner rate table, and an
/// unattributed-bytes counter.
pub(crate) struct OwnerBandwidthState {
    hook: AttributionHook,
    owners: FxHashMap<FlowKey, Option<Attribution>>,
    pub(crate) bw: BandwidthByKey<Attribution>,
    pub(crate) unknown: BandwidthByKey<()>,
}

impl OwnerBandwidthState {
    pub(crate) fn new(hook: AttributionHook, window: Duration, bucket: Duration) -> Self {
        Self {
            hook,
            owners: FxHashMap::default(),
            bw: BandwidthByKey::new_unbounded(window, bucket),
            unknown: BandwidthByKey::new_unbounded(window, bucket),
        }
    }

    /// Attribute a flow's bytes. Caches the owner on first sight of the flow.
    pub(crate) fn record(&mut self, key: &FlowKey, bytes: u64, now: flowscope::Timestamp) {
        let owner = *self.owners.entry(*key).or_insert_with(|| (self.hook)(key));
        match owner {
            Some(attr) => self.bw.record_tx(attr, bytes, now),
            None => self.unknown.record_tx((), bytes, now),
        }
    }

    /// Drop a finished flow's cached owner.
    pub(crate) fn forget(&mut self, key: &FlowKey) {
        self.owners.remove(key);
    }
}

impl Default for OwnerBandwidthState {
    /// Never-hit fallback for the `state_mut` `Default` bound — the real cell is
    /// seeded via `state_init` with the user's attribution hook. This default
    /// attributes nothing.
    fn default() -> Self {
        Self::new(
            Arc::new(|_: &FlowKey| None),
            OWNER_BW_WINDOW,
            OWNER_BW_BUCKET,
        )
    }
}

/// A read view over the owner-bandwidth table at a fixed instant (issue #130).
pub struct OwnerBandwidthReport<'a> {
    pub(crate) state: &'a OwnerBandwidthState,
    pub(crate) now: flowscope::Timestamp,
}

impl OwnerBandwidthReport<'_> {
    /// Top-`n` owners by total bytes/sec, descending.
    pub fn top(&self, n: usize) -> Vec<(Attribution, f64)> {
        self.state.bw.top_k(n, self.now)
    }

    /// Total bytes/sec for one owner (`0.0` if unseen in the window).
    pub fn rate(&self, owner: Attribution) -> f64 {
        self.state.bw.total_bps(&owner, self.now)
    }

    /// Bytes/sec that couldn't be attributed to any owner.
    pub fn unknown_rate(&self) -> f64 {
        self.state.unknown.total_bps(&(), self.now)
    }

    /// Fraction (`0.0..=1.0`) of observed bytes/sec that were unattributed.
    /// `0.0` when there's no traffic.
    pub fn unknown_share(&self) -> f64 {
        let known: f64 = self
            .state
            .bw
            .top_k(usize::MAX, self.now)
            .iter()
            .map(|(_, r)| r)
            .sum();
        let unknown = self.unknown_rate();
        let total = known + unknown;
        if total > 0.0 { unknown / total } else { 0.0 }
    }

    /// The byte-counting semantics (payload vs wire) of the underlying table.
    pub fn semantics(&self) -> ByteSemantics {
        self.state.bw.semantics()
    }

    /// A serializable snapshot of the top-`n` owners.
    pub fn to_snapshot(&self, n: usize) -> OwnerBandwidthSnapshot {
        OwnerBandwidthSnapshot {
            owners: self.top(n).into_iter().map(|(a, bps)| (a.0, bps)).collect(),
            unknown_bps: self.unknown_rate(),
            unknown_share: self.unknown_share(),
            semantics: self.semantics().as_str(),
        }
    }
}

/// Serializable owner-bandwidth snapshot (issue #130).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct OwnerBandwidthSnapshot {
    /// `(owner_id, bytes_per_sec)` for the top owners, descending.
    pub owners: Vec<(u64, f64)>,
    /// Unattributed bytes/sec.
    pub unknown_bps: f64,
    /// Unattributed fraction (`0.0..=1.0`).
    pub unknown_share: f64,
    /// Byte-counting semantics label (`"payload"` / `"wire"` / …).
    pub semantics: &'static str,
}
