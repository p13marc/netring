//! Query/response correlation by 16-bit DNS transaction ID.
//!
//! Bounded HashMap of pending queries, keyed by `(scope, tx_id)` so
//! two concurrent queries with the same ID from different flows
//! don't mis-correlate. `scope` is opaque — typically the flow
//! key, or `()` for a coarse "global" correlator.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Duration;

use ahash::RandomState;
use netring_flow::Timestamp;

use crate::types::{DnsConfig, DnsQuery};

/// Correlator state for query/response matching.
///
/// `S` is the scope type — usually a flow key. Use `()` to correlate
/// all queries in one global pool (works only when transaction IDs
/// don't collide across flows).
pub struct Correlator<S: Eq + Hash + Clone> {
    pending: HashMap<(S, u16), DnsQuery, RandomState>,
    config: DnsConfig,
}

impl<S: Eq + Hash + Clone> Correlator<S> {
    pub fn new() -> Self {
        Self::with_config(DnsConfig::default())
    }

    pub fn with_config(config: DnsConfig) -> Self {
        Self {
            pending: HashMap::with_hasher(RandomState::new()),
            config,
        }
    }

    /// Record a query observed from `scope` with transaction ID
    /// `q.transaction_id`. If the pending pool is full, evicts an
    /// oldest entry (single iteration; not strictly LRU but bounded).
    pub fn record_query(&mut self, scope: S, q: DnsQuery) {
        if self.pending.len() >= self.config.max_pending {
            // Drop the entry with the smallest started timestamp.
            // O(n) but only fires when full.
            if let Some(oldest_key) = self
                .pending
                .iter()
                .min_by_key(|(_, q)| q.timestamp)
                .map(|(k, _)| k.clone())
            {
                self.pending.remove(&oldest_key);
            }
        }
        let key = (scope, q.transaction_id);
        self.pending.insert(key, q);
    }

    /// Match a response. Returns `Some((query, elapsed))` if a
    /// pending query for `(scope, response.transaction_id)` exists;
    /// `None` if it's an orphan response.
    pub fn match_response(
        &mut self,
        scope: &S,
        tx_id: u16,
        response_time: Timestamp,
    ) -> Option<(DnsQuery, Duration)> {
        let key = (scope.clone(), tx_id);
        let q = self.pending.remove(&key)?;
        let elapsed = response_time
            .to_duration()
            .saturating_sub(q.timestamp.to_duration());
        Some((q, elapsed))
    }

    /// Return queries whose age exceeds `query_timeout`. The caller
    /// is responsible for emitting `on_unanswered` events.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<DnsQuery> {
        let now_d = now.to_duration();
        let timeout = self.config.query_timeout;
        let expired: Vec<(S, u16)> = self
            .pending
            .iter()
            .filter_map(|(k, q)| {
                let age = now_d.saturating_sub(q.timestamp.to_duration());
                if age >= timeout {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        let mut out = Vec::with_capacity(expired.len());
        for k in expired {
            if let Some(q) = self.pending.remove(&k) {
                out.push(q);
            }
        }
        out
    }

    /// Number of pending queries.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

impl<S: Eq + Hash + Clone> Default for Correlator<S> {
    fn default() -> Self {
        Self::new()
    }
}
