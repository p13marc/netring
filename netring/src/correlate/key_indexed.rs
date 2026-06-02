//! TTL'd kv-cache for cross-protocol correlation.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Duration;

use ahash::RandomState;
use flowscope::Timestamp;

/// A keyed value cache where entries expire after `ttl`. Use to
/// remember per-key observations (DNS resolutions, recent flow
/// activity, last-seen hostnames) for cross-protocol correlation.
///
/// Entries carry their insertion timestamp; [`get`](Self::get) checks
/// it against `now - ttl` and returns `None` for expired entries.
///
/// # Memory
///
/// O(entries). Expired entries linger until [`evict_expired`](Self::evict_expired)
/// is called or they're overwritten via [`insert`](Self::insert).
/// Insertion is O(1); a long-idle cache with thousands of expired
/// entries can grow unbounded — call `evict_expired` periodically
/// (e.g. from your sweep tick) for steady-state operation.
///
/// # Example
///
/// ```
/// use std::net::Ipv4Addr;
/// use std::time::Duration;
/// use flowscope::Timestamp;
/// use netring::correlate::KeyIndexed;
///
/// // Remember which name resolved to which IP for 30 seconds.
/// let mut dns_cache = KeyIndexed::<Ipv4Addr, String>::new(Duration::from_secs(30));
///
/// let ip: Ipv4Addr = "93.184.216.34".parse().unwrap();
/// dns_cache.insert(ip, "example.com".to_string(), Timestamp::new(100, 0));
///
/// // Within TTL — still there.
/// assert_eq!(dns_cache.get(&ip, Timestamp::new(120, 0)).map(String::as_str), Some("example.com"));
///
/// // Past TTL — gone.
/// assert!(dns_cache.get(&ip, Timestamp::new(200, 0)).is_none());
/// ```
pub struct KeyIndexed<K, V> {
    ttl: Duration,
    entries: HashMap<K, (V, Timestamp), RandomState>,
}

impl<K: std::fmt::Debug, V: std::fmt::Debug> std::fmt::Debug for KeyIndexed<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyIndexed")
            .field("ttl", &self.ttl)
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl<K: Hash + Eq, V> KeyIndexed<K, V> {
    /// Construct a cache where each entry lives for `ttl` after
    /// insertion. Subsequent inserts of the same key reset the TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: HashMap::with_hasher(RandomState::new()),
        }
    }

    /// Insert (or replace) the entry for `k` at time `now`. Resets
    /// TTL for an existing key.
    pub fn insert(&mut self, k: K, v: V, now: Timestamp) {
        self.entries.insert(k, (v, now));
    }

    /// Borrow the value for `k` if present and not expired.
    /// Doesn't mutate state.
    pub fn get(&self, k: &K, now: Timestamp) -> Option<&V> {
        let (v, inserted) = self.entries.get(k)?;
        if now.saturating_sub(*inserted) > self.ttl {
            None
        } else {
            Some(v)
        }
    }

    /// Borrow the value plus its insertion timestamp.
    pub fn get_with_ts(&self, k: &K, now: Timestamp) -> Option<(&V, Timestamp)> {
        let (v, inserted) = self.entries.get(k)?;
        if now.saturating_sub(*inserted) > self.ttl {
            None
        } else {
            Some((v, *inserted))
        }
    }

    /// Remove the entry for `k`, returning its value if present
    /// (regardless of TTL).
    pub fn remove(&mut self, k: &K) -> Option<V> {
        self.entries.remove(k).map(|(v, _)| v)
    }

    /// Return `true` if `k` has a non-expired entry at `now`.
    pub fn contains_fresh(&self, k: &K, now: Timestamp) -> bool {
        self.get(k, now).is_some()
    }

    /// Drop every entry older than `now - ttl`.
    pub fn evict_expired(&mut self, now: Timestamp) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, (_, inserted)| now.saturating_sub(*inserted) <= ttl);
    }

    /// Remove and return every entry older than `now - ttl`. Useful
    /// for "expected B-event-following-A but didn't see it" detectors
    /// — the drained entries are the unfulfilled observations.
    pub fn drain_expired(&mut self, now: Timestamp) -> Vec<(K, V)>
    where
        K: Clone,
    {
        let ttl = self.ttl;
        let expired: Vec<K> = self
            .entries
            .iter()
            .filter_map(|(k, (_, inserted))| {
                if now.saturating_sub(*inserted) > ttl {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        expired
            .into_iter()
            .map(|k| {
                let (v, _) = self.entries.remove(&k).expect("just observed");
                (k, v)
            })
            .collect()
    }

    /// Number of entries (fresh + stale; stale aren't proactively removed).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` iff no entries are stored (fresh or stale).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all currently fresh entries at `now`.
    pub fn iter_fresh(&self, now: Timestamp) -> impl Iterator<Item = (&K, &V)> + '_ {
        let ttl = self.ttl;
        self.entries
            .iter()
            .filter(move |(_, (_, ins))| now.saturating_sub(*ins) <= ttl)
            .map(|(k, (v, _))| (k, v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_within_ttl() {
        let mut c = KeyIndexed::<&'static str, u32>::new(Duration::from_secs(10));
        c.insert("a", 42, Timestamp::new(100, 0));
        assert_eq!(c.get(&"a", Timestamp::new(105, 0)), Some(&42));
        assert_eq!(c.get(&"a", Timestamp::new(110, 0)), Some(&42));
    }

    #[test]
    fn get_returns_none_past_ttl() {
        let mut c = KeyIndexed::<&'static str, u32>::new(Duration::from_secs(10));
        c.insert("a", 42, Timestamp::new(100, 0));
        assert_eq!(c.get(&"a", Timestamp::new(111, 0)), None);
    }

    #[test]
    fn reinsert_resets_ttl() {
        let mut c = KeyIndexed::<&'static str, u32>::new(Duration::from_secs(10));
        c.insert("a", 1, Timestamp::new(100, 0));
        c.insert("a", 2, Timestamp::new(105, 0));
        // At t=110, the second insert is 5s old — well within 10s TTL.
        assert_eq!(c.get(&"a", Timestamp::new(110, 0)), Some(&2));
        // At t=116, the second insert is 11s old — expired.
        assert_eq!(c.get(&"a", Timestamp::new(116, 0)), None);
    }

    #[test]
    fn evict_drops_stale_entries() {
        let mut c = KeyIndexed::<&'static str, u32>::new(Duration::from_secs(10));
        c.insert("a", 1, Timestamp::new(100, 0));
        c.insert("b", 2, Timestamp::new(105, 0));
        assert_eq!(c.len(), 2);
        c.evict_expired(Timestamp::new(115, 0));
        // "a" inserted at 100 — 115-100=15 > 10, expired.
        // "b" inserted at 105 — 115-105=10 ≤ 10, kept.
        assert_eq!(c.len(), 1);
        assert!(c.get(&"a", Timestamp::new(115, 0)).is_none());
        assert_eq!(c.get(&"b", Timestamp::new(115, 0)), Some(&2));
    }

    #[test]
    fn remove_returns_value_regardless_of_ttl() {
        let mut c = KeyIndexed::<&'static str, u32>::new(Duration::from_secs(10));
        c.insert("a", 42, Timestamp::new(100, 0));
        assert_eq!(c.remove(&"a"), Some(42));
        assert_eq!(c.len(), 0);
        assert_eq!(c.remove(&"a"), None);
    }

    #[test]
    fn iter_fresh_filters_stale() {
        let mut c = KeyIndexed::<&'static str, u32>::new(Duration::from_secs(10));
        c.insert("fresh", 1, Timestamp::new(100, 0));
        c.insert("stale", 2, Timestamp::new(50, 0));
        let mut fresh: Vec<(&&'static str, &u32)> = c.iter_fresh(Timestamp::new(105, 0)).collect();
        fresh.sort_by_key(|(k, _)| *k);
        assert_eq!(fresh, vec![(&"fresh", &1)]);
    }

    #[test]
    fn get_with_ts_returns_insertion_time() {
        let mut c = KeyIndexed::<&'static str, u32>::new(Duration::from_secs(10));
        c.insert("a", 42, Timestamp::new(100, 0));
        let (val, ts) = c.get_with_ts(&"a", Timestamp::new(105, 0)).unwrap();
        assert_eq!(*val, 42);
        assert_eq!(ts, Timestamp::new(100, 0));
    }

    #[test]
    fn drain_expired_returns_dropped() {
        let mut c = KeyIndexed::<&'static str, u32>::new(Duration::from_secs(10));
        c.insert("stale_a", 1, Timestamp::new(50, 0));
        c.insert("stale_b", 2, Timestamp::new(60, 0));
        c.insert("fresh", 3, Timestamp::new(100, 0));
        let mut drained = c.drain_expired(Timestamp::new(105, 0));
        drained.sort_by_key(|(k, _)| *k);
        assert_eq!(drained, vec![("stale_a", 1), ("stale_b", 2)]);
        // Only "fresh" remains.
        assert_eq!(c.len(), 1);
        assert_eq!(c.get(&"fresh", Timestamp::new(105, 0)), Some(&3));
    }

    #[test]
    fn drain_expired_empty_when_nothing_stale() {
        let mut c = KeyIndexed::<&'static str, u32>::new(Duration::from_secs(10));
        c.insert("a", 1, Timestamp::new(100, 0));
        let drained = c.drain_expired(Timestamp::new(105, 0));
        assert!(drained.is_empty());
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn contains_fresh_basic() {
        let mut c = KeyIndexed::<&'static str, u32>::new(Duration::from_secs(10));
        c.insert("a", 42, Timestamp::new(100, 0));
        assert!(c.contains_fresh(&"a", Timestamp::new(105, 0)));
        assert!(!c.contains_fresh(&"a", Timestamp::new(115, 0)));
        assert!(!c.contains_fresh(&"missing", Timestamp::new(100, 0)));
    }
}
