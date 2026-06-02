//! Sliding-window per-key event counter.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::Duration;

use ahash::RandomState;
use flowscope::Timestamp;

/// A sliding-window event counter keyed by `K`.
///
/// Internally splits the window into fixed-width buckets so eviction
/// is `O(1)` amortized per [`bump`](Self::bump). The total count
/// across all live buckets is returned by [`count`](Self::count) —
/// the canonical "how many events in the last `window` for this
/// key?" query.
///
/// # Choosing parameters
///
/// - `window`: total observation interval. Pick the time horizon
///   you care about (10s for connection bursts, 60s for slower
///   patterns).
/// - `bucket_width`: granularity of eviction. Smaller = more precise
///   eviction at the cost of more buckets. Rule of thumb:
///   `bucket_width ≈ window / 10`.
///
/// # Memory
///
/// Allocates one `HashMap<K, u64>` per bucket. With `window = 10s`
/// and `bucket_width = 1s` that's at most 10 maps; each map holds
/// entries for keys seen during its bucket.
///
/// Keys are never proactively removed from old buckets — they age
/// out when the bucket itself ages out.
pub struct TimeBucketedCounter<K> {
    window: Duration,
    bucket_width: Duration,
    /// Buckets in chronological order; front = oldest, back = newest.
    /// Each entry is (bucket_start_timestamp, per-key counts).
    buckets: VecDeque<(Timestamp, HashMap<K, u64, RandomState>)>,
}

impl<K> std::fmt::Debug for TimeBucketedCounter<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeBucketedCounter")
            .field("window", &self.window)
            .field("bucket_width", &self.bucket_width)
            .field("buckets", &self.buckets.len())
            .finish()
    }
}

impl<K: Hash + Eq + Clone> TimeBucketedCounter<K> {
    /// Construct a counter with the given `window` and per-bucket
    /// `bucket_width`.
    ///
    /// # Panics
    ///
    /// Panics if `bucket_width` is zero or greater than `window`.
    pub fn new(window: Duration, bucket_width: Duration) -> Self {
        assert!(
            !bucket_width.is_zero(),
            "TimeBucketedCounter: bucket_width must be non-zero"
        );
        assert!(
            bucket_width <= window,
            "TimeBucketedCounter: bucket_width ({bucket_width:?}) must be ≤ window ({window:?})"
        );
        Self {
            window,
            bucket_width,
            buckets: VecDeque::new(),
        }
    }

    /// Increment the count for `k` in the bucket containing `now`.
    /// Evicts buckets older than `now - window`.
    pub fn bump(&mut self, k: K, now: Timestamp) {
        let bucket_start = self.bucket_anchor(now);
        self.evict_older_than(now);

        // Append to the tail bucket if it matches; otherwise push new.
        match self.buckets.back_mut() {
            Some((start, map)) if *start == bucket_start => {
                *map.entry(k).or_insert(0) += 1;
            }
            _ => {
                let mut map = HashMap::with_hasher(RandomState::new());
                map.insert(k, 1);
                self.buckets.push_back((bucket_start, map));
            }
        }
    }

    /// Total count for `k` across all live buckets relative to `now`.
    /// Doesn't mutate state — buckets older than `now - window` are
    /// filtered but not removed (call [`evict_older_than`](Self::evict_older_than)
    /// explicitly to reclaim memory in a long-idle counter).
    pub fn count(&self, k: &K, now: Timestamp) -> u64 {
        let cutoff = self.cutoff(now);
        self.buckets
            .iter()
            .filter(|(start, _)| *start >= cutoff)
            .map(|(_, map)| map.get(k).copied().unwrap_or(0))
            .sum()
    }

    /// Total count for `k` over all retained buckets, ignoring the
    /// window. Mostly useful for tests and debugging.
    pub fn count_unbounded(&self, k: &K) -> u64 {
        self.buckets
            .iter()
            .map(|(_, map)| map.get(k).copied().unwrap_or(0))
            .sum()
    }

    /// Number of retained buckets (active or otherwise).
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// `true` iff no buckets have been allocated yet.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Drop all buckets whose start time is older than `now - window`.
    /// Called automatically by [`bump`](Self::bump); useful to call
    /// explicitly during quiet periods to free memory.
    pub fn evict_older_than(&mut self, now: Timestamp) {
        let cutoff = self.cutoff(now);
        while let Some((start, _)) = self.buckets.front() {
            if *start < cutoff {
                self.buckets.pop_front();
            } else {
                break;
            }
        }
    }

    /// Iterator over `(K, total_count)` pairs for keys whose count
    /// in the current live window exceeds `threshold`. Useful for
    /// rate-anomaly detectors that want "all hosts above threshold
    /// right now".
    ///
    /// O(buckets × keys-per-bucket). Suitable for periodic sweeps;
    /// inappropriate for per-packet calls on million-key counters.
    pub fn entries_above(&self, threshold: u64, now: Timestamp) -> Vec<(K, u64)> {
        let cutoff = self.cutoff(now);
        let mut totals: HashMap<K, u64, RandomState> = HashMap::with_hasher(RandomState::new());
        for (start, map) in &self.buckets {
            if *start < cutoff {
                continue;
            }
            for (k, v) in map {
                *totals.entry(k.clone()).or_insert(0) += *v;
            }
        }
        totals.into_iter().filter(|(_, v)| *v > threshold).collect()
    }

    /// The earliest timestamp considered "in window" relative to `now`.
    fn cutoff(&self, now: Timestamp) -> Timestamp {
        let now_dur = now.to_duration();
        let cutoff_dur = now_dur.saturating_sub(self.window);
        // Convert Duration → Timestamp (seconds + nanos).
        Timestamp::new(cutoff_dur.as_secs() as u32, cutoff_dur.subsec_nanos())
    }

    /// Truncate `ts` down to the start of its containing bucket.
    fn bucket_anchor(&self, ts: Timestamp) -> Timestamp {
        let ts_ns = ts.to_duration().as_nanos();
        let width_ns = self.bucket_width.as_nanos();
        let anchor_ns = (ts_ns / width_ns) * width_ns;
        let anchor_dur = Duration::from_nanos(anchor_ns as u64);
        Timestamp::new(anchor_dur.as_secs() as u32, anchor_dur.subsec_nanos())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_increments_single_bucket() {
        let mut c = TimeBucketedCounter::<&'static str>::new(
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        let now = Timestamp::new(100, 0);
        for _ in 0..7 {
            c.bump("a", now);
        }
        assert_eq!(c.count(&"a", now), 7);
        assert_eq!(c.count(&"b", now), 0);
    }

    #[test]
    fn buckets_age_out_after_window() {
        let mut c = TimeBucketedCounter::<&'static str>::new(
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        c.bump("a", Timestamp::new(100, 0));
        c.bump("a", Timestamp::new(100, 0));

        // Within window — still counted.
        assert_eq!(c.count(&"a", Timestamp::new(109, 999_999_999)), 2);
        // At window boundary — first bucket starts at 100s, cutoff at 110-10=100s.
        // 100 >= 100 → still in window.
        assert_eq!(c.count(&"a", Timestamp::new(110, 0)), 2);
        // Past window — cutoff at 111-10=101s, bucket at 100 < 101 → out.
        assert_eq!(c.count(&"a", Timestamp::new(111, 0)), 0);
    }

    #[test]
    fn multi_bucket_sum_across_window() {
        let mut c = TimeBucketedCounter::<&'static str>::new(
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        // Five separate buckets, one bump each.
        for sec in 100..105 {
            c.bump("a", Timestamp::new(sec, 0));
        }
        assert_eq!(c.len(), 5);
        // All five buckets are in window at t=109.
        assert_eq!(c.count(&"a", Timestamp::new(109, 0)), 5);
        // At t=112, buckets at 100 and 101 are gone (cutoff = 102).
        // Eviction happens on bump; count() filters but doesn't evict.
        // So count() still iterates 5 buckets but filters out 100/101.
        assert_eq!(c.count(&"a", Timestamp::new(112, 0)), 3);
    }

    #[test]
    fn bump_evicts_old_buckets() {
        let mut c = TimeBucketedCounter::<&'static str>::new(
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        c.bump("a", Timestamp::new(100, 0));
        assert_eq!(c.len(), 1);
        c.bump("a", Timestamp::new(120, 0)); // 20s later — first bucket aged
        assert_eq!(c.len(), 1);
        assert_eq!(c.count(&"a", Timestamp::new(120, 0)), 1);
    }

    #[test]
    fn entries_above_threshold() {
        let mut c = TimeBucketedCounter::<&'static str>::new(
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        let now = Timestamp::new(100, 0);
        for _ in 0..5 {
            c.bump("a", now);
        }
        for _ in 0..50 {
            c.bump("b", now);
        }
        let mut hot = c.entries_above(10, now);
        hot.sort_by_key(|(k, _)| *k);
        assert_eq!(hot, vec![("b", 50)]);
    }

    #[test]
    fn explicit_evict_clears_old_buckets() {
        let mut c = TimeBucketedCounter::<&'static str>::new(
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        c.bump("a", Timestamp::new(100, 0));
        assert_eq!(c.len(), 1);
        c.evict_older_than(Timestamp::new(200, 0));
        assert_eq!(c.len(), 0);
        assert!(c.is_empty());
    }

    #[test]
    fn bucket_anchor_truncates_correctly() {
        let c = TimeBucketedCounter::<&'static str>::new(
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        // 100.7s anchors to 100.0s with bucket_width=1s.
        let anchored = c.bucket_anchor(Timestamp::new(100, 700_000_000));
        assert_eq!(anchored, Timestamp::new(100, 0));
        // 100.0s anchors to itself.
        let anchored = c.bucket_anchor(Timestamp::new(100, 0));
        assert_eq!(anchored, Timestamp::new(100, 0));
    }

    #[test]
    #[should_panic(expected = "bucket_width must be non-zero")]
    fn zero_bucket_width_panics() {
        let _ = TimeBucketedCounter::<&'static str>::new(Duration::from_secs(10), Duration::ZERO);
    }

    #[test]
    #[should_panic(expected = "must be ≤ window")]
    fn bucket_wider_than_window_panics() {
        let _ = TimeBucketedCounter::<&'static str>::new(
            Duration::from_secs(1),
            Duration::from_secs(10),
        );
    }
}
