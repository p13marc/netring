//! Per-kind token-bucket rate limiter.

use std::time::Duration;

use flowscope::Timestamp;
use rustc_hash::FxHashMap;

use crate::anomaly::sink::{AnomalyRecord, AnomalySink};
use crate::layer::Layer;
use crate::layer::clock::{Reading, SteadyClock};

/// Drops anomalies of a given `kind` when they fire faster than
/// `max_per_period` per `period`. Each kind gets its own bucket;
/// kinds are independent.
///
/// Algorithm: a fixed window per kind — we track the window's start and
/// the count seen since. Once `period` has passed the count resets.
/// Measured in **packet time** (the anomalies' own timestamps), so a fast
/// [`Monitor::replay`](crate::monitor::Monitor) is limited exactly as a
/// live run over the same traffic would be. Time is the high-water mark of
/// those timestamps: an anomaly stamped earlier than the latest (another
/// capture queue's or NIC's clock, a reorder) counts toward the current
/// window, so clocks that interleave steadily don't refill the budget. A
/// clock that steps back for good — its anomalies still more than a
/// period behind after a period of their own time — is followed, with
/// fresh budgets; a clock ahead that only sends now and then may refill
/// them twice per record it sends (see the packet clock's notes in
/// `layer/clock.rs`).
///
/// `Clone` (0.22): the per-kind buckets live in the per-`wrap()` sink,
/// so the config clones cleanly for
/// [`LayerSpec`](crate::layer::LayerSpec) — each shard gets its own.
#[derive(Debug, Clone)]
pub struct RateLimitAnomalies {
    period: Duration,
    max_per_period: u32,
}

impl RateLimitAnomalies {
    /// `max_per_period` anomalies per `period` (of packet time), per kind.
    /// Overflow is silently dropped.
    pub fn new(max_per_period: u32, period: Duration) -> Self {
        Self {
            period,
            max_per_period,
        }
    }
}

impl Layer for RateLimitAnomalies {
    fn wrap(self: Box<Self>, inner: Box<dyn AnomalySink>) -> Box<dyn AnomalySink> {
        Box::new(RateLimitAnomaliesLayered {
            inner,
            period: self.period,
            max_per_period: self.max_per_period,
            buckets: FxHashMap::default(),
            clock: SteadyClock::default(),
        })
    }
}

struct Bucket {
    window_start: Timestamp,
    count: u32,
}

/// The applied layer — wraps an inner sink + per-kind buckets.
pub struct RateLimitAnomaliesLayered {
    inner: Box<dyn AnomalySink>,
    period: Duration,
    max_per_period: u32,
    buckets: FxHashMap<&'static str, Bucket>,
    clock: SteadyClock,
}

impl AnomalySink for RateLimitAnomaliesLayered {
    fn write(&mut self, record: &AnomalyRecord<'_>) {
        let kind = record.kind;
        let now = match self.clock.read(record.ts, self.period) {
            Reading::Now(now) => now,
            Reading::Restarted(now) => {
                // Windows on the old clock: none of them holds now.
                self.buckets.clear();
                now
            }
        };
        let bucket = self.buckets.entry(kind).or_insert(Bucket {
            window_start: now,
            count: 0,
        });
        if now.saturating_sub(bucket.window_start) >= self.period {
            bucket.window_start = now;
            bucket.count = 0;
        }
        // Every anomaly — a kind's first, a period's first — spends
        // budget, so a zero budget drops them all.
        let allow = bucket.count < self.max_per_period;
        if allow {
            bucket.count += 1;
            self.inner.write(record);
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use flowscope::Timestamp;

    use super::*;
    use crate::anomaly::Severity;

    #[derive(Default)]
    struct Capture(Arc<Mutex<u32>>);
    impl Capture {
        fn n(&self) -> Arc<Mutex<u32>> {
            Arc::clone(&self.0)
        }
    }
    impl AnomalySink for Capture {
        fn write(&mut self, _record: &AnomalyRecord<'_>) {
            *self.0.lock().unwrap() += 1;
        }
    }

    #[test]
    fn enforces_per_kind_budget() {
        let inner = Capture::default();
        let n = inner.n();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(RateLimitAnomalies::new(3, Duration::from_secs(60))).wrap(Box::new(inner));
        for _ in 0..10 {
            sink.begin("Burst", Severity::Info, Timestamp::new(0, 0))
                .emit();
        }
        assert_eq!(*n.lock().unwrap(), 3);
    }

    #[test]
    fn separate_kinds_have_independent_budgets() {
        let inner = Capture::default();
        let n = inner.n();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(RateLimitAnomalies::new(2, Duration::from_secs(60))).wrap(Box::new(inner));
        for _ in 0..5 {
            sink.begin("A", Severity::Info, Timestamp::new(0, 0)).emit();
        }
        for _ in 0..5 {
            sink.begin("B", Severity::Info, Timestamp::new(0, 0)).emit();
        }
        // 2 from A + 2 from B
        assert_eq!(*n.lock().unwrap(), 4);
    }

    /// A zero budget drops everything — the first anomaly of a kind
    /// (or of a new period) included.
    #[test]
    fn zero_budget_drops_everything() {
        let inner = Capture::default();
        let n = inner.n();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(RateLimitAnomalies::new(0, Duration::from_millis(10))).wrap(Box::new(inner));
        for _ in 0..3 {
            sink.begin("X", Severity::Info, Timestamp::new(0, 0)).emit();
        }
        sink.begin("X", Severity::Info, Timestamp::new(0, 20_000_000))
            .emit();
        assert_eq!(*n.lock().unwrap(), 0);
    }

    /// Review r2: a clock that steps back by more than a period starts a
    /// new window once the earlier clock has run a period (the budget
    /// stayed spent until the clock caught up).
    #[test]
    fn a_backward_clock_step_starts_a_new_window() {
        let inner = Capture::default();
        let n = inner.n();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(RateLimitAnomalies::new(1, Duration::from_millis(10))).wrap(Box::new(inner));
        for ts in [
            Timestamp::new(1_000, 0),
            Timestamp::new(1_000, 1),
            // The step: it counts toward the window it lands in.
            Timestamp::new(10, 0),
            Timestamp::new(10, 1),
            // A period of the earlier clock later: a new window.
            Timestamp::new(10, 10_000_000),
            Timestamp::new(10, 10_000_001),
        ] {
            sink.begin("X", Severity::Info, ts).emit();
        }
        assert_eq!(*n.lock().unwrap(), 2);
    }

    /// Review r3: two clocks interleaved (37 s apart): the step-back rule
    /// started a new window at every other record — 200 of 200 passed a
    /// 5/s limit. The windows follow the later clock now.
    #[test]
    fn interleaved_clocks_keep_the_budget() {
        let inner = Capture::default();
        let n = inner.n();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(RateLimitAnomalies::new(5, Duration::from_secs(1))).wrap(Box::new(inner));
        for i in 0..200u32 {
            let ms = i * 10;
            let base = if i % 2 == 0 { 1_037 } else { 1_000 };
            let ts = Timestamp::new(base + ms / 1000, (ms % 1000) * 1_000_000);
            sink.begin("X", Severity::Info, ts).emit();
        }
        // ~2 s of the later clock: at most 3 windows of 5.
        assert!(*n.lock().unwrap() <= 15, "{}", *n.lock().unwrap());
    }

    /// The period is packet time: the budget refills a full period after
    /// the window started, not a nanosecond before.
    #[test]
    fn period_resets_after_expiry() {
        let inner = Capture::default();
        let n = inner.n();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(RateLimitAnomalies::new(1, Duration::from_millis(10))).wrap(Box::new(inner));
        for ts in [
            Timestamp::new(3, 0),
            Timestamp::new(3, 0),
            Timestamp::new(3, 9_999_999),
            Timestamp::new(3, 10_000_000),
        ] {
            sink.begin("X", Severity::Info, ts).emit();
        }
        assert_eq!(*n.lock().unwrap(), 2);
    }
}
