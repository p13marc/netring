//! Per-kind token-bucket rate limiter.

use std::borrow::Cow;
use std::time::{Duration, Instant};

use flowscope::Timestamp;
use rustc_hash::FxHashMap;

use crate::anomaly::Severity;
use crate::anomaly::sink::AnomalySink;
use crate::layer::Layer;

/// Drops anomalies of a given `kind` when they fire faster than
/// `max_per_period` per `period`. Each kind gets its own bucket;
/// kinds are independent.
///
/// Algorithm: a sliding window — we track the bucket-start
/// timestamp and the count seen since. When `period` elapses the
/// count resets.
pub struct RateLimitAnomalies {
    period: Duration,
    max_per_period: u32,
}

impl RateLimitAnomalies {
    /// `max_per_period` anomalies per `period`, per kind. Overflow
    /// is silently dropped.
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
        })
    }
}

struct Bucket {
    window_start: Instant,
    count: u32,
}

/// The applied layer — wraps an inner sink + per-kind buckets.
pub struct RateLimitAnomaliesLayered {
    inner: Box<dyn AnomalySink>,
    period: Duration,
    max_per_period: u32,
    buckets: FxHashMap<&'static str, Bucket>,
}

impl AnomalySink for RateLimitAnomaliesLayered {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn crate::anomaly::Key>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        let now = Instant::now();
        let allow = match self.buckets.get_mut(kind) {
            Some(bucket) => {
                if now.duration_since(bucket.window_start) >= self.period {
                    bucket.window_start = now;
                    bucket.count = 1;
                    true
                } else if bucket.count < self.max_per_period {
                    bucket.count += 1;
                    true
                } else {
                    false
                }
            }
            None => {
                self.buckets.insert(
                    kind,
                    Bucket {
                        window_start: now,
                        count: 1,
                    },
                );
                true
            }
        };
        if allow {
            self.inner
                .write(kind, severity, ts, key, observations, metrics);
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread::sleep;

    use super::*;

    #[derive(Default)]
    struct Capture(Arc<Mutex<u32>>);
    impl Capture {
        fn n(&self) -> Arc<Mutex<u32>> {
            Arc::clone(&self.0)
        }
    }
    impl AnomalySink for Capture {
        fn write(
            &mut self,
            _: &'static str,
            _: Severity,
            _: Timestamp,
            _: Option<&dyn crate::anomaly::Key>,
            _: &[(&'static str, Cow<'_, str>)],
            _: &[(&'static str, f64)],
        ) {
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

    #[test]
    fn period_resets_after_expiry() {
        let inner = Capture::default();
        let n = inner.n();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(RateLimitAnomalies::new(1, Duration::from_millis(10))).wrap(Box::new(inner));
        sink.begin("X", Severity::Info, Timestamp::new(0, 0)).emit();
        sink.begin("X", Severity::Info, Timestamp::new(0, 0)).emit();
        sleep(Duration::from_millis(20));
        sink.begin("X", Severity::Info, Timestamp::new(0, 0)).emit();
        assert_eq!(*n.lock().unwrap(), 2);
    }
}
