//! Suppress repeated `(kind, key)` anomalies within a sliding window.

use std::borrow::Cow;
use std::time::{Duration, Instant};

use flowscope::Timestamp;
use rustc_hash::FxHashMap;

use crate::anomaly::Severity;
use crate::anomaly::sink::AnomalySink;
use crate::layer::Layer;

/// Suppress duplicate anomalies (same `kind` + same `Debug`-formatted
/// `key`) within a sliding `window`. Subsequent identical anomalies
/// within the window are dropped; once the window expires the next
/// one re-fires.
///
/// Allocates one `String` per unique `(kind, key)` pair seen at
/// least once. The internal hashmap is `FxHashMap` for fast lookup.
///
/// `Clone` (0.22): the dedup table lives in the per-`wrap()` sink, so
/// the config clones cleanly for [`LayerSpec`](crate::layer::LayerSpec)
/// — each shard gets its own empty table.
#[derive(Debug, Clone)]
pub struct DedupeAnomalies {
    window: Duration,
}

impl DedupeAnomalies {
    /// Suppress duplicates within `window`.
    pub fn within(window: Duration) -> Self {
        Self { window }
    }
}

impl Layer for DedupeAnomalies {
    fn wrap(self: Box<Self>, inner: Box<dyn AnomalySink>) -> Box<dyn AnomalySink> {
        Box::new(DedupeAnomaliesLayered {
            inner,
            window: self.window,
            seen: FxHashMap::default(),
        })
    }
}

/// The applied layer — wraps an inner sink + the dedup state.
pub struct DedupeAnomaliesLayered {
    inner: Box<dyn AnomalySink>,
    window: Duration,
    seen: FxHashMap<DedupeKey, Instant>,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct DedupeKey {
    kind: &'static str,
    key: String,
}

impl AnomalySink for DedupeAnomaliesLayered {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn crate::anomaly::Key>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        let key_str = key.map(|k| format!("{k:?}")).unwrap_or_default();
        let dk = DedupeKey { kind, key: key_str };
        let now = Instant::now();
        if let Some(prev) = self.seen.get(&dk)
            && now.duration_since(*prev) < self.window
        {
            return;
        }
        self.seen.insert(dk, now);
        // Evict aged entries opportunistically (every 1024 hits)
        // to bound the map size in long-running monitors.
        if self.seen.len().is_multiple_of(1024) {
            let cutoff = self.window;
            self.seen.retain(|_, ts| now.duration_since(*ts) < cutoff);
        }
        self.inner
            .write(kind, severity, ts, key, observations, metrics);
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
    struct Capture(Arc<Mutex<Vec<&'static str>>>);
    impl Capture {
        fn list(&self) -> Arc<Mutex<Vec<&'static str>>> {
            Arc::clone(&self.0)
        }
    }
    impl AnomalySink for Capture {
        fn write(
            &mut self,
            kind: &'static str,
            _: Severity,
            _: Timestamp,
            _: Option<&dyn crate::anomaly::Key>,
            _: &[(&'static str, Cow<'_, str>)],
            _: &[(&'static str, f64)],
        ) {
            self.0.lock().unwrap().push(kind);
        }
    }

    #[test]
    fn second_within_window_is_dropped() {
        let inner = Capture::default();
        let calls = inner.list();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(DedupeAnomalies::within(Duration::from_secs(10))).wrap(Box::new(inner));
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&1u32)
            .emit();
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&1u32)
            .emit();
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&1u32)
            .emit();
        let calls = calls.lock().unwrap();
        assert_eq!(*calls, vec!["X"]);
    }

    #[test]
    fn different_keys_not_deduped() {
        let inner = Capture::default();
        let calls = inner.list();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(DedupeAnomalies::within(Duration::from_secs(10))).wrap(Box::new(inner));
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&1u32)
            .emit();
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&2u32)
            .emit();
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&3u32)
            .emit();
        assert_eq!(calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn after_window_expiry_dup_passes_again() {
        let inner = Capture::default();
        let calls = inner.list();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(DedupeAnomalies::within(Duration::from_millis(10))).wrap(Box::new(inner));
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&1u32)
            .emit();
        sleep(Duration::from_millis(20));
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&1u32)
            .emit();
        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn no_key_dedups_by_kind_only() {
        let inner = Capture::default();
        let calls = inner.list();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(DedupeAnomalies::within(Duration::from_secs(10))).wrap(Box::new(inner));
        sink.begin("Y", Severity::Info, Timestamp::new(0, 0)).emit();
        sink.begin("Y", Severity::Info, Timestamp::new(0, 0)).emit();
        assert_eq!(calls.lock().unwrap().len(), 1);
    }
}
