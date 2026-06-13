//! Drop anomalies below a configured severity tier.

use std::borrow::Cow;

use flowscope::Timestamp;

use crate::anomaly::Severity;
use crate::anomaly::sink::AnomalySink;
use crate::layer::Layer;

/// Drops anomalies whose [`Severity`] is below `floor`.
///
/// Constructed via [`Self::at_least`] / [`Self::info`] /
/// [`Self::warning`] / [`Self::error`] — all `const`.
#[derive(Debug, Clone, Copy)]
pub struct MinSeverity {
    floor: Severity,
}

impl MinSeverity {
    /// Drop anomalies below `floor`.
    pub const fn at_least(floor: Severity) -> Self {
        Self { floor }
    }

    /// Convenience for `at_least(Severity::Info)` — passes everything
    /// (Info is the lowest tier). 0.22 §7.3: spelled out so the floor
    /// is explicit rather than an `at_least(Info)` foot-gun.
    pub const fn info() -> Self {
        Self::at_least(Severity::Info)
    }

    /// Convenience for `at_least(Severity::Warning)`.
    pub const fn warning() -> Self {
        Self::at_least(Severity::Warning)
    }

    /// Convenience for `at_least(Severity::Error)`.
    pub const fn error() -> Self {
        Self::at_least(Severity::Error)
    }
}

impl Layer for MinSeverity {
    fn wrap(self: Box<Self>, inner: Box<dyn AnomalySink>) -> Box<dyn AnomalySink> {
        Box::new(MinSeverityLayered {
            inner,
            floor: self.floor,
        })
    }
}

/// The applied layer — wraps an inner sink + a severity floor.
pub struct MinSeverityLayered {
    inner: Box<dyn AnomalySink>,
    floor: Severity,
}

impl AnomalySink for MinSeverityLayered {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn crate::anomaly::Key>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        if severity < self.floor {
            return;
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

    use super::*;

    #[derive(Default)]
    struct Capture {
        seen: Arc<Mutex<Vec<(&'static str, Severity)>>>,
    }
    impl Capture {
        fn list(&self) -> Arc<Mutex<Vec<(&'static str, Severity)>>> {
            Arc::clone(&self.seen)
        }
    }
    impl AnomalySink for Capture {
        fn write(
            &mut self,
            kind: &'static str,
            severity: Severity,
            _ts: Timestamp,
            _key: Option<&dyn crate::anomaly::Key>,
            _observations: &[(&'static str, Cow<'_, str>)],
            _metrics: &[(&'static str, f64)],
        ) {
            self.seen.lock().unwrap().push((kind, severity));
        }
    }

    #[test]
    fn drops_below_floor_passes_above() {
        let inner = Capture::default();
        let calls = inner.list();
        let mut sink: Box<dyn AnomalySink> = Box::new(MinSeverity::warning()).wrap(Box::new(inner));
        sink.begin("I", Severity::Info, Timestamp::new(0, 0)).emit();
        sink.begin("W", Severity::Warning, Timestamp::new(0, 0))
            .emit();
        sink.begin("E", Severity::Error, Timestamp::new(0, 0))
            .emit();
        sink.begin("C", Severity::Critical, Timestamp::new(0, 0))
            .emit();
        let calls = calls.lock().unwrap();
        assert_eq!(
            *calls,
            vec![
                ("W", Severity::Warning),
                ("E", Severity::Error),
                ("C", Severity::Critical)
            ]
        );
    }

    #[test]
    fn at_least_critical_only_lets_critical_through() {
        let inner = Capture::default();
        let calls = inner.list();
        let mut sink: Box<dyn AnomalySink> =
            Box::new(MinSeverity::at_least(Severity::Critical)).wrap(Box::new(inner));
        sink.begin("W", Severity::Warning, Timestamp::new(0, 0))
            .emit();
        sink.begin("E", Severity::Error, Timestamp::new(0, 0))
            .emit();
        sink.begin("C", Severity::Critical, Timestamp::new(0, 0))
            .emit();
        let calls = calls.lock().unwrap();
        assert_eq!(*calls, vec![("C", Severity::Critical)]);
    }
}
