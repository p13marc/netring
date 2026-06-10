//! Fan-out: write each anomaly to two sinks.

use std::borrow::Cow;
use std::fmt::Debug;

use flowscope::Timestamp;

use crate::anomaly::Severity;
use crate::anomaly::sink::AnomalySink;
use crate::layer::Layer;

/// Layer that fans out each anomaly to both the inner sink chain
/// (what was already configured) **and** a `secondary` sink
/// supplied at layer-construction time.
///
/// Useful for shipping the same anomalies to two destinations
/// without rebuilding the monitor — e.g. tracing + JSON log.
pub struct Tee {
    secondary: Box<dyn AnomalySink>,
}

impl Tee {
    /// Construct a Tee that mirrors every anomaly into `secondary`
    /// in addition to whatever sink chain it wraps.
    pub fn into(secondary: impl AnomalySink + 'static) -> Self {
        Self {
            secondary: Box::new(secondary),
        }
    }
}

impl Layer for Tee {
    fn wrap(self: Box<Self>, inner: Box<dyn AnomalySink>) -> Box<dyn AnomalySink> {
        Box::new(TeeLayered {
            inner,
            secondary: self.secondary,
        })
    }
}

/// The applied layer.
pub struct TeeLayered {
    inner: Box<dyn AnomalySink>,
    secondary: Box<dyn AnomalySink>,
}

impl AnomalySink for TeeLayered {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Debug>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        self.inner
            .write(kind, severity, ts, key, observations, metrics);
        self.secondary
            .write(kind, severity, ts, key, observations, metrics);
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        // Flush both; report the first error but always try the
        // second so a transient failure on one side doesn't
        // silently strand the other.
        let r1 = self.inner.flush();
        let r2 = self.secondary.flush();
        r1.and(r2)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

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
            _: Option<&dyn Debug>,
            _: &[(&'static str, Cow<'_, str>)],
            _: &[(&'static str, f64)],
        ) {
            *self.0.lock().unwrap() += 1;
        }
    }

    #[test]
    fn writes_to_both_sinks() {
        let primary = Capture::default();
        let secondary = Capture::default();
        let p_calls = primary.n();
        let s_calls = secondary.n();
        let mut sink: Box<dyn AnomalySink> = Box::new(Tee::into(secondary)).wrap(Box::new(primary));
        for _ in 0..3 {
            sink.begin("X", Severity::Info, Timestamp::new(0, 0)).emit();
        }
        assert_eq!(*p_calls.lock().unwrap(), 3);
        assert_eq!(*s_calls.lock().unwrap(), 3);
    }
}
