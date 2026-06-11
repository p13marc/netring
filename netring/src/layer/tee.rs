//! Fan-out: write each anomaly to two sinks.

use std::borrow::Cow;

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
///
/// Two construction shapes:
///
/// - [`Tee::into`] — takes a single owned sink. Use when you
///   already have one secondary sink instance ready and there's
///   only one monitor consuming it.
/// - [`Tee::factory`] — takes a closure returning a fresh sink
///   per invocation. Use when sinks aren't [`Clone`] but the
///   monitor (or the shard wrapper around it) needs to mint
///   multiple. Phase C's `ShardedRunner` is the canonical
///   consumer: each shard needs an independent sink instance,
///   and `Fn() -> S` lets the builder closure produce one per
///   shard without forcing `S: Clone` on every sink type.
pub struct Tee {
    secondary: TeeSecondary,
}

enum TeeSecondary {
    Owned(Box<dyn AnomalySink>),
    Factory(Box<dyn Fn() -> Box<dyn AnomalySink> + Send + Sync>),
}

impl Tee {
    /// Construct a Tee that mirrors every anomaly into `secondary`
    /// in addition to whatever sink chain it wraps.
    pub fn into(secondary: impl AnomalySink + 'static) -> Self {
        Self {
            secondary: TeeSecondary::Owned(Box::new(secondary)),
        }
    }

    /// 0.21 B.4: construct a Tee whose secondary sink is minted
    /// by `factory` at `wrap` time. The factory closure must be
    /// `Send + Sync + 'static` so the Tee can be moved across
    /// shards.
    ///
    /// At `wrap()` invocation the factory runs once and yields a
    /// fresh `Box<dyn AnomalySink>` for that monitor; calling
    /// `wrap()` again (re-wrapping into another monitor) runs the
    /// factory again. The two resulting Tees own independent
    /// secondary sinks.
    ///
    /// ```ignore
    /// use netring::prelude::*;
    /// let tee = Tee::factory(|| Box::new(StdoutSink::default()));
    /// Monitor::builder().interface("eth0").layer(tee).build()?;
    /// ```
    pub fn factory<F>(factory: F) -> Self
    where
        F: Fn() -> Box<dyn AnomalySink> + Send + Sync + 'static,
    {
        Self {
            secondary: TeeSecondary::Factory(Box::new(factory)),
        }
    }
}

impl Layer for Tee {
    fn wrap(self: Box<Self>, inner: Box<dyn AnomalySink>) -> Box<dyn AnomalySink> {
        let secondary = match self.secondary {
            TeeSecondary::Owned(b) => b,
            TeeSecondary::Factory(f) => f(),
        };
        Box::new(TeeLayered { inner, secondary })
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
        key: Option<&dyn crate::anomaly::Key>,
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
            _: Option<&dyn crate::anomaly::Key>,
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

    #[test]
    fn factory_mints_fresh_secondary_per_wrap() {
        // Counter shared between factory-produced sinks so we can
        // verify each Tee::wrap call invokes the factory once.
        let counter = Arc::new(Mutex::new(0u32));
        let factory_counter = Arc::clone(&counter);
        let factory =
            move || -> Box<dyn AnomalySink> { Box::new(Capture(Arc::clone(&factory_counter))) };

        let primary1 = Capture::default();
        let s1 = primary1.n();
        let mut sink1: Box<dyn AnomalySink> =
            Box::new(Tee::factory(factory.clone())).wrap(Box::new(primary1));
        sink1
            .begin("X", Severity::Info, Timestamp::new(0, 0))
            .emit();

        let primary2 = Capture::default();
        let s2 = primary2.n();
        let mut sink2: Box<dyn AnomalySink> =
            Box::new(Tee::factory(factory.clone())).wrap(Box::new(primary2));
        sink2
            .begin("X", Severity::Info, Timestamp::new(0, 0))
            .emit();
        sink2
            .begin("X", Severity::Info, Timestamp::new(0, 0))
            .emit();

        // Primary side: each sees its own count.
        assert_eq!(*s1.lock().unwrap(), 1);
        assert_eq!(*s2.lock().unwrap(), 2);
        // Factory side: two fresh sinks share the counter via the
        // closure; together they see all 3 emissions.
        assert_eq!(*counter.lock().unwrap(), 3);
    }
}
