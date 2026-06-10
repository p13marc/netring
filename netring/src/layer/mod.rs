//! Middleware over the [`AnomalySink`]
//! chain.
//!
//! A [`Layer`] takes an inner sink and wraps it with new
//! behaviour — drop low-severity anomalies, dedupe by `(kind, key)`,
//! rate-limit per kind, probabilistically sample, fan-out to a
//! second sink. Layers stack:
//!
//! ```ignore
//! Monitor::builder()
//!     .layer(MinSeverity::warning())
//!     .layer(DedupeAnomalies::within(Duration::from_secs(60)))
//!     .sink(StdoutJsonSink::default())
//! ```
//!
//! Order: the **first** registered layer is the outermost — the
//! one that sees every emission first. Above, `MinSeverity`
//! drops everything below Warning before `Dedupe` even sees it,
//! before the final `StdoutJsonSink` writes anything. Matches
//! `tower::ServiceBuilder` and `tracing-subscriber` conventions.
//!
//! Layers can be composed in any order; semantics are local to
//! each layer.

use crate::anomaly::sink::AnomalySink;

mod dedupe;
mod min_severity;
mod rate_limit;
mod sample;
mod tee;

pub use dedupe::DedupeAnomalies;
pub use min_severity::MinSeverity;
pub use rate_limit::RateLimitAnomalies;
pub use sample::Sample;
pub use tee::Tee;

/// Wraps an inner [`AnomalySink`] in middleware.
///
/// The trait is **object-safe** (`Self: Sized` only on `wrap` via
/// `Box<Self>`, so trait objects can be invoked). The Monitor
/// builder stores layers as `Vec<Box<dyn Layer>>` and applies
/// them at build time, innermost-first, to whatever sink was
/// registered via `MonitorBuilder::sink`.
pub trait Layer: Send + 'static {
    /// Wrap the inner sink and return the boxed-dyn layered sink.
    /// Consumes `self` so each layer can move its configuration
    /// into the produced wrapper.
    fn wrap(self: Box<Self>, inner: Box<dyn AnomalySink>) -> Box<dyn AnomalySink>;
}

#[cfg(test)]
mod tests {
    //! Cross-layer composition + ordering checks live here so
    //! they can use the test-only `CaptureSink` defined in each
    //! layer's submodule via re-export.

    use std::borrow::Cow;
    use std::fmt::Debug;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use flowscope::Timestamp;

    use super::*;
    use crate::anomaly::Severity;
    use crate::anomaly::sink::AnomalySink;

    #[derive(Default)]
    struct CaptureSink {
        calls: Arc<Mutex<Vec<(&'static str, Severity)>>>,
    }

    impl CaptureSink {
        fn calls(&self) -> Arc<Mutex<Vec<(&'static str, Severity)>>> {
            Arc::clone(&self.calls)
        }
    }

    impl AnomalySink for CaptureSink {
        fn write(
            &mut self,
            kind: &'static str,
            severity: Severity,
            _ts: Timestamp,
            _key: Option<&dyn Debug>,
            _observations: &[(&'static str, Cow<'_, str>)],
            _metrics: &[(&'static str, f64)],
        ) {
            self.calls.lock().unwrap().push((kind, severity));
        }
    }

    fn apply(layers: Vec<Box<dyn Layer>>, base: Box<dyn AnomalySink>) -> Box<dyn AnomalySink> {
        let mut s = base;
        for layer in layers.into_iter().rev() {
            s = layer.wrap(s);
        }
        s
    }

    #[test]
    fn layer_order_outermost_first() {
        // .layer(MinSeverity::warning()) (outer) drops Info before
        // .layer(DedupeAnomalies(very wide window)) (inner) — so
        // dedupe only ever sees Warning+ anomalies.
        let base = CaptureSink::default();
        let calls = base.calls();

        let layers: Vec<Box<dyn Layer>> = vec![
            Box::new(MinSeverity::at_least(Severity::Warning)),
            Box::new(DedupeAnomalies::within(Duration::from_secs(60))),
        ];
        let mut sink = apply(layers, Box::new(base));

        sink.begin("LowSev", Severity::Info, Timestamp::new(0, 0))
            .emit();
        sink.begin("MidSev", Severity::Warning, Timestamp::new(0, 0))
            .emit();
        sink.begin("MidSev", Severity::Warning, Timestamp::new(0, 0))
            .emit();
        sink.begin("HighSev", Severity::Error, Timestamp::new(0, 0))
            .emit();

        let calls = calls.lock().unwrap();
        // Info dropped by MinSeverity; second MidSev dropped by
        // Dedupe; HighSev passes both. Final order is the
        // first-seen sequence.
        assert_eq!(
            *calls,
            vec![("MidSev", Severity::Warning), ("HighSev", Severity::Error)]
        );
    }
}
