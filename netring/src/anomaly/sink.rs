//! Anomaly sink — minimal Phase B stub.
//!
//! Phase C will fill this in with the real `begin()` / `AnomalyWriter`
//! API and the `Layer`-style sink chain that lets users plug in
//! Prometheus exporters, JSON line writers, tracing subscribers,
//! etc. The trait is intentionally empty in Phase B so that:
//!
//! - the `Ctx<'a>::sink: &'a mut dyn AnomalySink` field has a real
//!   trait object type to point at,
//! - the `Sink<A>` extractor compiles and resolves to `&mut dyn
//!   AnomalySink` regardless of `A` (the type-tagged sink kinds
//!   land alongside the Phase C work), and
//! - the `NoopSink` default in [`crate::monitor::MonitorBuilder`]
//!   has something to construct.

/// Receives [`crate::anomaly::Anomaly`] values emitted from
/// handlers via the `Sink` extractor.
///
/// The trait body lands in Phase C — Phase B only requires the
/// trait to exist so the dispatcher compiles.
pub trait AnomalySink: Send {}

/// No-op sink — the default when no `.sink(...)` is set on the
/// [`crate::monitor::MonitorBuilder`].
pub struct NoopSink;

impl AnomalySink for NoopSink {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_sink_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<NoopSink>();
    }

    #[test]
    fn dyn_sink_type_compiles() {
        let mut sink: Box<dyn AnomalySink> = Box::new(NoopSink);
        let _: &mut dyn AnomalySink = sink.as_mut();
    }
}
