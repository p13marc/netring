//! Anomaly sink — destination for anomaly emissions from the 0.20
//! [`Monitor`](crate::monitor::Monitor) handler pipeline.
//!
//! Handlers do **not** construct an [`Anomaly`](crate::anomaly::Anomaly)
//! value. They invoke [`AnomalySink::begin`] which returns an
//! [`AnomalyWriter`] — a stack-only builder that writes directly
//! into a sink-owned buffer. The framework never materialises an
//! `Anomaly<K>` on the hot path, so the steady-state allocation
//! budget is whatever the sink itself decides to allocate.
//!
//! ```ignore
//! ctx.sink_mut()
//!     .begin("FlowStartedTcp", Severity::Info, ctx.ts)
//!     .with_key(flow_key)
//!     .with("note", "first packet")
//!     .with_metric("bytes", 64.0)
//!     .emit();
//! ```
//!
//! ## Allocation envelope
//!
//! - [`AnomalyWriter`] uses
//!   `ArrayVec<(&'static str, Cow<'_, str>), 8>` for observations
//!   and `ArrayVec<(&'static str, f64), 8>` for metrics. Both fit
//!   inline; a 9th entry is silently dropped (documented; switch
//!   to a custom sink if you need more).
//! - `&'static str` values pass through `with(...)` with zero
//!   allocations. `String` values cost one allocation per emit.
//! - The sink callback ([`AnomalySink::write`]) receives borrowed
//!   slices; sinks that need to retain the anomaly (e.g.
//!   `ChannelSink`) are responsible for the copy.
//!
//! ## Phase B → Phase C
//!
//! Phase B shipped an empty trait stub. Phase C fills in the real
//! API. The `NoopSink` default still works without changes —
//! `write` has no default and `NoopSink` overrides with an empty
//! body.

use std::borrow::Cow;
use std::fmt::Debug;

use arrayvec::ArrayVec;
use flowscope::Timestamp;

use crate::anomaly::Severity;

/// Maximum observations / metrics inline per [`AnomalyWriter`].
/// Values beyond this are silently dropped; the [`AnomalyWriter`]
/// docs surface the limit.
pub const ANOMALY_INLINE_CAPACITY: usize = 8;

/// Destination for anomalies emitted by the 0.20 [`Monitor`].
///
/// Implementations are usually small structs with a reusable
/// scratch buffer; the trait is **object-safe** so handlers can
/// receive `&mut dyn AnomalySink` without monomorphising per
/// sink type.
///
/// `begin(...)` (the writer-starting method) is provided in two
/// places to satisfy both monomorphic and trait-object call
/// sites:
/// - `impl dyn AnomalySink + '_` (below) for `&mut dyn AnomalySink`
/// - blanket [`AnomalySinkExt`] for any `T: AnomalySink + Sized`
pub trait AnomalySink: Send {
    /// Render the anomaly. Called by [`AnomalyWriter::emit`]; sinks
    /// own this — that's the one method every impl provides.
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Debug>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    );

    /// Optional shutdown hook. Default is a no-op.
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

/// `begin(...)` on `&mut dyn AnomalySink` — used by layered sink
/// chains and any code that holds a trait object.
impl dyn AnomalySink + '_ {
    /// Construct an [`AnomalyWriter`] anchored on this trait object.
    pub fn begin(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
    ) -> AnomalyWriter<'_> {
        AnomalyWriter::new(self, kind, severity, ts)
    }
}

/// Convenience extension — lets typed sinks call `.begin(...)`
/// directly without coercing through `&mut dyn AnomalySink`.
pub trait AnomalySinkExt: AnomalySink + Sized {
    /// Construct an [`AnomalyWriter`] anchored on this sink.
    fn begin(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
    ) -> AnomalyWriter<'_> {
        AnomalyWriter::new(self, kind, severity, ts)
    }
}

impl<T: AnomalySink + Sized> AnomalySinkExt for T {}

/// Erased key borrow — lets [`AnomalyWriter`] stay non-generic in
/// the key type so it can be returned from a `&mut dyn AnomalySink`.
struct KeyRepr<'a> {
    debug: &'a dyn Debug,
}

/// Stack-only builder for a single anomaly. Each `with_*` method
/// returns the writer by value; finalize with [`Self::emit`].
///
/// Storage is `ArrayVec` so the writer fits inside a single
/// stack frame. Overflow drops the offending entry silently.
pub struct AnomalyWriter<'sink> {
    sink: &'sink mut dyn AnomalySink,
    kind: &'static str,
    severity: Severity,
    ts: Timestamp,
    key_repr: Option<KeyRepr<'sink>>,
    obs: ArrayVec<(&'static str, Cow<'sink, str>), ANOMALY_INLINE_CAPACITY>,
    metrics: ArrayVec<(&'static str, f64), ANOMALY_INLINE_CAPACITY>,
}

impl<'sink> AnomalyWriter<'sink> {
    /// `pub(crate)` constructor — user code starts a writer via
    /// [`AnomalySink::begin`].
    pub(crate) fn new(
        sink: &'sink mut dyn AnomalySink,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
    ) -> Self {
        Self {
            sink,
            kind,
            severity,
            ts,
            key_repr: None,
            obs: ArrayVec::new(),
            metrics: ArrayVec::new(),
        }
    }

    /// Attach a `Debug`-able key (typically a flow key or IP).
    /// Held as `&dyn Debug` so the writer stays key-erased.
    pub fn with_key<K: Debug>(mut self, key: &'sink K) -> Self {
        self.key_repr = Some(KeyRepr { debug: key });
        self
    }

    /// Attach a textual observation. `&'static str` literals pass
    /// through with zero allocation; `String` values become
    /// `Cow::Owned` (one allocation).
    ///
    /// Drops silently past [`ANOMALY_INLINE_CAPACITY`] entries.
    pub fn with(mut self, label: &'static str, value: impl Into<Cow<'sink, str>>) -> Self {
        let _ = self.obs.try_push((label, value.into()));
        self
    }

    /// Attach a numeric metric. Drops silently past
    /// [`ANOMALY_INLINE_CAPACITY`] entries.
    pub fn with_metric(mut self, label: &'static str, value: f64) -> Self {
        let _ = self.metrics.try_push((label, value));
        self
    }

    /// Finalize and ship to the underlying sink.
    pub fn emit(self) {
        let key_dbg: Option<&dyn Debug> = self.key_repr.as_ref().map(|k| k.debug);
        self.sink.write(
            self.kind,
            self.severity,
            self.ts,
            key_dbg,
            &self.obs,
            &self.metrics,
        );
    }

    /// Number of observations queued. Useful for the saturation
    /// tests + diagnostics.
    pub fn observation_count(&self) -> usize {
        self.obs.len()
    }

    /// Number of metrics queued.
    pub fn metric_count(&self) -> usize {
        self.metrics.len()
    }
}

/// No-op sink — the default when no `.sink(...)` is set on the
/// [`crate::monitor::MonitorBuilder`].
pub struct NoopSink;

impl AnomalySink for NoopSink {
    fn write(
        &mut self,
        _kind: &'static str,
        _severity: Severity,
        _ts: Timestamp,
        _key: Option<&dyn Debug>,
        _observations: &[(&'static str, Cow<'_, str>)],
        _metrics: &[(&'static str, f64)],
    ) {
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    /// Test sink that records every call into a shared buffer so
    /// assertions can inspect the writer's output without going
    /// through stdout.
    #[derive(Default)]
    struct CaptureSink {
        calls: Rc<RefCell<Vec<CapturedCall>>>,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct CapturedCall {
        kind: &'static str,
        severity: Severity,
        obs_count: usize,
        metric_count: usize,
        has_key: bool,
    }

    // SAFETY: CaptureSink uses Rc<RefCell<_>> internally — it's
    // !Sync — but Send is fine because the test never hands it
    // across threads. The Send claim is required by AnomalySink.
    unsafe impl Send for CaptureSink {}

    impl AnomalySink for CaptureSink {
        fn write(
            &mut self,
            kind: &'static str,
            severity: Severity,
            _ts: Timestamp,
            key: Option<&dyn Debug>,
            observations: &[(&'static str, Cow<'_, str>)],
            metrics: &[(&'static str, f64)],
        ) {
            self.calls.borrow_mut().push(CapturedCall {
                kind,
                severity,
                obs_count: observations.len(),
                metric_count: metrics.len(),
                has_key: key.is_some(),
            });
        }
    }

    #[test]
    fn noop_sink_is_object_safe_and_zero_cost() {
        let mut sink = NoopSink;
        let s: &mut dyn AnomalySink = &mut sink;
        // Object-safe: this only compiles if AnomalySink is dyn-safe.
        s.write("k", Severity::Info, Timestamp::new(0, 0), None, &[], &[]);
    }

    #[test]
    fn writer_records_kind_severity_and_counts() {
        let mut sink = CaptureSink::default();
        let calls = Rc::clone(&sink.calls);
        sink.begin("TestKind", Severity::Warning, Timestamp::new(1, 0))
            .with("note", "hi")
            .with_metric("count", 7.0)
            .emit();
        let calls = calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].kind, "TestKind");
        assert_eq!(calls[0].severity, Severity::Warning);
        assert_eq!(calls[0].obs_count, 1);
        assert_eq!(calls[0].metric_count, 1);
        assert!(!calls[0].has_key);
    }

    #[test]
    fn writer_with_key_marks_has_key() {
        let mut sink = CaptureSink::default();
        let calls = Rc::clone(&sink.calls);
        let key = 42u32;
        sink.begin("WithKey", Severity::Info, Timestamp::new(0, 0))
            .with_key(&key)
            .emit();
        assert!(calls.borrow()[0].has_key);
    }

    #[test]
    fn writer_drops_extra_observations_past_capacity() {
        let mut sink = CaptureSink::default();
        let calls = Rc::clone(&sink.calls);
        // Static slug labels — the test exercises that they pass
        // through `with` without allocating per call.
        const LABELS: [&str; ANOMALY_INLINE_CAPACITY + 4] =
            ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"];
        let mut w = sink.begin("Sat", Severity::Info, Timestamp::new(0, 0));
        for label in &LABELS {
            w = w.with(label, "v");
        }
        w.emit();
        let calls = calls.borrow();
        assert_eq!(
            calls[0].obs_count, ANOMALY_INLINE_CAPACITY,
            "writer must cap observations at ANOMALY_INLINE_CAPACITY"
        );
    }

    #[test]
    fn writer_drops_extra_metrics_past_capacity() {
        let mut sink = CaptureSink::default();
        let calls = Rc::clone(&sink.calls);
        let mut w = sink.begin("Sat", Severity::Info, Timestamp::new(0, 0));
        for _ in 0..(ANOMALY_INLINE_CAPACITY + 4) {
            w = w.with_metric("m", 1.0);
        }
        w.emit();
        assert_eq!(calls.borrow()[0].metric_count, ANOMALY_INLINE_CAPACITY);
    }

    #[test]
    fn writer_static_str_value_stays_borrowed() {
        let mut sink = CaptureSink::default();
        let mut w = sink.begin("S", Severity::Info, Timestamp::new(0, 0));
        w = w.with("k", "static-literal");
        // Static literal must remain a `Cow::Borrowed`, never an `Owned`.
        match &w.obs[0].1 {
            Cow::Borrowed(_) => {}
            Cow::Owned(_) => panic!("static literal should not allocate"),
        }
        w.emit();
    }

    #[test]
    fn writer_counts_helpers() {
        let mut sink = NoopSink;
        let w = sink
            .begin("X", Severity::Info, Timestamp::new(0, 0))
            .with("a", "v")
            .with_metric("m", 1.0);
        assert_eq!(w.observation_count(), 1);
        assert_eq!(w.metric_count(), 1);
        w.emit();
    }
}
