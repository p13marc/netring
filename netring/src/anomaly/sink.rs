//! Anomaly sink — destination for anomaly emissions from the 0.20
//! [`Monitor`](crate::monitor::Monitor) handler pipeline.
//!
//! Handlers do **not** construct an [`Anomaly`](crate::anomaly::Anomaly)
//! value. They invoke [`AnomalySinkExt::begin`] which returns an
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

use arrayvec::ArrayVec;
use flowscope::Timestamp;

use crate::anomaly::Severity;
use crate::anomaly::key::Key;

/// Maximum observations / metrics inline per [`AnomalyWriter`].
/// Values beyond this are silently dropped; the [`AnomalyWriter`]
/// docs surface the limit.
pub const ANOMALY_INLINE_CAPACITY: usize = 8;

/// Destination for anomalies emitted by the 0.20 [`crate::monitor::Monitor`].
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
    ///
    /// `key` is `&dyn Key` (0.21 A.13 — `Key: KeyFields + Debug +
    /// Send + Sync`). Sinks needing the typed 5-tuple call
    /// `key.src_ip()` / `key.dest_port()` etc.; sinks needing a
    /// human-readable slug use `format!("{key:?}")` via the `Debug`
    /// super-bound. `FiveTupleKey` and `IpAddr`-style keys both
    /// satisfy the bounds out of the box.
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Key>,
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
/// Stored as `&dyn Key` so sinks get both `KeyFields` (typed 5-tuple)
/// and `Debug` (human render) on the read side.
struct KeyRepr<'a> {
    key: &'a dyn Key,
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

    /// Attach a key — typically a flow key (`FiveTupleKey`) or a
    /// host (`IpAddr`). Held as `&dyn Key` so the writer stays
    /// key-erased while sinks see both typed-field accessors
    /// ([`flowscope::KeyFields`]) and `Debug` rendering.
    pub fn with_key<K: Key>(mut self, key: &'sink K) -> Self {
        let erased: &dyn Key = key;
        self.key_repr = Some(KeyRepr { key: erased });
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
        let key: Option<&dyn Key> = self.key_repr.as_ref().map(|k| k.key);
        self.sink.write(
            self.kind,
            self.severity,
            self.ts,
            key,
            &self.obs,
            &self.metrics,
        );
    }

    /// Materialize as a [`flowscope::OwnedAnomaly`] instead of
    /// firing the sink. The writer's accumulated state — kind,
    /// severity, ts, observations, metrics — is folded into the
    /// returned owned value. Structured 5-tuple fields (`src_ip`,
    /// `dest_port`, …) are populated when the attached key
    /// downcasts to [`flowscope::extract::FiveTupleKey`].
    ///
    /// Use when retaining the anomaly past the dispatch frame
    /// (batch upload, cross-task channel, custom sink) without
    /// involving an intermediate [`AnomalySink`]. The caller owns
    /// what happens next; no sink callback is invoked.
    pub fn emit_owned(self) -> flowscope::OwnedAnomaly {
        let mut owned = flowscope::OwnedAnomaly::new(self.kind, self.severity.into(), self.ts);
        if let Some(repr) = self.key_repr
            && let Some(fkey) = repr
                .key
                .as_any()
                .downcast_ref::<flowscope::extract::FiveTupleKey>()
        {
            owned = owned.with_key(fkey);
        }
        for (label, value) in self.obs {
            owned = owned.with_observation(label, value.into_owned());
        }
        for (label, value) in self.metrics {
            owned = owned.with_metric(label, value);
        }
        owned
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
        _key: Option<&dyn Key>,
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
            key: Option<&dyn Key>,
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
    fn writer_emit_owned_materializes_without_firing_sink() {
        let mut sink = NoopSink;
        let owned = sink
            .begin("Materialize", Severity::Warning, Timestamp::new(7, 0))
            .with("note", "captured")
            .with_metric("rate", 4.5)
            .emit_owned();
        // Same `kind`, severity-mapped to flowscope's enum, ts intact.
        assert_eq!(owned.kind, "Materialize");
        assert_eq!(owned.severity, flowscope::event::Severity::Warning);
        assert_eq!(owned.ts, Timestamp::new(7, 0));
        // Observation + metric round-tripped.
        assert_eq!(owned.observations.len(), 1);
        assert_eq!(owned.observations[0].0, "note");
        assert_eq!(owned.observations[0].1.as_ref(), "captured");
        assert_eq!(owned.metrics[0], ("rate", 4.5));
        // No key attached → 5-tuple fields default to None.
        assert!(owned.src_ip.is_none() && owned.dest_ip.is_none());
    }

    #[test]
    fn writer_emit_owned_with_five_tuple_key_populates_structured_fields() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let key = flowscope::extract::FiveTupleKey {
            proto: flowscope::L4Proto::Tcp,
            a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
            b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
        };
        let mut sink = NoopSink;
        let owned = sink
            .begin("PortScan", Severity::Error, Timestamp::new(0, 0))
            .with_key(&key)
            .emit_owned();
        // KeyFields downcast populated the 5-tuple fields.
        assert_eq!(owned.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(owned.src_port, Some(12345));
        assert_eq!(owned.dest_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(owned.dest_port, Some(443));
        assert_eq!(owned.proto, Some("TCP"));
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
