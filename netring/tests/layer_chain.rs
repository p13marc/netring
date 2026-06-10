//! Integration tests for the layered [`AnomalySink`] chain.
//!
//! Exercises each shipped layer in isolation + 2–3 composed
//! chains so the ordering convention is covered.

#![cfg(all(feature = "tokio", feature = "flow"))]

use std::borrow::Cow;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowscope::Timestamp;
use netring::anomaly::Severity;
use netring::anomaly::sink::AnomalySink;
use netring::layer::{DedupeAnomalies, Layer, MinSeverity, RateLimitAnomalies, Sample, Tee};

/// Test sink that records every `(kind, severity)` write into a
/// shared `Vec`.
#[derive(Default)]
struct CaptureSink {
    seen: Arc<Mutex<Vec<(&'static str, Severity)>>>,
}

impl CaptureSink {
    fn list(&self) -> Arc<Mutex<Vec<(&'static str, Severity)>>> {
        Arc::clone(&self.seen)
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
        self.seen.lock().unwrap().push((kind, severity));
    }
}

/// Apply layers innermost-first onto a base sink — matches the
/// builder's composition rule.
fn compose(layers: Vec<Box<dyn Layer>>, base: Box<dyn AnomalySink>) -> Box<dyn AnomalySink> {
    let mut sink = base;
    for layer in layers.into_iter().rev() {
        sink = layer.wrap(sink);
    }
    sink
}

#[test]
fn min_severity_warning_only_passes_warning_and_above() {
    let base = CaptureSink::default();
    let calls = base.list();
    let layers: Vec<Box<dyn Layer>> = vec![Box::new(MinSeverity::warning())];
    let mut sink = compose(layers, Box::new(base));
    sink.begin("I", Severity::Info, Timestamp::new(0, 0)).emit();
    sink.begin("W", Severity::Warning, Timestamp::new(0, 0))
        .emit();
    sink.begin("E", Severity::Error, Timestamp::new(0, 0))
        .emit();
    sink.begin("C", Severity::Critical, Timestamp::new(0, 0))
        .emit();
    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            ("W", Severity::Warning),
            ("E", Severity::Error),
            ("C", Severity::Critical),
        ]
    );
}

#[test]
fn dedupe_drops_repeats_by_kind_plus_key() {
    let base = CaptureSink::default();
    let calls = base.list();
    let layers: Vec<Box<dyn Layer>> =
        vec![Box::new(DedupeAnomalies::within(Duration::from_secs(60)))];
    let mut sink = compose(layers, Box::new(base));

    // 3 emissions of same (kind, key) → 1 forwarded
    for _ in 0..3 {
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&7u32)
            .emit();
    }
    // 2 with a different key → both forward (different bucket)
    for _ in 0..2 {
        sink.begin("X", Severity::Info, Timestamp::new(0, 0))
            .with_key(&8u32)
            .emit();
    }
    let calls = calls.lock().unwrap();
    // First X(key=7), one X(key=8) — second X(key=8) is the dup.
    assert_eq!(calls.len(), 2);
}

#[test]
fn rate_limit_enforces_per_kind_budget() {
    let base = CaptureSink::default();
    let calls = base.list();
    let layers: Vec<Box<dyn Layer>> = vec![Box::new(RateLimitAnomalies::new(
        3,
        Duration::from_secs(60),
    ))];
    let mut sink = compose(layers, Box::new(base));

    for _ in 0..10 {
        sink.begin("Burst", Severity::Info, Timestamp::new(0, 0))
            .emit();
    }
    // Second kind has its own bucket
    for _ in 0..10 {
        sink.begin("Other", Severity::Info, Timestamp::new(0, 0))
            .emit();
    }
    assert_eq!(calls.lock().unwrap().len(), 6, "3+3");
}

#[test]
fn sample_at_rate_zero_drops_everything() {
    let base = CaptureSink::default();
    let calls = base.list();
    let layers: Vec<Box<dyn Layer>> = vec![Box::new(Sample::at_rate(0.0))];
    let mut sink = compose(layers, Box::new(base));
    for _ in 0..1000 {
        sink.begin("X", Severity::Info, Timestamp::new(0, 0)).emit();
    }
    assert_eq!(calls.lock().unwrap().len(), 0);
}

#[test]
fn sample_at_rate_one_keeps_everything() {
    let base = CaptureSink::default();
    let calls = base.list();
    let layers: Vec<Box<dyn Layer>> = vec![Box::new(Sample::at_rate(1.0))];
    let mut sink = compose(layers, Box::new(base));
    for _ in 0..100 {
        sink.begin("X", Severity::Info, Timestamp::new(0, 0)).emit();
    }
    assert_eq!(calls.lock().unwrap().len(), 100);
}

#[test]
fn tee_fans_out_to_both_destinations() {
    let primary = CaptureSink::default();
    let secondary = CaptureSink::default();
    let p_list = primary.list();
    let s_list = secondary.list();

    let layers: Vec<Box<dyn Layer>> = vec![Box::new(Tee::into(secondary))];
    let mut sink = compose(layers, Box::new(primary));

    for _ in 0..4 {
        sink.begin("T", Severity::Info, Timestamp::new(0, 0)).emit();
    }
    assert_eq!(p_list.lock().unwrap().len(), 4);
    assert_eq!(s_list.lock().unwrap().len(), 4);
}

#[test]
fn full_stack_min_severity_then_dedupe_then_rate_limit() {
    let base = CaptureSink::default();
    let calls = base.list();
    let layers: Vec<Box<dyn Layer>> = vec![
        Box::new(MinSeverity::warning()),
        Box::new(DedupeAnomalies::within(Duration::from_secs(60))),
        Box::new(RateLimitAnomalies::new(2, Duration::from_secs(60))),
    ];
    let mut sink = compose(layers, Box::new(base));

    // Outermost (MinSeverity) drops Info before Dedupe sees it.
    sink.begin("X", Severity::Info, Timestamp::new(0, 0))
        .with_key(&1u32)
        .emit();
    // Warning passes MinSeverity, gets cached by Dedupe.
    sink.begin("X", Severity::Warning, Timestamp::new(0, 0))
        .with_key(&1u32)
        .emit();
    // Same (kind, key) again → dropped by Dedupe.
    sink.begin("X", Severity::Warning, Timestamp::new(0, 0))
        .with_key(&1u32)
        .emit();
    // Different key → passes Dedupe, counted by RateLimit (2nd of 2).
    sink.begin("X", Severity::Warning, Timestamp::new(0, 0))
        .with_key(&2u32)
        .emit();
    // Different key again — past RateLimit budget for "X" → dropped.
    sink.begin("X", Severity::Warning, Timestamp::new(0, 0))
        .with_key(&3u32)
        .emit();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2, "RateLimit at 2/kind/60s");
    assert!(calls.iter().all(|(_, s)| *s == Severity::Warning));
}

#[test]
fn tee_inside_a_chain_still_fans_out() {
    let primary = CaptureSink::default();
    let secondary = CaptureSink::default();
    let p_list = primary.list();
    let s_list = secondary.list();

    let layers: Vec<Box<dyn Layer>> = vec![
        Box::new(MinSeverity::warning()),
        Box::new(Tee::into(secondary)),
    ];
    let mut sink = compose(layers, Box::new(primary));

    // Info — dropped by MinSeverity before Tee sees it.
    sink.begin("I", Severity::Info, Timestamp::new(0, 0)).emit();
    // Warning passes MinSeverity → Tee writes to both.
    sink.begin("W", Severity::Warning, Timestamp::new(0, 0))
        .emit();

    assert_eq!(p_list.lock().unwrap().len(), 1);
    assert_eq!(s_list.lock().unwrap().len(), 1);
}
