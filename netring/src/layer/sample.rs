//! Probabilistic per-anomaly sampling.

use std::borrow::Cow;
use std::cell::Cell;
use std::fmt::Debug;

use flowscope::Timestamp;

use crate::anomaly::Severity;
use crate::anomaly::sink::AnomalySink;
use crate::layer::Layer;

/// Forwards each anomaly with probability `rate`. Rate is clamped
/// to `0.0..=1.0`. Uses an inline xorshift64* generator (no
/// dependency on the `rand` crate); the seed is set at
/// construction time and can be overridden via [`Self::with_seed`].
pub struct Sample {
    rate: f64,
    seed: u64,
}

impl Sample {
    /// Sample at the given `rate` (0.0 drops everything; 1.0 keeps
    /// everything). Seed defaults to a non-zero constant for
    /// reproducibility across runs.
    pub fn at_rate(rate: f64) -> Self {
        Self {
            rate: rate.clamp(0.0, 1.0),
            // 0xDEADBEEFCAFEBABE — anything non-zero; keeps xorshift
            // healthy without a `Date.now()`-style entropy hop.
            seed: 0xDEAD_BEEF_CAFE_BABE,
        }
    }

    /// Override the xorshift seed (must be non-zero).
    pub fn with_seed(mut self, seed: u64) -> Self {
        if seed != 0 {
            self.seed = seed;
        }
        self
    }
}

impl Layer for Sample {
    fn wrap(self: Box<Self>, inner: Box<dyn AnomalySink>) -> Box<dyn AnomalySink> {
        Box::new(SampleLayered {
            inner,
            rate: self.rate,
            // Cell-wrapped so AnomalySink::write (which takes
            // &mut self) can advance the RNG without re-borrowing
            // `self` mutably for the call.
            state: Cell::new(self.seed),
        })
    }
}

/// The applied layer — wraps an inner sink + RNG state.
pub struct SampleLayered {
    inner: Box<dyn AnomalySink>,
    rate: f64,
    state: Cell<u64>,
}

// SAFETY: SampleLayered uses Cell<u64> for its RNG state — Cell
// is !Sync but the AnomalySink::write contract requires &mut self,
// so multi-threaded access is precluded by the trait alone. Send
// is required by AnomalySink: u64 is Send; Cell<u64> is Send;
// Box<dyn AnomalySink> is Send by construction.
unsafe impl Send for SampleLayered {}

impl SampleLayered {
    /// Advance xorshift64* and return a value in `[0, 1)`.
    fn next_unit(&self) -> f64 {
        let mut x = self.state.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state.set(x);
        let mantissa = (x >> 11) & ((1u64 << 53) - 1);
        mantissa as f64 / (1u64 << 53) as f64
    }
}

impl AnomalySink for SampleLayered {
    fn write(
        &mut self,
        kind: &'static str,
        severity: Severity,
        ts: Timestamp,
        key: Option<&dyn Debug>,
        observations: &[(&'static str, Cow<'_, str>)],
        metrics: &[(&'static str, f64)],
    ) {
        let r = self.next_unit();
        if r >= self.rate {
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
    fn rate_zero_drops_everything() {
        let inner = Capture::default();
        let n = inner.n();
        let mut sink: Box<dyn AnomalySink> = Box::new(Sample::at_rate(0.0)).wrap(Box::new(inner));
        for _ in 0..1000 {
            sink.begin("X", Severity::Info, Timestamp::new(0, 0)).emit();
        }
        assert_eq!(*n.lock().unwrap(), 0);
    }

    #[test]
    fn rate_one_keeps_everything() {
        let inner = Capture::default();
        let n = inner.n();
        let mut sink: Box<dyn AnomalySink> = Box::new(Sample::at_rate(1.0)).wrap(Box::new(inner));
        for _ in 0..100 {
            sink.begin("X", Severity::Info, Timestamp::new(0, 0)).emit();
        }
        assert_eq!(*n.lock().unwrap(), 100);
    }

    #[test]
    fn rate_half_lands_near_half() {
        let inner = Capture::default();
        let n = inner.n();
        let mut sink: Box<dyn AnomalySink> = Box::new(Sample::at_rate(0.5)).wrap(Box::new(inner));
        for _ in 0..10_000 {
            sink.begin("X", Severity::Info, Timestamp::new(0, 0)).emit();
        }
        let count = *n.lock().unwrap();
        // ±5% on 10k samples is comfortably within 3 stddev of
        // the binomial — flake-proof.
        assert!(
            (4500..=5500).contains(&count),
            "expected ≈5000, got {count}"
        );
    }
}
