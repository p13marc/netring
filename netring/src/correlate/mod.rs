//! Correlation primitives for multi-protocol anomaly detection.
//!
//! 0.21 G: netring's `TimeBucketedCounter` is gone — the flowscope
//! 0.12 plan 125 `new_unbounded(window, bucket)` ctor matches the
//! 2-arg shape netring users called, so a direct re-export is
//! transparent. flowscope's version is the canonical one; new
//! primitives (`BurstDetector`, `Ewma`, `TimeBucketedSet`, `TopK`,
//! `SequencePattern`, `KeylessSequencePattern`, `FlowStateMap`)
//! also re-export through this module.
//!
//! `KeyIndexed` is kept netring-side. flowscope 0.14 shipped its own
//! `KeyIndexed` with a `drain_expired`, but the two diverged into
//! genuinely different data structures: flowscope's is an **LRU cache**
//! whose `get(&mut self, …)` bumps recency, while netring's is a
//! **TTL map** with an immutable `get(&self, …)` plus `iter_fresh` /
//! `contains_fresh` / `get_with_ts` — the shape the "expected
//! B-after-A didn't happen" correlation detectors actually want
//! (e.g. `examples/anomaly/dns_resolved_no_connection.rs`). Re-exporting
//! flowscope's would force `&mut` reads and drop those helpers, so the
//! netring version stays. 0.22 added `drain_expired_into` here for
//! parity with flowscope's allocation-free variant. (flowscope 0.15
//! wishlist: reconcile the two — add immutable `get` + `iter_fresh`
//! upstream, or bless netring's as the canonical correlation map.)

mod key_indexed;

pub use key_indexed::KeyIndexed;

// 0.21 G: re-export every flowscope correlate primitive at the
// netring path so downstream `use netring::correlate::…` keeps
// working. `TimeBucketedCounter` is the flowscope version with
// `new_unbounded(window, bucket)` matching netring's old 2-arg
// shape.
#[cfg(feature = "flow")]
pub use flowscope::correlate::{
    BurstDetector, BurstHit, Ewma, FlowStateMap, KeylessSequencePattern, RateValue, RollingRate,
    SequencePattern, TimeBucketedCounter, TimeBucketedSet, TopK,
};
