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
//! `KeyIndexed` is kept netring-side because flowscope's version
//! lacks the `drain_expired(now) -> impl Iterator<Item = (K, V)>`
//! pattern (only `evict_expired(now)` with a `()` return). That
//! API is critical for "expected B-after-A didn't happen" detectors
//! — example: `examples/anomaly/dns_resolved_no_connection.rs` —
//! so the netring version stays until flowscope adds a matching
//! method.

mod key_indexed;

pub use key_indexed::KeyIndexed;

// 0.21 G: re-export every flowscope correlate primitive at the
// netring path so downstream `use netring::correlate::…` keeps
// working. `TimeBucketedCounter` is the flowscope version with
// `new_unbounded(window, bucket)` matching netring's old 2-arg
// shape.
#[cfg(feature = "flow")]
pub use flowscope::correlate::{
    BurstDetector, BurstHit, Ewma, FlowStateMap, KeylessSequencePattern, SequencePattern,
    TimeBucketedCounter, TimeBucketedSet, TopK,
};
