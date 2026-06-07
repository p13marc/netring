//! Correlation primitives for multi-protocol anomaly detection.
//!
//! Generic building blocks that anomaly detectors compose with.
//! The set is split in two by ownership:
//!
//! **netring-owned** (this module's `key_indexed` and `time_bucket`
//! submodules):
//!
//! - [`TimeBucketedCounter<K>`] — per-key rate counter with a
//!   sliding-window of fixed-width buckets.
//! - [`KeyIndexed<K, V>`] — TTL'd kv-cache with `drain_expired`
//!   for "expected B-after-A didn't happen" detectors.
//!
//! These types pre-date the flowscope-side `correlate` module and
//! ship with API surface (`drain_expired`, parameterless `new(ttl)`)
//! that the flowscope versions don't expose. Kept for backwards
//! compat with existing detectors. New detector authors are free
//! to use either set; reach for flowscope's when you want LRU-cap
//! bounded growth (the netring `KeyIndexed` grows unbounded) or
//! one of the richer primitives (`BurstDetector`, `Ewma`,
//! `TimeBucketedSet`, `TopK`, `SequencePattern`).
//!
//! **flowscope-re-exported** (under this module's root):
//!
//! - [`BurstDetector`], [`BurstHit`] — "N events of kind X within
//!   window, optionally followed by Y" — SYN floods, failed-auth
//!   bursts.
//! - [`Ewma`] — per-key exponentially weighted moving average.
//! - [`SequencePattern`], [`KeylessSequencePattern`] — generic FSM
//!   for event-stream pattern detectors (port scans,
//!   auth-failure-then-success).
//! - [`TimeBucketedSet<K, V>`] — TTL'd set keyed by `K` with value
//!   set `V`; cardinality + entries-above-threshold queries.
//! - [`TopK`] — bounded "top K by count" Misra-Gries tracker.
//!
//! All keyed by [`flowscope::Timestamp`] so they compose with
//! every event netring emits (`FlowEvent`, `SessionEvent`,
//! `PacketView`, …).

mod key_indexed;
mod time_bucket;

pub use key_indexed::KeyIndexed;
pub use time_bucket::TimeBucketedCounter;

// flowscope 0.10's correlate extensions that netring doesn't have
// its own copy of. Re-exported here for ergonomic parity with
// `netring::flow::*`.
#[cfg(feature = "flow")]
pub use flowscope::correlate::{
    BurstDetector, BurstHit, Ewma, KeylessSequencePattern, SequencePattern, TimeBucketedSet, TopK,
};
