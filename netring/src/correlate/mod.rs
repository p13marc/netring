//! Correlation primitives for multi-protocol anomaly detection.
//!
//! Generic building blocks that anomaly detectors compose with:
//!
//! - [`TimeBucketedCounter<K>`] — per-key rate counter with a
//!   sliding-window of fixed-width buckets. Use for "this host
//!   issued >N events in the last T seconds" detectors (DNS
//!   bursts, connection storms, log floods).
//! - [`KeyIndexed<K, V>`] — TTL'd kv-cache for cross-protocol
//!   correlation. Use for "the DNS response 200ms ago resolved
//!   this host to that IP — is the subsequent TCP flow going to
//!   the same IP?" detectors.
//!
//! Both keyed by [`flowscope::Timestamp`] so they compose with
//! every event netring emits (`FlowEvent`, `SessionEvent`,
//! `PacketView`, …).
//!
//! # Example
//!
//! ```
//! use std::net::Ipv4Addr;
//! use std::time::Duration;
//! use flowscope::Timestamp;
//! use netring::correlate::TimeBucketedCounter;
//!
//! let mut counter = TimeBucketedCounter::<Ipv4Addr>::new(
//!     Duration::from_secs(10),  // total window
//!     Duration::from_secs(1),   // bucket width
//! );
//!
//! let host = "10.0.0.1".parse().unwrap();
//! let now = Timestamp::new(1000, 0);
//!
//! for _ in 0..42 {
//!     counter.bump(host, now);
//! }
//! assert_eq!(counter.count(&host, now), 42);
//!
//! // 11 seconds later, all buckets have aged out.
//! let later = Timestamp::new(1011, 0);
//! assert_eq!(counter.count(&host, later), 0);
//! ```
//!
//! # Roadmap context
//!
//! These are the substrate for plan
//! [`netring-0.16-roadmap-2026-05-29.md`](https://github.com/p13marc/netring/blob/master/plans/netring-0.16-roadmap-2026-05-29.md)
//! Part III's `AnomalyMonitor` harness. Shipping them first as
//! standalone, well-tested primitives lets users build anomaly
//! detectors today; the harness layered on top is additive.

mod key_indexed;
mod time_bucket;

pub use key_indexed::KeyIndexed;
pub use time_bucket::TimeBucketedCounter;
