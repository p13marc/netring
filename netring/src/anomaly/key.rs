//! `Key` — the anomaly-key trait.
//!
//! `AnomalySink::write` and `AnomalyWriter::with_key` accept
//! `&dyn Key`. Combines `Any + Debug + Send + Sync`:
//!
//! - `Debug` powers the human-readable `key={k:?}` log line used by
//!   `StdoutSink` and `TracingSink`.
//! - `Any` (via the `std::any::Any` trait object) lets structured
//!   sinks downcast to a specific key type. `EveSink` and `MetricsSink`
//!   try downcasting to `flowscope::extract::FiveTupleKey` first to
//!   pull `src_ip`/`dest_port`/etc. via [`flowscope::KeyFields`];
//!   keys that aren't `FiveTupleKey` fall through to `Debug` rendering.
//! - `Send + Sync` are required by `AnomalySink: Send` and by Phase C
//!   sharding's cross-thread handler storage.
//!
//! Blanket-impl'd for every type satisfying the bounds — users never
//! implement `Key` directly. `FiveTupleKey` satisfies all four
//! (flowscope 0.13 ships `Debug + Send + Sync`; `Any` is automatic
//! for any `'static` type). Primitive keys (`u32`, `IpAddr`) also
//! work — `EveSink` falls back to `Debug` rendering for them.

pub use flowscope::KeyFields;

use std::any::Any;
use std::fmt::Debug;

/// Anomaly key — see module docs.
pub trait Key: Any + Debug + Send + Sync {
    /// Erase to `&dyn Any` for downcast. Lets sinks attempt
    /// `key.as_any().downcast_ref::<FiveTupleKey>()` to extract
    /// structured fields when the concrete key type is known at
    /// the sink site.
    ///
    /// Default impl returns `self` (auto-erased by the trait
    /// object machinery); custom impls almost never need to
    /// override.
    fn as_any(&self) -> &dyn Any;
}

impl<T> Key for T
where
    T: Any + Debug + Send + Sync,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
}
