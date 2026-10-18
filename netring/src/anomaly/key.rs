//! `Key` — the anomaly-key trait.
//!
//! [`AnomalyWriter::with_key`](crate::anomaly::sink::AnomalyWriter::with_key)
//! takes any `Key`; a sink gets it as `&dyn Key` in
//! [`AnomalyRecord::key`](crate::anomaly::sink::AnomalyRecord::key).
//! Combines `Any + Debug + Send + Sync`:
//!
//! - `Any` lets the writer recognise a flow key
//!   (`flowscope::extract::FiveTupleKey`) and resolve the record's
//!   [`Endpoints`](crate::anomaly::sink::Endpoints) — read from the flow's
//!   initiator when it is known — which sinks render as source and
//!   destination (EVE `src_ip` / `dest_port`, OCSF `src_endpoint`, the text
//!   sinks' `src=… dst=…`).
//!   [`AnomalyRecord::flow_key`](crate::anomaly::sink::AnomalyRecord::flow_key)
//!   gives the key back.
//! - `Debug` renders any other key (a host `IpAddr`, a counter key):
//!   `key=<Debug>` in the text sinks, `"key"` in the JSON ones.
//! - `Send + Sync` are required by `AnomalySink: Send` and by sharding's
//!   cross-thread handler storage.
//!
//! Blanket-impl'd for every type satisfying the bounds — users never
//! implement `Key` directly. `FiveTupleKey` satisfies all four; so do
//! primitive keys (`u32`, `IpAddr`).

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
