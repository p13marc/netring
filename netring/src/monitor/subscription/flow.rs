//! Flow-tier subscription runtime (0.25 S3).
//!
//! A flow subscription delivers **once per flow, at its end** ([`FlowEnded`]),
//! with the accumulated [`FlowStats`](flowscope::FlowStats) — the natural
//! completion point (Retina's `on_terminate`), so byte/packet-count filters
//! (`bytes_over` / `packets_over`) are meaningful. The filter is evaluated
//! against the flow's 5-tuple + final stats; the handler fires only on a match.
//!
//! Implemented as **sugar over the existing typed dispatch**: `flow::<P>()…​.to(h)`
//! installs a predicate-gated `on::<FlowEnded<P>>` handler. The flow tracker
//! already produces `FlowEnded<P>`; this just adds the filter gate.

use std::net::IpAddr;
use std::sync::Arc;

use flowscope::L4Proto;

use super::predicate::{FieldSource, Predicate};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::protocol::FlowProtocol;
use crate::protocol::event_typed::FlowEnded;

/// A flow-tier handler: the completed [`FlowEnded<P>`] (key + final stats +
/// reason) plus `&mut Ctx`. Synchronous (post-batch dispatch).
pub type FlowHandler<P> =
    Arc<dyn for<'c> Fn(&FlowEnded<P>, &mut Ctx<'c>) -> Result<()> + Send + Sync>;

/// A built flow subscription: the filter [`Predicate`] + its handler. Produced
/// by `flow::<P>()…​.to(handler)` and registered via
/// [`MonitorBuilder::subscribe`](crate::monitor::MonitorBuilder::subscribe).
#[derive(Clone)]
pub struct FlowSubscription<P: FlowProtocol> {
    pub(crate) predicate: Predicate,
    pub(crate) handler: FlowHandler<P>,
}

impl<P: FlowProtocol> std::fmt::Debug for FlowSubscription<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowSubscription")
            .field("predicate", &self.predicate)
            .field("handler", &"<fn>")
            .finish()
    }
}

/// [`FieldSource`] view over a completed flow for predicate evaluation: 5-tuple
/// from the (canonicalised) key, byte/packet counts from the final stats.
///
/// The key is bidirectionally canonicalised (`a`/`b` sorted), so `src_*`/`dst_*`
/// map to `a`/`b` as a best effort — flow filters use `port`/`host` (either
/// endpoint) and the count atoms, which are orientation-independent.
pub(crate) struct FlowEndedFields<'a, P: FlowProtocol> {
    pub(crate) evt: &'a FlowEnded<P>,
}

impl<P: FlowProtocol> FieldSource for FlowEndedFields<'_, P> {
    fn l4proto(&self) -> Option<L4Proto> {
        self.evt.l4.or(Some(self.evt.key.proto))
    }
    fn src_port(&self) -> Option<u16> {
        Some(self.evt.key.a.port())
    }
    fn dst_port(&self) -> Option<u16> {
        Some(self.evt.key.b.port())
    }
    fn src_ip(&self) -> Option<IpAddr> {
        Some(self.evt.key.a.ip())
    }
    fn dst_ip(&self) -> Option<IpAddr> {
        Some(self.evt.key.b.ip())
    }
    fn total_bytes(&self) -> Option<u64> {
        Some(self.evt.stats.total_bytes())
    }
    fn total_packets(&self) -> Option<u64> {
        Some(self.evt.stats.total_packets())
    }
}
