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
/// read from the flow's **initiator** (`src_*` = the endpoint that opened it,
/// from the final stats' `initiator_orientation`; 0.32, #215 — it was the
/// address-sorted key's `a`), byte/packet counts from the final stats.
pub(crate) struct FlowEndedFields<'a, P: FlowProtocol> {
    pub(crate) evt: &'a FlowEnded<P>,
}

impl<P: FlowProtocol> FieldSource for FlowEndedFields<'_, P> {
    fn l4proto(&self) -> Option<L4Proto> {
        self.evt.l4.or(Some(self.evt.key.proto))
    }
    fn src_port(&self) -> Option<u16> {
        Some(self.evt.initiator().port())
    }
    fn dst_port(&self) -> Option<u16> {
        Some(self.evt.responder().port())
    }
    fn src_ip(&self) -> Option<IpAddr> {
        Some(self.evt.initiator().ip())
    }
    fn dst_ip(&self) -> Option<IpAddr> {
        Some(self.evt.responder().ip())
    }
    fn total_bytes(&self) -> Option<u64> {
        Some(self.evt.stats.total_bytes())
    }
    fn total_packets(&self) -> Option<u64> {
        Some(self.evt.stats.total_packets())
    }
}
