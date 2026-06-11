//! 0.21 F: streaming consumer over a [`Protocol`]'s broadcast slot.
//!
//! Returned by [`super::Monitor::subscribe`]. Each `EventStream`
//! is its own subscriber on the underlying flowscope
//! [`flowscope::driver::BroadcastSlotHandle`]: every emitted
//! message is cloned once per live subscriber. Dropping the
//! stream prunes the subscriber list automatically (via the
//! `Weak` registration in flowscope).
//!
//! Use over the synchronous `.on::<P>(...)` handler path when:
//! - The consumer lives in a different task and needs to be
//!   decoupled from the run loop's borrow tree.
//! - Multiple downstream consumers want independent views of
//!   the same parser stream.
//! - Backpressure / batching is the consumer's concern.
//!
//! Trade-off: per-subscriber queue is unbounded. Slow consumers
//! see queue growth — pair with `recv_many(out, cap)` to bound.

use flowscope::driver::BroadcastSlotHandle;
use flowscope::extract::FiveTupleKey;

/// Subscriber over a [`flowscope::driver::BroadcastSlotHandle`].
///
/// Returned by [`super::Monitor::subscribe`] for any protocol
/// `P` registered via [`super::MonitorBuilder::with_broadcast`].
/// The handle is a clone — pushes from the run loop land in this
/// subscriber's private queue. Drop the stream and the
/// subscriber slot is pruned next push.
///
/// `M` is the protocol's `Message` type. Each emitted message is
/// cloned once per subscriber; `Clone` on the message is required
/// at the underlying flowscope layer.
pub struct EventStream<M>
where
    M: Send + Sync + Clone + 'static,
{
    handle: BroadcastSlotHandle<M, FiveTupleKey>,
    drain_buf: Vec<flowscope::driver::SlotMessage<M, FiveTupleKey>>,
}

impl<M> EventStream<M>
where
    M: Send + Sync + Clone + 'static,
{
    /// Wrap an already-cloned broadcast handle.
    pub(crate) fn new(handle: BroadcastSlotHandle<M, FiveTupleKey>) -> Self {
        Self {
            handle,
            drain_buf: Vec::with_capacity(32),
        }
    }

    /// Pop one pending message off the subscriber queue.
    /// Returns `None` when the queue is empty.
    pub fn try_recv(&mut self) -> Option<M> {
        self.drain_buf.clear();
        if self.handle.drain_n(&mut self.drain_buf, 1) == 0 {
            return None;
        }
        self.drain_buf.pop().map(|msg| msg.message)
    }

    /// Drain at most `max` messages into `out`. Returns the
    /// number of messages pushed.
    ///
    /// Reuses an internal scratch buffer so the drain itself
    /// doesn't allocate per-call. The messages are then moved
    /// into `out`.
    pub fn recv_many(&mut self, out: &mut Vec<M>, max: usize) -> usize {
        self.drain_buf.clear();
        let n = self.handle.drain_n(&mut self.drain_buf, max);
        out.reserve(n);
        out.extend(self.drain_buf.drain(..).map(|m| m.message));
        n
    }

    /// Number of pending messages on this subscriber's queue.
    pub fn pending(&self) -> usize {
        self.handle.pending()
    }

    /// Total live subscriber count across the broadcast set
    /// (this stream + any siblings produced by other
    /// `monitor.subscribe::<P>()` calls).
    pub fn subscribers(&self) -> usize {
        self.handle.subscribers()
    }

    /// flowscope's `parser_kind` slug for the broadcast slot
    /// (matches the corresponding [`crate::protocol::Protocol::NAME`]).
    pub fn parser_kind(&self) -> &'static str {
        self.handle.parser_kind()
    }
}

impl<M> std::fmt::Debug for EventStream<M>
where
    M: Send + Sync + Clone + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventStream")
            .field("parser_kind", &self.parser_kind())
            .field("pending", &self.pending())
            .field("subscribers", &self.subscribers())
            .finish()
    }
}
