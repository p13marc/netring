//! Periodic tick handler registration.
//!
//! Phase B accepts tick registrations but doesn't actually fire
//! them — the run loop is single-stream over the packet capture;
//! racing a `tokio::time::interval` would risk dropping packets.
//! Phase F's per-CPU sharded run loop introduces a separate tick
//! pump; this module is its forward declaration so the builder
//! API stays stable.

use std::sync::Arc;
use std::time::Duration;

use crate::ctx::Ctx;
use crate::error::Result;
use crate::monitor::handler::Handler;
use crate::protocol::event_typed::Tick;

/// Shared tick callback. `Arc<dyn Fn + Send + Sync>` to match
/// `BoxedHandler` for Phase C's `Dispatcher::clone_for_shard`.
/// The blanket `Handler<Tick, _>` impls already require `Fn`, so
/// the trampoline's `Fn` shape is natural.
type BoxedTickHandler = Arc<dyn Fn(&Tick, &mut Ctx<'_>) -> Result<()> + Send + Sync>;

/// One registered tick handler. The stored closure boxes the
/// caller's `Handler<Tick, _>` into a uniform call shape so the
/// run loop can iterate over a `Vec<TickRegistration>` without
/// caring about each handler's marker type.
pub struct TickRegistration {
    /// Requested firing period.
    pub period: Duration,
    /// Boxed dispatch closure. Phase B records but does not fire
    /// it; Phase F's per-CPU run loop is the consumer.
    #[allow(dead_code)]
    pub(crate) handler: BoxedTickHandler,
}

impl TickRegistration {
    /// Box a `Handler<Tick, M>` for storage in the registration list.
    pub fn new<H, M>(period: Duration, handler: H) -> Self
    where
        H: Handler<Tick, M>,
        M: 'static,
    {
        Self {
            period,
            handler: Arc::new(move |tick, ctx| handler.call(tick, ctx)),
        }
    }
}

impl std::fmt::Debug for TickRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TickRegistration")
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use flowscope::Timestamp;

    use super::*;
    use crate::anomaly::sink::NoopSink;
    use crate::ctx::{CounterRegistry, SourceIdx, StateMap};

    #[test]
    fn tick_registration_invokes_handler() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);
        let reg = TickRegistration::new(Duration::from_millis(100), move |_t: &Tick| {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });

        let mut state = StateMap::default();
        let mut sink = NoopSink;
        let mut counters = CounterRegistry::default();
        let mut flow_states = crate::ctx::FlowStateRegistry::default();
        let mut ctx = Ctx {
            flow: None,
            ts: Timestamp::new(0, 0),
            source: SourceIdx(0),
            monitor_name: None,
            state_map: &mut state,
            sink: &mut sink,
            counters: &mut counters,
            flow_states: &mut flow_states,
            label_table: crate::ctx::default_label_table(),
            tracker: None,
            arp_table: None,
        };

        let tick = Tick {
            now: Timestamp::new(0, 0),
            period: Duration::from_millis(100),
        };
        (reg.handler)(&tick, &mut ctx).unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert_eq!(reg.period, Duration::from_millis(100));
    }
}
