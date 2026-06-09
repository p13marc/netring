//! Periodic tick handler registration.
//!
//! Phase B accepts tick registrations but doesn't actually fire
//! them — the run loop is single-stream over the packet capture;
//! racing a `tokio::time::interval` would risk dropping packets.
//! Phase F's per-CPU sharded run loop introduces a separate tick
//! pump; this module is its forward declaration so the builder
//! API stays stable.

use std::time::Duration;

use crate::ctx::Ctx;
use crate::error::Result;
use crate::monitor::handler::Handler;
use crate::protocol::event_typed::Tick;

/// Boxed tick callback. The type alias keeps clippy
/// `type_complexity` happy and lets future commits swap in a
/// richer signature without touching every call-site.
type BoxedTickHandler = Box<dyn FnMut(&Tick, &mut Ctx<'_>) -> Result<()> + Send>;

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
            handler: Box::new(move |tick, ctx| handler.call(tick, ctx)),
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
        let mut reg = TickRegistration::new(Duration::from_millis(100), move |_t: &Tick| {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });

        let mut state = StateMap::default();
        let mut sink = NoopSink;
        let mut counters = CounterRegistry::default();
        let mut ctx = Ctx {
            flow: None,
            ts: Timestamp::new(0, 0),
            source: SourceIdx(0),
            state_map: &mut state,
            sink: &mut sink,
            counters: &mut counters,
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
