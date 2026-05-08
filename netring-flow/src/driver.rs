//! [`FlowDriver`] — sync wrapper that bundles a [`FlowTracker`] with
//! a [`ReassemblerFactory`] and dispatches TCP segments to the right
//! reassembler.
//!
//! The async equivalent lives in `netring`'s `FlowStream::with_async_reassembler`.

use std::collections::HashMap;

use ahash::RandomState;

use crate::event::{EndReason, FlowEvent, FlowSide};
use crate::extractor::FlowExtractor;
use crate::reassembler::{Reassembler, ReassemblerFactory};
use crate::tracker::{FlowEvents, FlowTracker, FlowTrackerConfig};
use crate::view::PacketView;

/// Sync flow driver: tracker + per-(flow, side) reassembler dispatch.
///
/// Use this when you want both flow events **and** TCP byte streams
/// in one synchronous loop (typical for pcap replay, embedded use,
/// non-tokio CLI tools).
///
/// For tokio integration, see `netring::FlowStream::with_async_reassembler`.
pub struct FlowDriver<E, F, S = ()>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    tracker: FlowTracker<E, S>,
    factory: F,
    reassemblers: HashMap<(E::Key, FlowSide), F::Reassembler, RandomState>,
}

impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Default + Send + 'static,
{
    /// Construct with default config and `S::default()` per-flow state.
    pub fn new(extractor: E, factory: F) -> Self {
        Self::with_config(extractor, factory, FlowTrackerConfig::default())
    }

    /// Construct with explicit config.
    pub fn with_config(extractor: E, factory: F, config: FlowTrackerConfig) -> Self {
        Self {
            tracker: FlowTracker::with_config(extractor, config),
            factory,
            reassemblers: HashMap::with_hasher(RandomState::new()),
        }
    }
}

impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    /// Process one packet. Drives the tracker and dispatches TCP
    /// payloads to the factory's reassemblers. Reassemblers are
    /// created on demand and cleaned up on `Ended`.
    pub fn track(&mut self, view: PacketView<'_>) -> FlowEvents<E::Key> {
        let factory = &mut self.factory;
        let reassemblers = &mut self.reassemblers;
        let events = self
            .tracker
            .track_with_payload(view, |key, side, seq, payload| {
                let r = reassemblers
                    .entry((key.clone(), side))
                    .or_insert_with(|| factory.new_reassembler(key, side));
                r.segment(seq, payload);
            });

        // Clean up reassemblers for ended flows.
        for ev in &events {
            if let FlowEvent::Ended { key, reason, .. } = ev {
                for side in [FlowSide::Initiator, FlowSide::Responder] {
                    if let Some(mut r) = reassemblers.remove(&(key.clone(), side)) {
                        match reason {
                            EndReason::Fin | EndReason::IdleTimeout => r.fin(),
                            EndReason::Rst | EndReason::Evicted => r.rst(),
                        }
                    }
                }
            }
        }

        events
    }

    /// Run the idle-timeout sweep and clean up reassemblers for
    /// ended flows.
    pub fn sweep(&mut self, now: crate::Timestamp) -> Vec<FlowEvent<E::Key>> {
        let events = self.tracker.sweep(now);
        for ev in &events {
            if let FlowEvent::Ended { key, reason, .. } = ev {
                for side in [FlowSide::Initiator, FlowSide::Responder] {
                    if let Some(mut r) = self.reassemblers.remove(&(key.clone(), side)) {
                        match reason {
                            EndReason::Fin | EndReason::IdleTimeout => r.fin(),
                            EndReason::Rst | EndReason::Evicted => r.rst(),
                        }
                    }
                }
            }
        }
        events
    }

    /// Borrow the inner tracker (for stats, introspection).
    pub fn tracker(&self) -> &FlowTracker<E, S> {
        &self.tracker
    }

    /// Borrow the inner tracker mutably.
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, S> {
        &mut self.tracker
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::FiveTuple;
    use crate::extract::parse::test_frames::*;
    use crate::reassembler::{BufferedReassembler, BufferedReassemblerFactory};
    use crate::{FlowEvent, Timestamp};

    fn view(frame: &[u8], sec: u32) -> PacketView<'_> {
        PacketView::new(frame, Timestamp::new(sec, 0))
    }

    #[test]
    fn buffered_reassembly_in_order() {
        let mut d = FlowDriver::<_, _>::new(FiveTuple::bidirectional(), BufferedReassemblerFactory);
        // SYN, SYN-ACK, ACK
        let syn = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1000,
            0,
            0x02,
            b"",
        );
        let synack = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            1234,
            5000,
            1001,
            0x12,
            b"",
        );
        let ack = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x10,
            b"",
        );
        // Initiator → responder data
        let req = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x18,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        // Responder → initiator data
        let resp = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            1234,
            5001,
            1019,
            0x18,
            b"HTTP/1.1 200 OK\r\n\r\nbody",
        );

        d.track(view(&syn, 0));
        d.track(view(&synack, 0));
        d.track(view(&ack, 0));
        d.track(view(&req, 0));
        d.track(view(&resp, 0));

        // The reassemblers are inside the driver; we pop them out
        // by ending the flow with FIN.
        let fin = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1019,
            5024,
            0x11,
            b"",
        );
        let fin_resp = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            1234,
            5024,
            1020,
            0x11,
            b"",
        );
        let last_ack = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1020,
            5025,
            0x10,
            b"",
        );

        let mut all_events = Vec::new();
        all_events.extend(d.track(view(&fin, 0)));
        all_events.extend(d.track(view(&fin_resp, 0)));
        all_events.extend(d.track(view(&last_ack, 0)));

        // Assertion: an Ended event was emitted (FIN/FIN/ACK closed the flow).
        let ended_count = all_events
            .iter()
            .filter(|e| matches!(e, FlowEvent::Ended { .. }))
            .count();
        assert_eq!(ended_count, 1);
    }

    #[test]
    fn no_dispatch_on_empty_payload() {
        // SYN/SYN-ACK have no payload — the reassemblers should not be
        // created. We don't have a direct way to introspect, but we can
        // capture via a test factory.
        struct CountingFactory(std::cell::RefCell<Vec<FlowSide>>);
        impl ReassemblerFactory<crate::extract::FiveTupleKey> for CountingFactory {
            type Reassembler = BufferedReassembler;
            fn new_reassembler(
                &mut self,
                _key: &crate::extract::FiveTupleKey,
                side: FlowSide,
            ) -> BufferedReassembler {
                self.0.borrow_mut().push(side);
                BufferedReassembler::new()
            }
        }
        // SAFETY-style: CountingFactory uses RefCell, not Cell, so shared
        // sequential access is fine inside a single test.
        unsafe impl Send for CountingFactory {}
        unsafe impl Sync for CountingFactory {}

        let factory = CountingFactory(std::cell::RefCell::new(Vec::new()));
        let mut d = FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory);
        let syn = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            0,
            0,
            0x02,
            b"",
        );
        d.track(view(&syn, 0));
        // No payload yet → no reassembler instantiated.
        assert!(d.factory.0.borrow().is_empty());
    }
}
