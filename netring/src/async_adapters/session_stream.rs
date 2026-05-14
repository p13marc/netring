//! [`SessionStream`] — async stream of typed L7 messages.
//!
//! Wraps an [`AsyncCapture`] + [`FlowTracker`] + a per-(flow, side)
//! [`BufferedReassembler`] + a per-flow [`SessionParser`]. On every TCP
//! segment, the reassembler accumulates in-order bytes (dropping out-of-
//! order segments per [`flowscope::OverflowPolicy`]); on the corresponding
//! [`FlowEvent::Packet`] the reassembler is drained and bytes are fed to
//! the parser via `feed_initiator` / `feed_responder`. Parser-emitted
//! messages surface as [`SessionEvent::Application`]; flow lifecycle
//! surfaces as [`SessionEvent::Started`] / [`SessionEvent::Closed`].
//!
//! Honours [`FlowTrackerConfig::max_reassembler_buffer`] +
//! [`FlowTrackerConfig::overflow_policy`]: under
//! [`flowscope::OverflowPolicy::DropFlow`] a per-side cap breach poisons the
//! reassembler, the tracker emits an `Ended { reason: BufferOverflow }`
//! event, and consumers see a `SessionEvent::Closed` with that reason.
//!
//! ```no_run
//! # use futures::StreamExt;
//! # use netring::AsyncCapture;
//! # use netring::flow::extract::FiveTuple;
//! # use flowscope::{FlowSide, SessionEvent, SessionParser};
//! # #[derive(Default, Clone)]
//! # struct MyParser;
//! # impl SessionParser for MyParser {
//! #     type Message = ();
//! #     fn feed_initiator(&mut self, _: &[u8]) -> Vec<()> { Vec::new() }
//! #     fn feed_responder(&mut self, _: &[u8]) -> Vec<()> { Vec::new() }
//! # }
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let cap = AsyncCapture::open("eth0")?;
//! let mut s = cap
//!     .flow_stream(FiveTuple::bidirectional())
//!     .session_stream(MyParser);
//! while let Some(evt) = s.next().await {
//!     match evt? {
//!         SessionEvent::Application { message, .. } => { let _ = message; }
//!         _ => {}
//!     }
//! }
//! # Ok(()) }
//! ```

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ahash::RandomState;
use flowscope::{
    BufferedReassembler, BufferedReassemblerFactory, EndReason, FlowEvent, FlowExtractor, FlowSide,
    FlowTracker, FlowTrackerConfig, Reassembler, ReassemblerFactory, SessionEvent, SessionParser,
    SessionParserFactory, Timestamp,
};
use futures_core::Stream;

use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::dedup::Dedup;
use crate::error::Error;
use crate::traits::PacketSource;

/// Async stream of [`SessionEvent`]s produced by reassembling TCP
/// byte streams and feeding them through a per-flow
/// [`SessionParser`].
pub struct SessionStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    cap: AsyncCapture<S>,
    tracker: FlowTracker<E, ()>,
    parser_factory: F,
    parsers: HashMap<E::Key, F::Parser, RandomState>,
    reassembler_factory: BufferedReassemblerFactory,
    reassemblers: HashMap<(E::Key, FlowSide), BufferedReassembler, RandomState>,
    pending: VecDeque<SessionEvent<E::Key, <F::Parser as SessionParser>::Message>>,
    sweep: tokio::time::Interval,
    dedup: Option<Dedup>,
    /// Plan 19: monotonic-timestamp clamp state (`None` = off).
    monotonic_ts: Option<Timestamp>,
    /// Plan 20: optional pcap tap (records each packet to disk
    /// before reassembler + parser process it).
    #[cfg(feature = "pcap")]
    tap: Option<crate::pcap_tap::PcapTap>,
}

impl<S, E, F> SessionStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    /// Plan 19: move an existing [`FlowTracker`] into a `SessionStream`
    /// without rebuilding it. Preserves `idle_timeout_fn` and any
    /// in-flight flow state from the source `FlowStream`.
    pub(crate) fn from_tracker(
        cap: AsyncCapture<S>,
        tracker: FlowTracker<E, ()>,
        parser_factory: F,
        dedup: Option<Dedup>,
        monotonic_ts: Option<Timestamp>,
        #[cfg(feature = "pcap")] tap: Option<crate::pcap_tap::PcapTap>,
    ) -> Self {
        let reassembler_factory = build_reassembler_factory(tracker.config());
        let sweep = tokio::time::interval(tracker.config().sweep_interval);
        Self {
            cap,
            tracker,
            parser_factory,
            parsers: HashMap::with_hasher(RandomState::new()),
            reassembler_factory,
            reassemblers: HashMap::with_hasher(RandomState::new()),
            pending: VecDeque::new(),
            sweep,
            dedup,
            monotonic_ts,
            #[cfg(feature = "pcap")]
            tap,
        }
    }

    /// Replace the inner [`FlowTracker`]'s config in place.
    ///
    /// Mirrors [`FlowStream::with_config`](super::flow_stream::FlowStream::with_config).
    /// Use this to set the per-side reassembler buffer cap and overflow
    /// policy for the session path. Re-arms the sweep timer if
    /// `sweep_interval` changed; rebuilds the reassembler factory so
    /// future flows pick up the new caps. Existing in-flight
    /// reassemblers keep their original caps.
    pub fn with_config(mut self, config: FlowTrackerConfig) -> Self {
        let new_interval = config.sweep_interval;
        self.reassembler_factory = build_reassembler_factory(&config);
        self.tracker.set_config(config);
        self.sweep = tokio::time::interval(new_interval);
        self
    }

    /// Apply per-packet deduplication before flow tracking. Useful for
    /// capturing on `lo` where each packet appears twice
    /// ([`PACKET_OUTGOING`](crate::PacketDirection::Outgoing) +
    /// [`PACKET_HOST`](crate::PacketDirection::Host)); pair with
    /// [`Dedup::loopback`](crate::Dedup::loopback).
    ///
    /// Replaces any previously-set dedup; counters reset.
    pub fn with_dedup(mut self, dedup: Dedup) -> Self {
        self.dedup = Some(dedup);
        self
    }

    /// Borrow the embedded dedup if any was set via [`with_dedup`](Self::with_dedup).
    pub fn dedup(&self) -> Option<&Dedup> {
        self.dedup.as_ref()
    }

    /// Borrow the embedded dedup mutably (e.g. to inspect counters
    /// `dropped()` / `seen()`).
    pub fn dedup_mut(&mut self) -> Option<&mut Dedup> {
        self.dedup.as_mut()
    }

    /// Borrow the inner tracker (stats / introspection).
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        &self.tracker
    }

    /// Override the per-flow idle timeout via a key predicate. See
    /// [`FlowStream::with_idle_timeout_fn`](super::flow_stream::FlowStream::with_idle_timeout_fn).
    pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
    where
        G: Fn(&E::Key, Option<flowscope::L4Proto>) -> Option<std::time::Duration>
            + Send
            + 'static,
    {
        self.tracker.set_idle_timeout_fn(f);
        self
    }

    /// Clamp NIC-supplied timestamps to a running max so the event
    /// stream is strictly non-decreasing in time. See
    /// [`FlowStream::with_monotonic_timestamps`](super::flow_stream::FlowStream::with_monotonic_timestamps).
    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.monotonic_ts = if enable {
            Some(Timestamp::default())
        } else {
            None
        };
        self
    }

    /// Borrow-iterator over live `(K, FlowStats)` pairs.
    pub fn snapshot_flow_stats(
        &self,
    ) -> impl Iterator<Item = (&E::Key, &flowscope::FlowStats)> + '_ {
        self.tracker.all_flow_stats()
    }

    /// Plan 20: tap every captured packet into `writer` before
    /// reassembly + parsing. Default error policy:
    /// [`TapErrorPolicy::Continue`](crate::pcap_tap::TapErrorPolicy::Continue).
    #[cfg(feature = "pcap")]
    pub fn with_pcap_tap<W>(self, writer: crate::pcap::CaptureWriter<W>) -> Self
    where
        W: std::io::Write + Send + 'static,
    {
        self.with_pcap_tap_policy(writer, crate::pcap_tap::TapErrorPolicy::default())
    }

    /// Plan 20: variant of [`with_pcap_tap`](Self::with_pcap_tap)
    /// with an explicit [`TapErrorPolicy`](crate::pcap_tap::TapErrorPolicy).
    #[cfg(feature = "pcap")]
    pub fn with_pcap_tap_policy<W>(
        mut self,
        writer: crate::pcap::CaptureWriter<W>,
        policy: crate::pcap_tap::TapErrorPolicy,
    ) -> Self
    where
        W: std::io::Write + Send + 'static,
    {
        self.tap = Some(crate::pcap_tap::PcapTap::new(writer, policy));
        self
    }
}

impl<S, E, F> Stream for SessionStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd + Unpin,
    E: FlowExtractor + Unpin,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static + Unpin,
    F: SessionParserFactory<E::Key> + Unpin,
    F::Parser: Unpin,
    <F::Parser as SessionParser>::Message: Unpin,
{
    type Item = Result<SessionEvent<E::Key, <F::Parser as SessionParser>::Message>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(ev) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(ev)));
            }

            if this.sweep.poll_tick(cx).is_ready() {
                let now = crate::async_adapters::flow_stream::clamp_now(
                    current_timestamp(),
                    &mut this.monotonic_ts,
                );
                let parsers = &mut this.parsers;
                let parser_factory = &mut this.parser_factory;
                let reassemblers = &mut this.reassemblers;
                let pending = &mut this.pending;
                for ev in this.tracker.sweep(now) {
                    process_session_event::<E::Key, F>(
                        ev,
                        parsers,
                        parser_factory,
                        reassemblers,
                        pending,
                    );
                }
                if !this.pending.is_empty() {
                    continue;
                }
            }

            let mut guard = match this.cap.poll_read_ready_mut(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(Error::Io(e)))),
                Poll::Pending => return Poll::Pending,
            };

            let got_batch = {
                let inner = guard.get_inner_mut();
                if let Some(batch) = inner.next_batch() {
                    #[cfg(feature = "pcap")]
                    let mut tap_error: Option<Error> = None;
                    for pkt in &batch {
                        // Plan 17: optional pre-tracking dedup.
                        if let Some(d) = this.dedup.as_mut()
                            && !d.keep(&pkt)
                        {
                            continue;
                        }

                        // Plan 20: pcap tap.
                        #[cfg(feature = "pcap")]
                        if let Some(tap) = this.tap.as_mut()
                            && let Some(err) = tap.write_or_handle(&pkt)
                        {
                            tap_error = Some(err);
                            break;
                        }

                        let view = crate::async_adapters::flow_stream::clamp_view(
                            pkt.view(),
                            &mut this.monotonic_ts,
                        );
                        let parsers = &mut this.parsers;
                        let parser_factory = &mut this.parser_factory;
                        let reassemblers = &mut this.reassemblers;
                        let reassembler_factory = &mut this.reassembler_factory;
                        let pending = &mut this.pending;

                        // Per-segment: route into the per-(flow, side) reassembler.
                        let evts =
                            this.tracker
                                .track_with_payload(view, |key, side, seq, payload| {
                                    if payload.is_empty() {
                                        return;
                                    }
                                    reassemblers
                                        .entry((key.clone(), side))
                                        .or_insert_with(|| {
                                            reassembler_factory.new_reassembler(key, side)
                                        })
                                        .segment(seq, payload);
                                });

                        // Per-event: drain reassembler on Packet, drain+fin on Ended,
                        // pass Started/Anomaly through.
                        for ev in evts {
                            process_session_event::<E::Key, F>(
                                ev,
                                parsers,
                                parser_factory,
                                reassemblers,
                                pending,
                            );
                        }
                    }
                    drop(batch);
                    #[cfg(feature = "pcap")]
                    if let Some(err) = tap_error {
                        return Poll::Ready(Some(Err(err)));
                    }
                    true
                } else {
                    false
                }
            };
            if !got_batch {
                guard.clear_ready();
            }
        }
    }
}

/// Build a [`BufferedReassemblerFactory`] honouring the cap + policy
/// fields on [`FlowTrackerConfig`].
fn build_reassembler_factory(config: &FlowTrackerConfig) -> BufferedReassemblerFactory {
    let mut factory = BufferedReassemblerFactory::default();
    if let Some(cap) = config.max_reassembler_buffer {
        factory = factory.with_max_buffer(cap);
    }
    factory.with_overflow_policy(config.overflow_policy)
}

/// Translate one flow event into zero or more [`SessionEvent`]s,
/// driving reassembler drain + parser feed in lockstep.
///
/// Generic over the parser factory `F` (rather than the parser `P`)
/// so we can lazily mint a fresh parser when a flow's first byte
/// arrives — matching the lazy-creation pattern on `parsers` /
/// `reassemblers` everywhere else.
fn process_session_event<K, F>(
    ev: FlowEvent<K>,
    parsers: &mut HashMap<K, F::Parser, RandomState>,
    parser_factory: &mut F,
    reassemblers: &mut HashMap<(K, FlowSide), BufferedReassembler, RandomState>,
    pending: &mut VecDeque<SessionEvent<K, <F::Parser as SessionParser>::Message>>,
) where
    K: Eq + std::hash::Hash + Clone,
    F: SessionParserFactory<K>,
{
    match ev {
        FlowEvent::Started { key, ts, .. } => {
            pending.push_back(SessionEvent::Started { key, ts });
        }
        FlowEvent::Packet { key, side, ts, .. } => {
            // Drain the just-arrived in-order bytes (if any) and feed
            // the parser. Reassembler-poison + cap-enforce already
            // applied inside `BufferedReassembler::segment`.
            let drained = match reassemblers.get_mut(&(key.clone(), side)) {
                Some(r) => r.take(),
                None => return,
            };
            if drained.is_empty() {
                return;
            }
            let parser = parsers
                .entry(key.clone())
                .or_insert_with(|| parser_factory.new_parser(&key));
            let messages = match side {
                FlowSide::Initiator => parser.feed_initiator(&drained),
                FlowSide::Responder => parser.feed_responder(&drained),
            };
            for m in messages {
                pending.push_back(SessionEvent::Application {
                    key: key.clone(),
                    side,
                    message: m,
                    ts,
                });
            }
        }
        FlowEvent::Ended {
            key, reason, stats, ..
        } => {
            // For graceful close paths, drain any residual bytes
            // before calling fin_*. For abort paths, drop the
            // reassemblers without feeding (data is suspect).
            let graceful = matches!(reason, EndReason::Fin | EndReason::IdleTimeout);
            for side in [FlowSide::Initiator, FlowSide::Responder] {
                let r = reassemblers.remove(&(key.clone(), side));
                if !graceful {
                    drop(r);
                    continue;
                }
                if let Some(mut r) = r {
                    let drained = r.take();
                    if !drained.is_empty() {
                        let parser = parsers
                            .entry(key.clone())
                            .or_insert_with(|| parser_factory.new_parser(&key));
                        let messages = match side {
                            FlowSide::Initiator => parser.feed_initiator(&drained),
                            FlowSide::Responder => parser.feed_responder(&drained),
                        };
                        for m in messages {
                            pending.push_back(SessionEvent::Application {
                                key: key.clone(),
                                side,
                                message: m,
                                ts: stats.last_seen,
                            });
                        }
                    }
                }
            }

            if let Some(mut parser) = parsers.remove(&key) {
                match reason {
                    EndReason::Fin | EndReason::IdleTimeout => {
                        for m in parser.fin_initiator() {
                            pending.push_back(SessionEvent::Application {
                                key: key.clone(),
                                side: FlowSide::Initiator,
                                message: m,
                                ts: stats.last_seen,
                            });
                        }
                        for m in parser.fin_responder() {
                            pending.push_back(SessionEvent::Application {
                                key: key.clone(),
                                side: FlowSide::Responder,
                                message: m,
                                ts: stats.last_seen,
                            });
                        }
                    }
                    EndReason::Rst
                    | EndReason::Evicted
                    | EndReason::BufferOverflow
                    | EndReason::ParseError => {
                        parser.rst_initiator();
                        parser.rst_responder();
                    }
                    _ => {
                        parser.rst_initiator();
                        parser.rst_responder();
                    }
                }
            }
            pending.push_back(SessionEvent::Closed { key, reason, stats });
        }
        FlowEvent::Anomaly { key, kind, ts } => {
            // Plan 19: forward as a typed `SessionEvent::Anomaly`. The
            // `Closed` event still carries `EndReason::BufferOverflow` /
            // `ParseError` when applicable, but the live anomaly is now
            // first-class on the typed surface.
            pending.push_back(SessionEvent::Anomaly { key, kind, ts });
        }
        // Established / StateChange are not surfaced — SessionStream's
        // contract is "messages and lifecycle endpoints".
        FlowEvent::Established { .. } | FlowEvent::StateChange { .. } => {}
    }
}

fn current_timestamp() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    Timestamp::new(now.as_secs() as u32, now.subsec_nanos())
}

// ── StreamCapture trait impl ───────────────────────────────────────

use crate::async_adapters::stream_capture::{Sealed, StreamCapture};

impl<S, E, F> Sealed for SessionStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
}

impl<S, E, F> StreamCapture for SessionStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    type Source = S;

    fn capture(&self) -> &AsyncCapture<S> {
        &self.cap
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowscope::{AnomalyKind, FlowStats, HistoryString, OverflowPolicy};

    /// Stub parser: each `feed_*` call produces one message that
    /// echoes the bytes. Lets us confirm reassembler→parser dispatch
    /// without mocking framing.
    #[derive(Default, Clone)]
    struct EchoParser;

    impl SessionParser for EchoParser {
        type Message = (FlowSide, Vec<u8>);
        fn feed_initiator(&mut self, b: &[u8]) -> Vec<(FlowSide, Vec<u8>)> {
            vec![(FlowSide::Initiator, b.to_vec())]
        }
        fn feed_responder(&mut self, b: &[u8]) -> Vec<(FlowSide, Vec<u8>)> {
            vec![(FlowSide::Responder, b.to_vec())]
        }
    }

    fn ts() -> Timestamp {
        Timestamp::new(0, 0)
    }

    type TestState = (
        HashMap<u32, EchoParser, RandomState>,
        EchoParser,
        HashMap<(u32, FlowSide), BufferedReassembler, RandomState>,
        VecDeque<SessionEvent<u32, (FlowSide, Vec<u8>)>>,
    );

    fn empty_state() -> TestState {
        (
            HashMap::with_hasher(RandomState::new()),
            EchoParser,
            HashMap::with_hasher(RandomState::new()),
            VecDeque::new(),
        )
    }

    #[test]
    fn started_event_pushes_session_started() {
        let (mut parsers, mut factory, mut reassemblers, mut pending) = empty_state();
        process_session_event::<u32, EchoParser>(
            FlowEvent::Started {
                key: 7,
                side: FlowSide::Initiator,
                ts: ts(),
                l4: None,
            },
            &mut parsers,
            &mut factory,
            &mut reassemblers,
            &mut pending,
        );
        assert!(matches!(
            pending.pop_front(),
            Some(SessionEvent::Started { key: 7, .. })
        ));
    }

    #[test]
    fn packet_event_drains_reassembler_into_parser() {
        let (mut parsers, mut factory, mut reassemblers, mut pending) = empty_state();
        // Pre-load the reassembler with bytes (simulating prior segment dispatch).
        let mut r = BufferedReassembler::new();
        r.segment(0, b"hello");
        reassemblers.insert((7u32, FlowSide::Initiator), r);

        process_session_event::<u32, EchoParser>(
            FlowEvent::Packet {
                key: 7,
                side: FlowSide::Initiator,
                len: 5,
                ts: ts(),
            },
            &mut parsers,
            &mut factory,
            &mut reassemblers,
            &mut pending,
        );

        match pending.pop_front() {
            Some(SessionEvent::Application {
                key, side, message, ..
            }) => {
                assert_eq!(key, 7);
                assert_eq!(side, FlowSide::Initiator);
                assert_eq!(message, (FlowSide::Initiator, b"hello".to_vec()));
            }
            other => panic!("expected Application, got {other:?}"),
        }
        // Reassembler now empty.
        assert!(
            reassemblers
                .get(&(7, FlowSide::Initiator))
                .map(|r| r.buffered_len())
                == Some(0)
        );
    }

    #[test]
    fn packet_event_with_no_reassembler_is_silent() {
        let (mut parsers, mut factory, mut reassemblers, mut pending) = empty_state();
        process_session_event::<u32, EchoParser>(
            FlowEvent::Packet {
                key: 7,
                side: FlowSide::Initiator,
                len: 0,
                ts: ts(),
            },
            &mut parsers,
            &mut factory,
            &mut reassemblers,
            &mut pending,
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn ended_fin_drains_reassembler_then_calls_fin() {
        let (mut parsers, mut factory, mut reassemblers, mut pending) = empty_state();
        // Residual bytes left in the initiator reassembler when FIN arrives.
        let mut r = BufferedReassembler::new();
        r.segment(0, b"residual");
        reassemblers.insert((7u32, FlowSide::Initiator), r);

        process_session_event::<u32, EchoParser>(
            FlowEvent::Ended {
                key: 7,
                reason: EndReason::Fin,
                stats: FlowStats::default(),
                history: HistoryString::default(),
            },
            &mut parsers,
            &mut factory,
            &mut reassemblers,
            &mut pending,
        );

        // Drained residual should appear before Closed.
        match pending.pop_front() {
            Some(SessionEvent::Application { message, .. }) => {
                assert_eq!(message, (FlowSide::Initiator, b"residual".to_vec()));
            }
            other => panic!("expected residual Application, got {other:?}"),
        }
        match pending.pop_front() {
            Some(SessionEvent::Closed { reason, key, .. }) => {
                assert_eq!(key, 7);
                assert!(matches!(reason, EndReason::Fin));
            }
            other => panic!("expected Closed, got {other:?}"),
        }
        // Reassemblers cleaned up.
        assert!(reassemblers.is_empty());
    }

    #[test]
    fn ended_buffer_overflow_drops_reassembler_without_drain() {
        let (mut parsers, mut factory, mut reassemblers, mut pending) = empty_state();
        let mut r = BufferedReassembler::new();
        r.segment(0, b"suspect-data-from-poisoned-flow");
        reassemblers.insert((7u32, FlowSide::Initiator), r);

        process_session_event::<u32, EchoParser>(
            FlowEvent::Ended {
                key: 7,
                reason: EndReason::BufferOverflow,
                stats: FlowStats::default(),
                history: HistoryString::default(),
            },
            &mut parsers,
            &mut factory,
            &mut reassemblers,
            &mut pending,
        );

        // No Application event — bytes are suspect, dropped.
        assert_eq!(pending.len(), 1);
        match pending.pop_front() {
            Some(SessionEvent::Closed { reason, key, .. }) => {
                assert_eq!(key, 7);
                assert!(matches!(reason, EndReason::BufferOverflow));
            }
            other => panic!("expected Closed, got {other:?}"),
        }
        assert!(reassemblers.is_empty());
    }

    #[test]
    fn ended_rst_drops_reassembler_without_drain() {
        let (mut parsers, mut factory, mut reassemblers, mut pending) = empty_state();
        // Pre-create a parser so we can confirm rst_* is called by checking removal.
        parsers.insert(7u32, EchoParser);

        let mut r = BufferedReassembler::new();
        r.segment(0, b"abc");
        reassemblers.insert((7u32, FlowSide::Responder), r);

        process_session_event::<u32, EchoParser>(
            FlowEvent::Ended {
                key: 7,
                reason: EndReason::Rst,
                stats: FlowStats::default(),
                history: HistoryString::default(),
            },
            &mut parsers,
            &mut factory,
            &mut reassemblers,
            &mut pending,
        );
        assert!(reassemblers.is_empty());
        assert!(!parsers.contains_key(&7));
        assert_eq!(pending.len(), 1);
        match pending.pop_front() {
            Some(SessionEvent::Closed { reason, .. }) => {
                assert!(matches!(reason, EndReason::Rst));
            }
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn anomaly_event_forwards_as_session_anomaly() {
        let (mut parsers, mut factory, mut reassemblers, mut pending) = empty_state();
        process_session_event::<u32, EchoParser>(
            FlowEvent::Anomaly {
                key: Some(42),
                kind: AnomalyKind::OutOfOrderSegment {
                    side: FlowSide::Initiator,
                    count: 3,
                },
                ts: ts(),
            },
            &mut parsers,
            &mut factory,
            &mut reassemblers,
            &mut pending,
        );
        assert_eq!(pending.len(), 1);
        match pending.pop_front().unwrap() {
            SessionEvent::Anomaly { key, kind, .. } => {
                assert_eq!(key, Some(42));
                assert!(matches!(kind, AnomalyKind::OutOfOrderSegment { .. }));
            }
            other => panic!("expected Anomaly, got {other:?}"),
        }
    }

    #[test]
    fn build_factory_picks_up_cap_and_policy() {
        let mut cfg = FlowTrackerConfig::default();
        cfg.max_reassembler_buffer = Some(64);
        cfg.overflow_policy = OverflowPolicy::DropFlow;
        let mut factory = build_reassembler_factory(&cfg);
        let mut r: BufferedReassembler = factory.new_reassembler(&7u32, FlowSide::Initiator);
        // Push enough bytes to trigger the cap; with DropFlow, reassembler
        // poisons (this is the flowscope contract; we just check we get a
        // poisoned flag).
        r.segment(0, &[0u8; 128]);
        assert!(r.is_poisoned());
    }

    #[test]
    fn build_factory_unbounded_when_cap_unset() {
        let cfg = FlowTrackerConfig::default();
        let mut factory = build_reassembler_factory(&cfg);
        let mut r: BufferedReassembler = factory.new_reassembler(&7u32, FlowSide::Initiator);
        r.segment(0, &vec![0u8; 4096]);
        assert!(!r.is_poisoned());
        assert_eq!(r.buffered_len(), 4096);
    }
}
