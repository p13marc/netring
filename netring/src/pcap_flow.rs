//! [`PcapFlowStream`] — flow tracking over offline pcap files.
//!
//! Bridges [`crate::pcap_source::AsyncPcapSource`]'s
//! `OwnedPacket` output to flowscope's `FlowTracker`, yielding
//! [`FlowEvent`]s through the same `Stream` trait as a live
//! [`FlowStream`](crate::FlowStream).
//!
//! Available under `pcap + flow + tokio`. Live and offline pipelines
//! can be unified by writing a generic consumer that takes any
//! `Stream<Item = Result<FlowEvent<K>, Error>>`:
//!
//! ```no_run
//! # use futures::StreamExt;
//! # use netring::flow::extract::FiveTuple;
//! # async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! use netring::pcap_source::AsyncPcapSource;
//!
//! let source = AsyncPcapSource::open("trace.pcap").await?;
//! let mut events = source.flow_events(FiveTuple::bidirectional());
//! while let Some(evt) = events.next().await {
//!     let _ = evt?;
//!     # break;
//! }
//! # Ok(()) }
//! ```

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ahash::RandomState;
use flowscope::tracker::FlowEvents;
use flowscope::{
    BufferedReassembler, BufferedReassemblerFactory, DatagramParser, FlowEvent, FlowExtractor,
    FlowSide, FlowTracker, FlowTrackerConfig, L4Proto, Orientation, PacketView, Reassembler,
    ReassemblerFactory, SessionParser, SessionParserFactory, Timestamp,
};
use futures_core::Stream;

use crate::async_adapters::datagram_stream::{convert_event, peek_udp_payload};
use crate::async_adapters::session_event::SessionEvent;
use crate::async_adapters::session_stream::{build_reassembler_factory, process_session_event};
use crate::error::Error;
use crate::pcap_source::AsyncPcapSource;

/// Async stream of [`FlowEvent`]s produced by feeding an offline
/// pcap source through flowscope's [`FlowTracker`]. Mirrors the
/// surface of [`FlowStream`](crate::FlowStream) for the bits that
/// apply to offline replay (no `with_dedup`, since pcap files
/// don't have loopback re-injection; no `capture_stats` since
/// there's no kernel ring).
pub struct PcapFlowStream<E>
where
    E: FlowExtractor,
{
    source: AsyncPcapSource,
    tracker: FlowTracker<E, ()>,
    pending: VecDeque<FlowEvent<E::Key>>,
    /// Set when the upstream source has signaled EOF.
    eof: bool,
}

impl<E> PcapFlowStream<E>
where
    E: FlowExtractor,
    E::Key: Clone + Send + 'static,
{
    pub(crate) fn new(source: AsyncPcapSource, extractor: E) -> Self {
        Self {
            source,
            tracker: FlowTracker::new(extractor),
            pending: VecDeque::new(),
            eof: false,
        }
    }

    /// Replace the inner [`FlowTracker`]'s config.
    pub fn with_config(mut self, config: FlowTrackerConfig) -> Self {
        self.tracker.set_config(config);
        self
    }

    /// Override the per-flow idle timeout via a key predicate.
    /// Mirrors [`FlowStream::with_idle_timeout_fn`](crate::FlowStream::with_idle_timeout_fn).
    pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
    where
        G: Fn(&E::Key, Option<flowscope::L4Proto>) -> Option<Duration> + Send + Sync + 'static,
    {
        self.tracker.set_idle_timeout_fn(f);
        self
    }

    /// Borrow the inner tracker for stats / introspection.
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        &self.tracker
    }

    /// Cumulative tracker counters: `flows_created`, `flows_ended`,
    /// `flows_evicted`, `packets_unmatched`. One-call accessor for
    /// the inner [`flowscope::FlowTrackerStats`].
    pub fn tracker_stats(&self) -> &flowscope::FlowTrackerStats {
        self.tracker.stats()
    }

    /// Count of live flow entries. O(n) walk; call from a metrics
    /// tick, not every poll.
    pub fn active_flows(&self) -> usize {
        self.tracker.flows().count()
    }

    /// Number of packets the upstream source has yielded so far.
    /// Analogue of `capture_stats().packets` for offline replay.
    pub fn packets_read(&self) -> u64 {
        self.source.packets_yielded()
    }
}

impl<E> Stream for PcapFlowStream<E>
where
    E: FlowExtractor + Unpin,
    E::Key: Clone + Unpin,
{
    type Item = Result<FlowEvent<E::Key>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(evt) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(evt)));
            }
            if this.eof {
                // flowscope 0.4: end-of-input flush via `Timestamp::MAX`.
                // Every still-open flow exceeds its idle threshold against
                // this anchor, so each emits its terminal `Ended` event.
                for ev in this.tracker.sweep(Timestamp::MAX) {
                    this.pending.push_back(ev);
                }
                if let Some(evt) = this.pending.pop_front() {
                    return Poll::Ready(Some(Ok(evt)));
                }
                return Poll::Ready(None);
            }

            // Pull the next OwnedPacket from the source.
            match Pin::new(&mut this.source).poll_next(cx) {
                Poll::Ready(Some(Ok(owned))) => {
                    let view = PacketView::new(&owned.data, owned.timestamp);
                    let evts: FlowEvents<E::Key> = this.tracker.track(view);
                    for ev in evts {
                        this.pending.push_back(ev);
                    }
                    // loop — pop the first pending event next iteration.
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    this.eof = true;
                    // loop — next iteration sweeps + drains tracker.
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncPcapSource {
    /// Consume the source into a [`PcapFlowStream`] that yields
    /// [`FlowEvent`]s from a flowscope [`FlowTracker`].
    pub fn flow_events<E>(self, extractor: E) -> PcapFlowStream<E>
    where
        E: FlowExtractor,
        E::Key: Clone + Send + 'static,
    {
        PcapFlowStream::new(self, extractor)
    }

    /// One-step offline L7 pipeline: feed the pcap source through a
    /// flowscope [`FlowTracker`] + per-flow [`SessionParser`] and
    /// yield netring's typed [`SessionEvent`]s.
    ///
    /// The end-of-input flush (a final sweep at
    /// [`Timestamp::MAX`](flowscope::Timestamp::MAX) that closes
    /// every still-open flow) is folded in — no manual driver
    /// `finish()` required.
    ///
    /// Reuses the exact translation the live
    /// [`SessionStream`](crate::async_adapters::session_stream::SessionStream)
    /// runs, so live and offline L7 pipelines are byte-for-byte
    /// equivalent. (flowscope 0.20 retired the per-parser
    /// `FlowSessionDriver`; netring drives the tracker directly.)
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use netring::AsyncPcapSource;
    /// # use netring::flow::extract::FiveTuple;
    /// # use netring::flow::SessionEvent;
    /// # use flowscope::{FlowSide, SessionParser, Timestamp};
    /// # #[derive(Default, Clone)]
    /// # struct MyParser;
    /// # impl SessionParser for MyParser {
    /// #     type Message = ();
    /// #     fn feed_initiator(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
    /// #     fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
    /// # }
    /// # async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = AsyncPcapSource::open("trace.pcap").await?;
    /// let mut sessions = source.sessions(FiveTuple::bidirectional(), MyParser);
    /// while let Some(evt) = sessions.next().await {
    ///     let _ = evt?;
    ///     # break;
    /// }
    /// # Ok(()) }
    /// ```
    pub fn sessions<E, P>(self, extractor: E, parser: P) -> PcapSessionStream<E, P>
    where
        E: FlowExtractor,
        E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
        P: SessionParser + Clone + Send + Sync,
    {
        PcapSessionStream::new(self, FlowTracker::new(extractor), parser)
    }

    /// One-step offline UDP-datagram pipeline — the
    /// [`DatagramParser`] mirror of [`Self::sessions`]. The
    /// end-of-input flush is automatic.
    pub fn datagrams<E, P>(self, extractor: E, parser: P) -> PcapDatagramStream<E, P>
    where
        E: FlowExtractor,
        E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
        P: DatagramParser + Clone + Send + Sync,
    {
        PcapDatagramStream::new(self, FlowTracker::new(extractor), parser)
    }
}

impl<E> PcapFlowStream<E>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
{
    /// Convert this flow-event stream into a typed session stream.
    /// Tracker config (idle timeouts, reassembler buffer caps,
    /// overflow policy) **and any in-flight flow state** carry over:
    /// the existing [`FlowTracker`] is moved into the session stream
    /// (flowscope 0.20 retired `FlowSessionDriver`, so netring no
    /// longer has to rebuild a fresh tracker here).
    pub fn session_stream<P>(self, parser: P) -> PcapSessionStream<E, P>
    where
        E::Key: std::hash::Hash + Eq,
        P: SessionParser + Clone + Send + Sync,
    {
        PcapSessionStream::new(self.source, self.tracker, parser)
    }

    /// UDP-datagram mirror of [`Self::session_stream`].
    pub fn datagram_stream<P>(self, parser: P) -> PcapDatagramStream<E, P>
    where
        E::Key: std::hash::Hash + Eq,
        P: DatagramParser + Clone + Send + Sync,
    {
        PcapDatagramStream::new(self.source, self.tracker, parser)
    }
}

/// A [`SessionParserFactory`] that clones a seed parser per flow.
///
/// flowscope's blanket `SessionParserFactory for P` uses `P::default()`,
/// which would discard a builder-configured seed (e.g. a parser tuned
/// via `with_*`). Cloning the seed preserves the config the retired
/// `FlowSessionDriver::new(extractor, parser)` carried, so we only
/// require `P: Clone`, not `P: Default`.
struct CloneSeed<P>(P);

impl<K, P> SessionParserFactory<K> for CloneSeed<P>
where
    P: SessionParser + Clone,
{
    type Parser = P;
    fn new_parser(&mut self, _key: &K) -> P {
        self.0.clone()
    }
}

// ── PcapSessionStream ─────────────────────────────────────────

/// Async stream of netring [`SessionEvent`]s produced by feeding an
/// offline pcap source through a flowscope [`FlowTracker`] +
/// per-flow [`SessionParser`].
///
/// flowscope 0.20 retired the per-parser `FlowSessionDriver`; this
/// stream drives the tracker, reassemblers, and parsers directly,
/// reusing the same `process_session_event` translation as the live
/// [`SessionStream`](crate::async_adapters::session_stream::SessionStream)
/// so the two paths stay equivalent. Drives `on_tick` on the EOF
/// flush and emits every still-open flow's terminal `Closed` event
/// (a final sweep at [`Timestamp::MAX`]).
///
/// Produced by [`AsyncPcapSource::sessions`] or
/// [`PcapFlowStream::session_stream`].
pub struct PcapSessionStream<E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Clone + Send + Sync,
{
    source: AsyncPcapSource,
    tracker: FlowTracker<E, ()>,
    parser_factory: CloneSeed<P>,
    parsers: HashMap<E::Key, P, RandomState>,
    reassembler_factory: BufferedReassemblerFactory,
    reassemblers: HashMap<(E::Key, FlowSide), BufferedReassembler, RandomState>,
    pending: VecDeque<SessionEvent<E::Key, <P as SessionParser>::Message>>,
    finished: bool,
}

impl<E, P> PcapSessionStream<E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Clone + Send + Sync,
{
    pub(crate) fn new(source: AsyncPcapSource, tracker: FlowTracker<E, ()>, parser: P) -> Self {
        let reassembler_factory = build_reassembler_factory(tracker.config());
        Self {
            source,
            tracker,
            parser_factory: CloneSeed(parser),
            parsers: HashMap::with_hasher(RandomState::new()),
            reassembler_factory,
            reassemblers: HashMap::with_hasher(RandomState::new()),
            pending: VecDeque::new(),
            finished: false,
        }
    }

    /// Borrow the inner [`FlowTracker`] — useful for
    /// `snapshot_flow_stats` / introspection mid-stream.
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        &self.tracker
    }

    /// Cumulative tracker counters.
    pub fn tracker_stats(&self) -> &flowscope::FlowTrackerStats {
        self.tracker.stats()
    }

    /// Count of live flow entries. O(n) walk.
    pub fn active_flows(&self) -> usize {
        self.tracker.flows().count()
    }

    /// Number of packets the upstream source has yielded so far.
    pub fn packets_read(&self) -> u64 {
        self.source.packets_yielded()
    }
}

impl<E, P> Stream for PcapSessionStream<E, P>
where
    E: FlowExtractor + Unpin,
    E::Key: std::hash::Hash + Eq + Clone + Send + Unpin + 'static,
    P: SessionParser + Clone + Send + Sync + Unpin,
    <P as SessionParser>::Message: Unpin,
{
    type Item = Result<SessionEvent<E::Key, <P as SessionParser>::Message>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(ev) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(ev)));
            }
            if this.finished {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.source).poll_next(cx) {
                Poll::Ready(Some(Ok(owned))) => {
                    let view = PacketView::new(&owned.data, owned.timestamp);
                    let view_ts = view.timestamp;
                    let parsers = &mut this.parsers;
                    let parser_factory = &mut this.parser_factory;
                    let reassemblers = &mut this.reassemblers;
                    let reassembler_factory = &mut this.reassembler_factory;
                    let pending = &mut this.pending;

                    // Route each TCP segment into its per-(flow, side)
                    // reassembler, then translate the tracker events
                    // exactly like the live SessionStream.
                    let evts = this
                        .tracker
                        .track_with_payload(view, |key, side, seq, payload| {
                            if payload.is_empty() {
                                return;
                            }
                            reassemblers
                                .entry((key.clone(), side))
                                .or_insert_with(|| reassembler_factory.new_reassembler(key, side))
                                .segment(seq, payload, view_ts);
                        });
                    for ev in evts {
                        process_session_event::<E::Key, CloneSeed<P>>(
                            ev,
                            parsers,
                            parser_factory,
                            reassemblers,
                            pending,
                        );
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    // End-of-input flush: drive `on_tick` once at
                    // `Timestamp::MAX`, then sweep so every still-open
                    // flow emits its terminal `Closed`.
                    let now = Timestamp::MAX;
                    let sweep_events: Vec<_> = this.tracker.sweep(now).into_iter().collect();
                    let mut scratch = Vec::new();
                    for (key, parser) in this.parsers.iter_mut() {
                        let parser_kind = parser.parser_kind();
                        let orientation = this
                            .tracker
                            .get(key)
                            .map(|e| e.initiator_orientation())
                            .unwrap_or_default();
                        scratch.clear();
                        parser.on_tick(now, &mut scratch);
                        for m in scratch.drain(..) {
                            this.pending.push_back(SessionEvent::Application {
                                key: key.clone(),
                                side: FlowSide::Initiator,
                                orientation,
                                message: m,
                                ts: now,
                                parser_kind,
                            });
                        }
                    }
                    for ev in sweep_events {
                        process_session_event::<E::Key, CloneSeed<P>>(
                            ev,
                            &mut this.parsers,
                            &mut this.parser_factory,
                            &mut this.reassemblers,
                            &mut this.pending,
                        );
                    }
                    this.finished = true;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ── PcapDatagramStream ────────────────────────────────────────

/// Async stream of netring [`SessionEvent`]s produced by feeding an
/// offline pcap source through a flowscope [`FlowTracker`] +
/// per-flow [`DatagramParser`]. The UDP mirror of
/// [`PcapSessionStream`]; reuses the live `DatagramStream`'s
/// `convert_event` translation and UDP payload-feed.
pub struct PcapDatagramStream<E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Clone + Send + Sync,
{
    source: AsyncPcapSource,
    tracker: FlowTracker<E, ()>,
    factory: P,
    parsers: HashMap<E::Key, P, RandomState>,
    pending: VecDeque<SessionEvent<E::Key, <P as DatagramParser>::Message>>,
    finished: bool,
}

impl<E, P> PcapDatagramStream<E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Clone + Send + Sync,
{
    pub(crate) fn new(source: AsyncPcapSource, tracker: FlowTracker<E, ()>, parser: P) -> Self {
        Self {
            source,
            tracker,
            factory: parser,
            parsers: HashMap::with_hasher(RandomState::new()),
            pending: VecDeque::new(),
            finished: false,
        }
    }

    /// Borrow the inner [`FlowTracker`].
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        &self.tracker
    }

    /// Cumulative tracker counters.
    pub fn tracker_stats(&self) -> &flowscope::FlowTrackerStats {
        self.tracker.stats()
    }

    /// Count of live flow entries. O(n) walk.
    pub fn active_flows(&self) -> usize {
        self.tracker.flows().count()
    }

    /// Number of packets the upstream source has yielded so far.
    pub fn packets_read(&self) -> u64 {
        self.source.packets_yielded()
    }
}

impl<E, P> Stream for PcapDatagramStream<E, P>
where
    E: FlowExtractor + Unpin,
    E::Key: std::hash::Hash + Eq + Clone + Send + Unpin + 'static,
    P: DatagramParser + Clone + Send + Sync + Unpin,
    <P as DatagramParser>::Message: Unpin,
{
    type Item = Result<SessionEvent<E::Key, <P as DatagramParser>::Message>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(ev) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(ev)));
            }
            if this.finished {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.source).poll_next(cx) {
                Poll::Ready(Some(Ok(owned))) => {
                    let view = PacketView::new(&owned.data, owned.timestamp);
                    let view_ts = view.timestamp;
                    let frame: &[u8] = &owned.data;
                    let extracted = this.tracker.extractor().extract(view);
                    for ev in this.tracker.track(view) {
                        convert_event(ev, &mut this.parsers, &mut this.pending);
                    }
                    // For UDP packets, feed the per-flow parser.
                    if let Some(extracted) = extracted
                        && extracted.l4 == Some(L4Proto::Udp)
                        && let Some(payload) = peek_udp_payload(frame)
                    {
                        let key = &extracted.key;
                        let side = match extracted.orientation {
                            Orientation::Forward => FlowSide::Initiator,
                            Orientation::Reverse => FlowSide::Responder,
                        };
                        let parser = this
                            .parsers
                            .entry(key.clone())
                            .or_insert_with(|| this.factory.clone());
                        let parser_kind = parser.parser_kind();
                        let mut messages = Vec::new();
                        parser.parse(payload, side, view_ts, &mut messages);
                        for message in messages {
                            this.pending.push_back(SessionEvent::Application {
                                key: key.clone(),
                                side,
                                orientation: extracted.orientation,
                                message,
                                ts: view_ts,
                                parser_kind,
                            });
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    // End-of-input flush: drive `on_tick` once at
                    // `Timestamp::MAX`, then sweep to close flows.
                    let now = Timestamp::MAX;
                    let sweep_events: Vec<_> = this.tracker.sweep(now).into_iter().collect();
                    let mut scratch = Vec::new();
                    for (key, parser) in this.parsers.iter_mut() {
                        let parser_kind = parser.parser_kind();
                        let orientation = this
                            .tracker
                            .get(key)
                            .map(|e| e.initiator_orientation())
                            .unwrap_or_default();
                        scratch.clear();
                        parser.on_tick(now, &mut scratch);
                        for m in scratch.drain(..) {
                            this.pending.push_back(SessionEvent::Application {
                                key: key.clone(),
                                side: FlowSide::Initiator,
                                orientation,
                                message: m,
                                ts: now,
                                parser_kind,
                            });
                        }
                    }
                    for ev in sweep_events {
                        convert_event(ev, &mut this.parsers, &mut this.pending);
                    }
                    this.finished = true;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
