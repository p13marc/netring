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

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use flowscope::tracker::FlowEvents;
use flowscope::{
    FlowDatagramDriver, FlowEvent, FlowExtractor, FlowSessionDriver, FlowTracker,
    FlowTrackerConfig, PacketView, SessionEvent, Timestamp,
};
use futures_core::Stream;

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
        G: Fn(&E::Key, Option<flowscope::L4Proto>) -> Option<Duration> + Send + 'static,
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

    /// One-step offline L7 pipeline: feed the pcap source into a
    /// [`flowscope::FlowSessionDriver`] and yield typed
    /// [`SessionEvent`]s straight through.
    ///
    /// Mirrors flowscope 0.4's `PcapFlowSource::sessions`. The
    /// end-of-input flush (a final sweep at
    /// [`Timestamp::MAX`](flowscope::Timestamp::MAX) that closes
    /// every still-open flow) is folded in — no manual
    /// `finish()` required.
    ///
    /// ```no_run
    /// # use futures::StreamExt;
    /// # use netring::AsyncPcapSource;
    /// # use netring::flow::extract::FiveTuple;
    /// # use flowscope::{FlowSide, SessionEvent, SessionParser, Timestamp};
    /// # #[derive(Default, Clone)]
    /// # struct MyParser;
    /// # impl SessionParser for MyParser {
    /// #     type Message = ();
    /// #     fn feed_initiator(&mut self, _: &[u8], _: Timestamp) -> Vec<()> { Vec::new() }
    /// #     fn feed_responder(&mut self, _: &[u8], _: Timestamp) -> Vec<()> { Vec::new() }
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
        P: flowscope::SessionParser + Clone,
    {
        PcapSessionStream::new(self, FlowSessionDriver::new(extractor, parser))
    }

    /// One-step offline UDP-datagram pipeline — the
    /// [`flowscope::DatagramParser`] mirror of [`Self::sessions`].
    /// The end-of-input flush is automatic.
    pub fn datagrams<E, P>(self, extractor: E, parser: P) -> PcapDatagramStream<E, P>
    where
        E: FlowExtractor,
        E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
        P: flowscope::DatagramParser + Clone,
    {
        PcapDatagramStream::new(self, FlowDatagramDriver::new(extractor, parser))
    }
}

impl<E> PcapFlowStream<E>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
{
    /// Convert this flow-event stream into a typed session stream.
    /// Tracker config (idle timeouts, reassembler buffer caps,
    /// overflow policy) carries over.
    ///
    /// The transition consumes the existing tracker — any
    /// in-flight flow state from `flow_events()` is dropped, since
    /// flowscope's `FlowSessionDriver` builds its own tracker. For
    /// most offline pcap pipelines this is fine (the pipeline
    /// usually goes straight from `open` to either `flow_events`
    /// *or* `sessions`, not both). If you need to preserve state,
    /// call `AsyncPcapSource::sessions(...)` directly.
    pub fn session_stream<P>(self, parser: P) -> PcapSessionStream<E, P>
    where
        P: flowscope::SessionParser + Clone,
    {
        let config = self.tracker.config().clone();
        let extractor = self.tracker.into_extractor();
        PcapSessionStream::new(
            self.source,
            FlowSessionDriver::with_config(extractor, parser, config),
        )
    }

    /// UDP-datagram mirror of [`Self::session_stream`].
    pub fn datagram_stream<P>(self, parser: P) -> PcapDatagramStream<E, P>
    where
        P: flowscope::DatagramParser + Clone,
    {
        let config = self.tracker.config().clone();
        let extractor = self.tracker.into_extractor();
        PcapDatagramStream::new(
            self.source,
            FlowDatagramDriver::with_config(extractor, parser, config),
        )
    }
}

// ── PcapSessionStream ─────────────────────────────────────────

/// Async stream of [`SessionEvent`]s produced by feeding an offline
/// pcap source through flowscope's
/// [`FlowSessionDriver`]. Drives
/// `on_tick` on every sweep (flowscope-internal); flushes every
/// still-open flow on EOF via `finish()`.
///
/// Produced by [`AsyncPcapSource::sessions`] or
/// [`PcapFlowStream::session_stream`].
pub struct PcapSessionStream<E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
    P: flowscope::SessionParser + Clone,
{
    source: AsyncPcapSource,
    driver: FlowSessionDriver<E, P>,
    pending: VecDeque<SessionEvent<E::Key, <P as flowscope::SessionParser>::Message>>,
    /// True once we've seen EOF from the source and driven
    /// [`FlowSessionDriver::finish`] to drain the tracker.
    finished: bool,
}

impl<E, P> PcapSessionStream<E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
    P: flowscope::SessionParser + Clone,
{
    pub(crate) fn new(source: AsyncPcapSource, driver: FlowSessionDriver<E, P>) -> Self {
        Self {
            source,
            driver,
            pending: VecDeque::new(),
            finished: false,
        }
    }

    /// Borrow the inner driver — useful for
    /// [`FlowSessionDriver::tracker`] / `snapshot_flow_stats`
    /// introspection mid-stream.
    pub fn driver(&self) -> &FlowSessionDriver<E, P> {
        &self.driver
    }

    /// Cumulative tracker counters from the inner driver.
    pub fn tracker_stats(&self) -> &flowscope::FlowTrackerStats {
        self.driver.tracker().stats()
    }

    /// Count of live flow entries. O(n) walk.
    pub fn active_flows(&self) -> usize {
        self.driver.tracker().flows().count()
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
    P: flowscope::SessionParser + Clone + Unpin,
    <P as flowscope::SessionParser>::Message: Unpin,
{
    type Item = Result<SessionEvent<E::Key, <P as flowscope::SessionParser>::Message>, Error>;

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
                    for ev in this.driver.track(view) {
                        this.pending.push_back(ev);
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    // End-of-input flush. Drives `on_tick` one last
                    // time on every live parser before emitting the
                    // terminal `Closed` events.
                    for ev in this.driver.finish() {
                        this.pending.push_back(ev);
                    }
                    this.finished = true;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ── PcapDatagramStream ────────────────────────────────────────

/// Async stream of [`SessionEvent`]s produced by feeding an offline
/// pcap source through flowscope's
/// [`FlowDatagramDriver`]. The UDP
/// mirror of [`PcapSessionStream`]; `on_tick` and `finish` semantics
/// are identical.
pub struct PcapDatagramStream<E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
    P: flowscope::DatagramParser + Clone,
{
    source: AsyncPcapSource,
    driver: FlowDatagramDriver<E, P>,
    pending: VecDeque<SessionEvent<E::Key, <P as flowscope::DatagramParser>::Message>>,
    finished: bool,
}

impl<E, P> PcapDatagramStream<E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
    P: flowscope::DatagramParser + Clone,
{
    pub(crate) fn new(source: AsyncPcapSource, driver: FlowDatagramDriver<E, P>) -> Self {
        Self {
            source,
            driver,
            pending: VecDeque::new(),
            finished: false,
        }
    }

    /// Borrow the inner driver.
    pub fn driver(&self) -> &FlowDatagramDriver<E, P> {
        &self.driver
    }

    /// Cumulative tracker counters from the inner driver.
    pub fn tracker_stats(&self) -> &flowscope::FlowTrackerStats {
        self.driver.tracker().stats()
    }

    /// Count of live flow entries. O(n) walk.
    pub fn active_flows(&self) -> usize {
        self.driver.tracker().flows().count()
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
    P: flowscope::DatagramParser + Clone + Unpin,
    <P as flowscope::DatagramParser>::Message: Unpin,
{
    type Item = Result<SessionEvent<E::Key, <P as flowscope::DatagramParser>::Message>, Error>;

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
                    for ev in this.driver.track(view) {
                        this.pending.push_back(ev);
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    for ev in this.driver.finish() {
                        this.pending.push_back(ev);
                    }
                    this.finished = true;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
