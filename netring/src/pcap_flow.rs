//! Flow and L7 streams over offline capture files.
//!
//! - [`PcapFlowStream`] — [`FlowEvent`]s from a flowscope
//!   [`FlowTracker`], the offline twin of [`FlowStream`](crate::FlowStream).
//! - [`PcapSessionStream`] / [`PcapDatagramStream`] — flowscope's
//!   [`SessionDriver`] / [`DatagramDriver`] over the file, the offline
//!   twins of [`SessionStream`](crate::SessionStream) /
//!   [`DatagramStream`](crate::DatagramStream). Same engine, same
//!   events.
//!
//! Replaying a capture reproduces what the live path would have seen:
//!
//! - **Idle timeouts run on packet time.** Every
//!   [`FlowTrackerConfig::sweep_interval`] of *capture* time the stream
//!   sweeps at the current packet's timestamp (the live streams sweep
//!   on a wall-clock timer), so a 10-minute pause in the capture ends
//!   the flow exactly as it would have live — `idle_timeout_fn`
//!   included. The end of the file flushes every remaining flow.
//! - [`with_dedup`](PcapFlowStream::with_dedup) drops duplicate frames
//!   before tracking. The packet direction is known when the capture
//!   recorded it (pcapng EPB flags, Linux cooked `tcpdump -i any`
//!   captures), so [`Dedup::loopback`](crate::Dedup::loopback) works on
//!   those; otherwise use a direction-agnostic
//!   [`Dedup::content`](crate::Dedup::content) — e.g. for merged
//!   multi-interface captures.
//! - [`with_monotonic_timestamps`](PcapFlowStream::with_monotonic_timestamps)
//!   clamps timestamps to a running max — for merged captures whose
//!   interfaces interleave out of order, or `loop_at_eof` replays.
//!
//! Available under `pcap + flow + tokio`.
//!
//! ```no_run
//! # use futures::StreamExt;
//! # use netring::flow::extract::FiveTuple;
//! # async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! use netring::pcap_source::AsyncPcapSource;
//!
//! let source = AsyncPcapSource::open("trace.pcapng").await?;
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

use flowscope::{
    DatagramDriver, DatagramParser, FlowEvent, FlowExtractor, FlowStats, FlowTracker,
    FlowTrackerConfig, PacketView, SessionDriver, SessionEvent, SessionParser, TemplateFactory,
    Timestamp,
};
use futures_core::Stream;

use crate::dedup::Dedup;
use crate::error::Error;
use crate::packet::OwnedPacket;
use crate::pcap_source::AsyncPcapSource;

/// Pre-tracking pipeline shared by the three pcap streams: dedup,
/// timestamp clamp, and the packet-time sweep schedule.
struct Replay {
    source: AsyncPcapSource,
    dedup: Option<Dedup>,
    monotonic_ts: Option<Timestamp>,
    sweep_interval: Duration,
    last_sweep: Option<Timestamp>,
    finished: bool,
}

/// What the replay produced on one poll.
enum Step {
    /// A packet to track, with its (clamped) timestamp. `sweep_first`
    /// is `Some(now)` when a sweep is due before it.
    Packet(OwnedPacket, Timestamp, Option<Timestamp>),
    /// The file is exhausted: flush.
    Eof,
    Err(Error),
    Pending,
}

impl Replay {
    fn new(source: AsyncPcapSource, sweep_interval: Duration) -> Self {
        Self {
            source,
            dedup: None,
            monotonic_ts: None,
            sweep_interval,
            last_sweep: None,
            finished: false,
        }
    }

    fn poll_step(&mut self, cx: &mut Context<'_>) -> Step {
        loop {
            match Pin::new(&mut self.source).poll_next(cx) {
                Poll::Ready(Some(Ok(pkt))) => {
                    if let Some(d) = self.dedup.as_mut()
                        && !d.keep_raw(&pkt.data, pkt.direction, pkt.timestamp)
                    {
                        continue;
                    }
                    let ts = match self.monotonic_ts.as_mut() {
                        Some(last) => {
                            *last = (*last).max(pkt.timestamp);
                            *last
                        }
                        None => pkt.timestamp,
                    };
                    let sweep = match self.last_sweep {
                        None => {
                            self.last_sweep = Some(ts);
                            None
                        }
                        Some(last) if ts.saturating_sub(last) >= self.sweep_interval => {
                            self.last_sweep = Some(ts);
                            Some(ts)
                        }
                        Some(_) => None,
                    };
                    return Step::Packet(pkt, ts, sweep);
                }
                Poll::Ready(Some(Err(e))) => return Step::Err(e),
                Poll::Ready(None) => return Step::Eof,
                Poll::Pending => return Step::Pending,
            }
        }
    }
}

macro_rules! replay_builders {
    () => {
        /// Drop duplicate frames before tracking. The direction-aware
        /// [`Dedup::loopback`](crate::Dedup::loopback) needs a capture
        /// that recorded it (pcapng EPB flags, Linux cooked); otherwise
        /// use [`Dedup::content`](crate::Dedup::content).
        pub fn with_dedup(mut self, dedup: Dedup) -> Self {
            self.replay.dedup = Some(dedup);
            self
        }

        /// Borrow the dedup, if one is set (for its counters).
        pub fn dedup(&self) -> Option<&Dedup> {
            self.replay.dedup.as_ref()
        }

        /// Clamp timestamps to a running max so time never goes
        /// backwards (merged captures, `loop_at_eof` replays).
        pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
            self.replay.monotonic_ts = enable.then(Timestamp::default);
            self
        }

        /// Number of packets the upstream source has yielded so far.
        /// Analogue of `capture_stats().packets` for offline replay.
        pub fn packets_read(&self) -> u64 {
            self.replay.source.packets_yielded()
        }
    };
}

// ── PcapFlowStream ────────────────────────────────────────────

/// Async stream of [`FlowEvent`]s produced by feeding an offline
/// capture through flowscope's [`FlowTracker`]. See the
/// [module docs](self) for the replay semantics.
pub struct PcapFlowStream<E>
where
    E: FlowExtractor,
{
    replay: Replay,
    tracker: FlowTracker<E, ()>,
    pending: VecDeque<FlowEvent<E::Key>>,
}

impl<E> PcapFlowStream<E>
where
    E: FlowExtractor,
    E::Key: Clone + Send + 'static,
{
    pub(crate) fn new(source: AsyncPcapSource, extractor: E) -> Self {
        let tracker = FlowTracker::new(extractor);
        Self {
            replay: Replay::new(source, tracker.config().sweep_interval),
            tracker,
            pending: VecDeque::new(),
        }
    }

    /// Replace the inner [`FlowTracker`]'s config.
    pub fn with_config(mut self, config: FlowTrackerConfig) -> Self {
        self.replay.sweep_interval = config.sweep_interval;
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

    replay_builders!();

    /// Borrow the inner tracker for stats / introspection.
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        &self.tracker
    }

    /// Cumulative tracker counters: `flows_created`, `flows_ended`,
    /// `flows_evicted`, `packets_unmatched`.
    pub fn tracker_stats(&self) -> &flowscope::FlowTrackerStats {
        self.tracker.stats()
    }

    /// Count of live flow entries.
    pub fn active_flows(&self) -> usize {
        self.tracker.flow_count()
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
            if this.replay.finished {
                return Poll::Ready(None);
            }
            match this.replay.poll_step(cx) {
                Step::Packet(pkt, ts, sweep) => {
                    if let Some(now) = sweep {
                        this.pending.extend(this.tracker.sweep(now));
                    }
                    this.pending
                        .extend(this.tracker.track(PacketView::new(&pkt.data, ts)));
                }
                Step::Eof => {
                    // End-of-input flush: every still-open flow exceeds
                    // its idle threshold against `Timestamp::MAX`.
                    this.pending.extend(this.tracker.sweep(Timestamp::MAX));
                    this.replay.finished = true;
                }
                Step::Err(e) => return Poll::Ready(Some(Err(e))),
                Step::Pending => return Poll::Pending,
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

    /// One-step offline L7 pipeline: flowscope's [`SessionDriver`]
    /// (flow tracking, TCP reassembly, per-flow `parser` clones) over
    /// the capture, yielding its [`SessionEvent`]s. The end-of-input
    /// flush is folded in.
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
        P: SessionParser + Clone,
    {
        self.flow_events(extractor).session_stream(parser)
    }

    /// One-step offline UDP-datagram pipeline — the
    /// [`DatagramParser`] mirror of [`Self::sessions`].
    pub fn datagrams<E, P>(self, extractor: E, parser: P) -> PcapDatagramStream<E, P>
    where
        E: FlowExtractor,
        E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
        P: DatagramParser + Clone,
    {
        self.flow_events(extractor).datagram_stream(parser)
    }
}

impl<E> PcapFlowStream<E>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
{
    /// Convert into a typed session stream. The tracker (config, idle
    /// predicate, in-flight flows) and the replay settings (dedup,
    /// monotonic clamp) carry over.
    pub fn session_stream<P>(self, parser: P) -> PcapSessionStream<E, P>
    where
        P: SessionParser + Clone,
    {
        PcapSessionStream {
            replay: self.replay,
            driver: SessionDriver::from_tracker(self.tracker, TemplateFactory(parser)),
            pending: VecDeque::new(),
            scratch: Vec::new(),
        }
    }

    /// UDP-datagram mirror of [`Self::session_stream`].
    pub fn datagram_stream<P>(self, parser: P) -> PcapDatagramStream<E, P>
    where
        P: DatagramParser + Clone,
    {
        PcapDatagramStream {
            replay: self.replay,
            driver: DatagramDriver::from_tracker(self.tracker, TemplateFactory(parser)),
            pending: VecDeque::new(),
            scratch: Vec::new(),
        }
    }
}

// ── PcapSessionStream / PcapDatagramStream ────────────────────

macro_rules! pcap_l7_stream {
    ($name:ident, $driver:ident, $parser:ident, $what:literal) => {
        #[doc = concat!("Async stream of [`SessionEvent`]s from flowscope's [`", stringify!($driver), "`] over an offline capture — ", $what, ".")]
        ///
        /// The offline twin of the live stream: same engine, same
        /// events, same parser-close / gap / overflow semantics; idle
        /// timeouts run on packet time (see the [module docs](self)).
        pub struct $name<E, P>
        where
            E: FlowExtractor,
            E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
            P: $parser + Clone,
        {
            replay: Replay,
            driver: $driver<E, TemplateFactory<P>>,
            pending: VecDeque<SessionEvent<E::Key, <P as $parser>::Message>>,
            scratch: Vec<SessionEvent<E::Key, <P as $parser>::Message>>,
        }

        impl<E, P> $name<E, P>
        where
            E: FlowExtractor,
            E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
            P: $parser + Clone,
        {
            /// Replace the config (flow table and reassembly limits).
            pub fn with_config(mut self, config: FlowTrackerConfig) -> Self {
                self.replay.sweep_interval = config.sweep_interval;
                self.driver.set_config(config);
                self
            }

            /// Emit [`SessionEvent::FlowAnomaly`] /
            /// [`SessionEvent::TrackerAnomaly`]. Default: off.
            pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
                self.driver.set_emit_anomalies(enable);
                self
            }

            /// Override the per-flow idle timeout via a key predicate.
            pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
            where
                G: Fn(&E::Key, Option<flowscope::L4Proto>) -> Option<Duration>
                    + Send
                    + Sync
                    + 'static,
            {
                self.driver.set_idle_timeout_fn(f);
                self
            }

            replay_builders!();

            /// Borrow the flow table.
            pub fn tracker(&self) -> &FlowTracker<E, ()> {
                self.driver.tracker()
            }

            /// Borrow the underlying flowscope driver.
            pub fn driver(&self) -> &$driver<E, TemplateFactory<P>> {
                &self.driver
            }

            /// Live `(key, stats)` for every tracked flow, reassembly
            /// diagnostics included.
            pub fn snapshot_flow_stats(&self) -> impl Iterator<Item = (E::Key, FlowStats)> + '_ {
                self.driver.snapshot_flow_stats()
            }

            /// Cumulative tracker counters.
            pub fn tracker_stats(&self) -> &flowscope::FlowTrackerStats {
                self.driver.tracker().stats()
            }

            /// Count of live flow entries.
            pub fn active_flows(&self) -> usize {
                self.driver.tracker().flow_count()
            }
        }

        impl<E, P> Stream for $name<E, P>
        where
            E: FlowExtractor + Unpin,
            E::Key: std::hash::Hash + Eq + Clone + Send + Unpin + 'static,
            P: $parser + Clone + Unpin,
            <P as $parser>::Message: Unpin,
        {
            type Item = Result<SessionEvent<E::Key, <P as $parser>::Message>, Error>;

            fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                let this = self.get_mut();
                loop {
                    if let Some(ev) = this.pending.pop_front() {
                        return Poll::Ready(Some(Ok(ev)));
                    }
                    if this.replay.finished {
                        return Poll::Ready(None);
                    }
                    match this.replay.poll_step(cx) {
                        Step::Packet(pkt, ts, sweep) => {
                            if let Some(now) = sweep {
                                this.driver.sweep_into(now, &mut this.scratch);
                            }
                            this.driver
                                .track_into(PacketView::new(&pkt.data, ts), &mut this.scratch);
                        }
                        Step::Eof => {
                            // End-of-input flush: final `on_tick`, then every
                            // still-open flow closes (`sweep(Timestamp::MAX)`).
                            this.driver.finish_into(&mut this.scratch);
                            this.replay.finished = true;
                        }
                        Step::Err(e) => return Poll::Ready(Some(Err(e))),
                        Step::Pending => return Poll::Pending,
                    }
                    this.pending.extend(this.scratch.drain(..));
                }
            }
        }
    };
}

pcap_l7_stream!(
    PcapSessionStream,
    SessionDriver,
    SessionParser,
    "TCP, reassembled"
);
pcap_l7_stream!(
    PcapDatagramStream,
    DatagramDriver,
    DatagramParser,
    "UDP / ICMP payloads"
);
