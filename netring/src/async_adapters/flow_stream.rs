//! [`FlowStream`] — `futures_core::Stream` of [`FlowEvent`]s built on
//! top of [`AsyncCapture`] and [`flowscope::FlowTracker`].
//!
//! Available under `flow + tokio` features. The headline async API:
//!
//! ```no_run
//! use futures::StreamExt;
//! use netring::AsyncCapture;
//! use netring::flow::extract::FiveTuple;
//!
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let cap = AsyncCapture::open("eth0")?;
//! let mut stream = cap.flow_stream(FiveTuple::bidirectional());
//! while let Some(evt) = stream.next().await {
//!     let _evt = evt?;
//!     # break;
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use flowscope::tracker::FlowEvents;
use flowscope::{FlowEvent, FlowExtractor, FlowTracker, FlowTrackerConfig, PacketView, Timestamp};
use futures_core::Stream;

use crate::async_adapters::async_reassembler::AsyncReassemblerFactory;
use crate::async_adapters::flow_source::{AsyncFlowSource, DrainOutcome, SourcePacket};
use crate::async_adapters::multi_config::SharedIdleTimeoutFn;
use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::dedup::Dedup;
use crate::error::Error;
use crate::traits::PacketSource;

/// Stream of [`FlowEvent`]s produced by feeding captured packets
/// through a [`FlowTracker`].
///
/// Generic over the packet source `C` (issue #104): an
/// [`AsyncCapture`] (AF_PACKET) or an
/// [`AsyncXdpCapture`](crate::AsyncXdpCapture) (AF_XDP). Both drive the same
/// tracking loop via the `AsyncFlowSource` trait.
pub struct FlowStream<C, E, U = ()>
where
    E: FlowExtractor,
    U: Send + 'static,
{
    cap: C,
    tracker: FlowTracker<E, U>,
    pending: VecDeque<FlowEvent<E::Key>>,
    sweep: tokio::time::Interval,
    dedup: Option<Dedup>,
    /// Plan 19: when `Some(_)`, every packet's timestamp is clamped
    /// to `max(view.timestamp, *self)` before flow extraction, so
    /// downstream consumers see a strictly non-decreasing timeline.
    monotonic_ts: Option<Timestamp>,
    /// Plan 20: optional pcap tap. Captures packets to disk before
    /// the flow tracker processes them. Survives `with_state`,
    /// `with_async_reassembler`, `session_stream`, `datagram_stream`
    /// conversions (same plumbing as `dedup`).
    #[cfg(feature = "pcap")]
    tap: Option<crate::pcap_tap::PcapTap>,
    /// The [`with_idle_timeout_fn`](Self::with_idle_timeout_fn)
    /// predicate, kept so [`with_state`](FlowStream::with_state) can
    /// install it in the tracker it rebuilds.
    idle_timeout_fn: Option<SharedIdleTimeoutFn<E::Key>>,
}

impl<C, E> FlowStream<C, E, ()>
where
    E: FlowExtractor,
{
    pub(crate) fn new(cap: C, extractor: E) -> Self {
        let tracker = FlowTracker::new(extractor);
        let sweep_interval = tracker.config().sweep_interval;
        Self {
            cap,
            tracker,
            pending: VecDeque::new(),
            sweep: sweep_timer(sweep_interval),
            dedup: None,
            monotonic_ts: None,
            #[cfg(feature = "pcap")]
            tap: None,
            idle_timeout_fn: None,
        }
    }

    /// Attach per-flow user state.
    ///
    /// The flow table is rebuilt for the new state type: the config, the
    /// [`with_idle_timeout_fn`](Self::with_idle_timeout_fn) predicate,
    /// dedup, timestamp clamp, pcap tap and already-queued events carry
    /// over, but flows already tracked do not (their `Ended` never
    /// comes) — call it before the first poll.
    pub fn with_state<U, F>(self, init: F) -> FlowStream<C, E, U>
    where
        U: Send + 'static,
        F: FnMut(&E::Key) -> U + Send + Sync + 'static,
    {
        let config = self.tracker.config().clone();
        let extractor = self.tracker.into_extractor();
        let mut tracker = FlowTracker::with_config_and_state(extractor, config, init);
        if let Some(f) = self.idle_timeout_fn.clone() {
            tracker.set_idle_timeout_fn(move |k, l4| f(k, l4));
        }
        FlowStream {
            cap: self.cap,
            tracker,
            pending: self.pending,
            sweep: self.sweep,
            dedup: self.dedup,
            monotonic_ts: self.monotonic_ts,
            #[cfg(feature = "pcap")]
            tap: self.tap,
            idle_timeout_fn: self.idle_timeout_fn,
        }
    }
}

impl<C, E, U> FlowStream<C, E, U>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    U: Send + 'static,
{
    /// Feed each TCP flow side's **reassembled** bytes (in order,
    /// retransmissions dropped, losses reported as gaps) to a
    /// per-side [`AsyncReassembler`](crate::async_adapters::async_reassembler::AsyncReassembler)
    /// built by `factory`, while still yielding the flow events. Each
    /// consumer future is awaited inline — backpressure flows from the
    /// consumer back to the kernel ring. See
    /// [`ReassemblyStream`](crate::async_adapters::async_reassembler::ReassemblyStream).
    ///
    /// The tracker (config, idle-timeout predicate, live flows), dedup,
    /// timestamp clamp, pcap tap and already-queued events carry over.
    pub fn with_async_reassembler<F>(
        self,
        factory: F,
    ) -> crate::async_adapters::async_reassembler::ReassemblyStream<C, E, U, F>
    where
        F: AsyncReassemblerFactory<E::Key>,
    {
        crate::async_adapters::async_reassembler::ReassemblyStream::from_parts(
            self.cap,
            self.tracker,
            factory,
            self.pending,
            self.dedup,
            self.monotonic_ts,
            #[cfg(feature = "pcap")]
            self.tap,
        )
    }
}

// L7 conversions are generic over the source `C` (issue #104): the
// `SessionStream` / `DatagramStream` they build are now source-agnostic, so
// AF_XDP (`AsyncXdpCapture`) gets `.session_stream()` / `.datagram_stream()`
// for free — same as AF_PACKET.
impl<C, E> FlowStream<C, E, ()>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
{
    /// Convert into a stream of typed L7 messages. Bytes from each
    /// flow's TCP segments are dispatched to a per-flow
    /// [`flowscope::SessionParser`] built by `factory`; whatever
    /// messages the parser returns are surfaced as
    /// [`SessionEvent::Application`](crate::flow::SessionEvent::Application).
    ///
    /// The current tracker [`FlowTrackerConfig`] is preserved across
    /// the conversion — `cap.flow_stream(ext).with_config(cfg).session_stream(parser)`
    /// runs the session-level tracker with `cfg`.
    pub fn session_stream<F>(
        self,
        factory: F,
    ) -> crate::async_adapters::session_stream::SessionStream<C, E, F>
    where
        F: flowscope::SessionParserFactory<E::Key>,
    {
        // Plan 19: move the tracker over instead of rebuilding from
        // the extractor. Preserves idle_timeout_fn, hot-cache, and
        // any in-flight flows.
        crate::async_adapters::session_stream::SessionStream::from_tracker(
            self.cap,
            self.tracker,
            factory,
            self.pending,
            self.dedup,
            self.monotonic_ts,
            #[cfg(feature = "pcap")]
            self.tap,
        )
    }

    /// Convert into a stream of typed L7 messages from packet-oriented
    /// (UDP) protocols. Each UDP payload is fed to a per-flow
    /// [`flowscope::DatagramParser`].
    ///
    /// As with [`session_stream`](Self::session_stream), the tracker
    /// config and any dedup set via [`with_dedup`](Self::with_dedup)
    /// are preserved across the conversion.
    pub fn datagram_stream<F>(
        self,
        factory: F,
    ) -> crate::async_adapters::datagram_stream::DatagramStream<C, E, F>
    where
        F: flowscope::DatagramParserFactory<E::Key>,
    {
        // Plan 19: move the tracker over so `idle_timeout_fn` and
        // in-flight flow state survive the conversion.
        crate::async_adapters::datagram_stream::DatagramStream::from_tracker(
            self.cap,
            self.tracker,
            factory,
            self.pending,
            self.dedup,
            self.monotonic_ts,
            #[cfg(feature = "pcap")]
            self.tap,
        )
    }
}

impl<C, E, U> FlowStream<C, E, U>
where
    E: FlowExtractor,
    U: Send + 'static,
{
    /// Replace tracker config in place.
    ///
    /// Resizes the LRU capacity if `max_flows` changed. Re-arms the
    /// sweep timer if `sweep_interval` changed.
    pub fn with_config(mut self, config: FlowTrackerConfig) -> Self {
        let new_interval = config.sweep_interval;
        self.tracker.set_config(config);
        self.sweep = sweep_timer(new_interval);
        self
    }

    /// Apply per-packet deduplication before flow tracking.
    ///
    /// Useful for capturing on `lo` where each packet appears twice
    /// ([`PACKET_OUTGOING`](crate::PacketDirection::Outgoing) +
    /// [`PACKET_HOST`](crate::PacketDirection::Host)); pair with
    /// [`Dedup::loopback`](crate::Dedup::loopback).
    ///
    /// The dedup is carried through subsequent
    /// [`session_stream`](Self::session_stream) /
    /// [`datagram_stream`](Self::datagram_stream) /
    /// [`with_async_reassembler`](Self::with_async_reassembler) /
    /// [`with_state`](Self::with_state) transitions.
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

    /// Borrow the inner tracker (for stats / introspection).
    pub fn tracker(&self) -> &FlowTracker<E, U> {
        &self.tracker
    }

    /// Borrow the inner tracker mutably (for poking user state).
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, U> {
        &mut self.tracker
    }

    /// Override the per-flow idle timeout via a key predicate. The
    /// closure receives `(&key, Option<L4Proto>)` and returns
    /// `Option<Duration>`; `None` falls back to the per-protocol
    /// defaults from [`FlowTrackerConfig`].
    ///
    /// Useful for protocols whose natural rhythm differs from the
    /// default sweep cadence — e.g. interactive control flows that
    /// stay alive long past the bulk-data idle threshold.
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use netring::AsyncCapture;
    /// # use netring::flow::extract::FiveTuple;
    /// # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
    /// let cap = AsyncCapture::open("eth0")?;
    /// let stream = cap.flow_stream(FiveTuple::bidirectional())
    ///     .with_idle_timeout_fn(|k, _l4| {
    ///         if k.either_port(53) {
    ///             Some(Duration::from_secs(5))
    ///         } else {
    ///             None
    ///         }
    ///     });
    /// # let _ = stream;
    /// # Ok(()) }
    /// ```
    pub fn with_idle_timeout_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&E::Key, Option<flowscope::L4Proto>) -> Option<Duration> + Send + Sync + 'static,
    {
        let f: SharedIdleTimeoutFn<E::Key> = std::sync::Arc::new(f);
        let shared = f.clone();
        self.tracker.set_idle_timeout_fn(move |k, l4| shared(k, l4));
        self.idle_timeout_fn = Some(f);
        self
    }

    /// Clamp NIC-supplied timestamps to a running max so the event
    /// stream is strictly non-decreasing in time. Useful for log
    /// correlation or replay pipelines that don't tolerate
    /// step-backs. Default: off.
    ///
    /// The clamp also applies to the periodic sweep's `now` argument.
    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.monotonic_ts = if enable {
            Some(Timestamp::default())
        } else {
            None
        };
        self
    }

    /// Live `(key, stats)` pairs, owned — the same shape as every other
    /// netring stream's `snapshot_flow_stats` (a plain flow stream
    /// reassembles nothing, so the reassembly fields stay zero — see
    /// [`ReassemblyStream::snapshot_flow_stats`](crate::ReassemblyStream::snapshot_flow_stats)).
    /// Lazy — pay only for what you consume. For borrowed access and
    /// the richer `ActiveFlow` shape (user state, TCP state, L4), use
    /// `self.tracker().iter_active()`.
    pub fn snapshot_flow_stats(&self) -> impl Iterator<Item = (E::Key, flowscope::FlowStats)> + '_
    where
        E::Key: Clone,
    {
        self.tracker
            .iter_active()
            .map(|af| (af.key.clone(), af.stats.clone()))
    }

    /// Cumulative tracker counters: `flows_created`, `flows_ended`,
    /// `flows_evicted`, `packets_unmatched`. One-call accessor for
    /// the inner [`flowscope::FlowTrackerStats`].
    ///
    /// Pair with [`active_flows`](Self::active_flows) for live count.
    pub fn tracker_stats(&self) -> &flowscope::FlowTrackerStats {
        self.tracker.stats()
    }

    /// Count of live flow entries (current LRU size).
    ///
    /// O(n) over the LRU; cheap (a few µs at 100k flows) but not
    /// free — call from a periodic metrics tick, not from every poll.
    pub fn active_flows(&self) -> usize {
        self.tracker.flows().count()
    }

    /// Plan 20: tap every captured packet into `writer` before
    /// passing it to the flow tracker. Default error policy:
    /// [`TapErrorPolicy::Continue`](crate::pcap_tap::TapErrorPolicy::Continue).
    ///
    /// The tap is carried through `with_state`, `with_async_reassembler`,
    /// `session_stream`, and `datagram_stream` conversions.
    ///
    /// For high-rate captures, wrap the writer in
    /// [`std::io::BufWriter`] before passing it in:
    ///
    /// ```no_run
    /// # use std::fs::File;
    /// # use std::io::BufWriter;
    /// # use netring::pcap::CaptureWriter;
    /// # fn _ex() -> Result<(), Box<dyn std::error::Error>> {
    /// let writer = CaptureWriter::create(BufWriter::new(File::create("out.pcap")?))?;
    /// # let _ = writer; Ok(()) }
    /// ```
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

    /// Plan 24: cap the recorded frame size on the pcap tap, in
    /// bytes. Same semantic as `tcpdump -s <snaplen>` — the pcap
    /// record's `orig_len` keeps the full wire length while
    /// `caplen` is bounded by `snaplen`.
    ///
    /// No-op if no tap is attached. Default unlimited.
    #[cfg(feature = "pcap")]
    pub fn with_pcap_tap_snaplen(mut self, snaplen: u32) -> Self {
        if let Some(tap) = self.tap.as_mut() {
            tap.set_snaplen(snaplen);
        }
        self
    }
}

// ── Stream impl ────────────────────────────────────────────────────

impl<C, E, U> Stream for FlowStream<C, E, U>
where
    C: AsyncFlowSource + Unpin,
    E: FlowExtractor + Unpin,
    E::Key: Clone + Unpin,
    U: Send + 'static + Unpin,
{
    type Item = Result<FlowEvent<E::Key>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(evt) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(evt)));
            }

            // `TapErrorPolicy::FailStream`: the queued events are out;
            // yield the write error once, then end.
            #[cfg(feature = "pcap")]
            if let Some(t) = this.tap.as_mut()
                && t.has_failed()
            {
                return Poll::Ready(t.take_failure().map(Err));
            }

            if poll_sweep(&mut this.sweep, cx) {
                let now = clamp_now(current_timestamp(), &mut this.monotonic_ts);
                for ev in this.tracker.sweep(now) {
                    this.pending.push_back(ev);
                }
                if let Some(evt) = this.pending.pop_front() {
                    return Poll::Ready(Some(Ok(evt)));
                }
            }

            // Disjoint field borrows so the sink closure can feed the tracker
            // while `cap` is borrowed by `poll_drain`.
            let cap = &mut this.cap;
            let tracker = &mut this.tracker;
            let pending = &mut this.pending;
            let dedup = &mut this.dedup;
            let monotonic_ts = &mut this.monotonic_ts;
            #[cfg(feature = "pcap")]
            let tap = &mut this.tap;

            let outcome = cap.poll_drain(cx, &mut |sp: SourcePacket<'_>| {
                // Plan 17: optional pre-tracking dedup (on the unclamped ts).
                if let Some(d) = dedup.as_mut()
                    && !d.keep_raw(sp.data, sp.direction, sp.view.timestamp)
                {
                    return;
                }

                // Plan 20: pcap tap — record what the tracker is about to
                // see, skipping duplicates so the file matches the events.
                // After a `FailStream` error nothing more is tracked.
                #[cfg(feature = "pcap")]
                if let Some(t) = tap.as_mut()
                    && !t.write_raw_or_handle(sp.data, sp.view.timestamp, sp.original_len)
                {
                    return;
                }

                let view = clamp_view(sp.view, monotonic_ts);
                let evts: FlowEvents<E::Key> = tracker.track(view);
                for ev in evts {
                    pending.push_back(ev);
                }
            });

            match outcome {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(Error::Io(e)))),
                Poll::Ready(Ok(DrainOutcome::Drained | DrainOutcome::Idle)) => {}
            }
        }
    }
}

/// Plan 19: clamp a packet view's timestamp against a running max
/// if monotonic mode is enabled. No-op when `state` is `None`.
pub(crate) fn clamp_view<'a>(
    view: PacketView<'a>,
    state: &mut Option<Timestamp>,
) -> PacketView<'a> {
    let Some(last) = state.as_mut() else {
        return view;
    };
    *last = (*last).max(view.timestamp);
    // Only the timestamp changes: the RX metadata (capture leg for
    // `FlowStats::source_idx_{forward,reverse}`, hardware hash / VLAN /
    // checksum hints) is kept whole. It used to be rebuilt keeping
    // `source_idx` only.
    let mut clamped = view;
    clamped.timestamp = *last;
    clamped
}

/// The live streams' sweep timer, ticking every `sweep_interval` — at
/// most every millisecond: a zero interval (valid for the pcap streams,
/// which sweep on packet time) would panic `tokio::time::interval`.
pub(crate) fn sweep_timer(sweep_interval: Duration) -> tokio::time::Interval {
    tokio::time::interval(sweep_interval.max(Duration::from_millis(1)))
}

/// Poll the sweep timer: `true` when a sweep is due.
///
/// When `Interval::poll_tick` returns `Ready` it re-arms its sleep
/// *without* registering it with the timer (tokio's
/// `reset_without_timer`); only a later `Pending` poll does. Poll on
/// until `Pending`, so the next tick wakes the task even if the source
/// stays quiet — otherwise a tick that ends nothing leaves no timer
/// armed and idle flows never end. Missed ticks fold into one sweep.
pub(crate) fn poll_sweep(sweep: &mut tokio::time::Interval, cx: &mut Context<'_>) -> bool {
    if sweep.poll_tick(cx).is_pending() {
        return false;
    }
    while sweep.poll_tick(cx).is_ready() {}
    true
}

/// Plan 19: clamp a sweep `now` argument against a running max if
/// monotonic mode is enabled. No-op when `state` is `None`.
pub(crate) fn clamp_now(now: Timestamp, state: &mut Option<Timestamp>) -> Timestamp {
    let Some(last) = state.as_mut() else {
        return now;
    };
    *last = (*last).max(now);
    *last
}

/// Approximate "now" using `SystemTime`.
pub(crate) fn current_timestamp() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    Timestamp::new(now.as_secs() as u32, now.subsec_nanos())
}

// ── AsyncCapture::flow_stream entry point ──────────────────────────

impl<S> AsyncCapture<S>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
{
    /// Convert this capture into a stream of [`FlowEvent`]s.
    ///
    /// Consumes the capture. The returned [`FlowStream`] uses
    /// default tracker config and `()` for per-flow user state.
    /// Chain `.with_state(...)`, `.with_config(...)`, and
    /// `.with_async_reassembler(...)` to customize.
    pub fn flow_stream<E>(self, extractor: E) -> FlowStream<AsyncCapture<S>, E>
    where
        E: FlowExtractor,
    {
        FlowStream::new(self, extractor)
    }
}

// ── AsyncXdpCapture::flow_stream entry point (issue #104) ───────────────────

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl crate::AsyncXdpCapture {
    /// Convert this multi-queue AF_XDP capture into a stream of
    /// [`FlowEvent`]s — the AF_XDP analogue of
    /// [`AsyncCapture::flow_stream`]. All RX queues feed one
    /// [`FlowTracker`]; chain `.with_state(...)` / `.with_config(...)` /
    /// `.with_async_reassembler(...)` as usual.
    ///
    /// The pcap-tap and loopback-dedup legs are AF_PACKET-oriented but work
    /// here too (dedup is a no-op without a meaningful packet direction).
    pub fn flow_stream<E>(self, extractor: E) -> FlowStream<crate::AsyncXdpCapture, E>
    where
        E: FlowExtractor,
    {
        FlowStream::new(self, extractor)
    }
}

/// Accessors for an AF_XDP-backed flow stream (issue #104). The AF_PACKET
/// equivalents come from the [`StreamCapture`] trait, which is AF_XDP's
/// `AsyncXdpCapture` source cannot satisfy (no `AsyncCapture` to lend).
#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl<E, U> FlowStream<crate::AsyncXdpCapture, E, U>
where
    E: FlowExtractor,
    U: Send + 'static,
{
    /// Borrow the inner multi-queue AF_XDP capture (for ring stats /
    /// zero-copy / queue introspection).
    pub fn xdp_capture(&self) -> &crate::AsyncXdpCapture {
        &self.cap
    }

    /// Unified kernel-ring [`CaptureStats`](crate::stats::CaptureStats) summed
    /// across the capture's RX queues.
    pub fn capture_stats(&self) -> Result<crate::stats::CaptureStats, Error> {
        self.cap.capture_stats()
    }
}

// ── MultiSource (fan-in introspection, #176 / #177) ──────────────

impl<C, E> crate::async_adapters::multi_source::Sealed for FlowStream<C, E, ()> where
    E: FlowExtractor
{
}

impl<C, E> crate::async_adapters::multi_source::MultiSource<E> for FlowStream<C, E, ()>
where
    C: AsyncFlowSource,
    E: FlowExtractor,
{
    fn tracker(&self) -> &FlowTracker<E, ()> {
        &self.tracker
    }

    fn snapshot_flow_stats(&self) -> Box<dyn Iterator<Item = (E::Key, flowscope::FlowStats)> + '_> {
        Box::new(
            self.tracker
                .iter_active()
                .map(|af| (af.key.clone(), af.stats.clone())),
        )
    }

    fn dedup(&self) -> Option<&Dedup> {
        self.dedup.as_ref()
    }

    fn dedup_mut(&mut self) -> Option<&mut Dedup> {
        self.dedup.as_mut()
    }

    fn capture_stats(&self) -> Option<Result<crate::stats::CaptureStats, Error>> {
        self.cap.capture_stats()
    }

    fn packets_read(&self) -> Option<u64> {
        None
    }
}

// ── StreamCapture trait impl ───────────────────────────────────────
//
// Restricted to the AF_PACKET source: `StreamCapture::capture()` returns a
// concrete `&AsyncCapture<S>`, which the AF_XDP source has no analogue for.

use crate::async_adapters::stream_capture::{Sealed, StreamCapture};

impl<S, E, U> Sealed for FlowStream<AsyncCapture<S>, E, U>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    U: Send + 'static,
{
}

impl<S, E, U> StreamCapture for FlowStream<AsyncCapture<S>, E, U>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    U: Send + 'static,
{
    type Source = S;

    fn capture(&self) -> &AsyncCapture<S> {
        &self.cap
    }

    fn dedup(&self) -> Option<&Dedup> {
        self.dedup.as_ref()
    }

    fn dedup_mut(&mut self) -> Option<&mut Dedup> {
        self.dedup.as_mut()
    }
}

#[cfg(test)]
pub(crate) mod monotonic_tests {
    use super::*;

    #[test]
    fn clamp_view_passthrough_when_off() {
        let mut state: Option<Timestamp> = None;
        let frame = [0u8; 4];
        let ts = Timestamp::new(100, 0);
        let v = PacketView::new(&frame, ts);
        let out = clamp_view(v, &mut state);
        assert_eq!(out.timestamp, ts);
        assert!(state.is_none());
    }

    #[test]
    fn clamp_view_advances_running_max() {
        let mut state: Option<Timestamp> = Some(Timestamp::default());
        let frame = [0u8; 4];
        let t1 = Timestamp::new(100, 0);
        let t2 = Timestamp::new(50, 0); // step backwards
        let t3 = Timestamp::new(200, 0); // step forward

        let v1 = clamp_view(PacketView::new(&frame, t1), &mut state);
        assert_eq!(v1.timestamp, t1);
        assert_eq!(state, Some(t1));

        let v2 = clamp_view(PacketView::new(&frame, t2), &mut state);
        assert_eq!(v2.timestamp, t1, "step-back clamps to running max");
        assert_eq!(state, Some(t1));

        let v3 = clamp_view(PacketView::new(&frame, t3), &mut state);
        assert_eq!(v3.timestamp, t3, "step-forward advances running max");
        assert_eq!(state, Some(t3));
    }

    /// #171: the clamp changes the timestamp only; the RX metadata
    /// (not just `source_idx`) survives.
    #[test]
    fn clamp_view_keeps_rx_metadata() {
        let mut state: Option<Timestamp> = Some(Timestamp::new(100, 0));
        let frame = [0u8; 4];
        let mut meta = flowscope::RxMetadata::default();
        meta.hw_timestamp = Some(Timestamp::new(5, 5));
        meta.source_idx = 3;
        let v = PacketView::new(&frame, Timestamp::new(50, 0)).with_rx_metadata(meta);
        let out = clamp_view(v, &mut state);
        assert_eq!(out.timestamp, Timestamp::new(100, 0));
        assert_eq!(out.rx_metadata, meta);
    }

    /// #171: events the flow stream had queued survive the conversion
    /// to a session stream in their session form.
    #[tokio::test(flavor = "current_thread")]
    async fn session_conversion_keeps_queued_events() {
        use crate::async_adapters::flow_source::VecSource;
        use flowscope::extract::FiveTuple;
        use flowscope::extract::parse::test_frames::ipv4_udp;
        use flowscope::{DatagramParser, FlowSide, SessionEvent};
        use futures::StreamExt;

        #[derive(Clone, Default)]
        struct Nop;
        impl DatagramParser for Nop {
            type Message = ();
            fn parse(&mut self, _: &[u8], _: FlowSide, _: Timestamp, _: &mut Vec<()>) {}
        }

        let ts = current_timestamp();
        // Two new UDP flows in one drain: Started + Packet each.
        let frames = [
            ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53, b"a"),
            ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 6000, 53, b"b"),
        ];
        let mut flows = FlowStream::new(
            VecSource(frames.into_iter().map(|f| (f, ts)).collect()),
            FiveTuple::bidirectional(),
        );
        let first = flows.next().await.unwrap().unwrap();
        assert!(matches!(first, FlowEvent::Started { .. }));
        let mut dgrams = flows.datagram_stream(Nop);
        let next = tokio::time::timeout(std::time::Duration::from_secs(1), dgrams.next())
            .await
            .expect("the queued Started of the second flow")
            .unwrap()
            .unwrap();
        assert!(
            matches!(next, SessionEvent::Started { key, .. } if key.a.port().max(key.b.port()) == 6000),
            "{next:?}"
        );
    }

    /// Idle timeouts short enough for a test, swept every 50 ms.
    pub(crate) fn quick_idle_config() -> FlowTrackerConfig {
        let mut cfg = FlowTrackerConfig::default();
        cfg.idle_timeout_tcp = Duration::from_millis(300);
        cfg.idle_timeout_udp = Duration::from_millis(300);
        cfg.idle_timeout_other = Duration::from_millis(300);
        cfg.sweep_interval = Duration::from_millis(50);
        cfg
    }

    /// One UDP datagram stamped now, from a source that then stays
    /// quiet (and never wakes the task).
    pub(crate) fn one_udp_datagram() -> crate::async_adapters::flow_source::VecSource {
        use flowscope::extract::parse::test_frames::ipv4_udp;
        crate::async_adapters::flow_source::VecSource(
            [(
                ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53, b"q"),
                current_timestamp(),
            )]
            .into(),
        )
    }

    /// Poll `s` until `done` matches an event; panics if the stream
    /// goes silent for 3 s first. (Not `tokio::time::timeout`: its own
    /// timer would re-poll the stream and mask a disarmed sweep timer.)
    pub(crate) async fn next_until<S, T>(s: &mut S, done: impl Fn(&T) -> bool)
    where
        S: Stream<Item = Result<T, Error>> + Unpin,
        T: std::fmt::Debug,
    {
        use futures::StreamExt;
        let deadline = tokio::time::sleep(Duration::from_secs(3));
        tokio::pin!(deadline);
        loop {
            let ev = tokio::select! {
                biased;
                () = &mut deadline => panic!("no matching event within 3 s (sweep timer disarmed?)"),
                ev = s.next() => ev.expect("a live stream never ends").unwrap(),
            };
            if done(&ev) {
                return;
            }
        }
    }

    /// A sweep tick that produces no event must leave the timer
    /// armed, so an idle flow still ends while the source stays quiet.
    #[tokio::test(flavor = "current_thread")]
    async fn idle_flow_ends_on_a_quiet_source() {
        use flowscope::extract::FiveTuple;
        let mut flows = FlowStream::new(one_udp_datagram(), FiveTuple::bidirectional())
            .with_config(quick_idle_config());
        next_until(&mut flows, |ev| matches!(ev, FlowEvent::Ended { .. })).await;
    }

    /// [`quick_idle_config`] with a zero `sweep_interval` — valid for
    /// the pcap streams (sweep on every packet).
    fn zero_sweep_config() -> FlowTrackerConfig {
        let mut cfg = quick_idle_config();
        cfg.sweep_interval = Duration::ZERO;
        cfg
    }

    /// A zero `sweep_interval` is not a panic in the live streams'
    /// sweep timer; idle flows still end.
    #[tokio::test(flavor = "current_thread")]
    async fn zero_sweep_interval_flow_stream() {
        let mut flows = FlowStream::new(
            one_udp_datagram(),
            flowscope::extract::FiveTuple::bidirectional(),
        )
        .with_config(zero_sweep_config());
        next_until(&mut flows, |ev| matches!(ev, FlowEvent::Ended { .. })).await;
    }

    /// Same, for the converted streams: a zero interval in the moved
    /// tracker, or set through their own `with_config`.
    #[tokio::test(flavor = "current_thread")]
    async fn zero_sweep_interval_converted_streams() {
        let zero_flows = || {
            let mut flows = FlowStream::new(
                one_udp_datagram(),
                flowscope::extract::FiveTuple::bidirectional(),
            );
            flows.tracker_mut().set_config(zero_sweep_config());
            flows
        };
        let closed = |ev: &flowscope::SessionEvent<_, ()>| {
            matches!(ev, flowscope::SessionEvent::Closed { .. })
        };
        let mut s = zero_flows().session_stream(NopParser);
        next_until(&mut s, closed).await;
        let mut s = quick_idle_flows()
            .session_stream(NopParser)
            .with_config(zero_sweep_config());
        next_until(&mut s, closed).await;
        let mut s = zero_flows().datagram_stream(NopParser);
        next_until(&mut s, closed).await;
        let mut s = quick_idle_flows()
            .datagram_stream(NopParser)
            .with_config(zero_sweep_config());
        next_until(&mut s, closed).await;
        let factory = || {
            crate::async_adapters::async_reassembler::channel_factory(
                |_: &flowscope::extract::FiveTupleKey, _: flowscope::FlowSide| {
                    tokio::sync::mpsc::channel(1).0
                },
            )
        };
        let mut s = zero_flows().with_async_reassembler(factory());
        next_until(&mut s, |ev| matches!(ev, FlowEvent::Ended { .. })).await;
        let mut s = quick_idle_flows()
            .with_async_reassembler(factory())
            .with_config(zero_sweep_config());
        next_until(&mut s, |ev| matches!(ev, FlowEvent::Ended { .. })).await;
    }

    /// `with_state` keeps an idle-timeout predicate set before it.
    #[tokio::test(flavor = "current_thread")]
    async fn with_state_keeps_the_idle_timeout_fn() {
        let mut cfg = FlowTrackerConfig::default();
        cfg.sweep_interval = Duration::from_millis(50);
        let mut flows = FlowStream::new(
            one_udp_datagram(),
            flowscope::extract::FiveTuple::bidirectional(),
        )
        .with_config(cfg)
        .with_idle_timeout_fn(|_, _| Some(Duration::from_millis(300)))
        .with_state(|_| 0u32);
        next_until(&mut flows, |ev| matches!(ev, FlowEvent::Ended { .. })).await;
    }

    /// `with_state` keeps the events the stream had already queued.
    #[tokio::test(flavor = "current_thread")]
    async fn with_state_keeps_queued_events() {
        use flowscope::extract::parse::test_frames::ipv4_udp;
        use futures::StreamExt;
        let ts = current_timestamp();
        let frames =
            [5000, 6000].map(|sp| (ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], sp, 53, b"q"), ts));
        let mut flows = FlowStream::new(
            crate::async_adapters::flow_source::VecSource(frames.into()),
            flowscope::extract::FiveTuple::bidirectional(),
        );
        let first = flows.next().await.unwrap().unwrap();
        assert!(matches!(first, FlowEvent::Started { .. }));
        let mut flows = flows.with_state(|_| 0u32);
        let mut started = 0;
        while let Ok(Some(ev)) =
            tokio::time::timeout(Duration::from_millis(300), flows.next()).await
        {
            if let FlowEvent::Started { key, .. } = ev.unwrap() {
                assert_eq!(key.a.port().max(key.b.port()), 6000);
                started += 1;
            }
        }
        assert_eq!(started, 1, "the second flow's queued Started");
    }

    #[derive(Clone, Default)]
    struct NopParser;
    impl flowscope::DatagramParser for NopParser {
        type Message = ();
        fn parse(&mut self, _: &[u8], _: flowscope::FlowSide, _: Timestamp, _: &mut Vec<()>) {}
    }
    impl flowscope::SessionParser for NopParser {
        type Message = ();
        fn feed_initiator(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
        fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
    }

    fn quick_idle_flows()
    -> FlowStream<crate::async_adapters::flow_source::VecSource, flowscope::extract::FiveTuple>
    {
        FlowStream::new(
            one_udp_datagram(),
            flowscope::extract::FiveTuple::bidirectional(),
        )
        .with_config(quick_idle_config())
    }

    /// Same, for the session stream.
    #[tokio::test(flavor = "current_thread")]
    async fn idle_session_closes_on_a_quiet_source() {
        let mut s = quick_idle_flows().session_stream(NopParser);
        next_until(&mut s, |ev| {
            matches!(ev, flowscope::SessionEvent::Closed { .. })
        })
        .await;
    }

    /// Same, for the datagram stream.
    #[tokio::test(flavor = "current_thread")]
    async fn idle_datagram_flow_closes_on_a_quiet_source() {
        let mut s = quick_idle_flows().datagram_stream(NopParser);
        next_until(&mut s, |ev| {
            matches!(ev, flowscope::SessionEvent::Closed { .. })
        })
        .await;
    }

    /// Same, for the reassembly stream.
    #[tokio::test(flavor = "current_thread")]
    async fn idle_reassembled_flow_ends_on_a_quiet_source() {
        let mut s = quick_idle_flows().with_async_reassembler(
            crate::async_adapters::async_reassembler::channel_factory(
                |_: &flowscope::extract::FiveTupleKey, _: flowscope::FlowSide| {
                    tokio::sync::mpsc::channel(1).0
                },
            ),
        );
        next_until(&mut s, |ev| matches!(ev, FlowEvent::Ended { .. })).await;
    }

    /// A tap whose second write fails.
    #[cfg(feature = "pcap")]
    struct FailSecondWrite(usize);

    #[cfg(feature = "pcap")]
    impl crate::pcap_tap::TapWriter for FailSecondWrite {
        fn write(
            &mut self,
            _: &crate::packet::Packet<'_>,
            _: Option<u32>,
        ) -> Result<(), pcap_file::PcapError> {
            unreachable!("the flow streams tap raw bytes")
        }

        fn write_raw(
            &mut self,
            _: &[u8],
            _: Timestamp,
            _: usize,
            _: Option<u32>,
        ) -> Result<(), pcap_file::PcapError> {
            self.0 += 1;
            if self.0 == 2 {
                return Err(pcap_file::PcapError::IoError(std::io::Error::other(
                    "disk full",
                )));
            }
            Ok(())
        }
    }

    /// Three single-datagram UDP flows (source ports 5000, 6000, 7000)
    /// in one drain, behind a `FailStream` tap whose second write fails.
    #[cfg(feature = "pcap")]
    fn flows_with_failing_tap()
    -> FlowStream<crate::async_adapters::flow_source::VecSource, flowscope::extract::FiveTuple>
    {
        use flowscope::extract::parse::test_frames::ipv4_udp;
        let ts = current_timestamp();
        let frames =
            [5000, 6000, 7000].map(|sp| (ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], sp, 53, b"q"), ts));
        let mut flows = FlowStream::new(
            crate::async_adapters::flow_source::VecSource(frames.into()),
            flowscope::extract::FiveTuple::bidirectional(),
        );
        flows.tap = Some(crate::pcap_tap::PcapTap::from_writer(
            Box::new(FailSecondWrite(0)),
            crate::pcap_tap::TapErrorPolicy::FailStream,
        ));
        flows
    }

    /// Everything `s` yields until it ends; panics if it stays open.
    #[cfg(feature = "pcap")]
    async fn until_end<S, T>(s: &mut S) -> Vec<Result<T, Error>>
    where
        S: Stream<Item = Result<T, Error>> + Unpin,
    {
        use futures::StreamExt;
        let mut items = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(1), s.next()).await {
                Ok(Some(item)) => items.push(item),
                Ok(None) => return items,
                Err(_) => panic!("a FailStream tap error must end the stream"),
            }
        }
    }

    /// `TapErrorPolicy::FailStream`: the events of the packets recorded
    /// before the failed write, then the error once, then the end —
    /// nothing about the packets the file is missing.
    #[cfg(feature = "pcap")]
    #[tokio::test(flavor = "current_thread")]
    async fn fail_stream_tap_ends_the_flow_stream() {
        let items = until_end(&mut flows_with_failing_tap()).await;
        let (last, events) = items.split_last().expect("items");
        assert!(matches!(last, Err(Error::Io(_))), "{items:?}");
        assert!(!events.is_empty());
        for ev in events {
            let ev = ev.as_ref().expect("one error, last");
            let key = ev.key().expect("per-flow event");
            assert_eq!(key.a.port().max(key.b.port()), 5000, "{ev:?}");
        }
    }

    /// Same, through the session / datagram / reassembly conversions
    /// (the tap carries over).
    #[cfg(feature = "pcap")]
    #[tokio::test(flavor = "current_thread")]
    async fn fail_stream_tap_ends_every_stream() {
        fn check<T: std::fmt::Debug>(items: Vec<Result<T, Error>>) {
            let (last, events) = items.split_last().expect("items");
            assert!(matches!(last, Err(Error::Io(_))), "{items:?}");
            assert!(events.iter().all(Result::is_ok), "{items:?}");
        }
        check(until_end(&mut flows_with_failing_tap().session_stream(NopParser)).await);
        check(until_end(&mut flows_with_failing_tap().datagram_stream(NopParser)).await);
        check(
            until_end(&mut flows_with_failing_tap().with_async_reassembler(
                crate::async_adapters::async_reassembler::channel_factory(
                    |_: &flowscope::extract::FiveTupleKey, _: flowscope::FlowSide| {
                        tokio::sync::mpsc::channel(1).0
                    },
                ),
            ))
            .await,
        );
    }

    #[test]
    fn clamp_now_passthrough_when_off() {
        let mut state: Option<Timestamp> = None;
        let ts = Timestamp::new(42, 0);
        assert_eq!(clamp_now(ts, &mut state), ts);
        assert!(state.is_none());
    }

    #[test]
    fn clamp_now_clamps_to_running_max() {
        let mut state: Option<Timestamp> = Some(Timestamp::new(100, 0));
        let clamped = clamp_now(Timestamp::new(50, 0), &mut state);
        assert_eq!(clamped, Timestamp::new(100, 0));
        let advanced = clamp_now(Timestamp::new(200, 0), &mut state);
        assert_eq!(advanced, Timestamp::new(200, 0));
        assert_eq!(state, Some(Timestamp::new(200, 0)));
    }
}
