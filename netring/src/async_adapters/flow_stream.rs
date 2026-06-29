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

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ahash::RandomState;
use bytes::Bytes;
use flowscope::tracker::FlowEvents;
use flowscope::{
    EndReason, FlowEvent, FlowExtractor, FlowSide, FlowTracker, FlowTrackerConfig, PacketView,
    Timestamp,
};
use futures_core::Stream;

use crate::async_adapters::async_reassembler::{AsyncReassembler, AsyncReassemblerFactory};
use crate::async_adapters::flow_source::{AsyncFlowSource, DrainOutcome, SourcePacket};
use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::dedup::Dedup;
use crate::error::Error;
use crate::traits::PacketSource;

/// Marker — no async reassembler attached.
pub struct NoReassembler;

/// Slot holding an [`AsyncReassemblerFactory`] plus per-(flow, side)
/// reassembler instances and the in-flight future.
pub struct AsyncReassemblerSlot<K, F>
where
    K: Eq + std::hash::Hash + Clone + Send + 'static,
    F: AsyncReassemblerFactory<K>,
{
    factory: F,
    instances: HashMap<(K, FlowSide), F::Reassembler, RandomState>,
    /// Buffered (key, side, seq, payload) tuples not yet dispatched.
    ///
    /// `track_with_payload` (sync) populates these inline during
    /// packet processing; the Stream impl drains them by awaiting
    /// each reassembler.segment(...) future before yielding the
    /// corresponding FlowEvent.
    pending_payloads: VecDeque<(K, FlowSide, u32, Bytes)>,
    /// Future currently being awaited, paired with the (key, side)
    /// for `Ended`-on-drop handling. None means "no future in flight".
    pending_future: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
}

/// Stream of [`FlowEvent`]s produced by feeding captured packets
/// through a [`FlowTracker`].
///
/// Generic over the packet source `C` (issue #104): an
/// [`AsyncCapture`] (AF_PACKET) or an
/// [`AsyncXdpCapture`](crate::AsyncXdpCapture) (AF_XDP). Both drive the same
/// tracking loop via the `AsyncFlowSource` trait.
pub struct FlowStream<C, E, U = (), R = NoReassembler>
where
    E: FlowExtractor,
    U: Send + 'static,
{
    cap: C,
    tracker: FlowTracker<E, U>,
    pending: VecDeque<FlowEvent<E::Key>>,
    sweep: tokio::time::Interval,
    reassembler: R,
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
}

impl<C, E> FlowStream<C, E, (), NoReassembler>
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
            sweep: tokio::time::interval(sweep_interval),
            reassembler: NoReassembler,
            dedup: None,
            monotonic_ts: None,
            #[cfg(feature = "pcap")]
            tap: None,
        }
    }

    /// Attach per-flow user state.
    pub fn with_state<U, F>(self, init: F) -> FlowStream<C, E, U, NoReassembler>
    where
        U: Send + 'static,
        F: FnMut(&E::Key) -> U + Send + Sync + 'static,
    {
        let config = self.tracker.config().clone();
        let extractor = self.tracker.into_extractor();
        FlowStream {
            cap: self.cap,
            tracker: FlowTracker::with_config_and_state(extractor, config, init),
            pending: VecDeque::new(),
            sweep: self.sweep,
            reassembler: NoReassembler,
            dedup: self.dedup,
            monotonic_ts: self.monotonic_ts,
            #[cfg(feature = "pcap")]
            tap: self.tap,
        }
    }
}

impl<C, E, U> FlowStream<C, E, U, NoReassembler>
where
    E: FlowExtractor,
    U: Send + 'static,
{
    /// Attach an async reassembler factory. On every TCP packet
    /// with a non-empty payload, the appropriate reassembler's
    /// `segment` future is awaited inline before the next event is
    /// yielded — backpressure flows from the consumer all the way
    /// back to the kernel ring.
    pub fn with_async_reassembler<F>(
        self,
        factory: F,
    ) -> FlowStream<C, E, U, AsyncReassemblerSlot<E::Key, F>>
    where
        F: AsyncReassemblerFactory<E::Key>,
    {
        FlowStream {
            cap: self.cap,
            tracker: self.tracker,
            pending: self.pending,
            sweep: self.sweep,
            reassembler: AsyncReassemblerSlot {
                factory,
                instances: HashMap::with_hasher(RandomState::new()),
                pending_payloads: VecDeque::new(),
                pending_future: None,
            },
            dedup: self.dedup,
            monotonic_ts: self.monotonic_ts,
            #[cfg(feature = "pcap")]
            tap: self.tap,
        }
    }
}

// L7 conversions are generic over the source `C` (issue #104): the
// `SessionStream` / `DatagramStream` they build are now source-agnostic, so
// AF_XDP (`AsyncXdpCapture`) gets `.session_stream()` / `.datagram_stream()`
// for free — same as AF_PACKET.
impl<C, E> FlowStream<C, E, (), NoReassembler>
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
            self.dedup,
            self.monotonic_ts,
            #[cfg(feature = "pcap")]
            self.tap,
        )
    }
}

impl<C, E, U, R> FlowStream<C, E, U, R>
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
        self.sweep = tokio::time::interval(new_interval);
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
        self.tracker.set_idle_timeout_fn(f);
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

    /// Borrow-iterator over live `(K, FlowStats)` pairs. Patches in
    /// reassembler high-watermark diagnostics. Lazy — pay only for
    /// what you consume.
    ///
    /// Built on
    /// [`flowscope::FlowTracker::iter_active`] (flowscope 0.8+);
    /// projects to the historical `(key, stats)` shape for
    /// callers that don't need per-flow user state, TCP state,
    /// or L4 protocol. New callers should reach
    /// `self.tracker().iter_active()` directly for the richer
    /// `ActiveFlow` shape.
    pub fn snapshot_flow_stats(
        &self,
    ) -> impl Iterator<Item = (&E::Key, &flowscope::FlowStats)> + '_ {
        self.tracker.iter_active().map(|af| (af.key, af.stats))
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

// ── Stream impl: NoReassembler (plan 02 path) ──────────────────────

impl<C, E, U> Stream for FlowStream<C, E, U, NoReassembler>
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

            if this.sweep.poll_tick(cx).is_ready() {
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
            #[cfg(feature = "pcap")]
            let mut tap_error: Option<Error> = None;

            let outcome = cap.poll_drain(cx, &mut |sp: SourcePacket<'_>| {
                // Plan 17: optional pre-tracking dedup (on the unclamped ts).
                if let Some(d) = dedup.as_mut()
                    && !d.keep_raw(sp.data, sp.direction, sp.view.timestamp)
                {
                    return;
                }

                // Plan 20: pcap tap — record what the tracker is about to
                // see, skipping duplicates so the file matches the events.
                #[cfg(feature = "pcap")]
                if let Some(t) = tap.as_mut() {
                    if tap_error.is_some() {
                        return;
                    }
                    if let Some(err) =
                        t.write_raw_or_handle(sp.data, sp.view.timestamp, sp.original_len)
                    {
                        tap_error = Some(err);
                        return;
                    }
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
                Poll::Ready(Ok(DrainOutcome::Drained)) =>
                {
                    #[cfg(feature = "pcap")]
                    if let Some(err) = tap_error {
                        return Poll::Ready(Some(Err(err)));
                    }
                }
                Poll::Ready(Ok(DrainOutcome::Idle)) => {}
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
    // Preserve the per-packet capture leg across the monotonic-clamp
    // rebuild (flowscope 0.20 #69 builder) so a shared/merged tracker
    // can bind `FlowStats::source_idx_{forward,reverse}` (#120).
    // Previously the rebuilt view defaulted `RxMetadata`, zeroing
    // `source_idx` — the blocker #105 called out.
    PacketView::new(view.frame, *last).with_source_idx(view.rx_metadata.source_idx)
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

// ── Stream impl: AsyncReassemblerSlot path ─────────────────────────

impl<C, E, U, F> Stream for FlowStream<C, E, U, AsyncReassemblerSlot<E::Key, F>>
where
    C: AsyncFlowSource + Unpin,
    E: FlowExtractor + Unpin,
    E::Key: Clone + Unpin,
    U: Send + 'static + Unpin,
    F: AsyncReassemblerFactory<E::Key> + Unpin,
    F::Reassembler: Unpin,
{
    type Item = Result<FlowEvent<E::Key>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            // 1. Drive any in-flight reassembler future to completion.
            if let Some(fut) = this.reassembler.pending_future.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.reassembler.pending_future = None;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            // 2. Drain queued payloads — kick off the next future.
            if let Some((key, side, seq, payload)) = this.reassembler.pending_payloads.pop_front() {
                let r = this
                    .reassembler
                    .instances
                    .entry((key.clone(), side))
                    .or_insert_with(|| this.reassembler.factory.new_reassembler(&key, side));
                let fut = r.segment(seq, payload);
                this.reassembler.pending_future = Some(fut);
                continue;
            }

            // 3. Drain pending events.
            if let Some(evt) = this.pending.pop_front() {
                // On Ended, kick off fin/rst on the side's reassembler
                // (drops it after the future completes). We do at most
                // one fin/rst per re-entry; remaining sides are handled
                // on subsequent loop iterations because the event is
                // pushed back in front.
                if let FlowEvent::Ended { key, reason, .. } = &evt {
                    let reason_copy = *reason;
                    let key_copy = key.clone();
                    let mut found_fut = None;
                    for side in [FlowSide::Initiator, FlowSide::Responder] {
                        if let Some(mut r) =
                            this.reassembler.instances.remove(&(key_copy.clone(), side))
                        {
                            let fut = match reason_copy {
                                EndReason::Fin | EndReason::IdleTimeout => r.fin(),
                                EndReason::Rst
                                | EndReason::Evicted
                                | EndReason::BufferOverflow
                                | EndReason::ParseError => r.rst(),
                                _ => r.rst(),
                            };
                            drop(r);
                            found_fut = Some(fut);
                            break;
                        }
                    }
                    if let Some(fut) = found_fut {
                        this.pending.push_front(evt);
                        this.reassembler.pending_future = Some(fut);
                        continue;
                    }
                }
                return Poll::Ready(Some(Ok(evt)));
            }

            // 4. Sweep tick.
            if this.sweep.poll_tick(cx).is_ready() {
                let now = clamp_now(current_timestamp(), &mut this.monotonic_ts);
                for ev in this.tracker.sweep(now) {
                    this.pending.push_back(ev);
                }
                if !this.pending.is_empty() {
                    continue;
                }
            }

            // 5. Pull a batch through the source-agnostic drain.
            let cap = &mut this.cap;
            let tracker = &mut this.tracker;
            let pending = &mut this.pending;
            let dedup = &mut this.dedup;
            let monotonic_ts = &mut this.monotonic_ts;
            let reassembler = &mut this.reassembler;
            #[cfg(feature = "pcap")]
            let tap = &mut this.tap;
            #[cfg(feature = "pcap")]
            let mut tap_error: Option<Error> = None;

            let outcome = cap.poll_drain(cx, &mut |sp: SourcePacket<'_>| {
                // Plan 17: optional pre-tracking dedup (on the unclamped ts).
                if let Some(d) = dedup.as_mut()
                    && !d.keep_raw(sp.data, sp.direction, sp.view.timestamp)
                {
                    return;
                }

                // Plan 20: pcap tap.
                #[cfg(feature = "pcap")]
                if let Some(t) = tap.as_mut() {
                    if tap_error.is_some() {
                        return;
                    }
                    if let Some(err) =
                        t.write_raw_or_handle(sp.data, sp.view.timestamp, sp.original_len)
                    {
                        tap_error = Some(err);
                        return;
                    }
                }

                let view = clamp_view(sp.view, monotonic_ts);
                let payloads = &mut reassembler.pending_payloads;
                let evts: FlowEvents<E::Key> =
                    tracker.track_with_payload(view, |key, side, seq, payload| {
                        payloads.push_back((
                            key.clone(),
                            side,
                            seq,
                            Bytes::copy_from_slice(payload),
                        ));
                    });
                for ev in evts {
                    pending.push_back(ev);
                }
            });

            match outcome {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(Error::Io(e)))),
                Poll::Ready(Ok(DrainOutcome::Drained)) =>
                {
                    #[cfg(feature = "pcap")]
                    if let Some(err) = tap_error {
                        return Poll::Ready(Some(Err(err)));
                    }
                }
                Poll::Ready(Ok(DrainOutcome::Idle)) => {}
            }
        }
    }
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
    pub fn flow_stream<E>(self, extractor: E) -> FlowStream<AsyncCapture<S>, E, (), NoReassembler>
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
    pub fn flow_stream<E>(
        self,
        extractor: E,
    ) -> FlowStream<crate::AsyncXdpCapture, E, (), NoReassembler>
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
impl<E, U, R> FlowStream<crate::AsyncXdpCapture, E, U, R>
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

// ── StreamCapture trait impl ───────────────────────────────────────
//
// Restricted to the AF_PACKET source: `StreamCapture::capture()` returns a
// concrete `&AsyncCapture<S>`, which the AF_XDP source has no analogue for.

use crate::async_adapters::stream_capture::{Sealed, StreamCapture};

impl<S, E, U, R> Sealed for FlowStream<AsyncCapture<S>, E, U, R>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    U: Send + 'static,
{
}

impl<S, E, U, R> StreamCapture for FlowStream<AsyncCapture<S>, E, U, R>
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
mod monotonic_tests {
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
