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
pub struct FlowStream<S, E, U = (), R = NoReassembler>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    U: Send + 'static,
{
    cap: AsyncCapture<S>,
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

impl<S, E> FlowStream<S, E, (), NoReassembler>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
{
    pub(crate) fn new(cap: AsyncCapture<S>, extractor: E) -> Self {
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
    pub fn with_state<U, F>(self, init: F) -> FlowStream<S, E, U, NoReassembler>
    where
        U: Send + 'static,
        F: FnMut(&E::Key) -> U + Send + 'static,
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

impl<S, E, U> FlowStream<S, E, U, NoReassembler>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
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
    ) -> FlowStream<S, E, U, AsyncReassemblerSlot<E::Key, F>>
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

impl<S, E> FlowStream<S, E, (), NoReassembler>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
{
    /// Convert into a stream of typed L7 messages. Bytes from each
    /// flow's TCP segments are dispatched to a per-flow
    /// [`flowscope::SessionParser`] built by `factory`; whatever
    /// messages the parser returns are surfaced as
    /// [`flowscope::SessionEvent::Application`].
    ///
    /// The current tracker [`FlowTrackerConfig`] is preserved across
    /// the conversion — `cap.flow_stream(ext).with_config(cfg).session_stream(parser)`
    /// runs the session-level tracker with `cfg`.
    pub fn session_stream<F>(
        self,
        factory: F,
    ) -> crate::async_adapters::session_stream::SessionStream<S, E, F>
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
    ) -> crate::async_adapters::datagram_stream::DatagramStream<S, E, F>
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

impl<S, E, U, R> FlowStream<S, E, U, R>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
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
        F: Fn(&E::Key, Option<flowscope::L4Proto>) -> Option<Duration> + Send + 'static,
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
    /// Mirrors
    /// [`flowscope::FlowTracker::all_flow_stats`].
    pub fn snapshot_flow_stats(
        &self,
    ) -> impl Iterator<Item = (&E::Key, &flowscope::FlowStats)> + '_ {
        self.tracker.all_flow_stats()
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
}

// ── Stream impl: NoReassembler (plan 02 path) ──────────────────────

impl<S, E, U> Stream for FlowStream<S, E, U, NoReassembler>
where
    S: PacketSource + std::os::unix::io::AsRawFd + Unpin,
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

                        // Plan 20: pcap tap — record what the tracker
                        // is about to see. Skip duplicates (above)
                        // so the recorded file matches the tracked
                        // event stream.
                        #[cfg(feature = "pcap")]
                        if let Some(tap) = this.tap.as_mut()
                            && let Some(err) = tap.write_or_handle(&pkt)
                        {
                            tap_error = Some(err);
                            break;
                        }

                        let view = clamp_view(pkt.view(), &mut this.monotonic_ts);
                        let evts: FlowEvents<E::Key> = this.tracker.track(view);
                        for ev in evts {
                            this.pending.push_back(ev);
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
    PacketView::new(view.frame, *last)
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

impl<S, E, U, F> Stream for FlowStream<S, E, U, AsyncReassemblerSlot<E::Key, F>>
where
    S: PacketSource + std::os::unix::io::AsRawFd + Unpin,
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

            // 5. Pull a batch.
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

                        let view = clamp_view(pkt.view(), &mut this.monotonic_ts);
                        let payloads = &mut this.reassembler.pending_payloads;
                        let evts: FlowEvents<E::Key> =
                            this.tracker
                                .track_with_payload(view, |key, side, seq, payload| {
                                    payloads.push_back((
                                        key.clone(),
                                        side,
                                        seq,
                                        Bytes::copy_from_slice(payload),
                                    ));
                                });
                        for ev in evts {
                            this.pending.push_back(ev);
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

/// Approximate "now" using `SystemTime`.
fn current_timestamp() -> Timestamp {
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
    pub fn flow_stream<E>(self, extractor: E) -> FlowStream<S, E, (), NoReassembler>
    where
        E: FlowExtractor,
    {
        FlowStream::new(self, extractor)
    }
}

// ── StreamCapture trait impl ───────────────────────────────────────

use crate::async_adapters::stream_capture::{Sealed, StreamCapture};

impl<S, E, U, R> Sealed for FlowStream<S, E, U, R>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    U: Send + 'static,
{
}

impl<S, E, U, R> StreamCapture for FlowStream<S, E, U, R>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    U: Send + 'static,
{
    type Source = S;

    fn capture(&self) -> &AsyncCapture<S> {
        &self.cap
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
