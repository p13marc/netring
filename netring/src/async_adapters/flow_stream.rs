//! [`FlowStream`] — `futures_core::Stream` of [`FlowEvent`]s built on
//! top of [`AsyncCapture`] and [`netring_flow::FlowTracker`].
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
use futures_core::Stream;
use netring_flow::tracker::FlowEvents;
use netring_flow::{
    EndReason, FlowEvent, FlowExtractor, FlowSide, FlowTracker, FlowTrackerConfig, Timestamp,
};

use crate::async_adapters::async_reassembler::{AsyncReassembler, AsyncReassemblerFactory};
use crate::async_adapters::tokio_adapter::AsyncCapture;
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
    /// [`netring_flow::SessionParser`] built by `factory`; whatever
    /// messages the parser returns are surfaced as
    /// [`netring_flow::SessionEvent::Application`].
    pub fn session_stream<F>(
        self,
        factory: F,
    ) -> crate::async_adapters::session_stream::SessionStream<S, E, F>
    where
        F: netring_flow::SessionParserFactory<E::Key>,
    {
        let extractor = self.tracker.into_extractor();
        crate::async_adapters::session_stream::SessionStream::new(self.cap, extractor, factory)
    }

    /// Convert into a stream of typed L7 messages from packet-oriented
    /// (UDP) protocols. Each UDP payload is fed to a per-flow
    /// [`netring_flow::DatagramParser`].
    pub fn datagram_stream<F>(
        self,
        factory: F,
    ) -> crate::async_adapters::datagram_stream::DatagramStream<S, E, F>
    where
        F: netring_flow::DatagramParserFactory<E::Key>,
    {
        let extractor = self.tracker.into_extractor();
        crate::async_adapters::datagram_stream::DatagramStream::new(self.cap, extractor, factory)
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

    /// Borrow the inner tracker (for stats / introspection).
    pub fn tracker(&self) -> &FlowTracker<E, U> {
        &self.tracker
    }

    /// Borrow the inner tracker mutably (for poking user state).
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, U> {
        &mut self.tracker
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
                let now = current_timestamp();
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
                    for pkt in &batch {
                        let view = pkt.view();
                        let evts: FlowEvents<E::Key> = this.tracker.track(view);
                        for ev in evts {
                            this.pending.push_back(ev);
                        }
                    }
                    drop(batch);
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
                                EndReason::Rst | EndReason::Evicted => r.rst(),
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
                let now = current_timestamp();
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
                    for pkt in &batch {
                        let view = pkt.view();
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
