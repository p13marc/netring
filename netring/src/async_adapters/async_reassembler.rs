//! Async consumers of reassembled TCP byte streams:
//! [`FlowStream::with_async_reassembler`](crate::FlowStream::with_async_reassembler)
//! turns a flow stream into a [`ReassemblyStream`].
//!
//! The stream runs flowscope's [`FlowDriver`] with its default
//! out-of-order reassembler — the same reassembly the session engines
//! use: out-of-order segments are held (bounded by
//! [`FlowTrackerConfig::reassembly_ooo_buffer`]) until the hole fills,
//! retransmissions are dropped, and a hole that never fills is skipped
//! and reported. Each flow side gets an [`AsyncReassembler`] from your
//! factory, which receives
//!
//! - [`data`](AsyncReassembler::data): the next in-order bytes;
//! - [`gap`](AsyncReassembler::gap): this many bytes never arrived
//!   (capture loss, or a segment the peer ACKed that we never saw);
//! - [`close`](AsyncReassembler::close): once, when the flow ends (its
//!   [`EndReason`]) or when reassembly of the side stops
//!   ([`EndReason::BufferOverflow`] — per-side cap or memcap). No call
//!   follows.
//!
//! Every future is awaited inside `poll_next` before the stream moves
//! on, so a slow consumer backpressures the whole pipeline, down to the
//! kernel ring. For "give me each flow's bytes" without writing a
//! factory, see [`Conversation`](crate::Conversation).
//!
//! Before 0.31 the "reassembler" was handed raw segments in arrival
//! order — retransmissions twice, reordered segments out of order,
//! losses silently — and `fin`/`rst` without the real end reason.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ahash::RandomState;
use bytes::Bytes;
use flowscope::{
    Chunk, EndReason, EventMask, FlowDriver, FlowEvent, FlowExtractor, FlowSide, FlowStats,
    FlowTracker, FlowTrackerConfig, SegmentBufferReassemblerFactory, StreamChunks, Timestamp,
};
use futures_core::Stream;
use tokio::sync::mpsc;

use crate::async_adapters::flow_source::{AsyncFlowSource, DrainOutcome, SourcePacket};
use crate::async_adapters::flow_stream::{clamp_now, clamp_view, current_timestamp};
use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::dedup::Dedup;
use crate::error::Error;
use crate::traits::PacketSource;

/// The future an [`AsyncReassembler`] method returns.
pub type ConsumerFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

fn ready() -> ConsumerFuture {
    Box::pin(std::future::ready(()))
}

/// Consumes the reassembled bytes of one direction of one TCP flow.
///
/// Methods take `&mut self` but return a `'static` future: move or
/// clone what the future needs (the stream stores it while it is
/// pending). Each future completes before the next call.
pub trait AsyncReassembler: Send + 'static {
    /// The next in-order bytes of this side.
    fn data(&mut self, bytes: Bytes) -> ConsumerFuture;

    /// `len` bytes of this side never arrived; the next
    /// [`data`](Self::data) starts after them. Default: ignored.
    fn gap(&mut self, len: u64) -> ConsumerFuture {
        let _ = len;
        ready()
    }

    /// The side is finished: the flow ended with `reason`, or
    /// reassembly of this side stopped
    /// ([`EndReason::BufferOverflow`]). Called at most once; the
    /// reassembler is dropped after its future completes. Not called
    /// when the stream itself is dropped. Default: nothing.
    fn close(&mut self, reason: EndReason) -> ConsumerFuture {
        let _ = reason;
        ready()
    }
}

/// Builds an [`AsyncReassembler`] for a flow side, on its first data
/// (or gap).
pub trait AsyncReassemblerFactory<K>: Send + 'static {
    /// The per-side consumer.
    type Reassembler: AsyncReassembler;

    /// A consumer for `side` of the flow `key`.
    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> Self::Reassembler;

    /// The flow `key` ended; both sides' consumers (if any) were
    /// closed. Release per-flow bookkeeping here. Default: nothing.
    fn flow_ended(&mut self, key: &K) {
        let _ = key;
    }
}

/// One item of a [`channel_factory`] stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReassembledChunk {
    /// The next in-order bytes.
    Data(Bytes),
    /// This many bytes never arrived.
    Gap(u64),
}

/// Common pattern: spawn a tokio task per (flow, side) and feed it
/// through an mpsc channel, with backpressure.
///
/// `make_sender` returns a `Sender<ReassembledChunk>` for each new
/// (flow, side). The sender is dropped when the side is closed, so the
/// task's `recv()` returns `None` (use a custom [`AsyncReassembler`]
/// to learn the [`EndReason`]).
///
/// Each spawned task must keep receiving: a full channel pauses the
/// whole stream until it drains.
///
/// # Example
///
/// ```no_run
/// use tokio::sync::mpsc;
/// use netring::AsyncCapture;
/// use netring::flow::extract::{FiveTuple, FiveTupleKey};
/// use netring::async_adapters::async_reassembler::{channel_factory, ReassembledChunk};
/// use futures::StreamExt;
///
/// # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
/// let cap = AsyncCapture::open("eth0")?;
/// let mut stream = cap
///     .flow_stream(FiveTuple::bidirectional())
///     .with_async_reassembler(channel_factory(|_key: &FiveTupleKey, _side| {
///         let (tx, mut rx) = mpsc::channel::<ReassembledChunk>(64);
///         tokio::spawn(async move {
///             while let Some(chunk) = rx.recv().await {
///                 match chunk {
///                     ReassembledChunk::Data(_bytes) => {}
///                     ReassembledChunk::Gap(_missing) => {}
///                     _ => {}
///                 }
///             }
///         });
///         tx
///     }));
/// // Driving the stream is what feeds the tasks.
/// while let Some(evt) = stream.next().await {
///     let _ = evt?;
/// }
/// # Ok(()) }
/// ```
pub fn channel_factory<K, F>(make_sender: F) -> ChannelFactory<K, F>
where
    F: FnMut(&K, FlowSide) -> mpsc::Sender<ReassembledChunk> + Send + 'static,
    K: Clone + Send + 'static,
{
    ChannelFactory {
        make_sender,
        _phantom: std::marker::PhantomData,
    }
}

/// Adapter built by [`channel_factory`].
pub struct ChannelFactory<K, F> {
    make_sender: F,
    _phantom: std::marker::PhantomData<fn(&K)>,
}

impl<K, F> AsyncReassemblerFactory<K> for ChannelFactory<K, F>
where
    F: FnMut(&K, FlowSide) -> mpsc::Sender<ReassembledChunk> + Send + 'static,
    K: Clone + Send + 'static,
{
    type Reassembler = ChannelReassembler;

    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> ChannelReassembler {
        ChannelReassembler {
            tx: Some((self.make_sender)(key, side)),
        }
    }
}

/// [`AsyncReassembler`] that forwards into an
/// `mpsc::Sender<ReassembledChunk>` (awaiting capacity) and drops the
/// sender on close. A closed receiver just discards.
pub struct ChannelReassembler {
    tx: Option<mpsc::Sender<ReassembledChunk>>,
}

impl ChannelReassembler {
    fn send(&self, chunk: ReassembledChunk) -> ConsumerFuture {
        let tx = self.tx.clone();
        Box::pin(async move {
            if let Some(tx) = tx {
                let _ = tx.send(chunk).await;
            }
        })
    }
}

impl AsyncReassembler for ChannelReassembler {
    fn data(&mut self, bytes: Bytes) -> ConsumerFuture {
        self.send(ReassembledChunk::Data(bytes))
    }

    fn gap(&mut self, len: u64) -> ConsumerFuture {
        self.send(ReassembledChunk::Gap(len))
    }

    fn close(&mut self, _reason: EndReason) -> ConsumerFuture {
        self.tx = None;
        ready()
    }
}

// ── ReassemblyStream ────────────────────────────────────────────────

/// Work queued by packet processing, delivered in order by `poll_next`.
// Events dominate the size; boxing them would allocate per event.
#[allow(clippy::large_enum_variant)]
enum Item<K> {
    Event(FlowEvent<K>),
    Data(K, FlowSide, Bytes),
    Gap(K, FlowSide, u64),
    Close(K, FlowSide, EndReason),
    FlowEnded(K),
}

/// Stream of [`FlowEvent`]s that also feeds each TCP flow side's
/// reassembled bytes to an [`AsyncReassembler`]. Built by
/// [`FlowStream::with_async_reassembler`](crate::FlowStream::with_async_reassembler);
/// see the [module docs](self).
///
/// The per-side bytes of a packet are delivered after that packet's
/// lifecycle events and before its flow's `Ended`. `Ended` is always
/// processed (consumers are closed) even when
/// [`FlowTrackerConfig::suppress_events`] hides it from the stream.
pub struct ReassemblyStream<C, E, U, F>
where
    E: FlowExtractor,
    E::Key: Eq + Hash + Clone + Send + 'static,
    U: Send + 'static,
    F: AsyncReassemblerFactory<E::Key>,
{
    cap: C,
    driver: FlowDriver<E, SegmentBufferReassemblerFactory, U>,
    factory: F,
    instances: HashMap<(E::Key, FlowSide), F::Reassembler, RandomState>,
    queue: VecDeque<Item<E::Key>>,
    in_flight: Option<ConsumerFuture>,
    scratch: StreamChunks,
    sweep: tokio::time::Interval,
    /// `false` when the caller's config suppresses `Ended`.
    yield_ended: bool,
    dedup: Option<Dedup>,
    monotonic_ts: Option<Timestamp>,
    #[cfg(feature = "pcap")]
    tap: Option<crate::pcap_tap::PcapTap>,
}

impl<C, E, U, F> ReassemblyStream<C, E, U, F>
where
    E: FlowExtractor,
    E::Key: Eq + Hash + Clone + Send + 'static,
    U: Send + 'static,
    F: AsyncReassemblerFactory<E::Key>,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        cap: C,
        tracker: FlowTracker<E, U>,
        factory: F,
        pending: VecDeque<FlowEvent<E::Key>>,
        dedup: Option<Dedup>,
        monotonic_ts: Option<Timestamp>,
        #[cfg(feature = "pcap")] tap: Option<crate::pcap_tap::PcapTap>,
    ) -> Self {
        let config = tracker.config().clone();
        let mut this = Self {
            cap,
            driver: FlowDriver::from_tracker(tracker, SegmentBufferReassemblerFactory::default()),
            factory,
            instances: HashMap::with_hasher(RandomState::new()),
            queue: pending.into_iter().map(Item::Event).collect(),
            in_flight: None,
            scratch: StreamChunks::new(),
            sweep: tokio::time::interval(config.sweep_interval),
            yield_ended: true,
            dedup,
            monotonic_ts,
            #[cfg(feature = "pcap")]
            tap,
        };
        this.apply_config(config);
        this
    }

    /// The driver must see every `Ended` to close consumers; the
    /// caller's `ENDED` suppression applies to the output only.
    fn apply_config(&mut self, mut config: FlowTrackerConfig) {
        self.yield_ended = !config.suppress_events.contains(EventMask::ENDED);
        config.suppress_events.remove(EventMask::ENDED);
        self.sweep = tokio::time::interval(config.sweep_interval);
        self.driver.set_config(config);
    }

    /// Replace the config (flow table and reassembly limits) in place.
    /// New flow sides pick up the new reassembly limits.
    pub fn with_config(mut self, config: FlowTrackerConfig) -> Self {
        self.apply_config(config);
        self
    }

    /// Also yield [`FlowEvent::FlowAnomaly`] / [`FlowEvent::TrackerAnomaly`]
    /// (gaps, retransmit inconsistencies, out-of-window segments,
    /// overflow, memcap, eviction pressure). Default: off.
    pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
        self.driver.set_emit_anomalies(enable);
        self
    }

    /// Apply per-packet deduplication before tracking (replaces any
    /// previous one).
    pub fn with_dedup(mut self, dedup: Dedup) -> Self {
        self.dedup = Some(dedup);
        self
    }

    /// The dedup set with [`with_dedup`](Self::with_dedup), if any.
    pub fn dedup(&self) -> Option<&Dedup> {
        self.dedup.as_ref()
    }

    /// Mutable access to the dedup (counters).
    pub fn dedup_mut(&mut self) -> Option<&mut Dedup> {
        self.dedup.as_mut()
    }

    /// Clamp packet timestamps to a running max (also the sweep's
    /// `now`). Default: off.
    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.monotonic_ts = enable.then(Timestamp::default);
        self
    }

    /// Override the per-flow idle timeout by key (see
    /// [`FlowStream::with_idle_timeout_fn`](crate::FlowStream::with_idle_timeout_fn)).
    pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
    where
        G: Fn(&E::Key, Option<flowscope::L4Proto>) -> Option<Duration> + Send + Sync + 'static,
    {
        self.driver = self.driver.with_idle_timeout_fn(f);
        self
    }

    /// The flow tracker (stats, per-flow state, introspection).
    pub fn tracker(&self) -> &FlowTracker<E, U> {
        self.driver.tracker()
    }

    /// Live `(key, stats)` pairs, including reassembly diagnostics
    /// (gaps, retransmits, out-of-order peak, …).
    pub fn snapshot_flow_stats(&self) -> impl Iterator<Item = (E::Key, FlowStats)> + '_ {
        self.driver.snapshot_flow_stats()
    }

    /// Cumulative tracker counters.
    pub fn tracker_stats(&self) -> &flowscope::FlowTrackerStats {
        self.driver.tracker().stats()
    }

    /// Bytes currently held by the reassemblers (out-of-order data
    /// waiting for a hole to fill).
    pub fn buffered_bytes(&self) -> u64 {
        self.driver.reassembly_memcap_bytes()
    }

    /// Tap every captured packet into `writer` before tracking.
    #[cfg(feature = "pcap")]
    pub fn with_pcap_tap<W>(self, writer: crate::pcap::CaptureWriter<W>) -> Self
    where
        W: std::io::Write + Send + 'static,
    {
        self.with_pcap_tap_policy(writer, crate::pcap_tap::TapErrorPolicy::default())
    }

    /// [`with_pcap_tap`](Self::with_pcap_tap) with an explicit error policy.
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

/// Queue a drained side's output: data, gaps, then a close if the
/// side stopped.
fn push_chunks<K: Clone>(
    queue: &mut VecDeque<Item<K>>,
    key: &K,
    side: FlowSide,
    chunks: &StreamChunks,
) {
    for chunk in chunks.iter() {
        queue.push_back(match chunk {
            Chunk::Data(b) => Item::Data(key.clone(), side, Bytes::copy_from_slice(b)),
            Chunk::Gap(n) => Item::Gap(key.clone(), side, n),
        });
    }
    if chunks.stop().is_some() {
        queue.push_back(Item::Close(key.clone(), side, EndReason::BufferOverflow));
    }
}

/// Queue the output of a `track_pending` / `sweep_pending*` call:
/// events in order, the tracked packet's flow data before the first
/// `Ended` (or after the events), and for each `Ended` its flushed
/// data, the closes and the end — then finalize the flow.
fn absorb<E, U, K>(
    driver: &mut FlowDriver<E, SegmentBufferReassemblerFactory, U>,
    events: impl IntoIterator<Item = FlowEvent<K>>,
    mut packet_flow: Option<K>,
    queue: &mut VecDeque<Item<K>>,
    scratch: &mut StreamChunks,
    yield_ended: bool,
) where
    E: FlowExtractor<Key = K>,
    K: Eq + Hash + Clone + Send + 'static,
    U: Send + 'static,
{
    let mut drain_flow = |driver: &mut FlowDriver<E, SegmentBufferReassemblerFactory, U>,
                          queue: &mut VecDeque<Item<K>>,
                          key: &K| {
        for side in [FlowSide::Initiator, FlowSide::Responder] {
            scratch.clear();
            if driver.drain_stream(key, side, scratch) {
                push_chunks(queue, key, side, scratch);
            }
        }
    };
    for ev in events {
        if let FlowEvent::Ended { key, reason, .. } = &ev {
            if let Some(k) = packet_flow.take() {
                drain_flow(driver, queue, &k);
            }
            let (key, reason) = (key.clone(), *reason);
            drain_flow(driver, queue, &key);
            for side in [FlowSide::Initiator, FlowSide::Responder] {
                queue.push_back(Item::Close(key.clone(), side, reason));
            }
            queue.push_back(Item::FlowEnded(key.clone()));
            driver.finalize_flow(&key, reason);
            if !yield_ended {
                continue;
            }
        }
        queue.push_back(Item::Event(ev));
    }
    if let Some(k) = packet_flow {
        drain_flow(driver, queue, &k);
    }
}

impl<C, E, U, F> Stream for ReassemblyStream<C, E, U, F>
where
    C: AsyncFlowSource + Unpin,
    E: FlowExtractor + Unpin,
    E::Key: Eq + Hash + Clone + Send + Unpin + 'static,
    U: Send + 'static + Unpin,
    F: AsyncReassemblerFactory<E::Key> + Unpin,
    F::Reassembler: Unpin,
{
    type Item = Result<FlowEvent<E::Key>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            // 1. Finish the consumer call in flight.
            if let Some(fut) = this.in_flight.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(()) => this.in_flight = None,
                    Poll::Pending => return Poll::Pending,
                }
            }

            // 2. Deliver queued work in order.
            if let Some(item) = this.queue.pop_front() {
                match item {
                    Item::Event(ev) => return Poll::Ready(Some(Ok(ev))),
                    Item::Data(key, side, bytes) => {
                        let factory = &mut this.factory;
                        let r = this
                            .instances
                            .entry((key.clone(), side))
                            .or_insert_with(|| factory.new_reassembler(&key, side));
                        this.in_flight = Some(r.data(bytes));
                    }
                    Item::Gap(key, side, len) => {
                        let factory = &mut this.factory;
                        let r = this
                            .instances
                            .entry((key.clone(), side))
                            .or_insert_with(|| factory.new_reassembler(&key, side));
                        this.in_flight = Some(r.gap(len));
                    }
                    Item::Close(key, side, reason) => {
                        if let Some(mut r) = this.instances.remove(&(key, side)) {
                            this.in_flight = Some(r.close(reason));
                        }
                    }
                    Item::FlowEnded(key) => this.factory.flow_ended(&key),
                }
                continue;
            }

            // 3. Periodic sweep: idle flows end, expired holes release.
            if this.sweep.poll_tick(cx).is_ready() {
                let now = clamp_now(current_timestamp(), &mut this.monotonic_ts);
                let queue = &mut this.queue;
                let events =
                    this.driver
                        .sweep_pending_drain(now, &mut this.scratch, |key, side, chunks| {
                            push_chunks(queue, key, side, chunks)
                        });
                absorb(
                    &mut this.driver,
                    events,
                    None,
                    &mut this.queue,
                    &mut this.scratch,
                    this.yield_ended,
                );
                if !this.queue.is_empty() {
                    continue;
                }
            }

            // 4. Pull packets.
            let cap = &mut this.cap;
            let driver = &mut this.driver;
            let queue = &mut this.queue;
            let scratch = &mut this.scratch;
            let yield_ended = this.yield_ended;
            let dedup = &mut this.dedup;
            let monotonic_ts = &mut this.monotonic_ts;
            #[cfg(feature = "pcap")]
            let tap = &mut this.tap;
            #[cfg(feature = "pcap")]
            let mut tap_error: Option<Error> = None;

            let outcome = cap.poll_drain(cx, &mut |sp: SourcePacket<'_>| {
                if let Some(d) = dedup.as_mut()
                    && !d.keep_raw(sp.data, sp.direction, sp.view.timestamp)
                {
                    return;
                }
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
                let events = driver.track_pending(view);
                let packet_flow = driver.last_packet().map(|p| p.key.clone());
                absorb(driver, events, packet_flow, queue, scratch, yield_ended);
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

// ── StreamCapture (AF_PACKET source) ────────────────────────────────

use crate::async_adapters::stream_capture::{Sealed, StreamCapture};

impl<S, E, U, F> Sealed for ReassemblyStream<AsyncCapture<S>, E, U, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + Hash + Clone + Send + 'static,
    U: Send + 'static,
    F: AsyncReassemblerFactory<E::Key>,
{
}

impl<S, E, U, F> StreamCapture for ReassemblyStream<AsyncCapture<S>, E, U, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + Hash + Clone + Send + 'static,
    U: Send + 'static,
    F: AsyncReassemblerFactory<E::Key>,
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
pub(crate) mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use flowscope::extract::FiveTuple;
    use flowscope::extract::parse::test_frames::ipv4_tcp;
    use futures::StreamExt;

    use crate::async_adapters::flow_source::VecSource;

    type Log = Arc<Mutex<Vec<String>>>;

    struct Recorder(Log);
    struct SideRecorder(Log, FlowSide);

    impl AsyncReassemblerFactory<flowscope::extract::FiveTupleKey> for Recorder {
        type Reassembler = SideRecorder;
        fn new_reassembler(
            &mut self,
            _key: &flowscope::extract::FiveTupleKey,
            side: FlowSide,
        ) -> SideRecorder {
            SideRecorder(Arc::clone(&self.0), side)
        }
        fn flow_ended(&mut self, _key: &flowscope::extract::FiveTupleKey) {
            self.0.lock().unwrap().push("ended".into());
        }
    }

    impl SideRecorder {
        fn log(&self, what: String) -> ConsumerFuture {
            let side = match self.1 {
                FlowSide::Initiator => "I",
                FlowSide::Responder => "R",
            };
            self.0.lock().unwrap().push(format!("{side} {what}"));
            ready()
        }
    }

    impl AsyncReassembler for SideRecorder {
        fn data(&mut self, bytes: Bytes) -> ConsumerFuture {
            self.log(format!("data {}", String::from_utf8_lossy(&bytes)))
        }
        fn gap(&mut self, len: u64) -> ConsumerFuture {
            self.log(format!("gap {len}"))
        }
        fn close(&mut self, reason: EndReason) -> ConsumerFuture {
            self.log(format!("close {reason:?}"))
        }
    }

    /// Client segments as `(offset, bytes)` after the handshake, a
    /// server reply, then the FIN exchange.
    pub(crate) fn flow(client: &[(u32, &[u8])], client_len: u32) -> VecDeque<(Vec<u8>, Timestamp)> {
        let (c, s, m) = ([10, 0, 0, 1], [10, 0, 0, 2], [0u8; 6]);
        let (ci, si) = (100u32, 900u32);
        let mut v = vec![
            ipv4_tcp(m, m, c, s, 40000, 80, ci, 0, 0x02, b""),
            ipv4_tcp(m, m, s, c, 80, 40000, si, ci + 1, 0x12, b""),
            ipv4_tcp(m, m, c, s, 40000, 80, ci + 1, si + 1, 0x10, b""),
        ];
        for (off, b) in client {
            v.push(ipv4_tcp(
                m,
                m,
                c,
                s,
                40000,
                80,
                ci + 1 + off,
                si + 1,
                0x18,
                b,
            ));
        }
        let cend = ci + 1 + client_len;
        v.push(ipv4_tcp(m, m, s, c, 80, 40000, si + 1, cend, 0x18, b"OK"));
        v.push(ipv4_tcp(m, m, c, s, 40000, 80, cend, si + 3, 0x11, b""));
        v.push(ipv4_tcp(m, m, s, c, 80, 40000, si + 3, cend + 1, 0x11, b""));
        v.push(ipv4_tcp(m, m, c, s, 40000, 80, cend + 1, si + 4, 0x10, b""));
        let base = current_timestamp();
        v.into_iter()
            .enumerate()
            .map(|(i, f)| {
                let us = base.to_duration().as_micros() as u64 + i as u64 * 100;
                (
                    f,
                    Timestamp::new((us / 1_000_000) as u32, (us % 1_000_000) as u32 * 1000),
                )
            })
            .collect()
    }

    async fn run(frames: VecDeque<(Vec<u8>, Timestamp)>) -> (Vec<String>, Vec<EndReason>) {
        let log: Log = Arc::default();
        let tracker: FlowTracker<_, ()> = FlowTracker::new(FiveTuple::bidirectional());
        let mut stream = ReassemblyStream::from_parts(
            VecSource(frames),
            tracker,
            Recorder(Arc::clone(&log)),
            VecDeque::new(),
            None,
            None,
            #[cfg(feature = "pcap")]
            None,
        );
        let mut ended = Vec::new();
        while let Ok(Some(ev)) =
            tokio::time::timeout(Duration::from_millis(200), stream.next()).await
        {
            if let FlowEvent::Ended { reason, .. } = ev.unwrap() {
                ended.push(reason);
            }
        }
        assert_eq!(stream.buffered_bytes(), 0);
        let log = log.lock().unwrap().clone();
        (log, ended)
    }

    /// Reordered and retransmitted segments come out in order, once;
    /// the close carries the flow's reason, before the flow's end.
    #[tokio::test(flavor = "current_thread")]
    async fn bytes_are_reassembled_in_order_without_duplicates() {
        let segs: &[(u32, &[u8])] = &[(0, b"hello "), (11, b"!"), (6, b"world"), (6, b"world")];
        let (log, ended) = run(flow(segs, 12)).await;
        let client: String = log
            .iter()
            .filter_map(|l| l.strip_prefix("I data "))
            .collect();
        assert_eq!(client, "hello world!", "{log:?}");
        assert!(log.contains(&"R data OK".to_string()), "{log:?}");
        assert!(!log.iter().any(|l| l.contains("gap")), "{log:?}");
        let tail: Vec<&str> = log[log.len() - 3..].iter().map(String::as_str).collect();
        assert_eq!(tail, ["I close Fin", "R close Fin", "ended"], "{log:?}");
        assert_eq!(ended, [EndReason::Fin]);
    }

    /// A segment that never arrives becomes a gap, and the bytes after
    /// it are still delivered (at flow end at the latest).
    #[tokio::test(flavor = "current_thread")]
    async fn a_lost_segment_is_a_gap_not_silence() {
        let segs: &[(u32, &[u8])] = &[(0, b"head "), (9, b"tail")];
        let (log, _) = run(flow(segs, 13)).await;
        let client: Vec<&str> = log
            .iter()
            .filter(|l| l.starts_with("I "))
            .map(String::as_str)
            .collect();
        assert_eq!(
            client,
            ["I data head ", "I gap 4", "I data tail", "I close Fin"],
            "{log:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn channel_factory_dispatches_per_flow_and_side() {
        let counts = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, FlowSide)>::new()));
        let counts_clone = counts.clone();
        let mut factory = channel_factory(move |key: &String, side: FlowSide| {
            counts_clone.lock().unwrap().push((key.clone(), side));
            let (tx, _rx) = mpsc::channel::<ReassembledChunk>(8);
            tx
        });

        let _r1 = factory.new_reassembler(&"flow-A".to_string(), FlowSide::Initiator);
        let _r2 = factory.new_reassembler(&"flow-A".to_string(), FlowSide::Responder);
        let _r3 = factory.new_reassembler(&"flow-B".to_string(), FlowSide::Initiator);

        let recorded = counts.lock().unwrap();
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[0].0, "flow-A");
        assert_eq!(recorded[0].1, FlowSide::Initiator);
        assert_eq!(recorded[1].1, FlowSide::Responder);
        assert_eq!(recorded[2].0, "flow-B");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn data_and_gaps_reach_the_channel_close_ends_it() {
        let (tx, mut rx) = mpsc::channel::<ReassembledChunk>(4);
        let mut r = ChannelReassembler { tx: Some(tx) };
        r.data(Bytes::from_static(b"abc")).await;
        r.gap(7).await;
        r.data(Bytes::from_static(b"def")).await;
        r.close(EndReason::Fin).await;
        assert_eq!(
            rx.recv().await,
            Some(ReassembledChunk::Data(Bytes::from_static(b"abc")))
        );
        assert_eq!(rx.recv().await, Some(ReassembledChunk::Gap(7)));
        assert_eq!(
            rx.recv().await,
            Some(ReassembledChunk::Data(Bytes::from_static(b"def")))
        );
        assert_eq!(rx.recv().await, None);
    }
}
