//! [`MultiFlowStream`], [`MultiSessionStream`], [`MultiDatagramStream`]
//! — fan-in of N per-source streams into one tagged async stream.
//!
//! Construction goes through
//! [`AsyncMultiCapture::flow_stream`](super::multi_capture::AsyncMultiCapture::flow_stream)
//! and siblings (one AF_PACKET stream per interface, uniformly
//! configured), through `from_streams` (per-source configuration), or
//! — since 0.31.1 — source by source with `empty()` + `push_source` /
//! `with_source`, which accept **any** netring source stream with the
//! same event type: AF_PACKET or AF_XDP live streams and the
//! `Pcap*Stream` replay streams alike. Every source hands back its
//! tracker, live flow snapshots, dedup and ring / file counters
//! through [`MultiSource`] (`source(idx)`), and a source that reaches
//! end-of-file stays in place with its final counters readable.
//! Internal round-robin polling avoids the
//! `futures::stream::select_all` dependency.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use flowscope::{
    DatagramParser, DatagramParserFactory, FlowEvent, FlowExtractor, FlowStats, FlowTracker,
    FlowTrackerStats, SessionParser, SessionParserFactory, Timestamp,
};
use futures_core::Stream;

use flowscope::SessionEvent;

use crate::Capture;
use crate::async_adapters::datagram_stream::DatagramStream;
use crate::async_adapters::flow_source::{AsyncFlowSource, DrainOutcome, SourcePacket};
use crate::async_adapters::flow_stream::{FlowStream, clamp_now, clamp_view, current_timestamp};
use crate::async_adapters::multi_source::MultiSource;
use crate::async_adapters::session_stream::SessionStream;
use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::dedup::Dedup;
use crate::error::Error;
use crate::stats::CaptureStats;

/// An event annotated with the source it came from within an
/// [`AsyncMultiCapture`](super::multi_capture::AsyncMultiCapture) or
/// any `Multi*Stream` built from sources.
///
/// `source_idx` is an index into the fan-in's source list
/// (0..[`len()`](MultiFlowStream::len), in the order the sources were
/// given or pushed). Map it back to a human-readable label via
/// [`MultiFlowStream::label`] (or the sibling methods), or introspect
/// the source with [`MultiFlowStream::source`].
#[derive(Debug, Clone)]
pub struct TaggedEvent<E> {
    /// Index of the source within the multi-capture.
    pub source_idx: u16,
    /// The underlying event payload.
    pub event: E,
}

// ── select_state ─────────────────────────────────────────────────
//
// Round-robin select over a Vec of owned streams. A slot that has
// returned `None` is marked done but kept, so indices stay stable and
// its final counters (tracker, dedup, packets read) remain readable
// after end-of-file (#176).

struct Slot<S> {
    stream: S,
    done: bool,
}

struct SelectState<S> {
    slots: Vec<Slot<S>>,
    /// Index to start polling at — incremented each yield for fairness.
    next: usize,
}

impl<S> SelectState<S> {
    fn new(streams: Vec<S>) -> Self {
        Self {
            slots: streams
                .into_iter()
                .map(|stream| Slot {
                    stream,
                    done: false,
                })
                .collect(),
            next: 0,
        }
    }

    fn alive_count(&self) -> usize {
        self.slots.iter().filter(|s| !s.done).count()
    }

    fn len(&self) -> usize {
        self.slots.len()
    }

    fn push(&mut self, stream: S) -> u16 {
        self.slots.push(Slot {
            stream,
            done: false,
        });
        (self.slots.len() - 1) as u16
    }

    fn is_alive(&self, idx: u16) -> Option<bool> {
        self.slots.get(idx as usize).map(|s| !s.done)
    }

    fn get(&self, idx: u16) -> Option<&S> {
        self.slots.get(idx as usize).map(|s| &s.stream)
    }

    fn get_mut(&mut self, idx: u16) -> Option<&mut S> {
        self.slots.get_mut(idx as usize).map(|s| &mut s.stream)
    }

    fn streams(&self) -> impl Iterator<Item = &S> {
        self.slots.iter().map(|s| &s.stream)
    }
}

impl<S, T> SelectState<S>
where
    S: Stream<Item = Result<T, Error>> + Unpin,
{
    /// Poll all alive streams in round-robin order. Yields the first
    /// `Ready` (Item or Err). Marks `None` slots done; returns
    /// `Poll::Ready(None)` when every slot is done (or there are none).
    fn poll_next_select(&mut self, cx: &mut Context<'_>) -> Poll<Option<(u16, Result<T, Error>)>> {
        let n = self.slots.len();
        for offset in 0..n {
            let i = (self.next + offset) % n;
            let slot = &mut self.slots[i];
            if slot.done {
                continue;
            }
            match Pin::new(&mut slot.stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    self.next = (i + 1) % n;
                    return Poll::Ready(Some((i as u16, item)));
                }
                Poll::Ready(None) => {
                    // Stream exhausted — keep it (final stats stay
                    // readable), stop polling it; keep iterating in
                    // case another slot is also ready this tick.
                    slot.done = true;
                }
                Poll::Pending => {}
            }
        }
        // Every slot still alive returned `Pending` above and registered
        // its waker. Decide on the state *after* the loop: a slot that
        // just finished must not leave us parked with no waker at all.
        if self.slots.iter().any(|s| !s.done) {
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }
}

// ── AnySource: the constructor's concrete stream, or anything boxed ──

/// Object-safe bundle of [`MultiSource`] + `Stream` for the boxed slot.
/// Blanket-implemented; users never name it.
pub(crate) trait DynSource<E: FlowExtractor>:
    MultiSource<E> + Stream<Item = Result<Self::Event, Error>>
{
    type Event;
}

impl<E, T, Ev> DynSource<E> for T
where
    E: FlowExtractor,
    T: MultiSource<E> + Stream<Item = Result<Ev, Error>>,
{
    type Event = Ev;
}

pub(crate) type BoxedSource<E, Ev> =
    Box<dyn DynSource<E, Event = Ev, Item = Result<Ev, Error>> + Send + Unpin>;

/// One fan-in slot: the concrete stream a constructor built (`Native`,
/// no indirection) or a source pushed through `push_source` (`Boxed`,
/// one vtable call per poll).
pub(crate) enum AnySource<E, N, Ev>
where
    E: FlowExtractor,
{
    Native(N),
    Boxed(BoxedSource<E, Ev>),
}

impl<E, N, Ev> AnySource<E, N, Ev>
where
    E: FlowExtractor,
    N: MultiSource<E>,
{
    fn as_dyn(&self) -> &dyn MultiSource<E> {
        match self {
            AnySource::Native(n) => n,
            AnySource::Boxed(b) => {
                let d: &dyn MultiSource<E> = &**b;
                d
            }
        }
    }

    fn as_dyn_mut(&mut self) -> &mut dyn MultiSource<E> {
        match self {
            AnySource::Native(n) => n,
            AnySource::Boxed(b) => {
                let d: &mut dyn MultiSource<E> = &mut **b;
                d
            }
        }
    }
}

impl<E, N, Ev> Stream for AnySource<E, N, Ev>
where
    E: FlowExtractor,
    N: Stream<Item = Result<Ev, Error>> + Unpin,
{
    type Item = Result<Ev, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            AnySource::Native(n) => Pin::new(n).poll_next(cx),
            AnySource::Boxed(b) => Pin::new(b).poll_next(cx),
        }
    }
}

/// A fan-in's slots.
type Slots<E, N, Ev> = SelectState<AnySource<E, N, Ev>>;
/// The AF_PACKET source the `AsyncMultiCapture` constructors build.
type AfPacket = crate::async_adapters::tokio_adapter::AsyncCapture<Capture>;
/// A session fan-in's event: the factory's parser's message type.
type SessionEv<E, F> = SessionEvent<
    <E as FlowExtractor>::Key,
    <<F as SessionParserFactory<<E as FlowExtractor>::Key>>::Parser as SessionParser>::Message,
>;
/// A datagram fan-in's event.
type DatagramEv<E, F> = SessionEvent<
    <E as FlowExtractor>::Key,
    <<F as DatagramParserFactory<<E as FlowExtractor>::Key>>::Parser as DatagramParser>::Message,
>;
/// [`per_source_snapshot_flow_stats`](MultiSessionStream::per_source_snapshot_flow_stats):
/// one `(label, live flows)` entry per source. New in 0.31.1.
pub type PerSourceFlowStats<K> = Vec<(String, Vec<(K, FlowStats)>)>;

/// The per-source accessor bodies, shared by the six fan-in types.
impl<E, N, Ev> SelectState<AnySource<E, N, Ev>>
where
    E: FlowExtractor,
    N: MultiSource<E>,
{
    fn source(&self, idx: u16) -> Option<&dyn MultiSource<E>> {
        self.get(idx).map(AnySource::as_dyn)
    }

    fn source_mut(&mut self, idx: u16) -> Option<&mut dyn MultiSource<E>> {
        self.get_mut(idx).map(AnySource::as_dyn_mut)
    }

    fn per_source_capture_stats(
        &self,
        labels: &[String],
    ) -> Vec<(String, Option<Result<CaptureStats, Error>>)> {
        self.streams()
            .enumerate()
            .map(|(i, s)| (labels[i].clone(), s.as_dyn().capture_stats()))
            .collect()
    }

    fn capture_stats(&self) -> CaptureStats {
        let mut acc = CaptureStats::default();
        for s in self.streams() {
            if let Some(Ok(stats)) = s.as_dyn().capture_stats() {
                acc.packets = acc.packets.saturating_add(stats.packets);
                acc.drops = acc.drops.saturating_add(stats.drops);
                acc.freeze_count = acc.freeze_count.saturating_add(stats.freeze_count);
            }
        }
        acc
    }

    fn per_source_tracker_stats(
        &self,
        labels: &[String],
    ) -> Vec<(String, Option<&FlowTrackerStats>)> {
        self.streams()
            .enumerate()
            .map(|(i, s)| (labels[i].clone(), Some(s.as_dyn().tracker_stats())))
            .collect()
    }

    fn per_source_snapshot_flow_stats(&self, labels: &[String]) -> PerSourceFlowStats<E::Key> {
        self.streams()
            .enumerate()
            .map(|(i, s)| {
                (
                    labels[i].clone(),
                    s.as_dyn().snapshot_flow_stats().collect(),
                )
            })
            .collect()
    }

    fn total_active_flows(&self) -> usize {
        self.streams().map(|s| s.as_dyn().active_flows()).sum()
    }
}

/// The public per-source API, identical on the six fan-in types.
/// `$ev` is the type's event (the `Stream` item without the
/// `TaggedEvent` / `Result` envelopes).
macro_rules! multi_source_api {
    ($ev:ty) => {
        /// Human-readable label for `source_idx`.
        pub fn label(&self, source_idx: u16) -> Option<&str> {
            self.labels.get(source_idx as usize).map(|s| s.as_str())
        }

        /// Number of sources still being polled (haven't returned `None`
        /// from their inner stream). Decrements as sources exhaust —
        /// replay sources do at end-of-file; live captures never.
        pub fn alive_sources(&self) -> usize {
            self.select.alive_count()
        }

        /// Number of sources, finished ones included (the range of
        /// `source_idx`).
        pub fn len(&self) -> usize {
            self.select.len()
        }

        /// `true` when no source was added.
        pub fn is_empty(&self) -> bool {
            self.select.len() == 0
        }

        /// A fan-in with no sources yet; add them with
        /// [`push_source`](Self::push_source) / [`with_source`](Self::with_source).
        /// Polling an empty fan-in ends the stream at once. New in 0.31.1.
        pub fn empty() -> Self {
            Self {
                select: SelectState::new(Vec::new()),
                labels: Vec::new(),
            }
        }

        /// Append a source of any kind — a live stream over AF_PACKET or
        /// AF_XDP, or a `Pcap*Stream` replaying a file — with its label.
        /// Returns its `source_idx` (the next free one). May be called
        /// before polling or between polls; the next `poll_next` picks
        /// the new source up. New in 0.31.1.
        ///
        /// The source must yield this fan-in's event type: for a session
        /// fan-in, `SessionEvent<E::Key, M>` with the same message type
        /// `M` — one parser type used both live and on replay (flowscope's
        /// blanket `SessionParserFactory` impl for `P: SessionParser +
        /// Default + Clone` and `TemplateFactory<P>` make that the common
        /// case).
        pub fn push_source<S>(&mut self, label: impl Into<String>, source: S) -> u16
        where
            S: MultiSource<E> + Stream<Item = Result<$ev, Error>> + Send + Unpin + 'static,
        {
            self.labels.push(label.into());
            self.select.push(AnySource::Boxed(Box::new(source)))
        }

        /// Builder form of [`push_source`](Self::push_source).
        pub fn with_source<S>(mut self, label: impl Into<String>, source: S) -> Self
        where
            S: MultiSource<E> + Stream<Item = Result<$ev, Error>> + Send + Unpin + 'static,
        {
            self.push_source(label, source);
            self
        }

        /// Introspect one source — tracker, live flow snapshots, dedup,
        /// ring / file counters — finished sources included. `None` for
        /// an index out of range. New in 0.31.1.
        pub fn source(&self, source_idx: u16) -> Option<&dyn MultiSource<E>> {
            self.select.source(source_idx)
        }

        /// Mutable form of [`source`](Self::source) (e.g. `dedup_mut()`).
        pub fn source_mut(&mut self, source_idx: u16) -> Option<&mut dyn MultiSource<E>> {
            self.select.source_mut(source_idx)
        }

        /// Whether `source_idx` is still being polled; `None` for an
        /// index out of range. New in 0.31.1.
        pub fn is_alive(&self, source_idx: u16) -> Option<bool> {
            self.select.is_alive(source_idx)
        }

        /// Per-source kernel ring stats. One entry per source, in order:
        /// `Some(Ok(..))` for a live source, `Some(Err(..))` when its
        /// `getsockopt` failed, `None` for a source without a kernel
        /// ring (a replay source — see
        /// [`MultiSource::packets_read`]). Reading resets the kernel
        /// counters. (Before 0.31.1 `None` meant "ended"; finished
        /// sources are now kept and report normally.)
        pub fn per_source_capture_stats(
            &self,
        ) -> Vec<(String, Option<Result<CaptureStats, Error>>)> {
            self.select.per_source_capture_stats(&self.labels)
        }

        /// Aggregate kernel ring stats across all live sources. `Err`
        /// from any individual source is silently skipped — use
        /// [`per_source_capture_stats`](Self::per_source_capture_stats)
        /// for fine-grained inspection.
        pub fn capture_stats(&self) -> CaptureStats {
            self.select.capture_stats()
        }

        /// Per-source tracker stats. One entry per source, in order;
        /// always `Some` since 0.31.1 (finished sources are kept — the
        /// `Option` remains for compatibility).
        pub fn per_source_tracker_stats(&self) -> Vec<(String, Option<&FlowTrackerStats>)> {
            self.select.per_source_tracker_stats(&self.labels)
        }

        /// Per-source live `(key, stats)` snapshots, owned, in
        /// `source_idx` order (a flushed replay source is simply empty).
        /// The per-flow report of a multi-interface capture. New in 0.31.1.
        pub fn per_source_snapshot_flow_stats(&self) -> PerSourceFlowStats<E::Key> {
            self.select.per_source_snapshot_flow_stats(&self.labels)
        }

        /// Sum of live flow counts across all sources. O(n × per-source LRU).
        pub fn total_active_flows(&self) -> usize {
            self.select.total_active_flows()
        }
    };
}

// ── MultiFlowStream ──────────────────────────────────────────────

/// Tagged fan-in of [`FlowStream`]s — one flow table per source.
///
/// Sources: the AF_PACKET streams
/// [`AsyncMultiCapture::flow_stream`](super::multi_capture::AsyncMultiCapture::flow_stream)
/// builds, [`from_streams`](Self::from_streams), or any flow stream
/// (AF_PACKET, AF_XDP, [`PcapFlowStream`](crate::PcapFlowStream)) via
/// [`push_source`](Self::push_source). See the [module docs](self).
pub struct MultiFlowStream<E>
where
    E: FlowExtractor,
{
    select: Slots<E, FlowStream<AfPacket, E>, FlowEvent<E::Key>>,
    labels: Vec<String>,
}

impl<E> MultiFlowStream<E>
where
    E: FlowExtractor,
{
    /// Assemble from per-source streams you built yourself, in
    /// `source_idx` order, each with its label.
    ///
    /// This is the escape hatch for per-source configuration the
    /// `*_stream_with` constructors apply uniformly: a BPF filter per
    /// interface ([`AsyncCapture::open_with_filter`](crate::AsyncCapture::open_with_filter)),
    /// a pcap tap per interface (`with_pcap_tap`), dedup only on `lo`,
    /// a different tracker config per source… The result keeps the
    /// fair round-robin fan-in, [`TaggedEvent`] and the per-source
    /// stats accessors. For sources of other kinds (AF_XDP, pcap
    /// replay) use [`push_source`](Self::push_source).
    pub fn from_streams<I>(sources: I) -> Self
    where
        I: IntoIterator<
            Item = (
                String,
                FlowStream<crate::async_adapters::tokio_adapter::AsyncCapture<Capture>, E>,
            ),
        >,
    {
        let (labels, streams): (Vec<_>, Vec<_>) = sources.into_iter().unzip();
        Self {
            select: SelectState::new(streams.into_iter().map(AnySource::Native).collect()),
            labels,
        }
    }

    multi_source_api!(FlowEvent<E::Key>);
}

impl<E> MultiFlowStream<E>
where
    E: FlowExtractor + Clone + Unpin + Send + 'static,
    E::Key: Clone + Unpin + Send + 'static,
{
    pub(crate) fn new(
        captures: Vec<crate::async_adapters::tokio_adapter::AsyncCapture<Capture>>,
        labels: Vec<String>,
        extractor: E,
    ) -> Self {
        Self::new_with_config(
            captures,
            labels,
            extractor,
            super::multi_config::MultiStreamConfig::default(),
        )
    }

    pub(crate) fn new_with_config(
        captures: Vec<crate::async_adapters::tokio_adapter::AsyncCapture<Capture>>,
        labels: Vec<String>,
        extractor: E,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> Self {
        let streams = captures
            .into_iter()
            .map(|cap| AnySource::Native(config.apply(cap.flow_stream(extractor.clone()))))
            .collect();
        Self {
            select: SelectState::new(streams),
            labels,
        }
    }
}

impl<E> Stream for MultiFlowStream<E>
where
    E: FlowExtractor + Unpin,
    E::Key: Clone + Unpin,
{
    type Item = Result<TaggedEvent<FlowEvent<E::Key>>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.select.poll_next_select(cx) {
            Poll::Ready(Some((idx, Ok(event)))) => Poll::Ready(Some(Ok(TaggedEvent {
                source_idx: idx,
                event,
            }))),
            Poll::Ready(Some((_, Err(e)))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ── XdpMultiFlowStream (issue #104) ──────────────────────────────
//
// AF_XDP analogue of `MultiFlowStream`: N multi-queue `AsyncXdpCapture`s
// (one per interface) fanned into one tagged stream. Each interface keeps
// its own `FlowTracker`; the `source_idx` on each `TaggedEvent` is the
// interface index. Built on the same `SelectState` round-robin.

/// Tagged fan-in of AF_XDP [`FlowStream`]s — one multi-queue capture per
/// interface, merged into a unified `TaggedEvent` stream (issue #104).
/// `push_source` also takes AF_PACKET and replay sources (0.31.1).
#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
pub struct XdpMultiFlowStream<E>
where
    E: FlowExtractor,
{
    select: Slots<E, FlowStream<crate::AsyncXdpCapture, E>, FlowEvent<E::Key>>,
    labels: Vec<String>,
}

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl<E> XdpMultiFlowStream<E>
where
    E: FlowExtractor,
{
    /// Assemble from per-interface streams you built yourself, in
    /// `source_idx` order, each with its label — per-source
    /// configuration the `*_stream_with` constructors apply uniformly
    /// (see [`MultiFlowStream::from_streams`]).
    pub fn from_streams<I>(sources: I) -> Self
    where
        I: IntoIterator<Item = (String, FlowStream<crate::AsyncXdpCapture, E>)>,
    {
        let (labels, streams): (Vec<_>, Vec<_>) = sources.into_iter().unzip();
        Self {
            select: SelectState::new(streams.into_iter().map(AnySource::Native).collect()),
            labels,
        }
    }

    multi_source_api!(FlowEvent<E::Key>);
}

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl<E> XdpMultiFlowStream<E>
where
    E: FlowExtractor + Clone + Unpin + Send + 'static,
    E::Key: Clone + Unpin + Send + 'static,
{
    pub(crate) fn new_with_config(
        captures: Vec<crate::AsyncXdpCapture>,
        labels: Vec<String>,
        extractor: E,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> Self {
        let streams = captures
            .into_iter()
            .map(|cap| AnySource::Native(config.apply(cap.flow_stream(extractor.clone()))))
            .collect();
        Self {
            select: SelectState::new(streams),
            labels,
        }
    }
}

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl<E> Stream for XdpMultiFlowStream<E>
where
    E: FlowExtractor + Unpin,
    E::Key: Clone + Unpin,
{
    type Item = Result<TaggedEvent<FlowEvent<E::Key>>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.select.poll_next_select(cx) {
            Poll::Ready(Some((idx, Ok(event)))) => Poll::Ready(Some(Ok(TaggedEvent {
                source_idx: idx,
                event,
            }))),
            Poll::Ready(Some((_, Err(e)))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ── XdpMultiSessionStream / XdpMultiDatagramStream (issue #104) ───
//
// AF_XDP analogues of MultiSessionStream / MultiDatagramStream: N
// multi-queue captures fanned into one tagged L7 stream, reusing the same
// SelectState round-robin and the same per-source API.

/// Tagged fan-in of AF_XDP [`SessionStream`]s (issue #104).
/// `push_source` also takes AF_PACKET and replay sources (0.31.1).
#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
pub struct XdpMultiSessionStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    select: Slots<E, SessionStream<crate::AsyncXdpCapture, E, F>, SessionEv<E, F>>,
    labels: Vec<String>,
}

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl<E, F> XdpMultiSessionStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    /// Assemble from per-interface streams you built yourself, in
    /// `source_idx` order, each with its label — per-source
    /// configuration the `*_stream_with` constructors apply uniformly
    /// (see [`MultiFlowStream::from_streams`]).
    pub fn from_streams<I>(sources: I) -> Self
    where
        I: IntoIterator<Item = (String, SessionStream<crate::AsyncXdpCapture, E, F>)>,
    {
        let (labels, streams): (Vec<_>, Vec<_>) = sources.into_iter().unzip();
        Self {
            select: SelectState::new(streams.into_iter().map(AnySource::Native).collect()),
            labels,
        }
    }

    multi_source_api!(SessionEvent<E::Key, <F::Parser as SessionParser>::Message>);
}

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl<E, F> XdpMultiSessionStream<E, F>
where
    E: FlowExtractor + Clone + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Unpin + Send + 'static,
    F: SessionParserFactory<E::Key> + Clone + Unpin + Send + 'static,
    F::Parser: Unpin + Send + 'static,
    <F::Parser as SessionParser>::Message: Unpin + Send + 'static,
{
    pub(crate) fn new_with_config(
        captures: Vec<crate::AsyncXdpCapture>,
        labels: Vec<String>,
        extractor: E,
        factory: F,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> Self {
        let streams = captures
            .into_iter()
            .map(|cap| {
                AnySource::Native(
                    config
                        .apply(cap.flow_stream(extractor.clone()))
                        .session_stream(factory.clone())
                        .with_emit_anomalies(config.emit_anomalies),
                )
            })
            .collect();
        Self {
            select: SelectState::new(streams),
            labels,
        }
    }
}

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl<E, F> Stream for XdpMultiSessionStream<E, F>
where
    E: FlowExtractor + Unpin,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static + Unpin,
    F: SessionParserFactory<E::Key> + Unpin,
    F::Parser: Unpin,
    <F::Parser as SessionParser>::Message: Unpin,
{
    type Item =
        Result<TaggedEvent<SessionEvent<E::Key, <F::Parser as SessionParser>::Message>>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.select.poll_next_select(cx) {
            Poll::Ready(Some((idx, Ok(event)))) => Poll::Ready(Some(Ok(TaggedEvent {
                source_idx: idx,
                event,
            }))),
            Poll::Ready(Some((_, Err(e)))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Tagged fan-in of AF_XDP [`DatagramStream`]s (issue #104).
/// `push_source` also takes AF_PACKET and replay sources (0.31.1).
#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
pub struct XdpMultiDatagramStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: DatagramParserFactory<E::Key>,
{
    select: Slots<E, DatagramStream<crate::AsyncXdpCapture, E, F>, DatagramEv<E, F>>,
    labels: Vec<String>,
}

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl<E, F> XdpMultiDatagramStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: DatagramParserFactory<E::Key>,
{
    /// Assemble from per-interface streams you built yourself, in
    /// `source_idx` order, each with its label — per-source
    /// configuration the `*_stream_with` constructors apply uniformly
    /// (see [`MultiFlowStream::from_streams`]).
    pub fn from_streams<I>(sources: I) -> Self
    where
        I: IntoIterator<Item = (String, DatagramStream<crate::AsyncXdpCapture, E, F>)>,
    {
        let (labels, streams): (Vec<_>, Vec<_>) = sources.into_iter().unzip();
        Self {
            select: SelectState::new(streams.into_iter().map(AnySource::Native).collect()),
            labels,
        }
    }

    multi_source_api!(SessionEvent<E::Key, <F::Parser as DatagramParser>::Message>);
}

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl<E, F> XdpMultiDatagramStream<E, F>
where
    E: FlowExtractor + Clone + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Unpin + Send + 'static,
    F: DatagramParserFactory<E::Key> + Clone + Unpin + Send + 'static,
    F::Parser: Unpin + Send + 'static,
    <F::Parser as DatagramParser>::Message: Unpin + Send + 'static,
{
    pub(crate) fn new_with_config(
        captures: Vec<crate::AsyncXdpCapture>,
        labels: Vec<String>,
        extractor: E,
        factory: F,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> Self {
        let streams = captures
            .into_iter()
            .map(|cap| {
                AnySource::Native(
                    config
                        .apply(cap.flow_stream(extractor.clone()))
                        .datagram_stream(factory.clone())
                        .with_emit_anomalies(config.emit_anomalies),
                )
            })
            .collect();
        Self {
            select: SelectState::new(streams),
            labels,
        }
    }
}

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl<E, F> Stream for XdpMultiDatagramStream<E, F>
where
    E: FlowExtractor + Unpin,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static + Unpin,
    F: DatagramParserFactory<E::Key> + Unpin,
    F::Parser: Unpin,
    <F::Parser as DatagramParser>::Message: Unpin,
{
    type Item =
        Result<TaggedEvent<SessionEvent<E::Key, <F::Parser as DatagramParser>::Message>>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.select.poll_next_select(cx) {
            Poll::Ready(Some((idx, Ok(event)))) => Poll::Ready(Some(Ok(TaggedEvent {
                source_idx: idx,
                event,
            }))),
            Poll::Ready(Some((_, Err(e)))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ── MergedFlowStream ─────────────────────────────────────────────

/// Source-agnostic **tap merge**: N captures feeding **one** shared
/// [`FlowTracker`], keyed by the bare bidirectional flow key.
///
/// Unlike [`MultiFlowStream`] (which builds one tracker *per* source
/// and tags each event with its `source_idx`), `MergedFlowStream`
/// coalesces the two directions of a tapped flow — TX on `eth0`, RX
/// on `eth1` — into **one** bidirectional flow. flowscope's
/// bidirectional 5-tuple canonicalizes endpoints by address order, so
/// the `a→b` and `b→a` legs hash to the **same** key with opposite
/// [`Orientation`](flowscope::Orientation) and coalesce by
/// construction when they share a tracker. Yields a plain
/// [`FlowEvent<E::Key>`] (no `source_idx` envelope — the whole point).
///
/// Each source's packets are stamped with a 1-based
/// `with_source_idx(i + 1)` (`0` is flowscope's "unused" sentinel)
/// before tracking, so the merged flow reports **which physical leg
/// each canonical direction arrived on** via
/// [`FlowStats::source_idx_forward`](flowscope::FlowStats) /
/// `source_idx_reverse`, plus
/// [`FlowStats::capture_leg_inconsistent`](flowscope::FlowStats) — the
/// tap-miswire / asymmetric-routing IOC (RFC 5103 biflow merge,
/// flowscope #120). These ride on `Ended` / `Tick` events and
/// `snapshot_flow_stats`.
///
/// **Use a bidirectional extractor** (e.g. `FiveTuple::bidirectional()`)
/// — a per-direction key would defeat the merge. Pairs with
/// [`MonitorBuilder::infer_tcp_initiator`](crate::monitor::MonitorBuilder::infer_tcp_initiator)
/// /
/// [`MultiStreamConfig::with_infer_tcp_initiator`](super::multi_config::MultiStreamConfig::with_infer_tcp_initiator)
/// for race-robust TCP roles across the two legs. See `docs/scaling.md`
/// → "merge vs distinct".
pub struct MergedFlowStream<C, E>
where
    E: FlowExtractor,
{
    caps: Vec<C>,
    labels: Vec<String>,
    tracker: FlowTracker<E, ()>,
    pending: VecDeque<FlowEvent<E::Key>>,
    sweep: tokio::time::Interval,
    monotonic_ts: Option<Timestamp>,
    dedup: Option<Dedup>,
    /// Round-robin start index for fairness across sources.
    next: usize,
}

impl<C, E> MergedFlowStream<C, E>
where
    E: FlowExtractor + Unpin + Send + 'static,
    E::Key: Clone + Unpin + Send + 'static,
{
    pub(crate) fn new_with_config(
        captures: Vec<C>,
        labels: Vec<String>,
        extractor: E,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> Self {
        let mut tracker = FlowTracker::new(extractor);
        tracker.set_config(config.tracker_config.clone());
        if let Some(f) = config.idle_timeout_fn.clone() {
            tracker.set_idle_timeout_fn(move |k, l4| f(k, l4));
        }
        let sweep = tokio::time::interval(config.tracker_config.sweep_interval);
        Self {
            caps: captures,
            labels,
            tracker,
            pending: VecDeque::new(),
            sweep,
            monotonic_ts: if config.monotonic_ts {
                Some(Timestamp::default())
            } else {
                None
            },
            dedup: config.dedup,
            next: 0,
        }
    }

    /// Borrow the single shared tracker (stats / `snapshot_flow_stats`
    /// / live capture-leg introspection).
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        &self.tracker
    }

    /// Cumulative counters of the shared tracker.
    pub fn tracker_stats(&self) -> &flowscope::FlowTrackerStats {
        self.tracker.stats()
    }

    /// Live flow count in the shared tracker (each tapped flow counts
    /// **once**, not once per leg). O(n) walk.
    pub fn active_flows(&self) -> usize {
        self.tracker.flows().count()
    }

    /// Live `(key, stats)` pairs of the merged tracker, owned (like
    /// every netring stream) — the capture-leg fields
    /// (`source_idx_forward` / `source_idx_reverse` /
    /// `capture_leg_inconsistent`) are readable here mid-stream.
    pub fn snapshot_flow_stats(&self) -> impl Iterator<Item = (E::Key, flowscope::FlowStats)> + '_ {
        self.tracker
            .iter_active()
            .map(|af| (af.key.clone(), af.stats.clone()))
    }

    /// Number of sources fed into the merge.
    pub fn sources(&self) -> usize {
        self.caps.len()
    }

    /// Human-readable label for a 0-based source index (the index is
    /// `source_idx - 1`, since legs are stamped 1-based).
    pub fn label(&self, source: usize) -> Option<&str> {
        self.labels.get(source).map(|s| s.as_str())
    }

    /// The one shared dedup
    /// ([`MultiStreamConfig::with_dedup`](super::multi_config::MultiStreamConfig::with_dedup)),
    /// if configured — its `dropped()` / `seen()` count across every
    /// leg. New in 0.31.1.
    pub fn dedup(&self) -> Option<&Dedup> {
        self.dedup.as_ref()
    }

    /// Mutable access to the shared dedup (e.g. `reset()`). New in 0.31.1.
    pub fn dedup_mut(&mut self) -> Option<&mut Dedup> {
        self.dedup.as_mut()
    }
}

// AF_PACKET-specific ring-stat accessors (the AF_XDP backend exposes the
// equivalents through `AsyncXdpCapture::capture_stats`; see the gated impl).
impl<E> MergedFlowStream<AsyncCapture<Capture>, E>
where
    E: FlowExtractor + Unpin + Send + 'static,
    E::Key: Clone + Unpin + Send + 'static,
{
    /// Per-source kernel ring stats, in registration order.
    pub fn per_source_capture_stats(&self) -> Vec<(String, Result<CaptureStats, Error>)> {
        self.caps
            .iter()
            .enumerate()
            .map(|(i, c)| (self.labels[i].clone(), c.stats()))
            .collect()
    }

    /// Aggregate kernel ring stats across all sources. `Err` from any
    /// one source is skipped.
    pub fn capture_stats(&self) -> CaptureStats {
        let mut acc = CaptureStats::default();
        for c in &self.caps {
            if let Ok(s) = c.stats() {
                acc.packets = acc.packets.saturating_add(s.packets);
                acc.drops = acc.drops.saturating_add(s.drops);
                acc.freeze_count = acc.freeze_count.saturating_add(s.freeze_count);
            }
        }
        acc
    }
}

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl<E> MergedFlowStream<crate::AsyncXdpCapture, E>
where
    E: FlowExtractor + Unpin + Send + 'static,
    E::Key: Clone + Unpin + Send + 'static,
{
    /// Per-source AF_XDP ring stats, in registration order.
    pub fn per_source_capture_stats(&self) -> Vec<(String, Result<CaptureStats, Error>)> {
        self.caps
            .iter()
            .enumerate()
            .map(|(i, c)| (self.labels[i].clone(), c.capture_stats()))
            .collect()
    }

    /// Aggregate AF_XDP ring stats across all sources. `Err` from any one
    /// source is skipped.
    pub fn capture_stats(&self) -> CaptureStats {
        let mut acc = CaptureStats::default();
        for c in &self.caps {
            if let Ok(s) = c.capture_stats() {
                acc.packets = acc.packets.saturating_add(s.packets);
                acc.drops = acc.drops.saturating_add(s.drops);
                acc.freeze_count = acc.freeze_count.saturating_add(s.freeze_count);
            }
        }
        acc
    }
}

impl<C, E> Stream for MergedFlowStream<C, E>
where
    C: AsyncFlowSource + Unpin,
    E: FlowExtractor + Unpin,
    E::Key: Clone + Unpin,
{
    type Item = Result<FlowEvent<E::Key>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let n = this.caps.len();
        if n == 0 {
            return Poll::Ready(None);
        }

        loop {
            if let Some(evt) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(evt)));
            }

            // One shared sweep timer drives idle/active timeouts on the
            // merged tracker.
            if this.sweep.poll_tick(cx).is_ready() {
                let now = clamp_now(current_timestamp(), &mut this.monotonic_ts);
                for ev in this.tracker.sweep(now) {
                    this.pending.push_back(ev);
                }
                if let Some(evt) = this.pending.pop_front() {
                    return Poll::Ready(Some(Ok(evt)));
                }
            }

            // Round-robin a single drain pass over all sources, feeding
            // every packet into the one shared tracker. Disjoint field
            // borrows let the per-source `poll_drain` sink stamp the
            // capture leg + feed the shared tracker (issue #104 trait).
            let caps = &mut this.caps;
            let tracker = &mut this.tracker;
            let pending = &mut this.pending;
            let dedup = &mut this.dedup;
            let monotonic_ts = &mut this.monotonic_ts;

            let mut got_any_batch = false;
            let mut any_idle = false;
            for offset in 0..n {
                let i = (this.next + offset) % n;
                let outcome = caps[i].poll_drain(cx, &mut |sp: SourcePacket<'_>| {
                    if let Some(d) = dedup.as_mut()
                        && !d.keep_raw(sp.data, sp.direction, sp.view.timestamp)
                    {
                        return;
                    }
                    // Stamp the capture leg (1-based; 0 = unused sentinel)
                    // so flowscope binds source_idx_forward/reverse on the
                    // merged bidirectional flow (RFC 5103, flowscope #120).
                    let view = clamp_view(sp.view, monotonic_ts).with_source_idx(i as u32 + 1);
                    for ev in tracker.track(view) {
                        pending.push_back(ev);
                    }
                });
                match outcome {
                    Poll::Pending => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(Error::Io(e)))),
                    Poll::Ready(Ok(DrainOutcome::Drained)) => {
                        got_any_batch = true;
                        this.next = (i + 1) % n;
                    }
                    Poll::Ready(Ok(DrainOutcome::Idle)) => any_idle = true,
                }
            }

            if got_any_batch || any_idle {
                // New events to drain, or a source was just cleared and
                // must be re-polled to register a fresh waker.
                continue;
            }
            // Every source reported Pending with a registered waker (or
            // there are none). Live captures don't signal EOF, so park.
            return Poll::Pending;
        }
    }
}

// ── MultiSessionStream ───────────────────────────────────────────

/// Tagged fan-in of [`SessionStream`]s — one flow table and one
/// parser set per source.
///
/// Sources: the AF_PACKET streams
/// [`AsyncMultiCapture::session_stream`](super::multi_capture::AsyncMultiCapture::session_stream)
/// builds, [`from_streams`](Self::from_streams), or any session stream
/// with the same message type — AF_PACKET, AF_XDP,
/// [`PcapSessionStream`](crate::PcapSessionStream) — via
/// [`push_source`](Self::push_source). That last form is what lets one
/// event loop serve both a live multi-interface capture and a
/// `--read capture.pcap` replay:
///
/// ```no_run
/// # #[cfg(feature = "pcap")]
/// # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
/// use futures::StreamExt;
/// use netring::flow::extract::FiveTuple;
/// use netring::{AsyncCapture, AsyncPcapSource, Dedup, MultiSessionStream};
/// # #[derive(Clone, Default)] struct MyParser;
/// # impl flowscope::SessionParser for MyParser { type Message = ();
/// #   fn feed_initiator(&mut self, _: &[u8], _: flowscope::Timestamp, _: &mut Vec<()>) {}
/// #   fn feed_responder(&mut self, _: &[u8], _: flowscope::Timestamp, _: &mut Vec<()>) {} }
///
/// let mut fanin = MultiSessionStream::<FiveTuple, MyParser>::empty();
/// for iface in ["lo", "eth0"] {
///     let live = AsyncCapture::open(iface)?
///         .flow_stream(FiveTuple::bidirectional())
///         .session_stream(MyParser);
///     fanin.push_source(iface, live);
/// }
/// let replay = AsyncPcapSource::open("capture.pcap")
///     .await?
///     .sessions(FiveTuple::bidirectional(), MyParser)
///     .with_dedup(Dedup::content(std::time::Duration::from_millis(1), 256));
/// let idx = fanin.push_source("capture.pcap", replay);
///
/// while let Some(ev) = fanin.next().await {
///     let ev = ev?;
///     println!("[{}] {:?}", fanin.label(ev.source_idx).unwrap_or("?"), ev.event);
///     if fanin.is_alive(idx) == Some(false) {
///         // The file is flushed; its final counters are still readable.
///         let src = fanin.source(idx).unwrap();
///         println!("read {:?} frames, {:?} dropped as duplicates",
///             src.packets_read(), src.dedup().map(|d| d.dropped()));
///     }
/// }
/// for (label, flows) in fanin.per_source_snapshot_flow_stats() {
///     println!("{label}: {} live flows", flows.len());
/// }
/// # Ok(()) }
/// ```
pub struct MultiSessionStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    select: Slots<E, SessionStream<AfPacket, E, F>, SessionEv<E, F>>,
    labels: Vec<String>,
}

impl<E, F> MultiSessionStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    /// Assemble from per-source streams you built yourself, in
    /// `source_idx` order, each with its label.
    ///
    /// This is the escape hatch for per-source configuration the
    /// `*_stream_with` constructors apply uniformly: a BPF filter per
    /// interface ([`AsyncCapture::open_with_filter`](crate::AsyncCapture::open_with_filter)),
    /// a pcap tap per interface (`with_pcap_tap`), dedup only on `lo`,
    /// a different tracker config per source… The result keeps the
    /// fair round-robin fan-in, [`TaggedEvent`] and the per-source
    /// stats accessors. For sources of other kinds (AF_XDP, pcap
    /// replay) use [`push_source`](Self::push_source).
    pub fn from_streams<I>(sources: I) -> Self
    where
        I: IntoIterator<
            Item = (
                String,
                SessionStream<crate::async_adapters::tokio_adapter::AsyncCapture<Capture>, E, F>,
            ),
        >,
    {
        let (labels, streams): (Vec<_>, Vec<_>) = sources.into_iter().unzip();
        Self {
            select: SelectState::new(streams.into_iter().map(AnySource::Native).collect()),
            labels,
        }
    }

    multi_source_api!(SessionEvent<E::Key, <F::Parser as SessionParser>::Message>);
}

impl<E, F> MultiSessionStream<E, F>
where
    E: FlowExtractor + Clone + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Unpin + Send + 'static,
    F: SessionParserFactory<E::Key> + Clone + Unpin + Send + 'static,
    F::Parser: Unpin + Send + 'static,
    <F::Parser as SessionParser>::Message: Unpin + Send + 'static,
{
    pub(crate) fn new(
        captures: Vec<crate::async_adapters::tokio_adapter::AsyncCapture<Capture>>,
        labels: Vec<String>,
        extractor: E,
        factory: F,
    ) -> Self {
        Self::new_with_config(
            captures,
            labels,
            extractor,
            factory,
            super::multi_config::MultiStreamConfig::default(),
        )
    }

    pub(crate) fn new_with_config(
        captures: Vec<crate::async_adapters::tokio_adapter::AsyncCapture<Capture>>,
        labels: Vec<String>,
        extractor: E,
        factory: F,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> Self {
        let streams = captures
            .into_iter()
            .map(|cap| {
                AnySource::Native(
                    config
                        .apply(cap.flow_stream(extractor.clone()))
                        .session_stream(factory.clone())
                        .with_emit_anomalies(config.emit_anomalies),
                )
            })
            .collect();
        Self {
            select: SelectState::new(streams),
            labels,
        }
    }
}

impl<E, F> Stream for MultiSessionStream<E, F>
where
    E: FlowExtractor + Unpin,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static + Unpin,
    F: SessionParserFactory<E::Key> + Unpin,
    F::Parser: Unpin,
    <F::Parser as SessionParser>::Message: Unpin,
{
    type Item =
        Result<TaggedEvent<SessionEvent<E::Key, <F::Parser as SessionParser>::Message>>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.select.poll_next_select(cx) {
            Poll::Ready(Some((idx, Ok(event)))) => Poll::Ready(Some(Ok(TaggedEvent {
                source_idx: idx,
                event,
            }))),
            Poll::Ready(Some((_, Err(e)))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ── MultiDatagramStream ──────────────────────────────────────────

/// Tagged fan-in of [`DatagramStream`]s — one flow table and one
/// parser set per source.
///
/// Sources: the AF_PACKET streams
/// [`AsyncMultiCapture::datagram_stream`](super::multi_capture::AsyncMultiCapture::datagram_stream)
/// builds, [`from_streams`](Self::from_streams), or any datagram
/// stream with the same message type — AF_PACKET, AF_XDP,
/// [`PcapDatagramStream`](crate::PcapDatagramStream) — via
/// [`push_source`](Self::push_source). See [`MultiSessionStream`] for
/// the live + replay pattern.
pub struct MultiDatagramStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: DatagramParserFactory<E::Key>,
{
    select: Slots<E, DatagramStream<AfPacket, E, F>, DatagramEv<E, F>>,
    labels: Vec<String>,
}

impl<E, F> MultiDatagramStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: DatagramParserFactory<E::Key>,
{
    /// Assemble from per-source streams you built yourself, in
    /// `source_idx` order, each with its label.
    ///
    /// This is the escape hatch for per-source configuration the
    /// `*_stream_with` constructors apply uniformly: a BPF filter per
    /// interface ([`AsyncCapture::open_with_filter`](crate::AsyncCapture::open_with_filter)),
    /// a pcap tap per interface (`with_pcap_tap`), dedup only on `lo`,
    /// a different tracker config per source… The result keeps the
    /// fair round-robin fan-in, [`TaggedEvent`] and the per-source
    /// stats accessors. For sources of other kinds (AF_XDP, pcap
    /// replay) use [`push_source`](Self::push_source).
    pub fn from_streams<I>(sources: I) -> Self
    where
        I: IntoIterator<
            Item = (
                String,
                DatagramStream<crate::async_adapters::tokio_adapter::AsyncCapture<Capture>, E, F>,
            ),
        >,
    {
        let (labels, streams): (Vec<_>, Vec<_>) = sources.into_iter().unzip();
        Self {
            select: SelectState::new(streams.into_iter().map(AnySource::Native).collect()),
            labels,
        }
    }

    multi_source_api!(SessionEvent<E::Key, <F::Parser as DatagramParser>::Message>);
}

impl<E, F> MultiDatagramStream<E, F>
where
    E: FlowExtractor + Clone + Unpin + Send + 'static,
    E::Key: Eq + std::hash::Hash + Clone + Unpin + Send + 'static,
    F: DatagramParserFactory<E::Key> + Clone + Unpin + Send + 'static,
    F::Parser: Unpin + Send + 'static,
    <F::Parser as DatagramParser>::Message: Unpin + Send + 'static,
{
    pub(crate) fn new(
        captures: Vec<crate::async_adapters::tokio_adapter::AsyncCapture<Capture>>,
        labels: Vec<String>,
        extractor: E,
        factory: F,
    ) -> Self {
        Self::new_with_config(
            captures,
            labels,
            extractor,
            factory,
            super::multi_config::MultiStreamConfig::default(),
        )
    }

    pub(crate) fn new_with_config(
        captures: Vec<crate::async_adapters::tokio_adapter::AsyncCapture<Capture>>,
        labels: Vec<String>,
        extractor: E,
        factory: F,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> Self {
        let streams = captures
            .into_iter()
            .map(|cap| {
                AnySource::Native(
                    config
                        .apply(cap.flow_stream(extractor.clone()))
                        .datagram_stream(factory.clone())
                        .with_emit_anomalies(config.emit_anomalies),
                )
            })
            .collect();
        Self {
            select: SelectState::new(streams),
            labels,
        }
    }
}

impl<E, F> Stream for MultiDatagramStream<E, F>
where
    E: FlowExtractor + Unpin,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static + Unpin,
    F: DatagramParserFactory<E::Key> + Unpin,
    F::Parser: Unpin,
    <F::Parser as DatagramParser>::Message: Unpin,
{
    type Item =
        Result<TaggedEvent<SessionEvent<E::Key, <F::Parser as DatagramParser>::Message>>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.select.poll_next_select(cx) {
            Poll::Ready(Some((idx, Ok(event)))) => Poll::Ready(Some(Ok(TaggedEvent {
                source_idx: idx,
                event,
            }))),
            Poll::Ready(Some((_, Err(e)))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ── AsyncXdpMultiCapture entry points (issue #104) ───────────────

#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl super::multi_capture::AsyncXdpMultiCapture {
    /// Convert into an [`XdpMultiFlowStream`] yielding
    /// [`TaggedEvent`]`<FlowEvent<E::Key>>` from all interfaces — the AF_XDP
    /// analogue of
    /// [`AsyncMultiCapture::flow_stream`](super::multi_capture::AsyncMultiCapture::flow_stream).
    /// `extractor` is cloned
    /// per source; each interface keeps its own [`FlowTracker`].
    pub fn flow_stream<E>(self, extractor: E) -> XdpMultiFlowStream<E>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Clone + Unpin + Send + 'static,
    {
        self.flow_stream_with(extractor, super::multi_config::MultiStreamConfig::default())
    }

    /// Like [`flow_stream`](Self::flow_stream) but applies `config` to every
    /// inner per-source stream (tracker config, optional dedup, idle-timeout
    /// predicate, monotonic-timestamp clamping).
    pub fn flow_stream_with<E>(
        self,
        extractor: E,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> XdpMultiFlowStream<E>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Clone + Unpin + Send + 'static,
    {
        let (captures, labels) = self.into_captures();
        XdpMultiFlowStream::new_with_config(captures, labels, extractor, config)
    }

    /// Convert into an [`XdpMultiSessionStream`] — per-interface AF_XDP TCP
    /// session L7, fanned into one tagged stream.
    pub fn session_stream<E, F>(self, extractor: E, factory: F) -> XdpMultiSessionStream<E, F>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Eq + std::hash::Hash + Clone + Unpin + Send + 'static,
        F: SessionParserFactory<E::Key> + Clone + Unpin + Send + 'static,
        F::Parser: Unpin + Send + 'static,
        <F::Parser as SessionParser>::Message: Unpin + Send + 'static,
    {
        self.session_stream_with(
            extractor,
            factory,
            super::multi_config::MultiStreamConfig::default(),
        )
    }

    /// Like [`session_stream`](Self::session_stream) with `config`
    /// applied to every per-interface stream.
    pub fn session_stream_with<E, F>(
        self,
        extractor: E,
        factory: F,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> XdpMultiSessionStream<E, F>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Eq + std::hash::Hash + Clone + Unpin + Send + 'static,
        F: SessionParserFactory<E::Key> + Clone + Unpin + Send + 'static,
        F::Parser: Unpin + Send + 'static,
        <F::Parser as SessionParser>::Message: Unpin + Send + 'static,
    {
        let (captures, labels) = self.into_captures();
        XdpMultiSessionStream::new_with_config(captures, labels, extractor, factory, config)
    }

    /// Convert into an [`XdpMultiDatagramStream`] — per-interface AF_XDP UDP
    /// datagram L7, fanned into one tagged stream.
    pub fn datagram_stream<E, F>(self, extractor: E, factory: F) -> XdpMultiDatagramStream<E, F>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Eq + std::hash::Hash + Clone + Unpin + Send + 'static,
        F: DatagramParserFactory<E::Key> + Clone + Unpin + Send + 'static,
        F::Parser: Unpin + Send + 'static,
        <F::Parser as DatagramParser>::Message: Unpin + Send + 'static,
    {
        self.datagram_stream_with(
            extractor,
            factory,
            super::multi_config::MultiStreamConfig::default(),
        )
    }

    /// Like [`datagram_stream`](Self::datagram_stream) with `config`
    /// applied to every per-interface stream.
    pub fn datagram_stream_with<E, F>(
        self,
        extractor: E,
        factory: F,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> XdpMultiDatagramStream<E, F>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Eq + std::hash::Hash + Clone + Unpin + Send + 'static,
        F: DatagramParserFactory<E::Key> + Clone + Unpin + Send + 'static,
        F::Parser: Unpin + Send + 'static,
        <F::Parser as DatagramParser>::Message: Unpin + Send + 'static,
    {
        let (captures, labels) = self.into_captures();
        XdpMultiDatagramStream::new_with_config(captures, labels, extractor, factory, config)
    }

    /// **Tap merge** over AF_XDP: fan all interfaces into **one** shared
    /// [`FlowTracker`], coalescing the two legs of a tapped flow into a
    /// single bidirectional flow — the AF_XDP analogue of
    /// [`AsyncMultiCapture::merged_flow_stream`](super::multi_capture::AsyncMultiCapture::merged_flow_stream).
    /// Yields a plain [`FlowEvent<E::Key>`] (no `source_idx` envelope).
    /// Pass a **bidirectional** extractor. See [`MergedFlowStream`] for the
    /// capture-leg semantics (`source_idx_{forward,reverse}` /
    /// `capture_leg_inconsistent`).
    pub fn merged_flow_stream<E>(self, extractor: E) -> MergedFlowStream<crate::AsyncXdpCapture, E>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Clone + Unpin + Send + 'static,
    {
        self.merged_flow_stream_with(extractor, super::multi_config::MultiStreamConfig::default())
    }

    /// Like [`merged_flow_stream`](Self::merged_flow_stream) but applies
    /// `config` to the single shared tracker (including
    /// [`infer_tcp_initiator`](super::multi_config::MultiStreamConfig::with_infer_tcp_initiator),
    /// recommended on the merged tap path for race-robust TCP roles).
    pub fn merged_flow_stream_with<E>(
        self,
        extractor: E,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> MergedFlowStream<crate::AsyncXdpCapture, E>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Clone + Unpin + Send + 'static,
    {
        let (captures, labels) = self.into_captures();
        MergedFlowStream::new_with_config(captures, labels, extractor, config)
    }
}

// ── AsyncMultiCapture entry points ───────────────────────────────

impl super::multi_capture::AsyncMultiCapture {
    /// Convert into a [`MultiFlowStream`] yielding
    /// [`TaggedEvent`]`<FlowEvent<E::Key>>` from all sources.
    /// `extractor` is cloned per source.
    pub fn flow_stream<E>(self, extractor: E) -> MultiFlowStream<E>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Clone + Unpin + Send + 'static,
    {
        let (captures, labels) = self.into_captures();
        MultiFlowStream::new(captures, labels, extractor)
    }

    /// **Tap merge**: fan all sources into **one** shared
    /// [`FlowTracker`], coalescing the two legs of a tapped flow into a
    /// single bidirectional flow. Yields a plain [`FlowEvent<E::Key>`]
    /// (no `source_idx` envelope). Pass a **bidirectional** extractor.
    /// See [`MergedFlowStream`] for the capture-leg semantics.
    ///
    /// Contrast with [`flow_stream`](Self::flow_stream), which keeps
    /// sources distinct (one tracker each, `TaggedEvent`) — correct for
    /// a routing gateway, wrong for a tap.
    pub fn merged_flow_stream<E>(self, extractor: E) -> MergedFlowStream<AsyncCapture<Capture>, E>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Clone + Unpin + Send + 'static,
    {
        self.merged_flow_stream_with(extractor, super::multi_config::MultiStreamConfig::default())
    }

    /// Like [`merged_flow_stream`](Self::merged_flow_stream) but applies
    /// `config` to the single shared tracker (tracker config — including
    /// [`infer_tcp_initiator`](super::multi_config::MultiStreamConfig::with_infer_tcp_initiator)
    /// — one shared dedup, a shared idle-timeout predicate, and shared
    /// monotonic-timestamp clamping).
    pub fn merged_flow_stream_with<E>(
        self,
        extractor: E,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> MergedFlowStream<AsyncCapture<Capture>, E>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Clone + Unpin + Send + 'static,
    {
        let (captures, labels) = self.into_captures();
        MergedFlowStream::new_with_config(captures, labels, extractor, config)
    }

    /// Convert into a [`MultiSessionStream`].
    pub fn session_stream<E, F>(self, extractor: E, factory: F) -> MultiSessionStream<E, F>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Eq + std::hash::Hash + Clone + Unpin + Send + 'static,
        F: SessionParserFactory<E::Key> + Clone + Unpin + Send + 'static,
        F::Parser: Unpin + Send + 'static,
        <F::Parser as SessionParser>::Message: Unpin + Send + 'static,
    {
        let (captures, labels) = self.into_captures();
        MultiSessionStream::new(captures, labels, extractor, factory)
    }

    /// Convert into a [`MultiDatagramStream`].
    pub fn datagram_stream<E, F>(self, extractor: E, factory: F) -> MultiDatagramStream<E, F>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Eq + std::hash::Hash + Clone + Unpin + Send + 'static,
        F: DatagramParserFactory<E::Key> + Clone + Unpin + Send + 'static,
        F::Parser: Unpin + Send + 'static,
        <F::Parser as DatagramParser>::Message: Unpin + Send + 'static,
    {
        let (captures, labels) = self.into_captures();
        MultiDatagramStream::new(captures, labels, extractor, factory)
    }

    /// Like [`flow_stream`](Self::flow_stream) but applies `config`
    /// to every inner per-source stream (tracker config, optional
    /// dedup template cloned per source, optional shared
    /// idle-timeout predicate, optional monotonic-timestamp clamping).
    pub fn flow_stream_with<E>(
        self,
        extractor: E,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> MultiFlowStream<E>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Clone + Unpin + Send + 'static,
    {
        let (captures, labels) = self.into_captures();
        MultiFlowStream::new_with_config(captures, labels, extractor, config)
    }

    /// Like [`session_stream`](Self::session_stream) with per-source
    /// config applied at construction.
    pub fn session_stream_with<E, F>(
        self,
        extractor: E,
        factory: F,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> MultiSessionStream<E, F>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Eq + std::hash::Hash + Clone + Unpin + Send + 'static,
        F: SessionParserFactory<E::Key> + Clone + Unpin + Send + 'static,
        F::Parser: Unpin + Send + 'static,
        <F::Parser as SessionParser>::Message: Unpin + Send + 'static,
    {
        let (captures, labels) = self.into_captures();
        MultiSessionStream::new_with_config(captures, labels, extractor, factory, config)
    }

    /// Like [`datagram_stream`](Self::datagram_stream) with per-source
    /// config applied at construction.
    pub fn datagram_stream_with<E, F>(
        self,
        extractor: E,
        factory: F,
        config: super::multi_config::MultiStreamConfig<E::Key>,
    ) -> MultiDatagramStream<E, F>
    where
        E: FlowExtractor + Clone + Unpin + Send + 'static,
        E::Key: Eq + std::hash::Hash + Clone + Unpin + Send + 'static,
        F: DatagramParserFactory<E::Key> + Clone + Unpin + Send + 'static,
        F::Parser: Unpin + Send + 'static,
        <F::Parser as DatagramParser>::Message: Unpin + Send + 'static,
    {
        let (captures, labels) = self.into_captures();
        MultiDatagramStream::new_with_config(captures, labels, extractor, factory, config)
    }
}

#[cfg(test)]
mod merged_tests {
    //! Cap-free tests of the **merge invariant** that
    //! [`MergedFlowStream`] relies on: feeding both legs of a flow into
    //! one bidirectional-keyed [`FlowTracker`] (stamped with distinct
    //! `source_idx`, exactly as `poll_next` does) coalesces them into a
    //! single bidirectional flow and binds each canonical direction's
    //! capture leg. The live `poll_next` / AF_XDP plumbing is covered by
    //! the root-gated `lo` integration tests.

    use flowscope::extract::{FiveTuple, FiveTupleKey};
    use flowscope::{FlowEvent, FlowTracker, PacketView, Timestamp};

    /// Minimal Ethernet/IPv4/TCP frame for `src:sp -> dst:dp` with a
    /// 4-byte payload.
    fn tcp_frame(src: [u8; 4], sp: u16, dst: [u8; 4], dp: u16) -> Vec<u8> {
        let builder = etherparse::PacketBuilder::ethernet2([0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 2])
            .ipv4(src, dst, 64)
            .tcp(sp, dp, 1, 1000);
        let mut buf = Vec::with_capacity(builder.size(4));
        builder.write(&mut buf, &[1, 2, 3, 4]).unwrap();
        buf
    }

    fn feed(
        tracker: &mut FlowTracker<FiveTuple, ()>,
        frame: &[u8],
        source_idx: u32,
    ) -> Vec<FlowEvent<FiveTupleKey>> {
        let view = PacketView::new(frame, Timestamp::new(1, 0)).with_source_idx(source_idx);
        tracker.track(view).into_iter().collect()
    }

    #[test]
    fn two_legs_merge_into_one_flow_with_distinct_capture_legs() {
        let a = [10, 0, 0, 1];
        let b = [10, 0, 0, 2];
        let mut tracker = FlowTracker::new(FiveTuple::bidirectional());

        // Leg 1: a:40000 -> b:443 on source 1.
        let evts = feed(&mut tracker, &tcp_frame(a, 40000, b, 443), 1);
        let key = evts
            .iter()
            .find_map(|e| match e {
                FlowEvent::Started { key, .. } => Some(*key),
                _ => None,
            })
            .expect("a Started event for the first leg");

        // Leg 2: the *reverse* direction b:443 -> a:40000 on source 2.
        // Same canonical key, opposite orientation — must coalesce.
        let _ = feed(&mut tracker, &tcp_frame(b, 443, a, 40000), 2);

        assert_eq!(tracker.flows().count(), 1, "two legs must be one flow");

        let stats = tracker.snapshot_stats(&key).expect("live stats");
        assert!(
            stats.source_idx_forward.is_some() && stats.source_idx_reverse.is_some(),
            "both canonical directions should be leg-bound",
        );
        assert_ne!(
            stats.source_idx_forward, stats.source_idx_reverse,
            "the two legs arrived on different sources",
        );
        assert_eq!(
            [
                stats.source_idx_forward.unwrap(),
                stats.source_idx_reverse.unwrap()
            ]
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
            [1u32, 2u32].into_iter().collect(),
        );
        assert!(
            !stats.capture_leg_inconsistent,
            "consistent tap wiring — no inconsistency flag",
        );
    }

    #[test]
    fn mismatched_third_leg_trips_capture_leg_inconsistent() {
        let a = [10, 0, 0, 1];
        let b = [10, 0, 0, 2];
        let mut tracker = FlowTracker::new(FiveTuple::bidirectional());

        let evts = feed(&mut tracker, &tcp_frame(a, 40000, b, 443), 1);
        let key = evts
            .iter()
            .find_map(|e| match e {
                FlowEvent::Started { key, .. } => Some(*key),
                _ => None,
            })
            .unwrap();
        let _ = feed(&mut tracker, &tcp_frame(b, 443, a, 40000), 2);
        assert!(
            !tracker
                .snapshot_stats(&key)
                .unwrap()
                .capture_leg_inconsistent
        );

        // A later packet on the SAME wire direction as leg 1 but from a
        // *different* source (3) — the tap-miswire / asymmetric-routing
        // IOC. The original binding is kept; the flag flips.
        let _ = feed(&mut tracker, &tcp_frame(a, 40000, b, 443), 3);
        assert!(
            tracker
                .snapshot_stats(&key)
                .unwrap()
                .capture_leg_inconsistent,
            "a second, different leg for a bound direction must trip the flag",
        );
    }
}

#[cfg(all(test, feature = "pcap"))]
mod mixed_source_tests {
    //! One `MultiSessionStream` over a live-shaped source (the test
    //! `VecSource`) and a pcap replay pushed through `push_source`
    //! (#176 / #177): tagged events from both, per-source introspection
    //! through `MultiSource`, and the replay source kept — with its final
    //! counters — after end-of-file.

    use std::time::Duration;

    use flowscope::extract::FiveTuple;
    use flowscope::extract::parse::test_frames::ipv4_tcp;
    use flowscope::{SessionEvent, SessionParser, Timestamp};
    use futures::StreamExt;
    use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
    use pcap_file::{DataLink, Endianness, TsResolution};

    use super::{MultiFlowStream, MultiSessionStream};
    use crate::async_adapters::flow_source::VecSource;
    use crate::async_adapters::flow_stream::{FlowStream, current_timestamp};
    use crate::dedup::Dedup;
    use crate::pcap_source::AsyncPcapSource;

    #[derive(Clone, Default)]
    struct Len;
    impl SessionParser for Len {
        type Message = usize;
        fn feed_initiator(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<usize>) {
            out.push(b.len());
        }
        fn feed_responder(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<usize>) {
            out.push(b.len());
        }
    }

    /// Handshake + one client segment (+ FIN exchange when `close`),
    /// 1 ms apart from t = 1 s.
    fn tcp_flow(cp: u16, close: bool) -> Vec<(Duration, Vec<u8>)> {
        let (c, s) = ([10, 0, 0, 1], [10, 0, 0, 2]);
        let (sp, m) = (9_000, [0u8; 6]);
        let (cisn, sisn) = (1000u32, 5000u32);
        let mut v = vec![
            ipv4_tcp(m, m, c, s, cp, sp, cisn, 0, 0x02, &[]),
            ipv4_tcp(m, m, s, c, sp, cp, sisn, cisn + 1, 0x12, &[]),
            ipv4_tcp(m, m, c, s, cp, sp, cisn + 1, sisn + 1, 0x10, &[]),
            ipv4_tcp(m, m, c, s, cp, sp, cisn + 1, sisn + 1, 0x18, b"hello"),
        ];
        if close {
            let end = cisn + 6;
            v.push(ipv4_tcp(m, m, c, s, cp, sp, end, sisn + 1, 0x11, &[]));
            v.push(ipv4_tcp(m, m, s, c, sp, cp, sisn + 1, end + 1, 0x11, &[]));
            v.push(ipv4_tcp(m, m, c, s, cp, sp, end + 1, sisn + 2, 0x10, &[]));
        }
        v.into_iter()
            .enumerate()
            .map(|(i, f)| (Duration::from_millis(1_000 + i as u64), f))
            .collect()
    }

    fn write_pcap(dir: &std::path::Path, frames: &[(Duration, Vec<u8>)]) -> std::path::PathBuf {
        let path = dir.join("replay.pcap");
        let header = PcapHeader {
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: u32::MAX,
            datalink: DataLink::ETHERNET,
            ts_resolution: TsResolution::NanoSecond,
            endianness: Endianness::native(),
        };
        let mut w = PcapWriter::with_header(std::fs::File::create(&path).unwrap(), header).unwrap();
        for (ts, f) in frames {
            w.write_packet(&PcapPacket::new_owned(*ts, f.len() as u32, f.clone()))
                .unwrap();
        }
        path
    }

    fn assert_send<T: Send>() {}

    #[tokio::test(flavor = "current_thread")]
    async fn mixed_live_shaped_and_replay_sources() {
        assert_send::<MultiSessionStream<FiveTuple, Len>>();
        assert_send::<MultiFlowStream<FiveTuple>>();

        // Source 0: live-shaped; the flow stays open (no FIN).
        let now = current_timestamp();
        let live = FlowStream::new(
            VecSource(
                tcp_flow(40_000, false)
                    .into_iter()
                    .map(|(_, f)| (f, now))
                    .collect(),
            ),
            FiveTuple::bidirectional(),
        )
        .session_stream(Len);

        // Source 1: a replay with every frame twice, 50 µs apart.
        let dir = tempfile::tempdir().unwrap();
        let frames: Vec<_> = tcp_flow(50_000, true)
            .into_iter()
            .flat_map(|(t, f)| [(t, f.clone()), (t + Duration::from_micros(50), f)])
            .collect();
        let path = write_pcap(dir.path(), &frames);
        let replay = AsyncPcapSource::open(&path)
            .await
            .unwrap()
            .sessions(FiveTuple::bidirectional(), Len)
            .with_dedup(Dedup::content(Duration::from_millis(1), 64));

        let mut m = MultiSessionStream::<FiveTuple, Len>::empty();
        assert!(m.is_empty());
        assert_eq!(m.push_source("vec", live), 0);
        assert_eq!(m.push_source("replay", replay), 1);
        assert_eq!((m.len(), m.alive_sources()), (2, 2));
        assert_eq!(m.label(1), Some("replay"));

        let mut from_live = 0;
        let mut data_from_replay = 0;
        loop {
            let ev = tokio::time::timeout(Duration::from_secs(5), m.next())
                .await
                .expect("events keep coming")
                .expect("a live source never ends the stream")
                .unwrap();
            match (ev.source_idx, &ev.event) {
                (0, _) => from_live += 1,
                (1, SessionEvent::Application { .. }) => data_from_replay += 1,
                (1, SessionEvent::Closed { .. }) => break,
                (1, _) => {}
                _ => unreachable!("{ev:?}"),
            }
        }
        assert!(from_live >= 1, "the live-shaped source produced events");
        assert_eq!(
            data_from_replay, 1,
            "the duplicates never reached the parser"
        );

        // The next poll retires the replay source (end-of-file) and finds
        // the live one idle.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), m.next())
                .await
                .is_err()
        );
        assert_eq!(m.is_alive(0), Some(true));
        assert_eq!(m.is_alive(1), Some(false));
        assert_eq!(m.is_alive(2), None);
        assert_eq!(m.alive_sources(), 1);
        assert_eq!(m.len(), 2);

        // Introspection, finished source included.
        let s1 = m.source(1).expect("kept after EOF");
        assert_eq!(s1.tracker_stats().flows_ended, 1);
        assert_eq!(s1.active_flows(), 0);
        assert_eq!(s1.packets_read(), Some(frames.len() as u64));
        assert_eq!(s1.dedup().unwrap().dropped(), frames.len() as u64 / 2);
        assert!(s1.capture_stats().is_none());
        let s0 = m.source(0).unwrap();
        assert_eq!(s0.active_flows(), 1);
        assert!(s0.dedup().is_none());
        assert!(
            s0.capture_stats().is_none(),
            "no kernel ring behind a VecSource"
        );
        assert_eq!(s0.packets_read(), None);
        assert!(m.source(2).is_none());

        let snap = m.per_source_snapshot_flow_stats();
        assert_eq!(snap.len(), 2);
        assert_eq!((snap[0].0.as_str(), snap[0].1.len()), ("vec", 1));
        assert_eq!((snap[1].0.as_str(), snap[1].1.len()), ("replay", 0));
        let ts = m.per_source_tracker_stats();
        assert_eq!(ts[1].1.map(|t| t.flows_created), Some(1));
        assert!(
            m.per_source_capture_stats()
                .iter()
                .all(|(_, s)| s.is_none())
        );
        assert_eq!(m.total_active_flows(), 1);

        m.source_mut(1).unwrap().dedup_mut().unwrap().reset();
        assert_eq!(m.source(1).unwrap().dedup().unwrap().dropped(), 0);
    }
}
