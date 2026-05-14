//! [`MultiFlowStream`], [`MultiSessionStream`], [`MultiDatagramStream`]
//! — fan-in of N per-source streams into one tagged async stream.
//!
//! Construction goes through
//! [`AsyncMultiCapture::flow_stream`](super::multi_capture::AsyncMultiCapture::flow_stream)
//! and siblings. Internal round-robin polling avoids the
//! `futures::stream::select_all` dependency.

use std::pin::Pin;
use std::task::{Context, Poll};

use flowscope::{
    DatagramParser, DatagramParserFactory, FlowEvent, FlowExtractor, SessionEvent, SessionParser,
    SessionParserFactory,
};
use futures_core::Stream;

use crate::Capture;
use crate::async_adapters::datagram_stream::DatagramStream;
use crate::async_adapters::flow_stream::{FlowStream, NoReassembler};
use crate::async_adapters::session_stream::SessionStream;
use crate::error::Error;
use crate::stats::CaptureStats;

/// An event annotated with the source it came from within an
/// [`AsyncMultiCapture`](super::multi_capture::AsyncMultiCapture).
///
/// `source_idx` is an index into the multi-capture's source list
/// (0..[`len()`](super::multi_capture::AsyncMultiCapture::len)).
/// Map it back to a human-readable label via
/// [`MultiFlowStream::label`] (or the sibling methods).
#[derive(Debug, Clone)]
pub struct TaggedEvent<E> {
    /// Index of the source within the multi-capture.
    pub source_idx: u16,
    /// The underlying event payload.
    pub event: E,
}

// ── select_state ─────────────────────────────────────────────────
//
// Round-robin select over a Vec of pinned, owned streams. None-out
// exhausted slots so indices stay stable for stats access.

struct SelectState<S> {
    streams: Vec<Option<S>>,
    /// Index to start polling at — incremented each yield for fairness.
    next: usize,
}

impl<S> SelectState<S> {
    fn new(streams: Vec<S>) -> Self {
        Self {
            streams: streams.into_iter().map(Some).collect(),
            next: 0,
        }
    }

    fn alive_count(&self) -> usize {
        self.streams.iter().filter(|s| s.is_some()).count()
    }
}

impl<S, T> SelectState<S>
where
    S: Stream<Item = Result<T, Error>> + Unpin,
{
    /// Poll all alive streams in round-robin order. Yields the first
    /// `Ready` (Item or Err). Drops `None` slots; returns
    /// `Poll::Ready(None)` when all slots are exhausted.
    fn poll_next_select(&mut self, cx: &mut Context<'_>) -> Poll<Option<(u16, Result<T, Error>)>> {
        let n = self.streams.len();
        if n == 0 {
            return Poll::Ready(None);
        }
        let mut any_alive = false;
        for offset in 0..n {
            let i = (self.next + offset) % n;
            let Some(stream) = self.streams[i].as_mut() else {
                continue;
            };
            any_alive = true;
            match Pin::new(stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    self.next = (i + 1) % n;
                    return Poll::Ready(Some((i as u16, item)));
                }
                Poll::Ready(None) => {
                    // Stream exhausted — None it out; keep iterating
                    // in case another slot is also ready this tick.
                    self.streams[i] = None;
                }
                Poll::Pending => {}
            }
        }
        if any_alive {
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }
}

// ── MultiFlowStream ──────────────────────────────────────────────

/// Tagged fan-in of [`FlowStream`]s.
pub struct MultiFlowStream<E>
where
    E: FlowExtractor,
{
    select: SelectState<FlowStream<Capture, E, (), NoReassembler>>,
    labels: Vec<String>,
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
        let streams = captures
            .into_iter()
            .map(|cap| cap.flow_stream(extractor.clone()))
            .collect();
        Self {
            select: SelectState::new(streams),
            labels,
        }
    }

    /// Human-readable label for `source_idx`.
    pub fn label(&self, source_idx: u16) -> Option<&str> {
        self.labels.get(source_idx as usize).map(|s| s.as_str())
    }

    /// Number of sources still being polled (haven't returned `None`
    /// from their inner stream). Decrements as sources exhaust.
    pub fn alive_sources(&self) -> usize {
        self.select.alive_count()
    }

    /// Per-source kernel ring stats. One entry per source, in order;
    /// sources that have ended return `None`, sources whose
    /// `getsockopt` failed return `Err`.
    pub fn per_source_capture_stats(&self) -> Vec<(String, Option<Result<CaptureStats, Error>>)> {
        use crate::async_adapters::stream_capture::StreamCapture;
        self.select
            .streams
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                let label = self.labels[i].clone();
                let stats = slot.as_ref().map(|s| s.capture_stats());
                (label, stats)
            })
            .collect()
    }

    /// Aggregate kernel ring stats across all live sources.
    /// `Err` from any individual source is silently skipped — use
    /// [`per_source_capture_stats`](Self::per_source_capture_stats)
    /// for fine-grained inspection.
    /// Aggregate kernel ring stats. See
    /// [`MultiFlowStream::capture_stats`].
    pub fn capture_stats(&self) -> CaptureStats {
        use crate::async_adapters::stream_capture::StreamCapture;
        let mut acc = CaptureStats::default();
        for slot in &self.select.streams {
            if let Some(s) = slot
                && let Ok(stats) = s.capture_stats()
            {
                acc.packets = acc.packets.saturating_add(stats.packets);
                acc.drops = acc.drops.saturating_add(stats.drops);
                acc.freeze_count = acc.freeze_count.saturating_add(stats.freeze_count);
            }
        }
        acc
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

// ── MultiSessionStream ───────────────────────────────────────────

/// Tagged fan-in of [`SessionStream`]s.
pub struct MultiSessionStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    select: SelectState<SessionStream<Capture, E, F>>,
    labels: Vec<String>,
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
        let streams = captures
            .into_iter()
            .map(|cap| {
                cap.flow_stream(extractor.clone())
                    .session_stream(factory.clone())
            })
            .collect();
        Self {
            select: SelectState::new(streams),
            labels,
        }
    }

    /// Human-readable label for `source_idx`.
    pub fn label(&self, source_idx: u16) -> Option<&str> {
        self.labels.get(source_idx as usize).map(|s| s.as_str())
    }

    /// Number of sources still being polled (haven't returned `None`
    /// from their inner stream). Decrements as sources exhaust.
    pub fn alive_sources(&self) -> usize {
        self.select.alive_count()
    }

    /// Per-source kernel ring stats. See
    /// [`MultiFlowStream::per_source_capture_stats`].
    pub fn per_source_capture_stats(&self) -> Vec<(String, Option<Result<CaptureStats, Error>>)> {
        use crate::async_adapters::stream_capture::StreamCapture;
        self.select
            .streams
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                (
                    self.labels[i].clone(),
                    slot.as_ref().map(|s| s.capture_stats()),
                )
            })
            .collect()
    }

    /// Aggregate kernel ring stats. See
    /// [`MultiFlowStream::capture_stats`].
    pub fn capture_stats(&self) -> CaptureStats {
        use crate::async_adapters::stream_capture::StreamCapture;
        let mut acc = CaptureStats::default();
        for slot in &self.select.streams {
            if let Some(s) = slot
                && let Ok(stats) = s.capture_stats()
            {
                acc.packets = acc.packets.saturating_add(stats.packets);
                acc.drops = acc.drops.saturating_add(stats.drops);
                acc.freeze_count = acc.freeze_count.saturating_add(stats.freeze_count);
            }
        }
        acc
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

/// Tagged fan-in of [`DatagramStream`]s.
pub struct MultiDatagramStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: DatagramParserFactory<E::Key>,
{
    select: SelectState<DatagramStream<Capture, E, F>>,
    labels: Vec<String>,
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
        let streams = captures
            .into_iter()
            .map(|cap| {
                cap.flow_stream(extractor.clone())
                    .datagram_stream(factory.clone())
            })
            .collect();
        Self {
            select: SelectState::new(streams),
            labels,
        }
    }

    /// Human-readable label for `source_idx`.
    pub fn label(&self, source_idx: u16) -> Option<&str> {
        self.labels.get(source_idx as usize).map(|s| s.as_str())
    }

    /// Number of sources still being polled (haven't returned `None`
    /// from their inner stream). Decrements as sources exhaust.
    pub fn alive_sources(&self) -> usize {
        self.select.alive_count()
    }

    /// Per-source kernel ring stats. See
    /// [`MultiFlowStream::per_source_capture_stats`].
    pub fn per_source_capture_stats(&self) -> Vec<(String, Option<Result<CaptureStats, Error>>)> {
        use crate::async_adapters::stream_capture::StreamCapture;
        self.select
            .streams
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                (
                    self.labels[i].clone(),
                    slot.as_ref().map(|s| s.capture_stats()),
                )
            })
            .collect()
    }

    /// Aggregate kernel ring stats. See
    /// [`MultiFlowStream::capture_stats`].
    pub fn capture_stats(&self) -> CaptureStats {
        use crate::async_adapters::stream_capture::StreamCapture;
        let mut acc = CaptureStats::default();
        for slot in &self.select.streams {
            if let Some(s) = slot
                && let Ok(stats) = s.capture_stats()
            {
                acc.packets = acc.packets.saturating_add(stats.packets);
                acc.drops = acc.drops.saturating_add(stats.drops);
                acc.freeze_count = acc.freeze_count.saturating_add(stats.freeze_count);
            }
        }
        acc
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
}
