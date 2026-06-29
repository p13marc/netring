//! [`MultiFlowStream`], [`MultiSessionStream`], [`MultiDatagramStream`]
//! — fan-in of N per-source streams into one tagged async stream.
//!
//! Construction goes through
//! [`AsyncMultiCapture::flow_stream`](super::multi_capture::AsyncMultiCapture::flow_stream)
//! and siblings. Internal round-robin polling avoids the
//! `futures::stream::select_all` dependency.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use flowscope::{
    DatagramParser, DatagramParserFactory, FlowEvent, FlowExtractor, FlowTracker, SessionParser,
    SessionParserFactory, Timestamp,
};
use futures_core::Stream;

use crate::async_adapters::session_event::SessionEvent;

use crate::Capture;
use crate::async_adapters::datagram_stream::DatagramStream;
use crate::async_adapters::flow_source::{AsyncFlowSource, DrainOutcome, SourcePacket};
use crate::async_adapters::flow_stream::{
    FlowStream, NoReassembler, clamp_now, clamp_view, current_timestamp,
};
use crate::async_adapters::session_stream::SessionStream;
use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::dedup::Dedup;
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
    select: SelectState<
        FlowStream<
            crate::async_adapters::tokio_adapter::AsyncCapture<Capture>,
            E,
            (),
            NoReassembler,
        >,
    >,
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
            .map(|cap| {
                let mut s = cap
                    .flow_stream(extractor.clone())
                    .with_config(config.tracker_config.clone());
                if let Some(d) = &config.dedup {
                    s = s.with_dedup(d.clone());
                }
                if let Some(f) = &config.idle_timeout_fn {
                    let f = f.clone();
                    s = s.with_idle_timeout_fn(move |k, l4| f(k, l4));
                }
                if config.monotonic_ts {
                    s = s.with_monotonic_timestamps(true);
                }
                s
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

    /// Per-source tracker stats. One entry per source, in order;
    /// `None` for sources that have ended.
    pub fn per_source_tracker_stats(&self) -> Vec<(String, Option<&flowscope::FlowTrackerStats>)> {
        self.select
            .streams
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                let label = self.labels[i].clone();
                let stats = slot.as_ref().map(|s| s.tracker_stats());
                (label, stats)
            })
            .collect()
    }

    /// Sum of live flow counts across all sources. O(n × per-source LRU).
    pub fn total_active_flows(&self) -> usize {
        self.select
            .streams
            .iter()
            .filter_map(|slot| slot.as_ref())
            .map(|s| s.active_flows())
            .sum()
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
#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
pub struct XdpMultiFlowStream<E>
where
    E: FlowExtractor,
{
    select: SelectState<FlowStream<crate::AsyncXdpCapture, E, (), NoReassembler>>,
    labels: Vec<String>,
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
            .map(|cap| {
                let mut s = cap
                    .flow_stream(extractor.clone())
                    .with_config(config.tracker_config.clone());
                if let Some(d) = &config.dedup {
                    s = s.with_dedup(d.clone());
                }
                if let Some(f) = &config.idle_timeout_fn {
                    let f = f.clone();
                    s = s.with_idle_timeout_fn(move |k, l4| f(k, l4));
                }
                if config.monotonic_ts {
                    s = s.with_monotonic_timestamps(true);
                }
                s
            })
            .collect();
        Self {
            select: SelectState::new(streams),
            labels,
        }
    }

    /// Human-readable label (interface name) for `source_idx`.
    pub fn label(&self, source_idx: u16) -> Option<&str> {
        self.labels.get(source_idx as usize).map(|s| s.as_str())
    }

    /// Number of sources still being polled.
    pub fn alive_sources(&self) -> usize {
        self.select.alive_count()
    }

    /// Per-source kernel-ring stats (summed across each capture's RX queues).
    /// One entry per interface, in order; `None` for ended sources.
    pub fn per_source_capture_stats(&self) -> Vec<(String, Option<Result<CaptureStats, Error>>)> {
        self.select
            .streams
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                let label = self.labels[i].clone();
                (label, slot.as_ref().map(|s| s.capture_stats()))
            })
            .collect()
    }

    /// Aggregate kernel-ring stats across all live sources.
    pub fn capture_stats(&self) -> CaptureStats {
        let mut acc = CaptureStats::default();
        for slot in self.select.streams.iter().flatten() {
            if let Ok(stats) = slot.capture_stats() {
                acc.packets = acc.packets.saturating_add(stats.packets);
                acc.drops = acc.drops.saturating_add(stats.drops);
                acc.freeze_count = acc.freeze_count.saturating_add(stats.freeze_count);
            }
        }
        acc
    }

    /// Per-source tracker stats. One entry per interface, in order.
    pub fn per_source_tracker_stats(&self) -> Vec<(String, Option<&flowscope::FlowTrackerStats>)> {
        self.select
            .streams
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                let label = self.labels[i].clone();
                (label, slot.as_ref().map(|s| s.tracker_stats()))
            })
            .collect()
    }

    /// Sum of live flow counts across all sources.
    pub fn total_active_flows(&self) -> usize {
        self.select
            .streams
            .iter()
            .filter_map(|slot| slot.as_ref())
            .map(|s| s.active_flows())
            .sum()
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
// SelectState round-robin. Per-source capture-stats come from the inherent
// AF_XDP accessor (StreamCapture is AF_PACKET-only).

/// Tagged fan-in of AF_XDP [`SessionStream`]s (issue #104).
#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
pub struct XdpMultiSessionStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    select: SelectState<SessionStream<crate::AsyncXdpCapture, E, F>>,
    labels: Vec<String>,
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
                let mut s = cap.flow_stream(extractor.clone());
                if let Some(d) = &config.dedup {
                    s = s.with_dedup(d.clone());
                }
                if let Some(f) = &config.idle_timeout_fn {
                    let f = f.clone();
                    s = s.with_idle_timeout_fn(move |k, l4| f(k, l4));
                }
                if config.monotonic_ts {
                    s = s.with_monotonic_timestamps(true);
                }
                s.with_config(config.tracker_config.clone())
                    .session_stream(factory.clone())
            })
            .collect();
        Self {
            select: SelectState::new(streams),
            labels,
        }
    }

    /// Label (interface name) for `source_idx`.
    pub fn label(&self, source_idx: u16) -> Option<&str> {
        self.labels.get(source_idx as usize).map(|s| s.as_str())
    }

    /// Number of sources still being polled.
    pub fn alive_sources(&self) -> usize {
        self.select.alive_count()
    }

    /// Per-source kernel-ring stats (summed across each capture's RX queues).
    pub fn per_source_capture_stats(&self) -> Vec<(String, Option<Result<CaptureStats, Error>>)> {
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

    /// Per-source tracker stats.
    pub fn per_source_tracker_stats(&self) -> Vec<(String, Option<&flowscope::FlowTrackerStats>)> {
        self.select
            .streams
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                (
                    self.labels[i].clone(),
                    slot.as_ref().map(|s| s.tracker_stats()),
                )
            })
            .collect()
    }

    /// Sum of live flow counts across all sources.
    pub fn total_active_flows(&self) -> usize {
        self.select
            .streams
            .iter()
            .filter_map(|slot| slot.as_ref())
            .map(|s| s.active_flows())
            .sum()
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
#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
pub struct XdpMultiDatagramStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: DatagramParserFactory<E::Key>,
{
    select: SelectState<DatagramStream<crate::AsyncXdpCapture, E, F>>,
    labels: Vec<String>,
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
                let mut s = cap.flow_stream(extractor.clone());
                if let Some(d) = &config.dedup {
                    s = s.with_dedup(d.clone());
                }
                if let Some(f) = &config.idle_timeout_fn {
                    let f = f.clone();
                    s = s.with_idle_timeout_fn(move |k, l4| f(k, l4));
                }
                if config.monotonic_ts {
                    s = s.with_monotonic_timestamps(true);
                }
                s.with_config(config.tracker_config.clone())
                    .datagram_stream(factory.clone())
            })
            .collect();
        Self {
            select: SelectState::new(streams),
            labels,
        }
    }

    /// Label (interface name) for `source_idx`.
    pub fn label(&self, source_idx: u16) -> Option<&str> {
        self.labels.get(source_idx as usize).map(|s| s.as_str())
    }

    /// Number of sources still being polled.
    pub fn alive_sources(&self) -> usize {
        self.select.alive_count()
    }

    /// Per-source kernel-ring stats (summed across each capture's RX queues).
    pub fn per_source_capture_stats(&self) -> Vec<(String, Option<Result<CaptureStats, Error>>)> {
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

    /// Per-source tracker stats.
    pub fn per_source_tracker_stats(&self) -> Vec<(String, Option<&flowscope::FlowTrackerStats>)> {
        self.select
            .streams
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                (
                    self.labels[i].clone(),
                    slot.as_ref().map(|s| s.tracker_stats()),
                )
            })
            .collect()
    }

    /// Sum of live flow counts across all sources.
    pub fn total_active_flows(&self) -> usize {
        self.select
            .streams
            .iter()
            .filter_map(|slot| slot.as_ref())
            .map(|s| s.active_flows())
            .sum()
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

    /// Borrow-iterator over live `(K, FlowStats)` pairs of the merged
    /// tracker — the capture-leg fields (`source_idx_forward` /
    /// `source_idx_reverse` / `capture_leg_inconsistent`) are readable
    /// here mid-stream.
    pub fn snapshot_flow_stats(
        &self,
    ) -> impl Iterator<Item = (&E::Key, &flowscope::FlowStats)> + '_ {
        self.tracker.iter_active().map(|af| (af.key, af.stats))
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

/// Tagged fan-in of [`SessionStream`]s.
pub struct MultiSessionStream<E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    select: SelectState<
        SessionStream<crate::async_adapters::tokio_adapter::AsyncCapture<Capture>, E, F>,
    >,
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
                let mut s = cap.flow_stream(extractor.clone());
                if let Some(d) = &config.dedup {
                    s = s.with_dedup(d.clone());
                }
                if let Some(f) = &config.idle_timeout_fn {
                    let f = f.clone();
                    s = s.with_idle_timeout_fn(move |k, l4| f(k, l4));
                }
                if config.monotonic_ts {
                    s = s.with_monotonic_timestamps(true);
                }
                s.with_config(config.tracker_config.clone())
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

    /// Per-source tracker stats. See
    /// [`MultiFlowStream::per_source_tracker_stats`].
    pub fn per_source_tracker_stats(&self) -> Vec<(String, Option<&flowscope::FlowTrackerStats>)> {
        self.select
            .streams
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                let label = self.labels[i].clone();
                let stats = slot.as_ref().map(|s| s.tracker_stats());
                (label, stats)
            })
            .collect()
    }

    /// Sum of live flow counts across all sources.
    pub fn total_active_flows(&self) -> usize {
        self.select
            .streams
            .iter()
            .filter_map(|slot| slot.as_ref())
            .map(|s| s.active_flows())
            .sum()
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
    select: SelectState<
        DatagramStream<crate::async_adapters::tokio_adapter::AsyncCapture<Capture>, E, F>,
    >,
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
                let mut s = cap.flow_stream(extractor.clone());
                if let Some(d) = &config.dedup {
                    s = s.with_dedup(d.clone());
                }
                if let Some(f) = &config.idle_timeout_fn {
                    let f = f.clone();
                    s = s.with_idle_timeout_fn(move |k, l4| f(k, l4));
                }
                if config.monotonic_ts {
                    s = s.with_monotonic_timestamps(true);
                }
                s.with_config(config.tracker_config.clone())
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

    /// Per-source tracker stats. See
    /// [`MultiFlowStream::per_source_tracker_stats`].
    pub fn per_source_tracker_stats(&self) -> Vec<(String, Option<&flowscope::FlowTrackerStats>)> {
        self.select
            .streams
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                let label = self.labels[i].clone();
                let stats = slot.as_ref().map(|s| s.tracker_stats());
                (label, stats)
            })
            .collect()
    }

    /// Sum of live flow counts across all sources.
    pub fn total_active_flows(&self) -> usize {
        self.select
            .streams
            .iter()
            .filter_map(|slot| slot.as_ref())
            .map(|s| s.active_flows())
            .sum()
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
        let (captures, labels) = self.into_captures();
        XdpMultiSessionStream::new_with_config(
            captures,
            labels,
            extractor,
            factory,
            super::multi_config::MultiStreamConfig::default(),
        )
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
        let (captures, labels) = self.into_captures();
        XdpMultiDatagramStream::new_with_config(
            captures,
            labels,
            extractor,
            factory,
            super::multi_config::MultiStreamConfig::default(),
        )
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
