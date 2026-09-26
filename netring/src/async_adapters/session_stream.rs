//! [`SessionStream`] — async stream of typed L7 messages.
//!
//! An async front for flowscope's [`flowscope::SessionDriver`]: packets
//! from an [`AsyncCapture`] (or an AF_XDP capture) go through
//! netring's optional dedup / pcap tap / timestamp clamp, then into the
//! driver, which tracks flows, reassembles TCP (out-of-order hole fill,
//! explicit gaps, size limits) and runs a per-flow [`SessionParser`].
//! The stream yields the driver's [`SessionEvent`]s in order.
//!
//! Because it *is* flowscope's engine, the stream behaves exactly like
//! [`PcapSessionStream`](crate::PcapSessionStream) and the typed
//! `flowscope::driver::Driver` (and so netring's `Monitor`):
//!
//! - A parser that reports `is_poisoned()` / `is_done()` is closed —
//!   [`SessionEvent::ParserClosed`] with [`EndReason::ParseError`](flowscope::EndReason::ParseError) /
//!   [`EndReason::ParserDone`](flowscope::EndReason::ParserDone) and its reason in `detail` — and never
//!   fed again for that flow. The flow stays tracked and ends later
//!   with [`SessionEvent::Closed`].
//! - Bytes that never arrived are reported to the parser through
//!   [`SessionParser::on_gap`]; the default answer closes it with
//!   [`EndReason::StreamGap`](flowscope::EndReason::StreamGap).
//! - Under [`FlowTrackerConfig::max_reassembler_buffer`] +
//!   [`OverflowPolicy::DropFlow`](flowscope::OverflowPolicy::DropFlow),
//!   a side that exceeds the cap stops being reassembled and the parser
//!   is closed with [`EndReason::BufferOverflow`](flowscope::EndReason::BufferOverflow). The flow is **not**
//!   ended (its later packets would otherwise start a new flow
//!   mid-stream); its final `Closed.stats` records
//!   `reassembly_stop_{initiator,responder}`.
//! - `Closed.stats` and [`SessionStream::snapshot_flow_stats`] include
//!   the reassembly diagnostics (gaps, retransmits, peak buffer, …).
//! - [`SessionStream::with_emit_anomalies`] adds
//!   [`SessionEvent::FlowAnomaly`] / [`SessionEvent::TrackerAnomaly`].
//!
//! ```no_run
//! # use futures::StreamExt;
//! # use netring::AsyncCapture;
//! # use netring::flow::extract::FiveTuple;
//! # use flowscope::{FlowSide, SessionParser, Timestamp};
//! # use netring::flow::SessionEvent;
//! # #[derive(Default, Clone)]
//! # struct MyParser;
//! # impl SessionParser for MyParser {
//! #     type Message = ();
//! #     fn feed_initiator(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
//! #     fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
//! # }
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let cap = AsyncCapture::open("eth0")?;
//! let mut s = cap
//!     .flow_stream(FiveTuple::bidirectional())
//!     .session_stream(MyParser);
//! while let Some(evt) = s.next().await {
//!     match evt? {
//!         SessionEvent::Application { message, .. } => { let _ = message; }
//!         SessionEvent::ParserClosed { reason, detail, .. } => { let _ = (reason, detail); }
//!         _ => {}
//!     }
//! }
//! # Ok(()) }
//! ```

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use flowscope::{
    FlowExtractor, FlowStats, FlowTracker, FlowTrackerConfig, SessionDriver, SessionEvent,
    SessionParser, SessionParserFactory, Timestamp,
};
use futures_core::Stream;

use crate::async_adapters::flow_source::{AsyncFlowSource, DrainOutcome, SourcePacket};
use crate::async_adapters::flow_stream::{clamp_now, clamp_view, current_timestamp};
use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::dedup::Dedup;
use crate::error::Error;
use crate::traits::PacketSource;

/// Async stream of [`SessionEvent`]s from a per-flow
/// [`SessionParser`] over reassembled TCP. See the
/// [module docs](self).
///
/// Generic over the packet source `C` (issue #104): an [`AsyncCapture`]
/// (AF_PACKET) or an [`AsyncXdpCapture`](crate::AsyncXdpCapture) (AF_XDP),
/// driven through the shared `AsyncFlowSource` drain.
pub struct SessionStream<C, E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    cap: C,
    driver: SessionDriver<E, F>,
    pending: VecDeque<SessionEvent<E::Key, <F::Parser as SessionParser>::Message>>,
    scratch: Vec<SessionEvent<E::Key, <F::Parser as SessionParser>::Message>>,
    sweep: tokio::time::Interval,
    dedup: Option<Dedup>,
    /// Monotonic-timestamp clamp state (`None` = off).
    monotonic_ts: Option<Timestamp>,
    /// Optional pcap tap (records each packet to disk before
    /// reassembly + parsing).
    #[cfg(feature = "pcap")]
    tap: Option<crate::pcap_tap::PcapTap>,
}

impl<C, E, F> SessionStream<C, E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    /// Move an existing [`FlowTracker`] into a `SessionStream` without
    /// rebuilding it. Preserves `idle_timeout_fn`, config and any
    /// in-flight flow state from the source `FlowStream`.
    pub(crate) fn from_tracker(
        cap: C,
        tracker: FlowTracker<E, ()>,
        parser_factory: F,
        dedup: Option<Dedup>,
        monotonic_ts: Option<Timestamp>,
        #[cfg(feature = "pcap")] tap: Option<crate::pcap_tap::PcapTap>,
    ) -> Self {
        let sweep = tokio::time::interval(tracker.config().sweep_interval);
        Self {
            cap,
            driver: SessionDriver::from_tracker(tracker, parser_factory),
            pending: VecDeque::new(),
            scratch: Vec::new(),
            sweep,
            dedup,
            monotonic_ts,
            #[cfg(feature = "pcap")]
            tap,
        }
    }

    /// Replace the config (flow table and reassembly limits) in place.
    ///
    /// Re-arms the sweep timer if `sweep_interval` changed. New flows
    /// pick up the new reassembly limits; live ones keep theirs.
    pub fn with_config(mut self, config: FlowTrackerConfig) -> Self {
        self.sweep = tokio::time::interval(config.sweep_interval);
        self.driver.set_config(config);
        self
    }

    /// Emit [`SessionEvent::FlowAnomaly`] / [`SessionEvent::TrackerAnomaly`]:
    /// reassembly gaps, buffer overflows, retransmits, overlap
    /// inconsistencies, parser poison
    /// ([`flowscope::AnomalyKind::SessionParseError`]), eviction and
    /// memcap pressure. Default: off.
    pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
        self.driver.set_emit_anomalies(enable);
        self
    }

    /// Apply per-packet deduplication before flow tracking. Useful for
    /// capturing on `lo` where each packet appears twice
    /// ([`PACKET_OUTGOING`](crate::PacketDirection::Outgoing) +
    /// [`PACKET_HOST`](crate::PacketDirection::Host)); pair with
    /// [`Dedup::loopback`](crate::Dedup::loopback).
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

    /// Borrow the flow table (stats / introspection).
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        self.driver.tracker()
    }

    /// Borrow the underlying flowscope driver.
    pub fn driver(&self) -> &SessionDriver<E, F> {
        &self.driver
    }

    /// Override the per-flow idle timeout via a key predicate. See
    /// [`FlowStream::with_idle_timeout_fn`](super::flow_stream::FlowStream::with_idle_timeout_fn).
    /// Parser state lives exactly as long as its flow, so this also
    /// decides when a parser is reset.
    pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
    where
        G: Fn(&E::Key, Option<flowscope::L4Proto>) -> Option<std::time::Duration>
            + Send
            + Sync
            + 'static,
    {
        self.driver.set_idle_timeout_fn(f);
        self
    }

    /// Clamp NIC-supplied timestamps to a running max so the event
    /// stream is strictly non-decreasing in time. See
    /// [`FlowStream::with_monotonic_timestamps`](super::flow_stream::FlowStream::with_monotonic_timestamps).
    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.monotonic_ts = enable.then(Timestamp::default);
        self
    }

    /// Live `(key, stats)` for every tracked flow, **including the
    /// reassembly diagnostics** (gaps, retransmits, peak buffer,
    /// oversize drops, stop).
    pub fn snapshot_flow_stats(&self) -> impl Iterator<Item = (E::Key, FlowStats)> + '_ {
        self.driver.snapshot_flow_stats()
    }

    /// Cumulative tracker counters: `flows_created`, `flows_ended`,
    /// `flows_evicted`, `packets_unmatched`.
    pub fn tracker_stats(&self) -> &flowscope::FlowTrackerStats {
        self.driver.tracker().stats()
    }

    /// Count of live flow entries.
    pub fn active_flows(&self) -> usize {
        self.driver.tracker().flow_count()
    }

    /// Tap every captured packet into `writer` before reassembly +
    /// parsing. Default error policy:
    /// [`TapErrorPolicy::Continue`](crate::pcap_tap::TapErrorPolicy::Continue).
    #[cfg(feature = "pcap")]
    pub fn with_pcap_tap<W>(self, writer: crate::pcap::CaptureWriter<W>) -> Self
    where
        W: std::io::Write + Send + 'static,
    {
        self.with_pcap_tap_policy(writer, crate::pcap_tap::TapErrorPolicy::default())
    }

    /// Variant of [`with_pcap_tap`](Self::with_pcap_tap) with an
    /// explicit [`TapErrorPolicy`](crate::pcap_tap::TapErrorPolicy).
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

    /// Cap the recorded frame size on the pcap tap. See
    /// [`FlowStream::with_pcap_tap_snaplen`](super::flow_stream::FlowStream::with_pcap_tap_snaplen).
    #[cfg(feature = "pcap")]
    pub fn with_pcap_tap_snaplen(mut self, snaplen: u32) -> Self {
        if let Some(tap) = self.tap.as_mut() {
            tap.set_snaplen(snaplen);
        }
        self
    }
}

/// AF_XDP-source accessors (issue #104) — the analogues of the AF_PACKET
/// `StreamCapture` accessors, which the AF_XDP source can't satisfy.
#[cfg(all(feature = "af-xdp", feature = "xdp-loader"))]
impl<E, F> SessionStream<crate::AsyncXdpCapture, E, F>
where
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    /// Borrow the inner multi-queue AF_XDP capture.
    pub fn xdp_capture(&self) -> &crate::AsyncXdpCapture {
        &self.cap
    }

    /// Unified kernel-ring stats summed across the capture's RX queues.
    pub fn capture_stats(&self) -> Result<crate::stats::CaptureStats, Error> {
        self.cap.capture_stats()
    }
}

impl<C, E, F> Stream for SessionStream<C, E, F>
where
    C: AsyncFlowSource + Unpin,
    E: FlowExtractor + Unpin,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static + Unpin,
    F: SessionParserFactory<E::Key> + Unpin,
    F::Parser: Unpin,
    <F::Parser as SessionParser>::Message: Unpin,
{
    type Item = Result<SessionEvent<E::Key, <F::Parser as SessionParser>::Message>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(ev) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(ev)));
            }

            if this.sweep.poll_tick(cx).is_ready() {
                let now = clamp_now(current_timestamp(), &mut this.monotonic_ts);
                this.driver.sweep_into(now, &mut this.scratch);
                this.pending.extend(this.scratch.drain(..));
                if !this.pending.is_empty() {
                    continue;
                }
            }

            // Disjoint field borrows so the sink closure can feed the
            // driver while `cap` is borrowed by `poll_drain`.
            let cap = &mut this.cap;
            let driver = &mut this.driver;
            let scratch = &mut this.scratch;
            let dedup = &mut this.dedup;
            let monotonic_ts = &mut this.monotonic_ts;
            #[cfg(feature = "pcap")]
            let tap = &mut this.tap;
            #[cfg(feature = "pcap")]
            let mut tap_error: Option<Error> = None;

            let outcome = cap.poll_drain(cx, &mut |sp: SourcePacket<'_>| {
                // Optional pre-tracking dedup (on the unclamped ts).
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

                driver.track_into(clamp_view(sp.view, monotonic_ts), scratch);
            });
            this.pending.extend(this.scratch.drain(..));

            match outcome {
                Poll::Pending => {
                    if !this.pending.is_empty() {
                        continue;
                    }
                    return Poll::Pending;
                }
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

// ── StreamCapture trait impl ───────────────────────────────────────

use crate::async_adapters::stream_capture::{Sealed, StreamCapture};

// `StreamCapture` (and `capture()` → `&AsyncCapture<S>`) is AF_PACKET-only;
// the AF_XDP source has no `AsyncCapture` to lend.
impl<S, E, F> Sealed for SessionStream<AsyncCapture<S>, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
}

impl<S, E, F> StreamCapture for SessionStream<AsyncCapture<S>, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    type Source = S;

    fn capture(&self) -> &AsyncCapture<S> {
        &self.cap
    }

    fn dedup(&self) -> Option<&crate::dedup::Dedup> {
        self.dedup.as_ref()
    }

    fn dedup_mut(&mut self) -> Option<&mut crate::dedup::Dedup> {
        self.dedup.as_mut()
    }
}
