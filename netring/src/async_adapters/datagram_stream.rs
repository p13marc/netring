//! [`DatagramStream`] — async stream of typed L7 messages from
//! packet-oriented protocols (DNS-over-UDP, syslog, NTP).
//!
//! Wraps an [`AsyncCapture`] + [`FlowTracker`] + a per-flow
//! [`DatagramParser`]. Packets are fed individually (no
//! reassembly); the parser receives the L4 payload and the
//! direction relative to the flow's initiator.
//!
//! ```no_run
//! # use futures::StreamExt;
//! # use netring::AsyncCapture;
//! # use netring::flow::extract::FiveTuple;
//! # use flowscope::{DatagramParser, FlowSide, SessionEvent};
//! # #[derive(Default, Clone)]
//! # struct MyParser;
//! # impl DatagramParser for MyParser {
//! #     type Message = ();
//! #     fn parse(&mut self, _: &[u8], _: FlowSide) -> Vec<()> { Vec::new() }
//! # }
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let cap = AsyncCapture::open("eth0")?;
//! let mut s = cap
//!     .flow_stream(FiveTuple::bidirectional())
//!     .datagram_stream(MyParser);
//! while let Some(_evt) = s.next().await { /* ... */ }
//! # Ok(()) }
//! ```

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ahash::RandomState;
use flowscope::{
    DatagramParser, DatagramParserFactory, FlowEvent, FlowExtractor, FlowTracker,
    FlowTrackerConfig, L4Proto, Orientation, SessionEvent, Timestamp,
};
use futures_core::Stream;

use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::dedup::Dedup;
use crate::error::Error;
use crate::traits::PacketSource;

/// Async stream of [`SessionEvent`]s produced by feeding UDP
/// payloads through a per-flow [`DatagramParser`].
///
/// UDP datagrams are atomic — there is no concept of out-of-order
/// segments or partial frames. The
/// [`FlowTrackerConfig::max_reassembler_buffer`] /
/// [`overflow_policy`](FlowTrackerConfig::overflow_policy) fields are
/// ignored on this stream (they apply to TCP reassembly under
/// [`SessionStream`](super::session_stream::SessionStream) only). The
/// per-flow LRU eviction (`max_flows`) and idle timeouts still apply.
pub struct DatagramStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: DatagramParserFactory<E::Key>,
{
    cap: AsyncCapture<S>,
    tracker: FlowTracker<E, ()>,
    factory: F,
    parsers: HashMap<E::Key, F::Parser, RandomState>,
    pending: VecDeque<SessionEvent<E::Key, <F::Parser as DatagramParser>::Message>>,
    sweep: tokio::time::Interval,
    dedup: Option<Dedup>,
    /// Plan 19: monotonic-timestamp clamp state (`None` = off).
    monotonic_ts: Option<Timestamp>,
}

impl<S, E, F> DatagramStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: DatagramParserFactory<E::Key>,
{
    /// Plan 19: move an existing [`FlowTracker`] into a `DatagramStream`
    /// without rebuilding it. Preserves `idle_timeout_fn` and any
    /// in-flight flow state from the source `FlowStream`.
    pub(crate) fn from_tracker(
        cap: AsyncCapture<S>,
        tracker: FlowTracker<E, ()>,
        factory: F,
        dedup: Option<Dedup>,
        monotonic_ts: Option<Timestamp>,
    ) -> Self {
        let sweep = tokio::time::interval(tracker.config().sweep_interval);
        Self {
            cap,
            tracker,
            factory,
            parsers: HashMap::with_hasher(RandomState::new()),
            pending: VecDeque::new(),
            sweep,
            dedup,
            monotonic_ts,
        }
    }

    /// Replace the inner [`FlowTracker`]'s config in place.
    ///
    /// Mirrors [`FlowStream::with_config`](super::flow_stream::FlowStream::with_config).
    /// Re-arms the sweep timer if `sweep_interval` changed. UDP
    /// datagrams don't use `max_reassembler_buffer` /
    /// `overflow_policy` — those fields are ignored on this stream.
    pub fn with_config(mut self, config: FlowTrackerConfig) -> Self {
        let new_interval = config.sweep_interval;
        self.tracker.set_config(config);
        self.sweep = tokio::time::interval(new_interval);
        self
    }

    /// Apply per-packet deduplication before flow tracking. Useful for
    /// capturing on `lo` where each packet appears twice
    /// ([`PACKET_OUTGOING`](crate::PacketDirection::Outgoing) +
    /// [`PACKET_HOST`](crate::PacketDirection::Host)).
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

    /// Borrow the embedded dedup mutably.
    pub fn dedup_mut(&mut self) -> Option<&mut Dedup> {
        self.dedup.as_mut()
    }

    /// Borrow the inner tracker (stats / introspection).
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        &self.tracker
    }

    /// Override the per-flow idle timeout via a key predicate. See
    /// [`FlowStream::with_idle_timeout_fn`](super::flow_stream::FlowStream::with_idle_timeout_fn).
    pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
    where
        G: Fn(&E::Key, Option<flowscope::L4Proto>) -> Option<std::time::Duration>
            + Send
            + 'static,
    {
        self.tracker.set_idle_timeout_fn(f);
        self
    }

    /// Clamp NIC-supplied timestamps to a running max so the event
    /// stream is strictly non-decreasing in time. See
    /// [`FlowStream::with_monotonic_timestamps`](super::flow_stream::FlowStream::with_monotonic_timestamps).
    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.monotonic_ts = if enable {
            Some(Timestamp::default())
        } else {
            None
        };
        self
    }

    /// Borrow-iterator over live `(K, FlowStats)` pairs.
    pub fn snapshot_flow_stats(
        &self,
    ) -> impl Iterator<Item = (&E::Key, &flowscope::FlowStats)> + '_ {
        self.tracker.all_flow_stats()
    }
}

impl<S, E, F> Stream for DatagramStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd + Unpin,
    E: FlowExtractor + Unpin,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static + Unpin,
    F: DatagramParserFactory<E::Key> + Unpin,
    F::Parser: Unpin,
    <F::Parser as DatagramParser>::Message: Unpin,
{
    type Item = Result<SessionEvent<E::Key, <F::Parser as DatagramParser>::Message>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(ev) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(ev)));
            }

            if this.sweep.poll_tick(cx).is_ready() {
                let now = crate::async_adapters::flow_stream::clamp_now(
                    current_timestamp(),
                    &mut this.monotonic_ts,
                );
                for ev in this.tracker.sweep(now) {
                    convert_event(ev, &mut this.parsers, &mut this.pending);
                }
                if !this.pending.is_empty() {
                    continue;
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
                        // Plan 17: optional pre-tracking dedup.
                        if let Some(d) = this.dedup.as_mut()
                            && !d.keep(&pkt)
                        {
                            continue;
                        }

                        let view = crate::async_adapters::flow_stream::clamp_view(
                            pkt.view(),
                            &mut this.monotonic_ts,
                        );
                        let view_ts = view.timestamp;
                        let frame = view.frame;
                        // Extract before track() so we have orientation
                        // (FlowExtractor::extract is cheap; double call OK).
                        let extracted = this.tracker.extractor().extract(view);
                        let evts = this.tracker.track(view);
                        for ev in evts {
                            convert_event(ev, &mut this.parsers, &mut this.pending);
                        }

                        // For UDP packets, look for an L4 payload and feed the parser.
                        if let Some(extracted) = extracted
                            && extracted.l4 == Some(L4Proto::Udp)
                            && let Some(payload) = peek_udp_payload(frame)
                        {
                            let key = &extracted.key;
                            // Initiator if same orientation as the recorded flow's first
                            // direction, else Responder. Use the FlowSide derived from the
                            // tracker's recorded orientation: the tracker just set it.
                            let side = match extracted.orientation {
                                Orientation::Forward => flowscope::FlowSide::Initiator,
                                Orientation::Reverse => flowscope::FlowSide::Responder,
                            };
                            let parser = this
                                .parsers
                                .entry(key.clone())
                                .or_insert_with(|| this.factory.new_parser(key));
                            let messages = parser.parse(payload, side);
                            for message in messages {
                                this.pending.push_back(SessionEvent::Application {
                                    key: key.clone(),
                                    side,
                                    message,
                                    ts: view_ts,
                                });
                            }
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

fn convert_event<K, P>(
    ev: FlowEvent<K>,
    parsers: &mut HashMap<K, P, RandomState>,
    pending: &mut VecDeque<SessionEvent<K, P::Message>>,
) where
    K: Eq + std::hash::Hash + Clone,
    P: DatagramParser,
{
    match ev {
        FlowEvent::Started { key, ts, .. } => {
            pending.push_back(SessionEvent::Started { key, ts });
        }
        FlowEvent::Ended {
            key, reason, stats, ..
        } => {
            // Datagram parsers have no fin/rst; just drop.
            parsers.remove(&key);
            pending.push_back(SessionEvent::Closed { key, reason, stats });
        }
        FlowEvent::Anomaly { key, kind, ts } => {
            // Plan 19: forward as a typed `SessionEvent::Anomaly`.
            pending.push_back(SessionEvent::Anomaly { key, kind, ts });
        }
        _ => {}
    }
}

fn current_timestamp() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    Timestamp::new(now.as_secs() as u32, now.subsec_nanos())
}

/// Walk Eth → optional VLAN×2 → IPv4/IPv6 → UDP and return the UDP
/// payload. Skips IP fragments and IPv6 extension headers.
fn peek_udp_payload(frame: &[u8]) -> Option<&[u8]> {
    let mut offset = 14usize;
    if frame.len() < offset {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    for _ in 0..2 {
        if ethertype != 0x8100 && ethertype != 0x88a8 {
            break;
        }
        if frame.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    let (proto, l4_offset) = match ethertype {
        0x0800 => {
            if frame.len() < offset + 20 {
                return None;
            }
            let ihl = (frame[offset] & 0x0f) as usize * 4;
            if ihl < 20 || frame.len() < offset + ihl {
                return None;
            }
            let proto = frame[offset + 9];
            let frag = u16::from_be_bytes([frame[offset + 6], frame[offset + 7]]);
            let frag_off = frag & 0x1FFF;
            let mf = (frag & 0x2000) != 0;
            if frag_off != 0 || mf {
                return None;
            }
            (proto, offset + ihl)
        }
        0x86dd => {
            if frame.len() < offset + 40 {
                return None;
            }
            (frame[offset + 6], offset + 40)
        }
        _ => return None,
    };

    if proto != 17 {
        return None;
    }
    if frame.len() < l4_offset + 8 {
        return None;
    }
    let udp_len = u16::from_be_bytes([frame[l4_offset + 4], frame[l4_offset + 5]]) as usize;
    if udp_len < 8 || frame.len() < l4_offset + udp_len {
        return None;
    }
    Some(&frame[l4_offset + 8..l4_offset + udp_len])
}
