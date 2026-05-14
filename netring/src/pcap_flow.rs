//! [`PcapFlowStream`] — flow tracking over offline pcap files.
//!
//! Bridges [`crate::pcap_source::AsyncPcapSource`]'s
//! `OwnedPacket` output to flowscope's `FlowTracker`, yielding
//! [`FlowEvent`]s through the same `Stream` trait as a live
//! [`FlowStream`](crate::FlowStream).
//!
//! Available under `pcap + flow + tokio`. Live and offline pipelines
//! can be unified by writing a generic consumer that takes any
//! `Stream<Item = Result<FlowEvent<K>, Error>>`:
//!
//! ```no_run
//! # use futures::StreamExt;
//! # use netring::flow::extract::FiveTuple;
//! # async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
//! use netring::pcap_source::AsyncPcapSource;
//!
//! let source = AsyncPcapSource::open("trace.pcap").await?;
//! let mut events = source.flow_events(FiveTuple::bidirectional());
//! while let Some(evt) = events.next().await {
//!     let _ = evt?;
//!     # break;
//! }
//! # Ok(()) }
//! ```

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use flowscope::tracker::FlowEvents;
use flowscope::{FlowEvent, FlowExtractor, FlowTracker, FlowTrackerConfig, PacketView, Timestamp};
use futures_core::Stream;

use crate::error::Error;
use crate::pcap_source::AsyncPcapSource;

/// Async stream of [`FlowEvent`]s produced by feeding an offline
/// pcap source through flowscope's [`FlowTracker`]. Mirrors the
/// surface of [`FlowStream`](crate::FlowStream) for the bits that
/// apply to offline replay (no `with_dedup`, since pcap files
/// don't have loopback re-injection; no `capture_stats` since
/// there's no kernel ring).
pub struct PcapFlowStream<E>
where
    E: FlowExtractor,
{
    source: AsyncPcapSource,
    tracker: FlowTracker<E, ()>,
    pending: VecDeque<FlowEvent<E::Key>>,
    /// Set when the upstream source has signaled EOF.
    eof: bool,
}

impl<E> PcapFlowStream<E>
where
    E: FlowExtractor,
    E::Key: Clone + Send + 'static,
{
    pub(crate) fn new(source: AsyncPcapSource, extractor: E) -> Self {
        Self {
            source,
            tracker: FlowTracker::new(extractor),
            pending: VecDeque::new(),
            eof: false,
        }
    }

    /// Replace the inner [`FlowTracker`]'s config.
    pub fn with_config(mut self, config: FlowTrackerConfig) -> Self {
        self.tracker.set_config(config);
        self
    }

    /// Override the per-flow idle timeout via a key predicate.
    /// Mirrors [`FlowStream::with_idle_timeout_fn`](crate::FlowStream::with_idle_timeout_fn).
    pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
    where
        G: Fn(&E::Key, Option<flowscope::L4Proto>) -> Option<Duration> + Send + 'static,
    {
        self.tracker.set_idle_timeout_fn(f);
        self
    }

    /// Borrow the inner tracker for stats / introspection.
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        &self.tracker
    }

    /// Number of packets the upstream source has yielded so far.
    /// Analogue of `capture_stats().packets` for offline replay.
    pub fn packets_read(&self) -> u64 {
        self.source.packets_yielded()
    }
}

impl<E> Stream for PcapFlowStream<E>
where
    E: FlowExtractor + Unpin,
    E::Key: Clone + Unpin,
{
    type Item = Result<FlowEvent<E::Key>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(evt) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(evt)));
            }
            if this.eof {
                // Final sweep: emit any flows still in the tracker as Ended.
                let now = current_timestamp();
                for ev in this.tracker.sweep(now) {
                    this.pending.push_back(ev);
                }
                if let Some(evt) = this.pending.pop_front() {
                    return Poll::Ready(Some(Ok(evt)));
                }
                return Poll::Ready(None);
            }

            // Pull the next OwnedPacket from the source.
            match Pin::new(&mut this.source).poll_next(cx) {
                Poll::Ready(Some(Ok(owned))) => {
                    let view = PacketView::new(&owned.data, owned.timestamp);
                    let evts: FlowEvents<E::Key> = this.tracker.track(view);
                    for ev in evts {
                        this.pending.push_back(ev);
                    }
                    // loop — pop the first pending event next iteration.
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    this.eof = true;
                    // loop — next iteration sweeps + drains tracker.
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncPcapSource {
    /// Consume the source into a [`PcapFlowStream`] that yields
    /// [`FlowEvent`]s from a flowscope [`FlowTracker`].
    pub fn flow_events<E>(self, extractor: E) -> PcapFlowStream<E>
    where
        E: FlowExtractor,
        E::Key: Clone + Send + 'static,
    {
        PcapFlowStream::new(self, extractor)
    }
}

fn current_timestamp() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    Timestamp::new(now.as_secs() as u32, now.subsec_nanos())
}
