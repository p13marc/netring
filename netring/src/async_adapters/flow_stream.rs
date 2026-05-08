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
//! # async fn ex() -> std::io::Result<()> {
//! let cap = AsyncCapture::open("eth0")?;
//! let mut stream = cap.flow_stream(FiveTuple::bidirectional());
//! while let Some(evt) = stream.next().await {
//!     let _evt = evt?;
//!     # break;
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_core::Stream;
use netring_flow::tracker::FlowEvents;
use netring_flow::{FlowEvent, FlowExtractor, FlowTracker, FlowTrackerConfig, Timestamp};

use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::error::Error;
use crate::traits::PacketSource;

/// Stream of [`FlowEvent`]s produced by feeding captured packets
/// through a [`FlowTracker`].
///
/// Created via [`AsyncCapture::flow_stream`]. Consumes the
/// `AsyncCapture`. Use `.with_state(...)` to attach per-flow user
/// state and `.with_config(...)` for non-default tracker config.
pub struct FlowStream<S, E, U = ()>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    U: Send + 'static,
{
    cap: AsyncCapture<S>,
    tracker: FlowTracker<E, U>,
    pending: VecDeque<FlowEvent<E::Key>>,
    sweep: tokio::time::Interval,
}

impl<S, E> FlowStream<S, E, ()>
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
        }
    }

    /// Attach per-flow user state.
    ///
    /// `init` is called once on first sight of each new flow; the
    /// returned value is stored in `FlowEntry::user` and accessible
    /// via [`FlowTracker::get`]/`get_mut`.
    pub fn with_state<U, F>(self, init: F) -> FlowStream<S, E, U>
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
        }
    }
}

impl<S, E, U> FlowStream<S, E, U>
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

impl<S, E, U> Stream for FlowStream<S, E, U>
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
            // 1. Drain pending events first.
            if let Some(evt) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(evt)));
            }

            // 2. Drive the sweep interval (non-blocking).
            if this.sweep.poll_tick(cx).is_ready() {
                let now = current_timestamp();
                for ev in this.tracker.sweep(now) {
                    this.pending.push_back(ev);
                }
                if let Some(evt) = this.pending.pop_front() {
                    return Poll::Ready(Some(Ok(evt)));
                }
            }

            // 3. Pull a batch from the kernel ring.
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

/// Approximate "now" using `SystemTime`. Used by the sweep driver.
/// Imprecise relative to per-packet kernel timestamps; sweep
/// granularity is bounded by `sweep_interval` anyway.
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
    /// Chain `.with_state(...)` and/or `.with_config(...)` to
    /// customize.
    pub fn flow_stream<E>(self, extractor: E) -> FlowStream<S, E, ()>
    where
        E: FlowExtractor,
    {
        FlowStream::new(self, extractor)
    }
}
