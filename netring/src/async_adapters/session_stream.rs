//! [`SessionStream`] — async stream of typed L7 messages.
//!
//! Wraps an [`AsyncCapture`] + [`FlowTracker`] + a per-flow
//! [`SessionParser`]. On every TCP segment with payload, the parser
//! is fed bytes via `feed_initiator` / `feed_responder`; whatever
//! messages it returns are surfaced as
//! [`SessionEvent::Application`]. Flow lifecycle is surfaced as
//! [`SessionEvent::Started`] / [`SessionEvent::Closed`].
//!
//! ```no_run
//! # use futures::StreamExt;
//! # use netring::AsyncCapture;
//! # use netring::flow::extract::FiveTuple;
//! # use netring_flow::{FlowSide, SessionEvent, SessionParser};
//! # #[derive(Default, Clone)]
//! # struct MyParser;
//! # impl SessionParser for MyParser {
//! #     type Message = ();
//! #     fn feed_initiator(&mut self, _: &[u8]) -> Vec<()> { Vec::new() }
//! #     fn feed_responder(&mut self, _: &[u8]) -> Vec<()> { Vec::new() }
//! # }
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let cap = AsyncCapture::open("eth0")?;
//! let mut s = cap
//!     .flow_stream(FiveTuple::bidirectional())
//!     .session_stream(MyParser);
//! while let Some(evt) = s.next().await {
//!     match evt? {
//!         SessionEvent::Application { message, .. } => { let _ = message; }
//!         _ => {}
//!     }
//! }
//! # Ok(()) }
//! ```

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ahash::RandomState;
use futures_core::Stream;
use netring_flow::{
    EndReason, FlowEvent, FlowExtractor, FlowSide, FlowTracker, SessionEvent, SessionParser,
    SessionParserFactory, Timestamp,
};

use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::error::Error;
use crate::traits::PacketSource;

/// Async stream of [`SessionEvent`]s produced by feeding TCP byte
/// streams through a per-flow [`SessionParser`].
pub struct SessionStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    cap: AsyncCapture<S>,
    tracker: FlowTracker<E, ()>,
    factory: F,
    parsers: HashMap<E::Key, F::Parser, RandomState>,
    pending: VecDeque<SessionEvent<E::Key, <F::Parser as SessionParser>::Message>>,
    sweep: tokio::time::Interval,
}

impl<S, E, F> SessionStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + std::hash::Hash + Clone + Send + 'static,
    F: SessionParserFactory<E::Key>,
{
    pub(crate) fn new(cap: AsyncCapture<S>, extractor: E, factory: F) -> Self {
        let tracker = FlowTracker::new(extractor);
        let sweep = tokio::time::interval(tracker.config().sweep_interval);
        Self {
            cap,
            tracker,
            factory,
            parsers: HashMap::with_hasher(RandomState::new()),
            pending: VecDeque::new(),
            sweep,
        }
    }

    /// Borrow the inner tracker (stats / introspection).
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        &self.tracker
    }
}

impl<S, E, F> Stream for SessionStream<S, E, F>
where
    S: PacketSource + std::os::unix::io::AsRawFd + Unpin,
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
                let now = current_timestamp();
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
                        let view = pkt.view();
                        let view_ts = view.timestamp;
                        let parsers = &mut this.parsers;
                        let factory = &mut this.factory;
                        let pending = &mut this.pending;
                        let evts =
                            this.tracker
                                .track_with_payload(view, |key, side, _seq, payload| {
                                    if payload.is_empty() {
                                        return;
                                    }
                                    let parser = parsers
                                        .entry(key.clone())
                                        .or_insert_with(|| factory.new_parser(key));
                                    let messages = match side {
                                        FlowSide::Initiator => parser.feed_initiator(payload),
                                        FlowSide::Responder => parser.feed_responder(payload),
                                    };
                                    for message in messages {
                                        pending.push_back(SessionEvent::Application {
                                            key: key.clone(),
                                            side,
                                            message,
                                            ts: view_ts,
                                        });
                                    }
                                });
                        for ev in evts {
                            convert_event(ev, parsers, pending);
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
    P: SessionParser,
{
    match ev {
        FlowEvent::Started { key, ts, .. } => {
            pending.push_back(SessionEvent::Started { key, ts });
        }
        FlowEvent::Ended {
            key, reason, stats, ..
        } => {
            if let Some(mut parser) = parsers.remove(&key) {
                match reason {
                    EndReason::Fin | EndReason::IdleTimeout => {
                        for m in parser.fin_initiator() {
                            pending.push_back(SessionEvent::Application {
                                key: key.clone(),
                                side: FlowSide::Initiator,
                                message: m,
                                ts: stats.last_seen,
                            });
                        }
                        for m in parser.fin_responder() {
                            pending.push_back(SessionEvent::Application {
                                key: key.clone(),
                                side: FlowSide::Responder,
                                message: m,
                                ts: stats.last_seen,
                            });
                        }
                    }
                    EndReason::Rst | EndReason::Evicted => {
                        parser.rst_initiator();
                        parser.rst_responder();
                    }
                }
            }
            pending.push_back(SessionEvent::Closed { key, reason, stats });
        }
        // Lifecycle-internal events (Packet, Established, StateChange) are not
        // surfaced — SessionStream's contract is "messages and lifecycle endpoints".
        _ => {}
    }
}

fn current_timestamp() -> Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    Timestamp::new(now.as_secs() as u32, now.subsec_nanos())
}
