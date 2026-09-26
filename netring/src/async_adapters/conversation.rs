//! [`Conversation<K>`] — a TCP flow's two reassembled byte streams as
//! one async iterator.
//!
//! Higher-level than `FlowStream::with_async_reassembler` for the
//! common "give me all the bytes of each flow" case: the
//! [`ConversationStream`] yields a `Conversation` per flow (on the
//! flow's first byte or gap), and each conversation yields that flow's
//! reassembled bytes — in order, retransmissions dropped, losses as
//! [`ConversationChunk::Gap`] — then [`ConversationChunk::Closed`] with
//! the flow's real [`EndReason`].
//!
//! # Quick start
//!
//! Bytes only flow while the [`ConversationStream`] is polled, so
//! consume each conversation on its own task (awaiting a conversation
//! inline, without polling the stream, would wait forever):
//!
//! ```no_run
//! use futures::StreamExt;
//! use netring::AsyncCapture;
//! use netring::async_adapters::conversation::ConversationChunk;
//! use netring::flow::extract::FiveTuple;
//!
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let cap = AsyncCapture::open("eth0")?;
//! let mut convs = cap.flow_stream(FiveTuple::bidirectional())
//!     .into_conversations();
//!
//! while let Some(conv) = convs.next().await {
//!     let mut conv = conv?;
//!     tokio::spawn(async move {
//!         while let Some(chunk) = conv.next_chunk().await {
//!             match chunk {
//!                 ConversationChunk::Initiator(_bytes) => {}
//!                 ConversationChunk::Responder(_bytes) => {}
//!                 ConversationChunk::Gap { side, len } => {
//!                     println!("{side:?} lost {len} bytes");
//!                 }
//!                 ConversationChunk::Closed { reason } => {
//!                     println!("{} <-> {} ended: {reason:?}", conv.key.a, conv.key.b);
//!                 }
//!                 _ => {} // ConversationChunk is #[non_exhaustive]
//!             }
//!         }
//!     });
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Trade-offs
//!
//! - **Backpressure**: each conversation owns an mpsc channel (default
//!   capacity 64 chunks). A conversation nobody reads fills up and
//!   pauses the whole stream — drop it instead (its bytes are then
//!   discarded).
//! - **Memory**: out-of-order data is held by the reassembler until
//!   its hole fills, bounded by
//!   [`FlowTrackerConfig::reassembly_ooo_buffer`](flowscope::FlowTrackerConfig::reassembly_ooo_buffer)
//!   per side; in-order bytes go straight to the channel.
//! - **Per-flow state `S`**: not supported. `into_conversations` is
//!   only available on `FlowStream<C, E, ()>`; compose
//!   `with_async_reassembler` + `with_state` manually for both.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use ahash::RandomState;
use bytes::Bytes;
use flowscope::{EndReason, FlowExtractor, FlowSide};
use futures_core::Stream;
use tokio::sync::mpsc;

use crate::async_adapters::async_reassembler::{
    AsyncReassembler, AsyncReassemblerFactory, ConsumerFuture, ReassemblyStream,
};
use crate::async_adapters::flow_source::AsyncFlowSource;
use crate::async_adapters::flow_stream::FlowStream;
use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::error::Error;
use crate::traits::PacketSource;

/// One item of a [`Conversation`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ConversationChunk {
    /// The Initiator's next in-order bytes.
    Initiator(Bytes),
    /// The Responder's next in-order bytes.
    Responder(Bytes),
    /// `len` bytes of `side` never arrived (capture loss, or data the
    /// peer acknowledged that was not seen); that side's next bytes
    /// start after them.
    Gap {
        /// The side with the hole.
        side: FlowSide,
        /// Missing bytes.
        len: u64,
    },
    /// Reassembly of `side` stopped (per-side buffer cap or memcap):
    /// no more bytes from it. The other side continues.
    SideStopped {
        /// The stopped side.
        side: FlowSide,
        /// Why ([`EndReason::BufferOverflow`]).
        reason: EndReason,
    },
    /// The conversation is over; `next_chunk` returns `None` after it.
    /// `reason` is the flow's [`EndReason`] (FIN, RST, idle timeout,
    /// eviction, …) — [`EndReason::BufferOverflow`] when every side
    /// that sent data was stopped first, [`EndReason::ForceClosed`]
    /// when the [`ConversationStream`] was dropped.
    Closed {
        /// Why the conversation ended.
        reason: EndReason,
    },
}

/// Messages from the per-side consumers to the conversation.
enum Msg {
    Data(FlowSide, Bytes),
    Gap(FlowSide, u64),
    SideStopped(FlowSide, EndReason),
}

/// One flow's bidirectional reassembled byte stream as an async
/// iterator. Iterate with [`Conversation::next_chunk`]; see the
/// [module docs](self).
pub struct Conversation<K> {
    /// The flow key that produced this conversation.
    pub key: K,
    rx: mpsc::Receiver<Msg>,
    end_reason: Arc<Mutex<Option<EndReason>>>,
    closed_emitted: bool,
}

impl<K> Conversation<K> {
    /// The next chunk from either side, or the terminal `Closed`.
    /// Returns `None` after `Closed`.
    pub async fn next_chunk(&mut self) -> Option<ConversationChunk> {
        if self.closed_emitted {
            return None;
        }
        Some(match self.rx.recv().await {
            Some(Msg::Data(FlowSide::Initiator, b)) => ConversationChunk::Initiator(b),
            Some(Msg::Data(FlowSide::Responder, b)) => ConversationChunk::Responder(b),
            Some(Msg::Gap(side, len)) => ConversationChunk::Gap { side, len },
            Some(Msg::SideStopped(side, reason)) => ConversationChunk::SideStopped { side, reason },
            None => {
                self.closed_emitted = true;
                let reason = self
                    .end_reason
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap_or(EndReason::ForceClosed);
                ConversationChunk::Closed { reason }
            }
        })
    }
}

// ── factory + side consumer ─────────────────────────────────────────

/// [`AsyncReassemblerFactory`] that builds one [`Conversation`] per
/// flow and queues it for the [`ConversationStream`].
pub struct ConversationFactory<K>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
{
    pending_emit: Arc<Mutex<VecDeque<Conversation<K>>>>,
    /// Live flows → their shared state, so the second side joins the
    /// first side's conversation. Weak: the senders live in the side
    /// consumers only. Entries are removed when the flow ends.
    in_flight: HashMap<K, Weak<ConvShared>, RandomState>,
    channel_capacity: usize,
}

struct ConvShared {
    tx: mpsc::Sender<Msg>,
    end_reason: Arc<Mutex<Option<EndReason>>>,
}

impl<K> ConversationFactory<K>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
{
    fn new(channel_capacity: usize) -> Self {
        Self {
            pending_emit: Arc::new(Mutex::new(VecDeque::new())),
            in_flight: HashMap::with_hasher(RandomState::new()),
            channel_capacity: channel_capacity.max(1),
        }
    }

    fn pending(&self) -> Arc<Mutex<VecDeque<Conversation<K>>>> {
        self.pending_emit.clone()
    }
}

impl<K> AsyncReassemblerFactory<K> for ConversationFactory<K>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
{
    type Reassembler = ConvSideReassembler;

    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> ConvSideReassembler {
        // The other side's consumer may still be alive; otherwise
        // (first side, or the other side already stopped and was
        // dropped with its conversation closed) start a conversation.
        let shared = match self.in_flight.get(key).and_then(Weak::upgrade) {
            Some(s) => s,
            None => {
                let (tx, rx) = mpsc::channel(self.channel_capacity);
                let end_reason = Arc::new(Mutex::new(None));
                self.pending_emit.lock().unwrap().push_back(Conversation {
                    key: key.clone(),
                    rx,
                    end_reason: end_reason.clone(),
                    closed_emitted: false,
                });
                let s = Arc::new(ConvShared { tx, end_reason });
                self.in_flight.insert(key.clone(), Arc::downgrade(&s));
                s
            }
        };
        ConvSideReassembler { shared, side }
    }

    fn flow_ended(&mut self, key: &K) {
        self.in_flight.remove(key);
    }
}

/// Per-(flow, side) consumer feeding the conversation's channel.
pub struct ConvSideReassembler {
    shared: Arc<ConvShared>,
    side: FlowSide,
}

impl ConvSideReassembler {
    fn send(&self, msg: Msg) -> ConsumerFuture {
        let shared = self.shared.clone();
        Box::pin(async move {
            // Backpressure; a dropped Conversation just discards.
            let _ = shared.tx.send(msg).await;
        })
    }
}

impl AsyncReassembler for ConvSideReassembler {
    fn data(&mut self, bytes: Bytes) -> ConsumerFuture {
        self.send(Msg::Data(self.side, bytes))
    }

    fn gap(&mut self, len: u64) -> ConsumerFuture {
        self.send(Msg::Gap(self.side, len))
    }

    fn close(&mut self, reason: EndReason) -> ConsumerFuture {
        // A side stop is reported in-band and only becomes the
        // conversation's reason if nothing ends it later; the flow's
        // end reason always wins.
        let side_stop = reason == EndReason::BufferOverflow;
        {
            let mut g = self.shared.end_reason.lock().unwrap();
            if !side_stop || g.is_none() {
                *g = Some(reason);
            }
        }
        if side_stop {
            self.send(Msg::SideStopped(self.side, reason))
        } else {
            Box::pin(std::future::ready(()))
        }
    }
}

// ── ConversationStream ──────────────────────────────────────────────

type ConvInnerStream<C, E> =
    ReassemblyStream<C, E, (), ConversationFactory<<E as FlowExtractor>::Key>>;

/// Stream of [`Conversation`]s, one per TCP flow that carries data.
///
/// Polling it drives capture, tracking and reassembly; the flow events
/// themselves are consumed internally. Generic over the packet source
/// (AF_PACKET [`AsyncCapture`] or AF_XDP).
pub struct ConversationStream<C, E>
where
    E: FlowExtractor,
    E::Key: Eq + Hash + Clone + Send + Sync + 'static,
{
    inner: ConvInnerStream<C, E>,
    pending: Arc<Mutex<VecDeque<Conversation<E::Key>>>>,
}

impl<C, E> ConversationStream<C, E>
where
    E: FlowExtractor,
    E::Key: Eq + Hash + Clone + Send + Sync + 'static,
{
    /// The underlying [`ReassemblyStream`] (stats, config).
    pub fn reassembly(&self) -> &ConvInnerStream<C, E> {
        &self.inner
    }
}

impl<C, E> Stream for ConversationStream<C, E>
where
    C: AsyncFlowSource + Unpin,
    E: FlowExtractor + Unpin,
    E::Key: Eq + Hash + Clone + Send + Sync + Unpin + 'static,
{
    type Item = Result<Conversation<E::Key>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(conv) = this.pending.lock().unwrap().pop_front() {
                return Poll::Ready(Some(Ok(conv)));
            }
            // Drive the reassembly stream; the factory queues new
            // conversations as their first bytes are delivered.
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(_evt))) => continue,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => {
                    return Poll::Ready(this.pending.lock().unwrap().pop_front().map(Ok));
                }
                Poll::Pending => {
                    // A consumer call may have queued a conversation
                    // before blocking on its channel.
                    if let Some(conv) = this.pending.lock().unwrap().pop_front() {
                        return Poll::Ready(Some(Ok(conv)));
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

// ── entry points ────────────────────────────────────────────────────

impl<C, E> FlowStream<C, E, ()>
where
    E: FlowExtractor,
    E::Key: Eq + Hash + Clone + Send + Sync + 'static,
{
    /// Convert into a [`ConversationStream`] that yields one
    /// [`Conversation`] per TCP flow carrying data. Per-conversation
    /// channel capacity: 64 chunks.
    pub fn into_conversations(self) -> ConversationStream<C, E> {
        self.into_conversations_with_capacity(64)
    }

    /// [`into_conversations`](Self::into_conversations) with an
    /// explicit per-conversation channel capacity (≥ 1).
    pub fn into_conversations_with_capacity(self, capacity: usize) -> ConversationStream<C, E> {
        let factory = ConversationFactory::<E::Key>::new(capacity);
        let pending = factory.pending();
        let inner = self.with_async_reassembler(factory);
        ConversationStream { inner, pending }
    }
}

impl<S> AsyncCapture<S>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
{
    /// Shortcut for `cap.flow_stream(extractor).into_conversations()`.
    pub fn flow_conversations<E>(self, extractor: E) -> ConversationStream<AsyncCapture<S>, E>
    where
        E: FlowExtractor,
        E::Key: Eq + Hash + Clone + Send + Sync + 'static,
    {
        self.flow_stream(extractor).into_conversations()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn one_conversation_per_flow_and_flow_end_prunes() {
        let mut f = ConversationFactory::<u32>::new(8);
        let pending = f.pending();
        let _a_i = f.new_reassembler(&1u32, FlowSide::Initiator);
        let _a_r = f.new_reassembler(&1u32, FlowSide::Responder);
        let _b_i = f.new_reassembler(&2u32, FlowSide::Initiator);
        let queued: Vec<_> = pending.lock().unwrap().drain(..).map(|c| c.key).collect();
        assert_eq!(queued, vec![1, 2]);
        f.flow_ended(&1);
        f.flow_ended(&2);
        assert!(f.in_flight.is_empty(), "ended flows are forgotten");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunks_and_the_flow_reason_round_trip() {
        let mut f = ConversationFactory::<u32>::new(8);
        let pending = f.pending();
        let mut ri = f.new_reassembler(&7u32, FlowSide::Initiator);
        let mut rr = f.new_reassembler(&7u32, FlowSide::Responder);
        let mut conv = pending.lock().unwrap().pop_front().unwrap();

        ri.data(Bytes::from_static(b"hello")).await;
        rr.gap(3).await;
        rr.data(Bytes::from_static(b"world")).await;
        ri.close(EndReason::IdleTimeout).await;
        rr.close(EndReason::IdleTimeout).await;
        drop((ri, rr));

        assert!(
            matches!(conv.next_chunk().await, Some(ConversationChunk::Initiator(b)) if &b[..] == b"hello")
        );
        assert!(matches!(
            conv.next_chunk().await,
            Some(ConversationChunk::Gap {
                side: FlowSide::Responder,
                len: 3
            })
        ));
        assert!(
            matches!(conv.next_chunk().await, Some(ConversationChunk::Responder(b)) if &b[..] == b"world")
        );
        // The real reason — not `Fin` for an idle timeout.
        assert!(matches!(
            conv.next_chunk().await,
            Some(ConversationChunk::Closed {
                reason: EndReason::IdleTimeout
            })
        ));
        assert!(conv.next_chunk().await.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_side_stop_is_in_band_and_the_flow_reason_wins() {
        let mut f = ConversationFactory::<u32>::new(8);
        let pending = f.pending();
        let mut ri = f.new_reassembler(&7u32, FlowSide::Initiator);
        let mut rr = f.new_reassembler(&7u32, FlowSide::Responder);
        let mut conv = pending.lock().unwrap().pop_front().unwrap();

        ri.close(EndReason::BufferOverflow).await;
        drop(ri);
        rr.data(Bytes::from_static(b"still here")).await;
        rr.close(EndReason::Rst).await;
        drop(rr);

        assert!(matches!(
            conv.next_chunk().await,
            Some(ConversationChunk::SideStopped {
                side: FlowSide::Initiator,
                reason: EndReason::BufferOverflow
            })
        ));
        assert!(matches!(
            conv.next_chunk().await,
            Some(ConversationChunk::Responder(_))
        ));
        assert!(matches!(
            conv.next_chunk().await,
            Some(ConversationChunk::Closed {
                reason: EndReason::Rst
            })
        ));
    }

    /// End to end over real frames: the conversation arrives, its
    /// consumer runs on its own task while the stream keeps being
    /// polled (the documented pattern), bytes come reassembled with the
    /// loss as a gap, and `Closed` carries `Fin`.
    #[tokio::test(flavor = "current_thread")]
    async fn conversation_stream_end_to_end() {
        use crate::async_adapters::async_reassembler::tests::flow;
        use crate::async_adapters::flow_source::VecSource;
        use flowscope::extract::FiveTuple;
        use futures::StreamExt;

        let segs: &[(u32, &[u8])] = &[(0, b"GET "), (4, b"/x "), (7, b"HTTP")];
        let mut frames = flow(segs, 11);
        frames.remove(4); // "/x " is lost

        let mut convs =
            FlowStream::new(VecSource(frames), FiveTuple::bidirectional()).into_conversations();
        let mut conv = tokio::time::timeout(std::time::Duration::from_secs(2), convs.next())
            .await
            .expect("a conversation")
            .unwrap()
            .unwrap();
        let consumer = tokio::spawn(async move {
            let mut out = Vec::new();
            while let Some(c) = conv.next_chunk().await {
                out.push(match c {
                    ConversationChunk::Initiator(b) => format!("I {}", String::from_utf8_lossy(&b)),
                    ConversationChunk::Responder(b) => format!("R {}", String::from_utf8_lossy(&b)),
                    ConversationChunk::Gap { side, len } => format!("gap {side:?} {len}"),
                    ConversationChunk::SideStopped { side, .. } => format!("stop {side:?}"),
                    ConversationChunk::Closed { reason } => format!("closed {reason:?}"),
                });
            }
            out
        });
        // Keep driving the stream (no more conversations come).
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), convs.next()).await;
        let out = consumer.await.unwrap();
        assert_eq!(
            out,
            // The hole is only given up at flow end (the peer's ACK
            // proves the loss, but the grace period runs on packet
            // time), so the reply comes first.
            ["I GET ", "R OK", "gap Initiator 3", "I HTTP", "closed Fin"],
            "{out:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropped_consumers_close_as_force_closed() {
        let mut f = ConversationFactory::<u32>::new(8);
        let pending = f.pending();
        let ri = f.new_reassembler(&7u32, FlowSide::Initiator);
        let mut conv = pending.lock().unwrap().pop_front().unwrap();
        drop(ri);
        assert!(matches!(
            conv.next_chunk().await,
            Some(ConversationChunk::Closed {
                reason: EndReason::ForceClosed
            })
        ));
    }
}
