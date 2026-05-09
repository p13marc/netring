//! [`Conversation<K>`] — bundle a flow's two byte streams into a
//! single async iterator.
//!
//! Higher-level than `FlowStream::with_async_reassembler` for the
//! common "give me all the bytes from this flow" case. No spawning,
//! no per-flow channel wiring — `ConversationStream` does it for you
//! and yields a `Conversation` per flow.
//!
//! # Quick start
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
//!     println!("flow {} <-> {}", conv.key.a, conv.key.b);
//!     while let Some(chunk) = conv.next_chunk().await {
//!         match chunk {
//!             ConversationChunk::Initiator(_bytes) => {}
//!             ConversationChunk::Responder(_bytes) => {}
//!             ConversationChunk::Closed { reason } => {
//!                 println!("flow ended: {reason:?}");
//!                 break;
//!             }
//!         }
//!     }
//!     # break;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Trade-offs
//!
//! - **Memory**: each in-flight conversation owns an mpsc channel
//!   (default capacity 64). 100k concurrent flows × 64 slots ≈ tens
//!   of MiB at full capacity. Tune with `into_conversations_with_capacity`.
//! - **Throughput**: one extra mpsc hop per TCP segment. For
//!   message-stream needs at high rates, a `SessionParser` (plan 31)
//!   is more efficient.
//! - **Per-flow state `S`**: not supported. `into_conversations` is
//!   only available on `FlowStream<S, E, (), NoReassembler>`. Users
//!   who need both per-flow state and per-flow byte streams
//!   compose `with_async_reassembler` + `with_state` manually.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use ahash::RandomState;
use bytes::Bytes;
use flowscope::{EndReason, FlowExtractor, FlowSide};
use futures_core::Stream;
use tokio::sync::mpsc;

use crate::async_adapters::async_reassembler::{AsyncReassembler, AsyncReassemblerFactory};
use crate::async_adapters::flow_stream::{AsyncReassemblerSlot, FlowStream, NoReassembler};
use crate::async_adapters::tokio_adapter::AsyncCapture;
use crate::error::Error;
use crate::traits::PacketSource;

/// One byte-chunk or terminal close marker for a conversation.
#[derive(Debug, Clone)]
pub enum ConversationChunk {
    /// Bytes flowing from the Initiator (first-seen direction).
    Initiator(Bytes),
    /// Bytes flowing from the Responder.
    Responder(Bytes),
    /// Flow ended; the iterator will return `None` on the next call.
    Closed {
        /// Why the flow ended (FIN, RST, IdleTimeout, Evicted).
        reason: EndReason,
    },
}

/// One flow's bidirectional byte stream as an async iterator.
///
/// Iterate via [`Conversation::next_chunk`]. The iterator returns
/// `None` after the terminal `Closed` chunk.
pub struct Conversation<K> {
    /// The flow key that produced this conversation.
    pub key: K,
    rx: mpsc::Receiver<(FlowSide, Bytes)>,
    end_reason: Arc<Mutex<Option<EndReason>>>,
    closed_emitted: bool,
}

impl<K> Conversation<K> {
    /// Get the next byte chunk from either side, or the terminal
    /// `Closed` marker. Returns `None` after `Closed`.
    pub async fn next_chunk(&mut self) -> Option<ConversationChunk> {
        if self.closed_emitted {
            return None;
        }
        match self.rx.recv().await {
            Some((FlowSide::Initiator, bytes)) => Some(ConversationChunk::Initiator(bytes)),
            Some((FlowSide::Responder, bytes)) => Some(ConversationChunk::Responder(bytes)),
            None => {
                self.closed_emitted = true;
                let reason = self
                    .end_reason
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap_or(EndReason::IdleTimeout);
                Some(ConversationChunk::Closed { reason })
            }
        }
    }
}

// ── factory + side reassembler ──────────────────────────────────────

/// `AsyncReassemblerFactory` that builds a [`Conversation`] per
/// flow and yields it via the side queue read by `ConversationStream`.
pub struct ConversationFactory<K>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
{
    pending_emit: Arc<Mutex<VecDeque<Conversation<K>>>>,
    /// Map of in-flight flows to a **weak** ref to their shared
    /// state. Weak so the map never keeps the sender alive past the
    /// last reassembler drop. Stale entries linger until the next
    /// lookup or until the next call for the same key replaces them.
    in_flight: Arc<Mutex<HashMap<K, Weak<ConvShared>, RandomState>>>,
    channel_capacity: usize,
}

struct ConvShared {
    tx: mpsc::Sender<(FlowSide, Bytes)>,
    end_reason: Arc<Mutex<Option<EndReason>>>,
}

impl<K> ConversationFactory<K>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
{
    fn new(channel_capacity: usize) -> Self {
        Self {
            pending_emit: Arc::new(Mutex::new(VecDeque::new())),
            in_flight: Arc::new(Mutex::new(HashMap::with_hasher(RandomState::new()))),
            channel_capacity,
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
        let mut in_flight = self.in_flight.lock().unwrap();

        // Try to upgrade any existing weak ref to find this flow's
        // shared state. If the weak ref is stale (last Arc dropped),
        // treat as a fresh flow.
        let shared = match in_flight.get(key).and_then(Weak::upgrade) {
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
                in_flight.insert(key.clone(), Arc::downgrade(&s));
                s
            }
        };

        ConvSideReassembler { shared, side }
    }
}

/// Per-(flow, side) reassembler that pushes bytes into the
/// conversation's shared channel.
pub struct ConvSideReassembler {
    shared: Arc<ConvShared>,
    side: FlowSide,
}

impl AsyncReassembler for ConvSideReassembler {
    fn segment(
        &mut self,
        _seq: u32,
        payload: Bytes,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let shared = self.shared.clone();
        let side = self.side;
        Box::pin(async move {
            // Send with backpressure. If receiver dropped, just discard.
            let _ = shared.tx.send((side, payload)).await;
        })
    }

    fn fin(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let shared = self.shared.clone();
        Box::pin(async move {
            let mut g = shared.end_reason.lock().unwrap();
            if g.is_none() {
                *g = Some(EndReason::Fin);
            }
        })
    }

    fn rst(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let shared = self.shared.clone();
        Box::pin(async move {
            let mut g = shared.end_reason.lock().unwrap();
            *g = Some(EndReason::Rst);
        })
    }
}

// ── ConversationStream ──────────────────────────────────────────────

/// Stream of [`Conversation`]s, one per flow.
///
/// Polls the underlying [`FlowStream`] forward, yielding a new
/// `Conversation` each time the factory observes a new flow.
/// Underlying FlowStream specialization used by `ConversationStream`.
type ConvInnerStream<S, E> = FlowStream<
    S,
    E,
    (),
    AsyncReassemblerSlot<<E as FlowExtractor>::Key, ConversationFactory<<E as FlowExtractor>::Key>>,
>;

/// Stream of [`Conversation`]s, one per flow.
///
/// Polls the underlying [`FlowStream`] forward, yielding a new
/// `Conversation` each time the factory observes a new flow.
pub struct ConversationStream<S, E>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + Hash + Clone + Send + Sync + 'static,
{
    inner: ConvInnerStream<S, E>,
    pending: Arc<Mutex<VecDeque<Conversation<E::Key>>>>,
}

impl<S, E> Stream for ConversationStream<S, E>
where
    S: PacketSource + std::os::unix::io::AsRawFd + Unpin,
    E: FlowExtractor + Unpin,
    E::Key: Eq + Hash + Clone + Send + Sync + Unpin + 'static,
{
    type Item = Result<Conversation<E::Key>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            // Drain newly-built Conversations first.
            {
                let mut p = this.pending.lock().unwrap();
                if let Some(conv) = p.pop_front() {
                    return Poll::Ready(Some(Ok(conv)));
                }
            }
            // Drive the inner FlowStream to push bytes / produce more
            // Conversations. Discard the inner FlowEvent — the
            // factory captured what we need.
            let inner_pinned = Pin::new(&mut this.inner);
            match inner_pinned.poll_next(cx) {
                Poll::Ready(Some(Ok(_evt))) => continue,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ── entry points ────────────────────────────────────────────────────

impl<S, E> FlowStream<S, E, (), NoReassembler>
where
    S: PacketSource + std::os::unix::io::AsRawFd,
    E: FlowExtractor,
    E::Key: Eq + Hash + Clone + Send + Sync + 'static,
{
    /// Convert into a [`ConversationStream`] that yields one
    /// [`Conversation`] per flow.
    ///
    /// Each conversation owns an mpsc channel of default capacity 64
    /// — slow consumers backpressure all the way to the kernel ring.
    pub fn into_conversations(self) -> ConversationStream<S, E> {
        self.into_conversations_with_capacity(64)
    }

    /// Same as [`into_conversations`](Self::into_conversations) with
    /// an explicit per-flow channel capacity.
    pub fn into_conversations_with_capacity(self, capacity: usize) -> ConversationStream<S, E> {
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
    pub fn flow_conversations<E>(self, extractor: E) -> ConversationStream<S, E>
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

    /// Drive a ConversationFactory directly (without a live FlowStream)
    /// to test the per-flow channel wiring + EndReason propagation.
    #[tokio::test(flavor = "current_thread")]
    async fn factory_emits_one_conversation_per_flow() {
        let mut f = ConversationFactory::<u32>::new(8);
        let pending = f.pending();

        // Two new flows: each emits a Conversation when the first
        // side's reassembler is built.
        let _r_a_init = f.new_reassembler(&1u32, FlowSide::Initiator);
        let _r_a_resp = f.new_reassembler(&1u32, FlowSide::Responder);
        let _r_b_init = f.new_reassembler(&2u32, FlowSide::Initiator);

        let queued: Vec<_> = pending.lock().unwrap().drain(..).collect();
        assert_eq!(queued.len(), 2, "expected 2 conversations");
        assert_eq!(queued[0].key, 1);
        assert_eq!(queued[1].key, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn segment_dispatch_round_trips() {
        let mut f = ConversationFactory::<u32>::new(8);
        let pending = f.pending();

        let mut r_init = f.new_reassembler(&7u32, FlowSide::Initiator);
        let mut r_resp = f.new_reassembler(&7u32, FlowSide::Responder);

        let mut conv = pending.lock().unwrap().pop_front().unwrap();

        r_init.segment(0, Bytes::from_static(b"hello")).await;
        r_resp.segment(0, Bytes::from_static(b"world")).await;

        match conv.next_chunk().await.unwrap() {
            ConversationChunk::Initiator(b) => assert_eq!(&*b, b"hello"),
            other => panic!("expected Initiator(hello), got {other:?}"),
        }
        match conv.next_chunk().await.unwrap() {
            ConversationChunk::Responder(b) => assert_eq!(&*b, b"world"),
            other => panic!("expected Responder(world), got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fin_emits_closed_with_fin_reason() {
        let mut f = ConversationFactory::<u32>::new(8);
        let pending = f.pending();

        let mut r_init = f.new_reassembler(&7u32, FlowSide::Initiator);
        let mut r_resp = f.new_reassembler(&7u32, FlowSide::Responder);

        let mut conv = pending.lock().unwrap().pop_front().unwrap();
        r_init.segment(0, Bytes::from_static(b"x")).await;

        // FlowStream's FlowEvent::Ended path: call fin on each side
        // then drop the reassembler.
        r_init.fin().await;
        drop(r_init);
        r_resp.fin().await;
        drop(r_resp);

        // First chunk is the buffered "x"
        let c1 = conv.next_chunk().await.unwrap();
        assert!(matches!(c1, ConversationChunk::Initiator(_)));

        let c2 = conv.next_chunk().await.unwrap();
        assert!(
            matches!(
                c2,
                ConversationChunk::Closed {
                    reason: EndReason::Fin
                }
            ),
            "expected Closed{{Fin}}, got {c2:?}"
        );

        // After Closed, returns None.
        assert!(conv.next_chunk().await.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rst_emits_closed_with_rst_reason() {
        let mut f = ConversationFactory::<u32>::new(8);
        let pending = f.pending();

        let mut r_init = f.new_reassembler(&7u32, FlowSide::Initiator);
        let mut r_resp = f.new_reassembler(&7u32, FlowSide::Responder);

        let mut conv = pending.lock().unwrap().pop_front().unwrap();

        r_init.rst().await;
        drop(r_init);
        r_resp.rst().await;
        drop(r_resp);

        let c = conv.next_chunk().await.unwrap();
        assert!(matches!(
            c,
            ConversationChunk::Closed {
                reason: EndReason::Rst
            }
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unidirectional_flow_works() {
        // Only Initiator side ever fires segments. Responder
        // reassembler exists but never sends. Must still close
        // cleanly when both fin().
        let mut f = ConversationFactory::<u32>::new(8);
        let pending = f.pending();

        let mut r_init = f.new_reassembler(&7u32, FlowSide::Initiator);
        let mut r_resp = f.new_reassembler(&7u32, FlowSide::Responder);

        let mut conv = pending.lock().unwrap().pop_front().unwrap();

        r_init
            .segment(0, Bytes::from_static(b"only-initiator"))
            .await;
        r_init.fin().await;
        drop(r_init);
        r_resp.fin().await;
        drop(r_resp);

        let c1 = conv.next_chunk().await.unwrap();
        assert!(matches!(c1, ConversationChunk::Initiator(_)));
        let c2 = conv.next_chunk().await.unwrap();
        assert!(matches!(
            c2,
            ConversationChunk::Closed {
                reason: EndReason::Fin
            }
        ));
    }
}
